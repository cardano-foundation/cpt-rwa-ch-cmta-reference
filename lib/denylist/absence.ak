use aiken/builtin
use aiken/collection/list
use aiken/primitive/bytearray
use aiken_design_patterns/linked_list.{get_element_info, run_element_with}
use cardano/address.{Address, Script}
use cardano/transaction.{Input}
use constants
use types/denylist.{Denylist}
use utils

/// Pure predicate: given a node's own key (`None` = Root) and its link
/// (`None` = tail sentinel), does this node "cover" `target_pkh` for an
/// absence proof? A node covers `target_pkh` iff
///   node.key < target_pkh  (treating Root as -∞)
/// AND
///   target_pkh < node.link (treating tail as +∞).
///
/// The covering-node pattern is the standard CIP-113 absence-proof idiom (see
/// `registry_mint.ak` in the programmable-tokens reference): the list's sort
/// invariant (ascending keys, maintained by add/remove) lets one node witness
/// absence in O(1). Kept separate so it can be unit-tested without a full
/// Input / Element fixture.
pub fn covers_key(
  covering_key_opt: Option<ByteArray>,
  covering_link: Option<ByteArray>,
  target_pkh: ByteArray,
) -> Bool {
  let covers_from_below = when covering_key_opt is {
    None -> True
    Some(covering_key) -> builtin.less_than_bytearray(covering_key, target_pkh)
  }
  let covers_from_above = when covering_link is {
    None -> True
    Some(next_key) -> builtin.less_than_bytearray(target_pkh, next_key)
  }
  covers_from_below && covers_from_above
}

/// What a party's denylist element proves, given that element's bounds and
/// data (`with_denylist_element`) and the party's bare credential hash.
///
/// The element a party cites is one of exactly two things, and its own key
/// says which:
///
/// * **The party's own node** (`key == Some(party_hash)`): the party IS
///   listed. Its `frozen_amount` decides:
///   - `None` — fully frozen: rejected, whatever side the party is on.
///   - `Some(f)` — partially frozen: `on_partially_frozen(party_hash, f)`
///     decides. Receiving sides pass `fn(_, _) { True }`; the transfer path's
///     senders pass the "paid at least `f` back to themselves" rule.
/// * **Any other element**: it must COVER the party — an absence proof,
///   exactly as before partial freezes existed.
///
/// The two cases cannot both be shown for one hash: keys are unique and
/// strictly ascending, so a listed party's predecessor links TO the party's key
/// and `covers_key` is strict. A listed party cannot prove absence, and an
/// unlisted one has no node of its own.
///
/// The node's data is read with a SOFT cast, deliberately. Every write of node
/// data (`AddToDenylist`, `UpdateDenylistEntry`) decodes strictly and traps on
/// a malformed entry, so a malformed one cannot be in the list; if a reader
/// meets one anyway, the safe answer is to reject this party — returning False
/// does that without trapping the parties a covering element vouches for.
/// Aiken's soft cast is as strict as `expect` (a missing or extra field, or an
/// `Option` with a foreign constructor, does not match).
///
/// `frozen_amount` is read from the authenticated element, never from the
/// redeemer.
///
/// For a node, `key < party_hash` is tested FIRST: that is the covering case
/// every unlisted party takes, and it then costs one comparison instead of an
/// equality test followed by `covers_key`. The decision is the same as testing
/// equality first: `key < party_hash` excludes `key == party_hash`, and a key
/// above the party covers nothing. A listed party pays one comparison more.
/// Pinned by `party_permitted_matches_the_reference_formulation`.
pub fn party_permitted(
  element_key: Option<ByteArray>,
  element_link: Option<ByteArray>,
  element_data: Data,
  party_hash: ByteArray,
  on_partially_frozen: fn(ByteArray, Int) -> Bool,
) -> Bool {
  when element_key is {
    Some(key) ->
      if builtin.less_than_bytearray(key, party_hash) {
        when element_link is {
          None -> True
          Some(next_key) -> builtin.less_than_bytearray(party_hash, next_key)
        }
      } else if key == party_hash {
        if element_data is entry: Denylist {
          when entry.frozen_amount is {
            None -> False
            Some(frozen_amount) ->
              on_partially_frozen(party_hash, frozen_amount)
          }
        } else {
          False
        }
      } else {
        False
      }
    None -> covers_key(None, element_link, party_hash)
  }
}

/// `party_permitted` for a single party, authenticating the element first.
///
/// An unlisted party passes through a covering node; a listed party passes
/// only through its own node's `Some(f)` and `on_partially_frozen`.
pub fn verify_denylist_permits(
  target_pkh: ByteArray,
  element_ref_input_index: Int,
  reference_inputs: List<Input>,
  denylist_policy_id: ByteArray,
  /// The DENYLIST SPEND VALIDATOR's script hash — deliberately not the list
  /// policy id. `denylist_validator` (spend) and `mint` are separate
  /// validators in the same file and therefore have different hashes.
  denylist_script_hash: ByteArray,
  on_partially_frozen: fn(ByteArray, Int) -> Bool,
) -> Bool {
  with_denylist_element(
    element_ref_input_index,
    reference_inputs,
    denylist_policy_id,
    denylist_script_hash,
    fn(element_key, element_link, element_data) {
      party_permitted(
        element_key,
        element_link,
        element_data,
        target_pkh,
        on_partially_frozen,
      )
    },
  )
}

/// Authenticate the denylist element at `element_ref_input_index` and hand its
/// own key (`None` = Root), its link (`None` = tail sentinel) and its data to
/// `continue_with`.
///
/// Authentication is the expensive half of a denylist proof: the library
/// re-reads the UTxO's value to find the list NFT, re-parses the datum and
/// re-derives the key from the asset name — and none of it depends on the
/// party being vetted, only on the reference input. A caller that vets many
/// parties against the same element (`compliance.verify_parties`) can
/// therefore authenticate once and decide per party. The accepted set is
/// identical: the element at a given reference-input index is one immutable
/// UTxO for the whole transaction, so its key, link and data cannot differ
/// between parties. Continuation style rather than returning a tuple keeps the
/// single-party path free of any extra allocation.
///
/// The library authenticates the element: a genuine single-NFT UTxO of
/// `denylist_policy_id`, holding exactly ADA plus that one NFT, with a
/// well-formed `Element` datum and the correct `"Node"` key prefix. It hands
/// back the element's address, its own key, its data and its link.
///
/// Authentication says nothing about WHERE the element sits, so we pin the
/// address ourselves. Without that, one denylist NFT in a private wallet would
/// authenticate whatever datum its holder writes — and since the key is fixed
/// by the NFT's asset name but the LINK and the DATA come from the datum, a
/// wallet-held node keyed at 00…00 with `link: None` would certify absence for
/// every address on chain, and a wallet-held copy of a holder's own node could
/// claim any frozen amount. Requiring the element to still live at the list's
/// own spend address is what makes "authenticated" mean "in the list".
///
/// Fails loudly (UPLC error) if the reference input does not carry the denylist
/// NFT, has a malformed `Element` datum, or does not sit at
/// `denylist_script_hash`.
pub fn with_denylist_element(
  element_ref_input_index: Int,
  reference_inputs: List<Input>,
  denylist_policy_id: ByteArray,
  denylist_script_hash: ByteArray,
  continue_with: fn(Option<ByteArray>, Option<ByteArray>, Data) -> a,
) -> a {
  let element_ref = utils.safe_list_at(
    reference_inputs,
    element_ref_input_index,
  )
  get_element_info(
    element_ref.output,
    fn(address, _lovelace, node_key, data, link) {
      expect Address { payment_credential: Script(element_script), .. } = address
      expect element_script == denylist_script_hash
      continue_with(node_key, link, data)
    },
  )
    |> run_element_with(
        denylist_policy_id,
        constants.linked_list_root_key,
        constants.linked_list_node_key_prefix,
        constants.linked_list_node_key_prefix_length,
      )
}

// ============================================================================
// Tests — `covers_key` structural cases
// ============================================================================
//
// The unit tests below exercise `covers_key` in isolation with hand-supplied
// link values. Keep in mind what that does NOT cover: the link-reading bug this
// function was once subject to lived in what `with_denylist_element` FEEDS
// `covers_key`, not in `covers_key` itself, so no amount of testing here would
// have caught it. Full `verify_denylist_permits` coverage — an authentic
// denylist Input with the correct NFT and inline Element datum, over a
// multi-node list — lives in `validators/regression.ak`, because a test module
// that imports validators must live in `validators/`. Keep both: this file
// proves the predicate, that one proves the plumbing.

const pkh_low: ByteArray =
  #"00000000000000000000000000000000000000000000000000000000"

const pkh_mid: ByteArray =
  #"88888888888888888888888888888888888888888888888888888888"

const pkh_high: ByteArray =
  #"ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

// Root covers everything: no predecessor, no successor (empty list).
test covers_empty_list_from_root() {
  covers_key(None, None, pkh_mid) == True
}

// Root with a successor covers any target < successor.
test covers_root_before_head() {
  covers_key(None, Some(pkh_high), pkh_mid) == True
}

// Root with a successor does NOT cover a target >= successor.
test covers_root_before_head_sad() {
  covers_key(None, Some(pkh_low), pkh_mid) == False
}

// Node with key < target and next > target covers.
test covers_middle() {
  covers_key(Some(pkh_low), Some(pkh_high), pkh_mid) == True
}

// Tail node (key < target, link = None) covers.
test covers_tail() {
  covers_key(Some(pkh_low), None, pkh_mid) == True
}

// Node whose key equals target does not cover (target is present).
test covers_target_equal_key_sad() {
  covers_key(Some(pkh_mid), None, pkh_mid) == False
}

// Node whose link equals target does not cover (target is the successor).
test covers_target_equal_link_sad() {
  covers_key(Some(pkh_low), Some(pkh_mid), pkh_mid) == False
}

// Node whose key is greater than target does not cover.
test covers_key_above_target_sad() {
  covers_key(Some(pkh_high), None, pkh_mid) == False
}

// ============================================================================
// Tests — `party_permitted` equals its earlier, equality-first formulation
// ============================================================================
//
// `party_permitted` tests `key < party_hash` before `key == party_hash` to save
// a comparison on the covering path. This pins that the reorder decides exactly
// what the equality-first body (c025bec) decided, verbatim below, over an
// EXHAUSTIVE domain rather than a sample: keys, links and parties from a set
// that includes the empty string and prefix pairs (so ordering by length
// occurs), every entry shape a node can carry — well-formed or not — and
// callbacks that depend on both arguments and answer both ways, so calling the
// callback in a different case or with a different amount shows up.

fn reference_party_permitted(
  element_key: Option<ByteArray>,
  element_link: Option<ByteArray>,
  element_data: Data,
  party_hash: ByteArray,
  on_partially_frozen: fn(ByteArray, Int) -> Bool,
) -> Bool {
  when element_key is {
    Some(key) ->
      if key == party_hash {
        if element_data is entry: Denylist {
          when entry.frozen_amount is {
            None -> False
            Some(frozen_amount) ->
              on_partially_frozen(party_hash, frozen_amount)
          }
        } else {
          False
        }
      } else {
        covers_key(element_key, element_link, party_hash)
      }
    None -> covers_key(None, element_link, party_hash)
  }
}

const eq_bytes: List<ByteArray> =
  [#"", #"00", #"01", #"0100", #"0101", #"01ff", #"02", #"ff", #"ff00"]

fn eq_entries() -> List<Data> {
  [
    as_data(Denylist { frozen_amount: None, metadata: as_data(#"") }),
    as_data(Denylist { frozen_amount: Some(0), metadata: as_data(#"") }),
    as_data(Denylist { frozen_amount: Some(7), metadata: as_data(1) }),
    as_data(Denylist { frozen_amount: Some(8), metadata: as_data(1) }),
    // An `Option` with a foreign constructor.
    builtin.constr_data(0, [builtin.constr_data(2, []), as_data(1)]),
    // A missing field.
    builtin.constr_data(0, [builtin.constr_data(0, [as_data(7)])]),
    // The wrong outer constructor.
    builtin.constr_data(1, [builtin.constr_data(0, [as_data(7)]), as_data(1)]),
    as_data(1),
    as_data(#"00"),
  ]
}

// Selected by index: a function cannot be an element of a `List`.
fn eq_callback(i: Int) -> fn(ByteArray, Int) -> Bool {
  if i == 0 {
    fn(_, _) { True }
  } else if i == 1 {
    fn(_, _) { False }
  } else if i == 2 {
    fn(h, f) { f > 7 && bytearray.length(h) > 1 }
  } else {
    fn(h, f) { f == 7 || h == #"01" }
  }
}

test party_permitted_matches_the_reference_formulation() {
  let bounds = [None, ..list.map(eq_bytes, Some)]
  list.all(
    bounds,
    fn(key) {
      list.all(
        bounds,
        fn(link) {
          list.all(
            eq_bytes,
            fn(party) {
              list.all(
                eq_entries(),
                fn(data) {
                  list.all(
                    [0, 1, 2, 3],
                    fn(i) {
                      party_permitted(key, link, data, party, eq_callback(i)) == reference_party_permitted(
                        key,
                        link,
                        data,
                        party,
                        eq_callback(i),
                      )
                    },
                  )
                },
              )
            },
          )
        },
      )
    },
  )
}
