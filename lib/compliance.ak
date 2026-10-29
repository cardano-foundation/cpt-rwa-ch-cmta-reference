use cardano/address.{Credential}
use cardano/transaction.{Transaction}
use denylist/absence.{
  party_permitted, verify_denylist_permits, with_denylist_element,
}
use kyc/verify.{verify_kyc_proof}
use types/global_state.{GlobalStateDatum}
use types/kyc_proof.{KycProof}
use utils

/// Vet one party per compliance action, walking both lists in LOCKSTEP.
///
/// Every party that sends or receives the security token has to clear the same
/// two gates — the denylist, and KYC when the corresponding GlobalState flag is
/// set — and the redeemer supplies one action per party, positionally.
///
/// The denylist gate (`absence.party_permitted`): the element a party's action
/// cites is either a covering node (the party is not listed: pass) or the
/// party's OWN node. An own node with `frozen_amount: None` rejects; with
/// `Some(f)` it hands `(party_hash, f)` to `on_partially_frozen`, which is the
/// only thing that differs between the sides — receivers pass
/// `fn(_, _) { True }`, the transfer path's senders pass the paid-back rule.
/// Three call sites need exactly this: the transfer path's senders, the
/// transfer path's destinations, and the seizure path's destinations. They used
/// to carry three copies of it.
///
/// Two reasons this is one shared function rather than three near-copies:
///
/// 1. **Correctness drift.** The three copies differed only in which field of
///    the action they read (`source_*` vs `destination_*`). That is precisely
///    the kind of difference a copy-paste gets wrong silently — and this
///    codebase has already had one such regression, where the sender gate read
///    the receiver's KYC flag. The accessors are now passed in, so the
///    difference is one argument at the call site instead of a duplicated body.
///
/// 2. **Cost.** The copies paired party `i` with action `i` using
///    `safe_list_at(actions, i)` inside a fold. `safe_list_at` walks from the
///    head, so aligning n parties cost Σi = O(n²) list steps — pure indexing
///    overhead. Consuming both lists together is O(n).
///
/// FAILS CLOSED on a short action list: `expect [action, ..rest] = actions`
/// traps when the redeemer supplies fewer actions than there are parties, which
/// is the same outcome the old `safe_list_at` produced when it ran off the end.
/// A `list.zip` would instead truncate silently and skip the checks for the
/// unmatched parties — do not "simplify" this into one.
///
/// Extra actions beyond the last party are ignored, exactly as before: they
/// authorise nothing on their own, since every party is checked against the
/// action at its own position.
pub fn verify_parties(
  parties: List<Credential>,
  actions: List<action>,
  proof_of: fn(action) -> KycProof,
  denylist_index_of: fn(action) -> Int,
  on_partially_frozen: fn(ByteArray, Int) -> Bool,
  requires_kyc: Bool,
  gs_datum: GlobalStateDatum,
  issuance_policy_id: ByteArray,
  denylist_script_hash: ByteArray,
  self: Transaction,
) -> Bool {
  when parties is {
    [] -> True
    [party, ..rest_parties] -> {
      expect [action, ..rest_actions] = actions
      and {
        kyc_ok(
          party,
          action,
          proof_of,
          requires_kyc,
          gs_datum,
          issuance_policy_id,
          self,
        ),
        when rest_parties is {
          // One party on this side — by far the commonest shape — takes the
          // plain proof with no memo machinery at all, so it costs exactly
          // what it did before the memo existed.
          [] ->
            verify_denylist_permits(
              utils.credential_hash(party),
              denylist_index_of(action),
              self.reference_inputs,
              gs_datum.denylist_linked_list_policy_id,
              denylist_script_hash,
              on_partially_frozen,
            )
          // Several parties: authenticate this party's element and start the
          // walk with it remembered (`vet_remembering`).
          _ -> {
            let element_index = denylist_index_of(action)
            with_denylist_element(
              element_index,
              self.reference_inputs,
              gs_datum.denylist_linked_list_policy_id,
              denylist_script_hash,
              fn(element_key, element_link, element_data) {
                and {
                  // The denylist keys on the BARE HASH: listing a hash must
                  // list both credential forms, which is the conservative
                  // direction. Only the KYC path distinguishes them.
                  party_permitted(
                    element_key,
                    element_link,
                    element_data,
                    utils.credential_hash(party),
                    on_partially_frozen,
                  ),
                  vet_remembering(
                    rest_parties,
                    rest_actions,
                    proof_of,
                    denylist_index_of,
                    on_partially_frozen,
                    requires_kyc,
                    gs_datum,
                    issuance_policy_id,
                    denylist_script_hash,
                    self,
                    element_index,
                    element_key,
                    element_link,
                    element_data,
                  ),
                }
              },
            )
          }
        },
      }
    }
  }
}

/// KYC first, then the denylist. Deliberate, and measured: an earlier revision
/// put the cheaper denylist check first as a "cheap gate first" optimisation
/// and benchmarking made the invalid-KYC reject path ~13% MORE expensive,
/// because the denylist proof it then ran first was work the KYC failure would
/// have made unnecessary.
fn kyc_ok(
  party: Credential,
  action: action,
  proof_of: fn(action) -> KycProof,
  requires_kyc: Bool,
  gs_datum: GlobalStateDatum,
  issuance_policy_id: ByteArray,
  self: Transaction,
) -> Bool {
  if requires_kyc {
    verify_kyc_proof(
      proof_of(action),
      party,
      gs_datum,
      issuance_policy_id,
      gs_datum.network_id,
      self,
    )
  } else {
    True
  }
}

/// The walk after the first of several parties: `last_index` / `last_key` /
/// `last_link` / `last_data` are the reference-input index, bounds and data of
/// the denylist element this walk most recently authenticated. A party citing
/// the same index reuses them; any other index is authenticated afresh and
/// becomes the remembered element.
///
/// Authenticating an element — the library re-reading the UTxO's value,
/// re-parsing its datum, re-deriving its key — was the dominant per-party cost,
/// and it depends only on the reference input, never on the party. A
/// transaction with a short denylist cites the same covering node for most or
/// all of its parties, so the node was being authenticated once PER PARTY for
/// the same bytes. Now a party that cites the index the previous party cited
/// pays only the per-party decision, `party_permitted`.
///
/// Why only the last element and not a map of all of them: four plain arguments
/// cost nothing to carry, whereas a lookup structure costs an allocation per
/// call even for the one-party transfers that dominate real traffic. A builder
/// that orders parties so that those sharing a node are adjacent gets the full
/// benefit; one that interleaves merely pays what it pays today.
///
/// This cannot widen the accepted set: the element at a given index is one
/// immutable UTxO for the whole transaction, so re-authenticating it would
/// return the same bounds (or trap the same way), and the remembered element
/// is ALWAYS one this walk authenticated — `verify_parties` seeds it from its
/// own authentication, this function is private, and there is no "nothing yet"
/// sentinel a redeemer could collide with. A party citing an index that fails
/// authentication still traps, on its first use.
///
/// Why the fresh-element case is written out here rather than in a helper: the
/// walk is then a SELF-recursive function, whose eight arguments that never
/// change are not re-applied per party by the compiled code. With a helper the
/// two functions recursed into each other and paid for every argument on every
/// party (measured: about 2% of memory at 30 parties per side). In the
/// fresh-element arm both the remembered `last_*` and the new `element_*` are
/// in scope: the decision and the recursion take `element_*`, never `last_*`
/// (pinned by `memo_never_judges_a_party_against_another_index_element` and
/// `memo_never_judges_a_party_against_a_stale_element`).
fn vet_remembering(
  parties: List<Credential>,
  actions: List<action>,
  proof_of: fn(action) -> KycProof,
  denylist_index_of: fn(action) -> Int,
  on_partially_frozen: fn(ByteArray, Int) -> Bool,
  requires_kyc: Bool,
  gs_datum: GlobalStateDatum,
  issuance_policy_id: ByteArray,
  denylist_script_hash: ByteArray,
  self: Transaction,
  last_index: Int,
  last_key: Option<ByteArray>,
  last_link: Option<ByteArray>,
  last_data: Data,
) -> Bool {
  when parties is {
    [] -> True
    [party, ..rest_parties] -> {
      expect [action, ..rest_actions] = actions
      and {
        kyc_ok(
          party,
          action,
          proof_of,
          requires_kyc,
          gs_datum,
          issuance_policy_id,
          self,
        ),
        // Bound inside this conjunct, so a party failing KYC evaluates no
        // more than it did before.
        {
          let element_index = denylist_index_of(action)
          if element_index == last_index {
            // Only the ELEMENT is remembered, never a verdict: whether it is
            // this party's own node, and what that means, is decided afresh for
            // this party's hash. A node one party proved membership with can
            // only ever cover — or reject — anyone else.
            and {
              party_permitted(
                last_key,
                last_link,
                last_data,
                utils.credential_hash(party),
                on_partially_frozen,
              ),
              vet_remembering(
                rest_parties,
                rest_actions,
                proof_of,
                denylist_index_of,
                on_partially_frozen,
                requires_kyc,
                gs_datum,
                issuance_policy_id,
                denylist_script_hash,
                self,
                last_index,
                last_key,
                last_link,
                last_data,
              ),
            }
          } else {
            with_denylist_element(
              element_index,
              self.reference_inputs,
              gs_datum.denylist_linked_list_policy_id,
              denylist_script_hash,
              fn(element_key, element_link, element_data) {
                and {
                  // The denylist keys on the BARE HASH: listing a hash must list
                  // both credential forms, which is the conservative direction.
                  // Only the KYC path distinguishes them.
                  party_permitted(
                    element_key,
                    element_link,
                    element_data,
                    utils.credential_hash(party),
                    on_partially_frozen,
                  ),
                  vet_remembering(
                    rest_parties,
                    rest_actions,
                    proof_of,
                    denylist_index_of,
                    on_partially_frozen,
                    requires_kyc,
                    gs_datum,
                    issuance_policy_id,
                    denylist_script_hash,
                    self,
                    element_index,
                    element_key,
                    element_link,
                    element_data,
                  ),
                }
              },
            )
          }
        },
      }
    }
  }
}
