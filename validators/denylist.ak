use aiken/builtin
use aiken/collection/dict
use aiken/collection/list
use aiken/interval.{Interval, IntervalBound, NegativeInfinity, PositiveInfinity}
use aiken/primitive/bytearray
use aiken_design_patterns/linked_list.{
  Element, Node, Root, deinit, init, insert_ascending, remove, run_element_with,
  run_root_with, spend_for_adding_or_removing_an_element,
  spend_for_updating_elements_data,
}
use cardano/address.{Address, Script, VerificationKey}
use cardano/assets.{
  Assets, PolicyId, from_asset, from_lovelace, merge, tokens, zero,
}
use cardano/transaction.{
  InlineDatum, Input, NoDatum, Output, OutputReference, Transaction, find_input,
}
use constants
use tests
use types/denylist.{
  AddToDenylist, Deinit, Denylist, Init, InitAfterGenesis, MintRedeemer,
  RemoveFromDenylist, SpendRedeemer, StateTransition, UpdateDenylistEntry,
  valid_frozen_amount,
}
use types/global_state.{
  GlobalStateDatum, genesis_global_state, gs_core_from_ref_input,
}
use types/power_users.{PowerUser}
use utils.{must_be_signed_by_credential}

/// Resolves the GS reference input (for the power-user linked-list policy id)
/// and the power-user node reference input at `power_user_node_ref_input_index`,
/// authenticating the node against that list. Returns the node's credential hash
/// and parsed `PowerUser` data. Callers gate sanctions on `is_admin` + the
/// returned credential's signature.
fn power_user_from_refs(
  self: Transaction,
  global_state_ref_input_index: Int,
  global_state_policy_id: ByteArray,
  power_user_node_ref_input_index: Int,
) -> (ByteArray, PowerUser) {
  let gs = gs_core_from_ref_input(
    self.reference_inputs,
    global_state_ref_input_index,
    global_state_policy_id,
  )
  // No sanctions administration on a decommissioned protocol.
  expect !gs.deactivated
  let power_user_node_ref_input = utils.safe_list_at(
    self.reference_inputs,
    power_user_node_ref_input_index,
  )
  let (power_user_credential_hash, power_user_data) = utils.authenticated_power_user(
    power_user_node_ref_input.output,
    gs.power_user_linked_list_policy_id,
  )
  // Never the GlobalState logic named in field 0: its withdrawal would sign
  // for the operator. Today it cannot appear here — it needs GlobalState
  // SPENT (or, once, minted at genesis, before any GlobalState exists to
  // read), and this reads GlobalState as a reference input, which the ledger
  // keeps disjoint from the inputs — but that is a ledger rule, not ours.
  expect power_user_credential_hash != gs.global_state_script_credential_hash
  (power_user_credential_hash, power_user_data)
}

/// The only parameter is the GlobalState policy, `mint`'s first. This list's
/// own policy id is not a parameter: the mint takes this validator's hash, so
/// the spend reads the policy off the element it spends.
validator denylist_validator(
  /// Needed only by `UpdateDenylistEntry`, which — unlike Add/Remove — runs no
  /// mint and so must authorise the sanctions officer here. Not circular: the
  /// GlobalState policy depends on neither denylist hash.
  global_state_policy_id: ByteArray,
) {
  spend(
    _datum_opt: Option<Data>,
    redeemer: SpendRedeemer,
    input_out_ref: OutputReference,
    self: Transaction,
  ) {
    // This list's policy id is not a parameter: the list mint takes this
    // validator's hash, so taking the policy id back would be circular. It is
    // read off the UTxO being spent instead, which must hold lovelace plus
    // exactly one NFT (`utils.sole_nft_policy_id` traps on any other shape).
    //
    // That also binds every arm to a UTxO shaped like a list element. A stray
    // value-bearing UTxO parked at the list address with no token at all —
    // not list state — cannot ride along with a genuine list mutation
    // elsewhere in the same transaction: it traps here. A UTxO holding some
    // other policy's NFT yields that other policy, so its spend is decided by
    // that policy's mint, never by this list's; readers name this list's
    // policy, so such a UTxO is never list state either.
    expect Some(own_input) = find_input(self.inputs, input_out_ref)
    let denylist_linked_list_policy_id = utils.sole_nft_policy_id(
      own_input.output.value,
    )
    when redeemer is {
      StateTransition ->
        // Delegate to the mint validator: the library's gate requires a mint
        // or burn under this list's policy, so the list mint runs and proves
        // the exact transition.
        spend_for_adding_or_removing_an_element(
          denylist_linked_list_policy_id,
          self.mint,
        )
      UpdateDenylistEntry {
        own_input_index,
        own_output_index,
        global_state_ref_input_index,
        power_user_node_ref_input_index,
      } -> {
        // Change a node's frozen amount and/or metadata IN PLACE. Removing and
        // re-adding cannot do this: the burn and the re-mint of the same node
        // NFT cancel out in one transaction, so it would take two, with the
        // holder unlisted in between.
        //
        // Gated exactly like Add/Remove: a power user holding `is_admin`,
        // signed by that user, on a protocol that is not deactivated.
        let (power_user_credential_hash, power_user_data) = power_user_from_refs(
          self,
          global_state_ref_input_index,
          global_state_policy_id,
          power_user_node_ref_input_index,
        )
        and {
          power_user_data.is_admin?,
          must_be_signed_by_credential(self, power_user_credential_hash)?,
          // The library binds this spend to its own input (`one_to_one` on
          // `input_out_ref`), forbids any list-policy mint in the transaction
          // — which is what keeps this apart from `StateTransition` — and
          // requires the continuation to keep the address, the NFT (so the
          // key), the element constructor and the link. What it leaves to us
          // is the lovelace change and the data.
          //
          // There is no "wanted state" in the redeemer, unlike
          // `ModifyPowerUser`: the officer's signature covers the whole
          // transaction body, the continuation's datum included.
          spend_for_updating_elements_data(
            own_input_index,
            own_output_index,
            input_out_ref,
            self.inputs,
            self.outputs,
            self.mint,
            fn(
              _address,
              lovelace_change,
              node_key_opt,
              _old_data,
              new_data,
              _link,
            ) {
              // Nodes only: the root carries no entry, and its data is frozen
              // for life by insert and remove.
              expect Some(_node_key) = node_key_opt
              // Strict: malformed data must never enter the list. A reader
              // meeting it would reject the holder outright, but a write is
              // where it is refused.
              expect denylist_data: Denylist = new_data
              and {
                valid_frozen_amount(denylist_data.frozen_amount)?,
                (bytearray.length(
                  builtin.serialise_data(denylist_data.metadata),
                ) <= constants.max_denylist_metadata_bytes)?,
                // The node's ADA is the list's, not the officer's to take.
                (lovelace_change >= 0)?,
              }
            },
          )
            |> run_element_with(
                denylist_linked_list_policy_id,
                constants.linked_list_root_key,
                constants.linked_list_node_key_prefix,
                constants.linked_list_node_key_prefix_length,
              ),
        }
      }
    }
  }

  else(_) {
    fail
  }
}

validator mint(
  global_state_policy_id: ByteArray,
  init_input_out_ref: OutputReference,
  /// The DENYLIST SPEND VALIDATOR's script hash: where every NFT of this
  /// policy must live. Not circular: the spend validator reads the list policy
  /// off the element it spends, so its hash depends only on the GlobalState
  /// policy.
  list_script_hash: ByteArray,
) {
  mint(redeemer: MintRedeemer, policy_id: PolicyId, self: Transaction) {
    when redeemer is {
      Init { root_output_index } -> {
        // Nonce-gated. GS is only being created in this same transaction (it is
        // an output, not yet an input) — the operator-held one-shot UTxO is the
        // implicit gate, same pattern as power_users.
        let nonce_validated = list.any(
          self.inputs,
          fn(input) { input.output_reference == init_input_out_ref },
        )
        let root_output = utils.safe_list_at(self.outputs, root_output_index)
        and {
          dict.size(tokens(self.mint, policy_id)) == 1,
          // Genesis: no list node exists yet, so none may be spent.
          (utils.count_inputs_with_policy(self.inputs, policy_id) == 0)?,
          // Genesis binding: the GlobalState minted in this same transaction
          // must name THIS list. The GlobalState mint only checks that the
          // policy its datum names mints something, and the id changes
          // afterwards only through `MigrateLists`, before `LockUpgrades` — so
          // a deployment naming another list would leave this one, and the
          // role or sanctions checks it carries, unreachable. Not circular:
          // the GlobalState policy is a parameter here.
          (genesis_global_state(self.outputs, global_state_policy_id).denylist_linked_list_policy_id == policy_id)?,
          creates_the_root(
            self,
            nonce_validated,
            root_output,
            policy_id,
            list_script_hash,
          ),
        }
      }
      InitAfterGenesis { root_output_index, global_state_ref_input_index } -> {
        // A NEW INSTANCE OF THIS LIST AFTER GENESIS, so that `MigrateLists`
        // has a list built from this repository to switch to — same rule and
        // the same reasoning as the power-users list's `InitAfterGenesis`.
        // `Init` cannot serve: it needs the GlobalState minted in the same
        // transaction to name this policy, and once GlobalState exists only
        // `MigrateLists` writes that field, which needs this root first.
        //
        // Each instance is a mint applied with its own `init_input_out_ref`,
        // so its own policy id, and this branch spends that one-shot UTxO
        // like `Init`: an instance has one root, created once. Gated by the
        // GlobalState admin, not by an `is_admin` power user: choosing a new
        // list is the admin's, as `MigrateLists` is.
        //
        // Not gated on `upgrades_locked`: this script can never be redeployed
        // and reads only the GlobalState core, which does not hold the lock.
        // A list created after `LockUpgrades` is inert, because `MigrateLists`
        // is closed then and no reader authenticates under its policy.
        //
        // `gs_core_from_ref_input` with an explicit `deactivated` conjunct,
        // as `Deinit` reads it: a decommissioned protocol gets no new list.
        let gs = gs_core_from_ref_input(
          self.reference_inputs,
          global_state_ref_input_index,
          global_state_policy_id,
        )
        let nonce_validated = list.any(
          self.inputs,
          fn(input) { input.output_reference == init_input_out_ref },
        )
        let root_output = utils.safe_list_at(self.outputs, root_output_index)
        and {
          (!gs.deactivated)?,
          must_be_signed_by_credential(self, gs.admin_credential_hash)?,
          dict.size(tokens(self.mint, policy_id)) == 1,
          // A new list: no element of this policy exists yet, so none may be
          // spent.
          (utils.count_inputs_with_policy(self.inputs, policy_id) == 0)?,
          creates_the_root(
            self,
            nonce_validated,
            root_output,
            policy_id,
            list_script_hash,
          ),
        }
      }
      Deinit { global_state_ref_input_index } -> {
        // POST-DECOMMISSION CLEANUP ONLY.
        //
        // Burning the root is irreversible: `Init` is gated on a one-shot UTxO
        // consumed at genesis, so a root can never be re-created. Only
        // `MigrateLists` writes `denylist_linked_list_policy_id`, admin-signed
        // and before `LockUpgrades`, and it needs GlobalState spent — so after
        // the lock, or once deactivated, GlobalState can never be pointed at a
        // replacement list either.
        //
        // What that costs while the protocol is LIVE: every movement of the
        // security token needs a covering node of THIS list as a reference
        // input — the transfer path, the seizure path and every mint
        // destination all go through `lib/denylist/absence.ak`. With no root
        // there is no element to cover anything, so a `Deinit` on a live
        // protocol freezes the register — until a `MigrateLists` before the
        // lock, for good after it — while the token still reports itself
        // active. That is a worse state than decommissioning,
        // because it is invisible: `deactivated` stays False.
        //
        // Requiring `deactivated` first forces the two irreversible decisions
        // into the only honest order — retire the token, then dismantle its
        // lists — and makes this branch what its name suggests: cleanup, not a
        // kill switch.
        //
        // Read with `gs_core_from_ref_input`, NOT `active_admin_from_ref_input`:
        // the latter traps on a deactivated protocol, which is exactly the
        // state this branch now requires. The GlobalState UTxO can no longer be
        // spent once deactivated, but it is still readable as a reference
        // input, so the admin credential remains available here.
        let gs = gs_core_from_ref_input(
          self.reference_inputs,
          global_state_ref_input_index,
          global_state_policy_id,
        )
        and {
          gs.deactivated?,
          must_be_signed_by_credential(self, gs.admin_credential_hash),
          dict.size(tokens(self.mint, policy_id)) == 1,
          // Only the root is spent, and `deinit` already requires the list to
          // be empty. See the note on the Add branch for why this count is
          // kept alongside the library's own scan.
          (utils.count_inputs_with_policy(self.inputs, policy_id) == 1)?,
          deinit(self.inputs, self.mint, fn(_, _, _) { True })
            |> run_root_with(policy_id, constants.linked_list_root_key),
          // Every output carrying this policy — after a deinit there should be
          // none — is at the list spend script. See the note on the Add branch.
          utils.policy_only_at_script(self.outputs, policy_id, list_script_hash)?,
        }
      }
      AddToDenylist {
        user_pkh,
        anchor_node_output_index,
        appended_node_output_index,
        global_state_ref_input_index,
        power_user_node_ref_input_index,
      } -> {
        // Sanctioning is delegated: any power user holding `is_admin` can add a
        // denylist entry (signed by that user). The GS admin grants the flag.
        let (power_user_credential_hash, power_user_data) = power_user_from_refs(
          self,
          global_state_ref_input_index,
          global_state_policy_id,
          power_user_node_ref_input_index,
        )
        let anchor_output = utils.safe_list_at(
          self.outputs,
          anchor_node_output_index,
        )
        let new_node_output = utils.safe_list_at(
          self.outputs,
          appended_node_output_index,
        )
        and {
          // A key of any other length can never be the asset name of a real
          // node (`"Node" ++` a 28-byte credential hash), so it could only
          // ever match a node that will never exist — silently locking the
          // sanction out rather than rejecting it up front.
          bytearray.length(user_pkh) == 28,
          power_user_data.is_admin,
          must_be_signed_by_credential(self, power_user_credential_hash),
          dict.size(tokens(self.mint, policy_id)) == 1,
          // An insert spends exactly one element — the anchor, which
          // `insert_ascending` infers from `self.inputs` itself. The new node
          // is an OUTPUT.
          //
          // The library performs its own exact-one scan, so this line is
          // defence in depth. It is kept because the two counts are not
          // identical: the library's scanner only recognises CANONICAL
          // elements (exactly ADA plus one list NFT) and silently IGNORES an
          // input carrying the list policy in any other value shape, whereas
          // this one counts every input bearing the policy. Element outputs
          // are strictly canonical, so the gap should be unreachable — but a
          // list is an access-control structure, and this costs one fold.
          (utils.count_inputs_with_policy(self.inputs, policy_id) == 1)?,
          insert_ascending(
            anchor_output,
            new_node_output,
            self.inputs,
            self.mint,
            fn(
              _anchor_input,
              _lovelace_change,
              _anchor_key,
              _anchor_data,
              _new_lovelace,
              node_key,
              node_data,
              _link,
            ) {
              expect denylist_data: Denylist = node_data
              and {
                node_key == user_pkh,
                // `None` (full freeze) or a strictly positive partial freeze.
                valid_frozen_amount(denylist_data.frozen_amount)?,
                bytearray.length(builtin.serialise_data(denylist_data.metadata)) <= constants.max_denylist_metadata_bytes,
              }
            },
          )
            |> run_element_with(
                policy_id,
                constants.linked_list_root_key,
                constants.linked_list_node_key_prefix,
                constants.linked_list_node_key_prefix_length,
              ),
          // Every output carrying this policy — here the continued anchor and
          // the new node — is at the list spend script.
          //
          // Defence in depth, on every branch: the library already keeps the
          // continued anchor at the anchor's address and the new node at its
          // payment credential, and the anchor got there by induction from the
          // root that `Init` pins. This one fold states the end result
          // directly, so it holds even if one of those steps were loosened.
          utils.policy_only_at_script(self.outputs, policy_id, list_script_hash)?,
        }
      }
      RemoveFromDenylist {
        user_pkh,
        anchor_node_input_index,
        anchor_node_output_index,
        global_state_ref_input_index,
        power_user_node_ref_input_index,
      } -> {
        // Un-sanctioning is gated the same as adding: a power user holding
        // `is_admin`, signed by that user.
        let (power_user_credential_hash, power_user_data) = power_user_from_refs(
          self,
          global_state_ref_input_index,
          global_state_policy_id,
          power_user_node_ref_input_index,
        )
        // `remove` finds both spent elements itself; the index only says
        // WHICH of the two is the anchor.
        let anchor_out_ref = utils.safe_list_at(
          self.inputs,
          anchor_node_input_index,
        ).output_reference
        let anchor_output = utils.safe_list_at(
          self.outputs,
          anchor_node_output_index,
        )
        and {
          // Same length pin as the Add branch — see its comment.
          bytearray.length(user_pkh) == 28,
          power_user_data.is_admin,
          must_be_signed_by_credential(self, power_user_credential_hash),
          dict.size(tokens(self.mint, policy_id)) == 1,
          // A remove spends exactly two elements: the anchor and the node
          // being removed. Defence in depth beside the library's own exact-two
          // scan — see the note on the Add branch.
          (utils.count_inputs_with_policy(self.inputs, policy_id) == 2)?,
          remove(
            anchor_out_ref,
            anchor_output,
            self.inputs,
            self.mint,
            fn(
              _anchor_input,
              _lovelace_change,
              _anchor_key,
              _anchor_data,
              _removing_input,
              _rem_lovelace,
              rem_key,
              rem_data,
              _link,
            ) {
              expect _parsed: Denylist = rem_data
              rem_key == user_pkh
            },
          )
            |> run_element_with(
                policy_id,
                constants.linked_list_root_key,
                constants.linked_list_node_key_prefix,
                constants.linked_list_node_key_prefix_length,
              ),
          // Every output carrying this policy — here the continued anchor — is
          // at the list spend script. See the note on the Add branch.
          utils.policy_only_at_script(self.outputs, policy_id, list_script_hash)?,
        }
      }
    }
  }

  else(_) {
    fail
  }
}

/// The root's creation, shared by `Init` and `InitAfterGenesis`: the nonce
/// UTxO is spent, the root is the only token of this policy minted, and it is
/// pinned to the list spend script.
///
/// The library hands the callback the produced root's address, and the root is
/// pinned there: its whole payment credential must be
/// `Script(list_script_hash)`, so a key credential carrying the same hash is
/// refused; the stake part stays free. The library `expect`s the nonce and the
/// callback, so a missing nonce or a misplaced root traps.
///
/// Not circular: the spend validator takes no list policy id (it reads the
/// policy off the element it spends), so its hash depends only on the
/// GlobalState policy, and this mint takes that hash.
fn creates_the_root(
  self: Transaction,
  nonce_validated: Bool,
  root_output: Output,
  policy_id: PolicyId,
  list_script_hash: ByteArray,
) -> Bool {
  and {
    init(
      nonce_validated,
      root_output,
      self.mint,
      fn(address, _, _) {
        (address.payment_credential == Script(list_script_hash))?
      },
    )
      |> run_root_with(policy_id, constants.linked_list_root_key),
    // Every output carrying this policy — here only the root — is at the list
    // spend script. See the note on the Add branch.
    utils.policy_only_at_script(self.outputs, policy_id, list_script_hash)?,
  }
}

// ============================================================================
// Tests
// ============================================================================

const t_dl_policy: ByteArray =
  #"dddddddddddddddddddddddddddddddddddddddddddddddddddddddd"

const t_gs_policy: ByteArray =
  #"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

const t_pu_policy: ByteArray =
  #"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

/// A policy unrelated to the lists, sorting before `t_dl_policy`.
const t_foreign_policy: ByteArray =
  #"1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f"

const t_dl_script_hash: ByteArray =
  #"d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0"

const t_pu_script_hash: ByteArray =
  #"d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1"

const t_gs_script_hash: ByteArray =
  #"0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d"

const t_admin: ByteArray =
  #"0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a"

const t_pu_cred: ByteArray =
  #"0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c"

/// A 28-byte credential hash — the width every node key must have.
const t_key_28: ByteArray =
  #"02020202020202020202020202020202020202020202020202020202"

/// One byte short of a credential hash.
const t_key_27: ByteArray =
  #"030303030303030303030303030303030303030303030303030303"

/// One byte long of a credential hash.
const t_key_29: ByteArray =
  #"0404040404040404040404040404040404040404040404040404040404"

fn t_oref(ix: Int) -> OutputReference {
  OutputReference {
    transaction_id: #"0000000000000000000000000000000000000000000000000000000000000000",
    output_index: ix,
  }
}

fn t_ll_asset_name(key: ByteArray) -> ByteArray {
  bytearray.concat(constants.linked_list_node_key_prefix, key)
}

fn t_base_tx() -> Transaction {
  Transaction {
    inputs: [],
    reference_inputs: [],
    outputs: [],
    fee: 0,
    mint: zero,
    certificates: [],
    withdrawals: [],
    validity_range: Interval {
      lower_bound: IntervalBound {
        bound_type: NegativeInfinity,
        is_inclusive: True,
      },
      upper_bound: IntervalBound {
        bound_type: PositiveInfinity,
        is_inclusive: False,
      },
    },
    extra_signatories: [],
    redeemers: [],
    datums: dict.empty,
    id: #"0000000000000000000000000000000000000000000000000000000000000000",
    votes: [],
    proposal_procedures: [],
    current_treasury_amount: None,
    treasury_donation: None,
  }
}

/// A genuine denylist NODE at the list's spend address, carrying the list's
/// NFT.
fn t_dl_node_input(ix: Int, key: ByteArray) -> Input {
  let element: Element<Data, Data> = Element {
    data: Node { data: builtin.constr_data(0, []) },
    link: None,
  }
  Input {
    output_reference: t_oref(ix),
    output: Output {
      address: Address {
        payment_credential: Script(t_dl_script_hash),
        stake_credential: None,
      },
      value: merge(
        from_lovelace(2_000_000),
        from_asset(t_dl_policy, t_ll_asset_name(key), 1),
      ),
      datum: InlineDatum(element),
      reference_script: None,
    },
  }
}

/// The denylist ROOT with an empty list.
fn t_dl_root_input(ix: Int) -> Input {
  let element: Element<Data, Data> = Element {
    data: Root { data: builtin.constr_data(0, []) },
    link: None,
  }
  Input {
    output_reference: t_oref(ix),
    output: Output {
      address: Address {
        payment_credential: Script(t_dl_script_hash),
        stake_credential: None,
      },
      value: merge(
        from_lovelace(2_000_000),
        from_asset(t_dl_policy, constants.linked_list_root_key, 1),
      ),
      datum: InlineDatum(element),
      reference_script: None,
    },
  }
}

/// The denylist ROOT as an OUTPUT, with a settable link — an insert or
/// remove must reproduce the anchor pointing past the mutation.
fn t_dl_root_output(link: Option<ByteArray>) -> Output {
  let element: Element<Data, Data> = Element {
    data: Root { data: builtin.constr_data(0, []) },
    link,
  }
  Output { ..t_dl_root_input(0).output, datum: InlineDatum(element) }
}

/// The denylist ROOT as an INPUT with a settable link — a remove spends a
/// root that points AT the node being removed.
fn t_dl_root_input_linked(ix: Int, link: Option<ByteArray>) -> Input {
  Input { output_reference: t_oref(ix), output: t_dl_root_output(link) }
}

/// A denylist node whose data is a well-formed `Denylist` — required wherever
/// the mint branch decodes a node's data, on both the appended-node output and
/// the removed-node input.
fn t_dl_sanction_node_output_with_metadata(
  key: ByteArray,
  metadata: Data,
) -> Output {
  let element: Element<Data, Denylist> = Element {
    data: Node { data: Denylist { frozen_amount: None, metadata } },
    link: None,
  }
  Output { ..t_dl_node_input(0, key).output, datum: InlineDatum(element) }
}

fn t_dl_sanction_node_output(key: ByteArray) -> Output {
  t_dl_sanction_node_output_with_metadata(key, builtin.constr_data(0, []))
}

/// A UTxO sitting at the denylist's own spend address that carries NO
/// denylist-policy token — e.g. value sent there by mistake. Structurally it
/// looks nothing like a list element (no `Element` datum at all), which is
/// exactly the point: the ONLY thing that made the pre-fix gate treat it as
/// spendable was that some unrelated denylist mint/burn happened anywhere in
/// the same transaction.
fn t_dl_stray_input(ix: Int) -> Input {
  Input {
    output_reference: t_oref(ix),
    output: Output {
      address: Address {
        payment_credential: Script(t_dl_script_hash),
        stake_credential: None,
      },
      value: from_lovelace(5_000_000),
      datum: NoDatum,
      reference_script: None,
    },
  }
}

fn t_gs_datum(deactivated: Bool) -> GlobalStateDatum {
  GlobalStateDatum {
    global_state_script_credential_hash: #"9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a",
    transfers_paused: False,
    deactivated,
    mintable_amount: 1_000_000_000,
    admin_credential_hash: t_admin,
    power_user_linked_list_policy_id: t_pu_policy,
    denylist_linked_list_policy_id: t_dl_policy,
    security_info: builtin.constr_data(0, []),
    trusted_entity_vkeys: [],
    member_root_hash: #"",
    requires_sender_kyc: False,
    requires_receiver_kyc: False,
    network_id: 1,
    minting_script_credential_hash: t_admin,
    upgrades_locked: False,
  }
}

fn t_gs_utxo(ix: Int, datum: GlobalStateDatum) -> Input {
  Input {
    output_reference: t_oref(ix),
    output: Output {
      address: Address {
        payment_credential: Script(t_gs_script_hash),
        stake_credential: None,
      },
      value: merge(
        from_lovelace(2_000_000),
        from_asset(t_gs_policy, constants.global_state_asset_name, 1),
      ),
      datum: InlineDatum(datum),
      reference_script: None,
    },
  }
}

fn t_power_user(is_admin: Bool) -> PowerUser {
  PowerUser {
    credential_hash: t_pu_cred,
    is_admin,
    can_mint: False,
    can_burn: False,
    can_pause: False,
    can_force_transfer: False,
  }
}

fn t_pu_node_input(ix: Int, pu: PowerUser) -> Input {
  let element: Element<Data, PowerUser> = Element {
    data: Node { data: pu },
    link: None,
  }
  Input {
    output_reference: t_oref(ix),
    output: Output {
      address: Address {
        payment_credential: Script(t_pu_script_hash),
        stake_credential: None,
      },
      value: merge(
        from_lovelace(2_000_000),
        from_asset(t_pu_policy, t_ll_asset_name(t_pu_cred), 1),
      ),
      datum: InlineDatum(element),
      reference_script: None,
    },
  }
}

fn t_data_of_raw_length(raw_len: Int) -> Data {
  builtin.b_data(bytearray.from_int_big_endian(0, raw_len))
}

const t_metadata_len_at_cap: Int = 494

const t_metadata_len_over_cap: Int = 495

// ── Guard 1: the spend gate binds to the UTxO actually being spent ─────────

/// POSITIVE control. A genuine node spend under `StateTransition`, with a
/// genuine denylist mint/burn present — the ordinary shape of every
/// insert/remove's element-side spend. Must still succeed.
test denylist_spend_accepts_a_genuine_node_spend_alongside_a_mutation() {
  let no_datum: Option<Data> = None
  let tx = Transaction {
    ..t_base_tx(),
    inputs: [t_dl_node_input(0, t_key_28)],
    mint: from_asset(t_dl_policy, t_ll_asset_name(t_key_28), 1),
  }
  denylist_validator.spend(
    t_gs_policy,
    no_datum,
    StateTransition,
    t_oref(0),
    tx,
  )
}

/// THE GUARD under test. A UTxO sitting at the denylist address with NO
/// denylist-policy token — not list state at all — spent under
/// `StateTransition` while a genuine denylist mint/burn happens elsewhere in
/// the very same transaction. `spend_for_adding_or_removing_an_element` asks
/// only "does the mint field carry this policy anywhere", so without a check
/// on the spent UTxO itself its value could be swept out alongside any real
/// insert/remove. The validator reads the list policy off ITS OWN spent input,
/// which must hold lovelace plus exactly one NFT; this one holds only
/// lovelace, so the derivation traps — hence `fail`, written `… || True` so
/// that a validator merely returning False cannot pass it.
test denylist_spend_rejects_a_stray_no_token_utxo_swept_alongside_a_mutation() fail {
  let no_datum: Option<Data> = None
  let tx = Transaction {
    ..t_base_tx(),
    inputs: [t_dl_stray_input(0)],
    mint: from_asset(t_dl_policy, t_ll_asset_name(t_key_28), 1),
  }
  denylist_validator.spend(
    t_gs_policy,
    no_datum,
    StateTransition,
    t_oref(0),
    tx,
  ) || True
}

// ── The spend reads its list policy off its own input ───────────────────────
//
// Each refusal below is the accepted control above
// (`denylist_spend_accepts_a_genuine_node_spend_alongside_a_mutation`) with
// only the spent node's value changed. The derivation traps on any shape but
// lovelace plus one NFT, so each is written `… || True`: a validator that
// merely returns False cannot pass it, only a trap can.

/// The control's node with `extra` merged into its value.
fn t_dl_node_with(extra: Assets) -> Input {
  let node = t_dl_node_input(0, t_key_28)
  Input {
    ..node,
    output: Output { ..node.output, value: merge(node.output.value, extra) },
  }
}

fn t_run_dl_state_transition(own_input: Input) -> Bool {
  let no_datum: Option<Data> = None
  denylist_validator.spend(
    t_gs_policy,
    no_datum,
    StateTransition,
    t_oref(0),
    Transaction {
      ..t_base_tx(),
      inputs: [own_input],
      mint: from_asset(t_dl_policy, t_ll_asset_name(t_key_28), 1),
    },
  )
}

/// A second policy beside the list NFT. It sorts before the list policy, so a
/// derivation reading the first token's policy would pick it.
test denylist_spend_refuses_an_own_input_with_two_policies() fail {
  t_run_dl_state_transition(
    t_dl_node_with(from_asset(t_foreign_policy, t_ll_asset_name(t_key_28), 1)),
  ) || True
}

/// A second asset name under the list policy.
test denylist_spend_refuses_an_own_input_with_two_names_of_one_policy() fail {
  t_run_dl_state_transition(
    t_dl_node_with(from_asset(t_dl_policy, t_ll_asset_name(t_pu_cred), 1)),
  ) || True
}

/// The list NFT at quantity 2.
test denylist_spend_refuses_an_own_input_with_quantity_two() fail {
  t_run_dl_state_transition(
    t_dl_node_with(from_asset(t_dl_policy, t_ll_asset_name(t_key_28), 1)),
  ) || True
}

/// A UTxO at the list address holding an unrelated policy's NFT, spent under
/// `StateTransition` beside a mint of that unrelated policy: accepted. This is
/// harmless. The spend reads the unrelated policy off the UTxO, so its own
/// mint decides the spend, not this list's; and every reader names the list
/// policy, so such a UTxO is never list state.
test denylist_spend_accepts_a_foreign_utxo_under_its_own_mint() {
  let no_datum: Option<Data> = None
  let node = t_dl_node_input(0, t_key_28)
  let foreign_input = Input {
    ..node,
    output: Output {
      ..node.output,
      value: merge(
        from_lovelace(2_000_000),
        from_asset(t_foreign_policy, t_ll_asset_name(t_key_28), 1),
      ),
    },
  }
  denylist_validator.spend(
    t_gs_policy,
    no_datum,
    StateTransition,
    t_oref(0),
    Transaction {
      ..t_base_tx(),
      inputs: [foreign_input],
      mint: from_asset(t_foreign_policy, t_ll_asset_name(t_pu_cred), 1),
    },
  )
}

// ── Guard 2: node keys must be exactly 28 bytes ─────────────────────────────

fn t_dl_insert_tx(key: ByteArray) -> Transaction {
  Transaction {
    ..t_base_tx(),
    inputs: [t_dl_root_input(0)],
    reference_inputs: [
      t_gs_utxo(0, t_gs_datum(False)),
      t_pu_node_input(1, t_power_user(True)),
    ],
    mint: from_asset(t_dl_policy, t_ll_asset_name(key), 1),
    outputs: [t_dl_root_output(Some(key)), t_dl_sanction_node_output(key)],
    extra_signatories: [t_pu_cred],
  }
}

fn t_run_denylist_add(key: ByteArray, tx: Transaction) -> Bool {
  mint.mint(
    t_gs_policy,
    t_oref(99),
    t_dl_script_hash,
    AddToDenylist {
      user_pkh: key,
      anchor_node_output_index: 0,
      appended_node_output_index: 1,
      global_state_ref_input_index: 0,
      power_user_node_ref_input_index: 1,
    },
    t_dl_policy,
    tx,
  )
}

/// POSITIVE control for the insert length checks below — everything else
/// about `t_dl_insert_tx` is exactly what the negatives reuse, differing
/// only in the key's length.
test denylist_insert_accepts_a_28_byte_key() {
  t_run_denylist_add(t_key_28, t_dl_insert_tx(t_key_28))
}

test denylist_insert_accepts_metadata_at_the_size_cap() {
  let tx = Transaction {
    ..t_dl_insert_tx(t_key_28),
    outputs: [
      t_dl_root_output(Some(t_key_28)),
      t_dl_sanction_node_output_with_metadata(
        t_key_28,
        t_data_of_raw_length(t_metadata_len_at_cap),
      ),
    ],
  }
  t_run_denylist_add(t_key_28, tx)
}

test denylist_insert_rejects_metadata_one_byte_over_the_size_cap() fail {
  let tx = Transaction {
    ..t_dl_insert_tx(t_key_28),
    outputs: [
      t_dl_root_output(Some(t_key_28)),
      t_dl_sanction_node_output_with_metadata(
        t_key_28,
        t_data_of_raw_length(t_metadata_len_over_cap),
      ),
    ],
  }
  t_run_denylist_add(t_key_28, tx)
}

/// THE GUARD under test, one byte short. `bytearray.length(user_pkh) == 28`
/// is the FIRST conjunct of the branch's `and { }`, so it short-circuits
/// before `insert_ascending` ever runs — the failure is exactly this check,
/// not some downstream key comparison. Returns False, hence `!`.
test denylist_insert_rejects_a_27_byte_key() {
  !t_run_denylist_add(t_key_27, t_dl_insert_tx(t_key_27))
}

/// Same guard, one byte long.
test denylist_insert_rejects_a_29_byte_key() {
  !t_run_denylist_add(t_key_29, t_dl_insert_tx(t_key_29))
}

fn t_dl_remove_tx(key: ByteArray) -> Transaction {
  Transaction {
    ..t_base_tx(),
    inputs: [
      t_dl_root_input_linked(0, Some(key)),
      Input {
        output_reference: t_oref(1),
        output: t_dl_sanction_node_output(key),
      },
    ],
    reference_inputs: [
      t_gs_utxo(0, t_gs_datum(False)),
      t_pu_node_input(1, t_power_user(True)),
    ],
    mint: from_asset(t_dl_policy, t_ll_asset_name(key), -1),
    outputs: [t_dl_root_output(None)],
    extra_signatories: [t_pu_cred],
  }
}

fn t_run_denylist_remove(key: ByteArray, tx: Transaction) -> Bool {
  mint.mint(
    t_gs_policy,
    t_oref(99),
    t_dl_script_hash,
    RemoveFromDenylist {
      user_pkh: key,
      anchor_node_input_index: 0,
      anchor_node_output_index: 0,
      global_state_ref_input_index: 0,
      power_user_node_ref_input_index: 1,
    },
    t_dl_policy,
    tx,
  )
}

/// POSITIVE control for the remove length checks below.
test denylist_remove_accepts_a_28_byte_key() {
  t_run_denylist_remove(t_key_28, t_dl_remove_tx(t_key_28))
}

/// THE GUARD under test on the Remove branch, one byte short. Same
/// short-circuit reasoning as the insert case: the length conjunct is first,
/// so `remove` never runs. Returns False, hence `!`.
test denylist_remove_rejects_a_27_byte_key() {
  !t_run_denylist_remove(t_key_27, t_dl_remove_tx(t_key_27))
}

/// Same guard, one byte long.
test denylist_remove_rejects_a_29_byte_key() {
  !t_run_denylist_remove(t_key_29, t_dl_remove_tx(t_key_29))
}

// Non-upgradeable: must keep reading a GlobalState datum a future version
// extended with trailing fields (see decode_global_state_core).
test denylist_insert_accepts_a_global_state_with_trailing_fields() {
  t_run_denylist_add(
    t_key_28,
    tests.with_trailing_gs_fields(t_dl_insert_tx(t_key_28), t_gs_policy),
  )
}

// Frozen core: the sanctions path's GlobalState read is permanent and tolerates
// any tail after fields 0–4. A rotation is append-only, so such a tail only
// arises from a successor logic's own later actions.
test denylist_insert_accepts_a_global_state_with_a_reshaped_tail() {
  t_run_denylist_add(
    t_key_28,
    tests.with_reshaped_gs_tail(t_dl_insert_tx(t_key_28), t_gs_policy),
  )
}

// The sanctions path must treat a malformed `deactivated` as an error, never
// as "live".
test denylist_insert_rejects_a_malformed_deactivated_flag() fail {
  t_run_denylist_add(
    t_key_28,
    tests.with_malformed_gs_deactivated(t_dl_insert_tx(t_key_28), t_gs_policy),
  )
}

// ── Partial freeze: `frozen_amount` on insert ────────────────────────────────

fn t_dl_entry_output(key: ByteArray, frozen_amount: Option<Int>) -> Output {
  let element: Element<Data, Denylist> = Element {
    data: Node {
      data: Denylist { frozen_amount, metadata: builtin.constr_data(0, []) },
    },
    link: None,
  }
  Output { ..t_dl_node_input(0, key).output, datum: InlineDatum(element) }
}

fn t_dl_insert_frozen(frozen_amount: Option<Int>) -> Bool {
  let tx = Transaction {
    ..t_dl_insert_tx(t_key_28),
    outputs: [
      t_dl_root_output(Some(t_key_28)),
      t_dl_entry_output(t_key_28, frozen_amount),
    ],
  }
  t_run_denylist_add(t_key_28, tx)
}

test denylist_insert_accepts_a_partial_freeze() {
  t_dl_insert_frozen(Some(1))
}

test denylist_insert_accepts_a_full_freeze() {
  t_dl_insert_frozen(None)
}

// The insert callback's verdict is `expect`ed by the library, so a rejected
// entry traps — `fail`, not `!`.
test denylist_insert_rejects_a_zero_partial_freeze() fail {
  t_dl_insert_frozen(Some(0))
}

test denylist_insert_rejects_a_negative_partial_freeze() fail {
  t_dl_insert_frozen(Some(-1))
}

// ── Partial freeze: `UpdateDenylistEntry` ────────────────────────────────────
//
// Reference inputs: 0 GlobalState, 1 power-user node. Input 0 is the node
// being updated, output 0 its continuation.

fn t_entry_input(ix: Int, key: ByteArray, data: Data, lovelace: Int) -> Input {
  let element: Element<Data, Data> = Element { data: Node { data }, link: None }
  Input {
    output_reference: t_oref(ix),
    output: Output {
      ..t_dl_node_input(ix, key).output,
      value: merge(
        from_lovelace(lovelace),
        from_asset(t_dl_policy, t_ll_asset_name(key), 1),
      ),
      datum: InlineDatum(element),
    },
  }
}

fn t_entry(frozen_amount: Option<Int>) -> Data {
  let entry: Data = Denylist {
    frozen_amount,
    metadata: builtin.constr_data(0, []),
  }
  entry
}

fn t_update_tx(old: Data, new: Data, new_lovelace: Int) -> Transaction {
  Transaction {
    ..t_base_tx(),
    inputs: [t_entry_input(0, t_key_28, old, 2_000_000)],
    reference_inputs: [
      t_gs_utxo(0, t_gs_datum(False)),
      t_pu_node_input(1, t_power_user(True)),
    ],
    outputs: [t_entry_input(0, t_key_28, new, new_lovelace).output],
    extra_signatories: [t_pu_cred],
  }
}

fn t_run_update(tx: Transaction) -> Bool {
  let no_datum: Option<Data> = None
  denylist_validator.spend(
    t_gs_policy,
    no_datum,
    UpdateDenylistEntry {
      own_input_index: 0,
      own_output_index: 0,
      global_state_ref_input_index: 0,
      power_user_node_ref_input_index: 1,
    },
    t_oref(0),
    tx,
  )
}

test denylist_update_changes_the_frozen_amount() {
  t_run_update(t_update_tx(t_entry(Some(400)), t_entry(Some(500)), 2_000_000))
}

test denylist_update_escalates_a_partial_freeze_to_a_full_freeze() {
  t_run_update(t_update_tx(t_entry(Some(400)), t_entry(None), 2_000_000))
}

test denylist_update_relaxes_a_full_freeze_to_a_partial_one() {
  t_run_update(t_update_tx(t_entry(None), t_entry(Some(10)), 2_000_000))
}

test denylist_update_accepts_more_lovelace() {
  t_run_update(t_update_tx(t_entry(None), t_entry(None), 3_000_000))
}

test denylist_update_rejects_a_power_user_without_is_admin() {
  let tx = Transaction {
    ..t_update_tx(t_entry(None), t_entry(Some(10)), 2_000_000),
    reference_inputs: [
      t_gs_utxo(0, t_gs_datum(False)),
      t_pu_node_input(1, t_power_user(False)),
    ],
  }
  !t_run_update(tx)
}

test denylist_update_rejects_a_missing_signature() {
  let tx = Transaction {
    ..t_update_tx(t_entry(None), t_entry(Some(10)), 2_000_000),
    extra_signatories: [],
  }
  !t_run_update(tx)
}

test denylist_update_rejects_a_deactivated_protocol() fail {
  let tx = Transaction {
    ..t_update_tx(t_entry(None), t_entry(Some(10)), 2_000_000),
    reference_inputs: [
      t_gs_utxo(0, t_gs_datum(True)),
      t_pu_node_input(1, t_power_user(True)),
    ],
  }
  t_run_update(tx)
}

test denylist_update_rejects_a_zero_partial_freeze() fail {
  t_run_update(t_update_tx(t_entry(None), t_entry(Some(0)), 2_000_000))
}

test denylist_update_rejects_a_negative_partial_freeze() fail {
  t_run_update(t_update_tx(t_entry(None), t_entry(Some(-1)), 2_000_000))
}

test denylist_update_rejects_data_that_is_not_an_entry() fail {
  t_run_update(
    t_update_tx(t_entry(None), builtin.constr_data(0, []), 2_000_000),
  )
}

test denylist_update_rejects_oversized_metadata() fail {
  let new: Data = Denylist {
    frozen_amount: None,
    metadata: t_data_of_raw_length(t_metadata_len_over_cap),
  }
  t_run_update(t_update_tx(t_entry(None), new, 2_000_000))
}

test denylist_update_accepts_metadata_at_the_size_cap() {
  let new: Data = Denylist {
    frozen_amount: None,
    metadata: t_data_of_raw_length(t_metadata_len_at_cap),
  }
  t_run_update(t_update_tx(t_entry(None), new, 2_000_000))
}

test denylist_update_rejects_taking_lovelace() fail {
  t_run_update(t_update_tx(t_entry(None), t_entry(None), 1_999_999))
}

// The root carries a well-formed entry here, so the node-only guard is the
// only thing that can reject the update.
test denylist_update_rejects_the_root() fail {
  let root: Element<Data, Data> = Element {
    data: Root { data: t_entry(None) },
    link: None,
  }
  let root_output = Output {
    ..t_dl_root_input(0).output,
    datum: InlineDatum(root),
  }
  let tx = Transaction {
    ..t_update_tx(t_entry(None), t_entry(None), 2_000_000),
    inputs: [Input { output_reference: t_oref(0), output: root_output }],
    outputs: [root_output],
  }
  t_run_update(tx)
}

// Exclusivity with `StateTransition`: any list-policy mint in the transaction
// and the update refuses to run.
test denylist_update_rejects_a_list_mint_in_the_same_transaction() fail {
  let tx = Transaction {
    ..t_update_tx(t_entry(None), t_entry(Some(10)), 2_000_000),
    mint: from_asset(t_dl_policy, t_ll_asset_name(t_key_28), 1),
  }
  t_run_update(tx)
}

// Two updates cannot share one continuation: the second spend's own node NFT
// is not in the output both cite.
test denylist_update_rejects_two_spends_sharing_one_continuation() fail {
  let other_key = #"05050505050505050505050505050505050505050505050505050505"
  let no_datum: Option<Data> = None
  let tx = Transaction {
    ..t_update_tx(t_entry(None), t_entry(Some(10)), 2_000_000),
    inputs: [
      t_entry_input(0, t_key_28, t_entry(None), 2_000_000),
      t_entry_input(1, other_key, t_entry(None), 2_000_000),
    ],
  }
  denylist_validator.spend(
    t_gs_policy,
    no_datum,
    UpdateDenylistEntry {
      own_input_index: 1,
      own_output_index: 0,
      global_state_ref_input_index: 0,
      power_user_node_ref_input_index: 1,
    },
    t_oref(1),
    tx,
  )
}

// Positive control for the test above: the same transaction, first spend.
test denylist_update_accepts_the_first_of_two_spends() {
  let other_key = #"05050505050505050505050505050505050505050505050505050505"
  let tx = Transaction {
    ..t_update_tx(t_entry(None), t_entry(Some(10)), 2_000_000),
    inputs: [
      t_entry_input(0, t_key_28, t_entry(None), 2_000_000),
      t_entry_input(1, other_key, t_entry(None), 2_000_000),
    ],
  }
  t_run_update(tx)
}

// ── `UpdateDenylistEntry`: what the continuation must keep ───────────────────
//
// The library pins these; the tests make a library bump or a refactor that
// loosens them fail here rather than reopen NFT escape through the officer
// path.

// The NFT may not leave the list address.
test denylist_update_rejects_a_continuation_at_another_address() fail {
  let out = t_entry_input(0, t_key_28, t_entry(Some(10)), 2_000_000).output
  let tx = Transaction {
    ..t_update_tx(t_entry(None), t_entry(Some(10)), 2_000_000),
    outputs: [
      Output {
        ..out,
        address: Address {
          payment_credential: VerificationKey(t_pu_cred),
          stake_credential: None,
        },
      },
    ],
  }
  t_run_update(tx)
}

// The link may not change: an update must never re-order the list.
test denylist_update_rejects_a_changed_link() fail {
  let other_key = #"05050505050505050505050505050505050505050505050505050505"
  let relinked: Element<Data, Data> = Element {
    data: Node { data: t_entry(Some(10)) },
    link: Some(other_key),
  }
  let out = t_entry_input(0, t_key_28, t_entry(Some(10)), 2_000_000).output
  let tx = Transaction {
    ..t_update_tx(t_entry(None), t_entry(Some(10)), 2_000_000),
    outputs: [Output { ..out, datum: InlineDatum(relinked) }],
  }
  t_run_update(tx)
}

// A stray UTxO at the list address without the list NFT is not list state and
// may not be spent under the update.
test denylist_update_rejects_an_own_input_without_the_list_nft() fail {
  let entry = t_entry_input(0, t_key_28, t_entry(None), 2_000_000)
  let tx = Transaction {
    ..t_update_tx(t_entry(None), t_entry(Some(10)), 2_000_000),
    inputs: [
      Input {
        ..entry,
        output: Output { ..entry.output, value: from_lovelace(2_000_000) },
      },
    ],
  }
  t_run_update(tx)
}

// The redeemer's input and output indices are honoured as given: the entry is
// input 1 and its continuation output 0, so swapping the two in the validator
// would point at the wrong input and trap.
test denylist_update_accepts_distinct_input_and_output_indices() {
  let no_datum: Option<Data> = None
  let wallet_input = Input {
    output_reference: t_oref(5),
    output: Output {
      address: Address {
        payment_credential: VerificationKey(t_pu_cred),
        stake_credential: None,
      },
      value: from_lovelace(5_000_000),
      datum: NoDatum,
      reference_script: None,
    },
  }
  let tx = Transaction {
    ..t_update_tx(t_entry(None), t_entry(Some(10)), 2_000_000),
    inputs: [wallet_input, t_entry_input(1, t_key_28, t_entry(None), 2_000_000)],
    outputs: [
      t_entry_input(1, t_key_28, t_entry(Some(10)), 2_000_000).output,
      wallet_input.output,
    ],
  }
  denylist_validator.spend(
    t_gs_policy,
    no_datum,
    UpdateDenylistEntry {
      own_input_index: 1,
      own_output_index: 0,
      global_state_ref_input_index: 0,
      power_user_node_ref_input_index: 1,
    },
    t_oref(1),
    tx,
  )
}

// ── Add/Remove authorisation ─────────────────────────────────────────────────
// Each test isolates one authorisation check of Add or Remove.

const t_other_key: ByteArray =
  #"06060606060606060606060606060606060606060606060606060606"

test dl_add_rejects_a_power_user_without_is_admin() {
  let tx = Transaction {
    ..t_dl_insert_tx(t_key_28),
    reference_inputs: [
      t_gs_utxo(0, t_gs_datum(False)),
      t_pu_node_input(1, t_power_user(False)),
    ],
  }
  !t_run_denylist_add(t_key_28, tx)
}

test dl_add_rejects_a_missing_signature() {
  !t_run_denylist_add(
    t_key_28,
    Transaction { ..t_dl_insert_tx(t_key_28), extra_signatories: [] },
  )
}

test dl_add_rejects_a_node_keyed_other_than_the_redeemer() fail {
  t_run_denylist_add(t_key_28, t_dl_insert_tx(t_other_key))
}

test dl_remove_rejects_a_missing_signature() {
  !t_run_denylist_remove(
    t_key_28,
    Transaction { ..t_dl_remove_tx(t_key_28), extra_signatories: [] },
  )
}

// ── A list NFT never leaves the list script ─────────────────────────────────
//
// One refusal per path through which a denylist NFT is minted, moved or kept
// in this file's fixtures (Init, Deinit and the spend gate are in
// `validators/regression.ak`). Each is an accepted fixture above with only the
// NFT's destination changed; its accepted control is named in its comment. A
// `fail` test here is written `… || True`, so a validator that merely returns
// False cannot pass it — only a trap can.

/// A key (wallet) address outside the list.
const t_wallet: ByteArray =
  #"0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e"

fn t_at_wallet(output: Output) -> Output {
  Output {
    ..output,
    address: Address {
      payment_credential: VerificationKey(t_wallet),
      stake_credential: None,
    },
  }
}

// AddToDenylist: control `denylist_insert_accepts_a_28_byte_key`. The new node
// must share the anchor's payment credential (the library's insert check), so
// it traps.
test denylist_insert_refuses_a_new_node_at_a_wallet() fail {
  let tx = t_dl_insert_tx(t_key_28)
  t_run_denylist_add(
    t_key_28,
    Transaction {
      ..tx,
      outputs: [
        t_dl_root_output(Some(t_key_28)),
        t_at_wallet(t_dl_sanction_node_output(t_key_28)),
      ],
    },
  ) || True
}

// The continued anchor must keep the anchor's full address (library), so it
// traps.
test denylist_insert_refuses_an_anchor_continuation_at_a_wallet() fail {
  let tx = t_dl_insert_tx(t_key_28)
  t_run_denylist_add(
    t_key_28,
    Transaction {
      ..tx,
      outputs: [
        t_at_wallet(t_dl_root_output(Some(t_key_28))),
        t_dl_sanction_node_output(t_key_28),
      ],
    },
  ) || True
}

// RemoveFromDenylist: control `denylist_remove_accepts_a_28_byte_key`. The
// continued anchor must keep the anchor's address (library), so it traps.
test denylist_remove_refuses_an_anchor_continuation_at_a_wallet() fail {
  t_run_denylist_remove(
    t_key_28,
    Transaction {
      ..t_dl_remove_tx(t_key_28),
      outputs: [t_at_wallet(t_dl_root_output(None))],
    },
  ) || True
}

// The removed node's NFT is paid to a wallet instead of burnt, so nothing of
// this policy is minted and the branch's one-asset mint conjunct returns
// False, hence `!`.
test denylist_remove_refuses_a_removed_node_kept_in_a_wallet() {
  !t_run_denylist_remove(
    t_key_28,
    Transaction {
      ..t_dl_remove_tx(t_key_28),
      mint: zero,
      outputs: [
        t_dl_root_output(None),
        t_at_wallet(t_dl_sanction_node_output(t_key_28)),
      ],
    },
  )
}

// The same, with another node NFT minted in place of the burn so that this
// policy still runs. The library requires the removal to burn exactly the
// removed node's NFT, so it traps.
test denylist_remove_refuses_a_removed_node_kept_under_another_list_mint() fail {
  t_run_denylist_remove(
    t_key_28,
    Transaction {
      ..t_dl_remove_tx(t_key_28),
      mint: from_asset(t_dl_policy, t_ll_asset_name(t_other_key), 1),
      outputs: [
        t_dl_root_output(None),
        t_at_wallet(t_dl_sanction_node_output(t_key_28)),
      ],
    },
  ) || True
}

// The same, burning another node's NFT instead: the quantity is right, so
// only the library's burnt-name check refuses it, by trapping. In-process
// only: no input carries that NFT, so the ledger could not balance the burn.
test denylist_remove_refuses_burning_another_node_in_place_of_the_removed_one() fail {
  t_run_denylist_remove(
    t_key_28,
    Transaction {
      ..t_dl_remove_tx(t_key_28),
      mint: from_asset(t_dl_policy, t_ll_asset_name(t_other_key), -1),
      outputs: [
        t_dl_root_output(None),
        t_at_wallet(t_dl_sanction_node_output(t_key_28)),
      ],
    },
  ) || True
}

// UpdateDenylistEntry: control
// `denylist_update_relaxes_a_full_freeze_to_a_partial_one`, the same
// transaction with the continuation at the list script. The wallet case is
// `denylist_update_rejects_a_continuation_at_another_address`; here the
// continuation sits at the power-users spend script. The library requires the
// continuation to keep the spent element's address, so it traps.
test denylist_update_refuses_a_continuation_at_another_script() fail {
  let out = t_entry_input(0, t_key_28, t_entry(Some(10)), 2_000_000).output
  t_run_update(
    Transaction {
      ..t_update_tx(t_entry(None), t_entry(Some(10)), 2_000_000),
      outputs: [
        Output {
          ..out,
          address: Address {
            payment_credential: Script(t_pu_script_hash),
            stake_credential: None,
          },
        },
      ],
    },
  ) || True
}
