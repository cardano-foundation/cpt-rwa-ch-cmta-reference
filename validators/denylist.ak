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
use cardano/assets.{PolicyId, from_asset, from_lovelace, merge, tokens, zero}
use cardano/transaction.{
  InlineDatum, Input, NoDatum, Output, OutputReference, Transaction, find_input,
}
use constants
use tests
use types/denylist.{
  AddToDenylist, Deinit, Denylist, Init, MintRedeemer, RemoveFromDenylist,
  SpendRedeemer, StateTransition, UpdateDenylistEntry, valid_frozen_amount,
}
use types/global_state.{
  GlobalStateDatum, genesis_global_state, gs_core_from_ref_input,
}
use types/power_users.{PowerUser}
use utils.{must_be_signed_by_credential, quantity_of_policy_id}

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
  power_user_list_script_hash: ByteArray,
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
    power_user_list_script_hash,
  )
  // Never the GlobalState logic named in field 0: its withdrawal would sign
  // for the operator. Today it cannot appear here — it needs GlobalState
  // SPENT (or, once, minted at genesis, before any GlobalState exists to
  // read), and this reads GlobalState as a reference input, which the ledger
  // keeps disjoint from the inputs — but that is a ledger rule, not ours.
  expect power_user_credential_hash != gs.global_state_script_credential_hash
  (power_user_credential_hash, power_user_data)
}

/// Parameters sit in the same positions as `mint`'s: GlobalState policy first,
/// then what identifies THIS list (here its policy id, there the one-shot
/// nonce), then the power-users spend hash.
validator denylist_validator(
  /// Needed only by `UpdateDenylistEntry`, which — unlike Add/Remove — runs no
  /// mint and so must authorise the sanctions officer here. Not circular: the
  /// GlobalState policy depends on neither denylist hash.
  global_state_policy_id: ByteArray,
  denylist_linked_list_policy_id: ByteArray,
  /// The POWER-USERS SPEND VALIDATOR's script hash, for the same reason. Not
  /// circular: the power-users validators never depend on the denylist.
  power_user_list_script_hash: ByteArray,
) {
  spend(
    _datum_opt: Option<Data>,
    redeemer: SpendRedeemer,
    input_out_ref: OutputReference,
    self: Transaction,
  ) {
    when redeemer is {
      StateTransition -> {
        // Delegate to mint validator.
        //
        // `spend_for_adding_or_removing_an_element` only asks whether SOME
        // denylist-policy mint/burn happens anywhere in this transaction — it
        // says nothing about the UTxO actually being spent under this
        // redeemer. Without pinning that, a stray value-bearing UTxO parked at
        // the list address (holding no list NFT, and therefore not list state
        // at all) could be swept up and spent here, riding along with any
        // genuine list mutation elsewhere in the same transaction. Resolving
        // this validator's own input and requiring it to carry the list's NFT
        // closes that: only a genuine list element (root or node) may be spent
        // under `StateTransition`.
        expect Some(own_input) = find_input(self.inputs, input_out_ref)
        and {
          (quantity_of_policy_id(
            own_input.output.value,
            denylist_linked_list_policy_id,
          ) > 0)?,
          spend_for_adding_or_removing_an_element(
            denylist_linked_list_policy_id,
            self.mint,
          ),
        }
      }
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
          power_user_list_script_hash,
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
  /// The POWER-USERS SPEND VALIDATOR's script hash. Not circular: the
  /// power-users validators depend on the GlobalState mint hash, never on the
  /// denylist policy id.
  power_user_list_script_hash: ByteArray,
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
          // policy its datum names mints something, and the id is immutable
          // afterwards — so a deployment naming another list would leave this
          // one, and the role or sanctions checks it carries, unreachable for
          // good. Not circular: the GlobalState policy is a parameter here.
          (genesis_global_state(self.outputs, global_state_policy_id).denylist_linked_list_policy_id == policy_id)?,
          // The library hands this callback the produced root's ADDRESS, so a
          // caller could in principle pin where the root lands. THIS ONE CANNOT,
          // and the reason is worth recording so nobody tries to "fix" it:
          //
          // pinning it would mean passing the list SPEND validator's hash to this
          // MINT validator — but the spend validator is parameterised by the list
          // policy id, which IS this mint validator's own hash. The dependency
          // would be circular, so no compile-time value exists.
          //
          // Genesis is therefore verified off-chain: after `Init`, confirm the
          // root NFT actually sits at the list spend validator's address. `Init`
          // is nonce-gated to a one-shot operator-held UTxO, so the only party
          // who can get this wrong is the deployer, and only once. Every LATER
          // read of a list element does pin the address, so a misplaced root
          // fails closed rather than silently granting authority.
          init(nonce_validated, root_output, self.mint, fn(_, _, _) { True })
            |> run_root_with(policy_id, constants.linked_list_root_key),
        }
      }
      Deinit { global_state_ref_input_index } -> {
        // POST-DECOMMISSION CLEANUP ONLY.
        //
        // Burning the root is irreversible in both directions: `Init` is gated
        // on a one-shot UTxO consumed at genesis, so a root can never be
        // re-created, and `denylist_linked_list_policy_id` is immutable in the
        // GlobalState datum — no spend branch writes it — so GlobalState can
        // never be pointed at a replacement list either.
        //
        // What that costs while the protocol is LIVE: every movement of the
        // security token needs a covering node of THIS list as a reference
        // input — the transfer path, the seizure path and every mint
        // destination all go through `lib/denylist/absence.ak`. With no root
        // there is no element to cover anything, so a `Deinit` on a live
        // protocol permanently freezes the register while the token still
        // reports itself active. That is a worse state than decommissioning,
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
          power_user_list_script_hash,
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
          power_user_list_script_hash,
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
        }
      }
    }
  }

  else(_) {
    fail
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
    t_dl_policy,
    t_pu_script_hash,
    no_datum,
    StateTransition,
    t_oref(0),
    tx,
  )
}

/// THE GUARD under test. A UTxO sitting at the denylist address with NO
/// denylist-policy token — not list state at all — spent under
/// `StateTransition` while a genuine denylist mint/burn happens elsewhere in
/// the very same transaction. Before this fix, `spend_for_adding_or_removing_
/// an_element` asked only "does the mint field carry this policy anywhere",
/// so this stray UTxO's value could be swept out alongside any real
/// insert/remove. Now the validator additionally resolves ITS OWN spent
/// input and requires that specific UTxO to carry the list token, so the new
/// `(quantity_of_policy_id(own_input.output.value, ...) > 0)?` conjunct is
/// False and the `and { }` block returns False — hence `!`, not `fail`.
test denylist_spend_rejects_a_stray_no_token_utxo_swept_alongside_a_mutation() {
  let no_datum: Option<Data> = None
  let tx = Transaction {
    ..t_base_tx(),
    inputs: [t_dl_stray_input(0)],
    mint: from_asset(t_dl_policy, t_ll_asset_name(t_key_28), 1),
  }
  !denylist_validator.spend(
    t_gs_policy,
    t_dl_policy,
    t_pu_script_hash,
    no_datum,
    StateTransition,
    t_oref(0),
    tx,
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
    t_pu_script_hash,
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
    t_pu_script_hash,
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

// Frozen core: the sanctions path keeps working when a later logic reshapes
// every field after 0–4.
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
    t_dl_policy,
    t_pu_script_hash,
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

test denylist_update_rejects_a_power_user_node_outside_its_list() fail {
  let pu = t_pu_node_input(1, t_power_user(True))
  let tx = Transaction {
    ..t_update_tx(t_entry(None), t_entry(Some(10)), 2_000_000),
    reference_inputs: [
      t_gs_utxo(0, t_gs_datum(False)),
      Input {
        ..pu,
        output: Output {
          ..pu.output,
          address: Address {
            payment_credential: VerificationKey(t_pu_cred),
            stake_credential: None,
          },
        },
      },
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
    t_dl_policy,
    t_pu_script_hash,
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
    t_dl_policy,
    t_pu_script_hash,
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
