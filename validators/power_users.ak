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
use cardano/address.{Address, Inline, Script, VerificationKey}
use cardano/assets.{
  Assets, PolicyId, from_asset, from_lovelace, merge, tokens, zero,
}
use cardano/transaction.{
  InlineDatum, Input, NoDatum, Output, OutputReference, Transaction, find_input,
}
use constants
use tests
use types/global_state.{
  GlobalStateDatum, active_admin_from_ref_input, genesis_global_state,
  gs_core_from_ref_input,
}
use types/power_users.{
  AddPowerUser, Deinit, Init, MintRedeemer, ModifyPowerUser, PowerUser,
  RemovePowerUser, SpendRedeemer, StateTransition,
}
use utils.{must_be_signed_by_credential}

validator power_users_validator(global_state_policy_id: ByteArray) {
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
    let power_users_linked_list_policy_id = utils.sole_nft_policy_id(
      own_input.output.value,
    )
    when redeemer is {
      StateTransition ->
        // Delegating responsibility to the mint validator: the library's gate
        // requires a mint or burn under this list's policy, so the list mint
        // runs and proves the exact transition.
        spend_for_adding_or_removing_an_element(
          power_users_linked_list_policy_id,
          self.mint,
        )
      ModifyPowerUser {
        own_input_index,
        own_output_index,
        wanted_user_state,
        global_state_ref_input_index,
      } -> {
        let admin = active_admin_from_ref_input(
          self.reference_inputs,
          global_state_ref_input_index,
          global_state_policy_id,
        )
        and {
          must_be_signed_by_credential(self, admin),
          //Ensure you're only modifying data, and output has the desired data
          spend_for_updating_elements_data(
            own_input_index,
            own_output_index,
            input_out_ref,
            self.inputs,
            self.outputs,
            self.mint,
            fn(
              _address,
              _lovelace_change,
              node_key_opt,
              _old_data,
              new_data,
              _link,
            ) {
              expect Some(node_key) = node_key_opt
              expect power_user_data: PowerUser = new_data
              and {
                power_user_data == wanted_user_state,
                power_user_data.credential_hash == node_key,
              }
            },
          )
            |> run_element_with(
                power_users_linked_list_policy_id,
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
  /// The POWER-USERS SPEND VALIDATOR's script hash: where every NFT of this
  /// policy must live. Not circular: the spend validator reads the list policy
  /// off the element it spends, so its hash depends only on the GlobalState
  /// policy.
  list_script_hash: ByteArray,
) {
  mint(redeemer: MintRedeemer, policy_id: PolicyId, self: Transaction) {
    when redeemer is {
      Init { root_output_index } -> {
        // Init is nonce-gated — GS is only being created in this same
        // transaction (an output, not yet an input), so admin-via-datum lookup
        // isn't feasible. The one-shot UTxO is
        // operator-held, which implicitly gates this action to the operator.
        let nonce_validated = list.any(
          self.inputs,
          fn(input) { input.output_reference == init_input_out_ref },
        )
        let root_output = utils.safe_list_at(self.outputs, root_output_index)
        and {
          //Only 1 token of this policy must be minted (the root NFT)
          dict.size(tokens(self.mint, policy_id)) == 1,
          // Genesis: no list node exists yet, so none may be spent.
          (utils.count_inputs_with_policy(self.inputs, policy_id) == 0)?,
          // Genesis binding: the GlobalState minted in this same transaction
          // must name THIS list. The GlobalState mint only checks that the
          // policy its datum names mints something, and the id is immutable
          // afterwards — so a deployment naming another list would leave this
          // one, and the role or sanctions checks it carries, unreachable for
          // good. Not circular: the GlobalState policy is a parameter here.
          (genesis_global_state(self.outputs, global_state_policy_id).power_user_linked_list_policy_id == policy_id)?,
          // The library hands this callback the produced root's address, and
          // the root is pinned there: its whole payment credential must be
          // `Script(list_script_hash)`, so a key credential carrying the same
          // hash is refused; the stake part stays free. The library `expect`s
          // the callback, so a misplaced root traps.
          //
          // Not circular: the spend validator takes no list policy id (it
          // reads the policy off the element it spends), so its hash depends
          // only on the GlobalState policy, and this mint takes that hash.
          init(
            nonce_validated,
            root_output,
            self.mint,
            fn(address, _, _) {
              (address.payment_credential == Script(list_script_hash))?
            },
          )
            |> run_root_with(policy_id, constants.linked_list_root_key),
          // Every output carrying this policy — here only the root — is at
          // the list spend script. See the note on the Add branch.
          utils.policy_only_at_script(self.outputs, policy_id, list_script_hash)?,
        }
      }
      Deinit { global_state_ref_input_index } -> {
        // POST-DECOMMISSION CLEANUP ONLY — same rule and the same reasoning as
        // the denylist's `Deinit`, and here the consequence of getting it wrong
        // is if anything broader.
        //
        // Burning this root is irreversible: `Init` is gated on a one-shot UTxO
        // consumed at genesis, `AddPowerUser` needs an existing element as its
        // anchor, and `power_user_linked_list_policy_id` is immutable in the
        // GlobalState datum. So once the root is gone no operator can ever be
        // added again — mint, burn, pause, unpause, seizure and sanctions all
        // authenticate against a node of THIS list and would be lost for good.
        // If transfers happened to be paused at that moment they stay paused
        // forever, since unpausing needs a `can_pause` node.
        //
        // Requiring `deactivated` keeps the branch to its purpose: reclaiming
        // the root's min-ADA after the token has been retired.
        //
        // `gs_core_from_ref_input`, not `active_admin_from_ref_input`, for the
        // reason given in `validators/denylist.ak`: the latter traps precisely
        // on the state this branch requires.
        let gs = gs_core_from_ref_input(
          self.reference_inputs,
          global_state_ref_input_index,
          global_state_policy_id,
        )
        and {
          gs.deactivated?,
          // L-6: Deinit must require admin signature. Without this, anyone
          // can burn the root NFT while the list is empty. Admin now comes
          // from GS datum (rotatable); previously compile-time owner.
          must_be_signed_by_credential(self, gs.admin_credential_hash),
          dict.size(tokens(self.mint, policy_id)) == 1,
          // Only the root is spent, and `deinit` already requires the list to
          // be empty. Defence in depth beside the library's own scan — see the
          // note on the Add branch.
          (utils.count_inputs_with_policy(self.inputs, policy_id) == 1)?,
          deinit(self.inputs, self.mint, fn(_, _, _) { True })
            |> run_root_with(policy_id, constants.linked_list_root_key),
          // Every output carrying this policy — after a deinit there should be
          // none — is at the list spend script. See the note on the Add branch.
          utils.policy_only_at_script(self.outputs, policy_id, list_script_hash)?,
        }
      }
      AddPowerUser {
        new_power_user_key,
        anchor_node_output_index,
        appended_node_output_index,
        global_state_ref_input_index,
      } -> {
        let admin = active_admin_from_ref_input(
          self.reference_inputs,
          global_state_ref_input_index,
          global_state_policy_id,
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
          // grant out rather than rejecting it up front.
          bytearray.length(new_power_user_key) == 28,
          must_be_signed_by_credential(self, admin),
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
              expect power_user_data: PowerUser = node_data
              and {
                node_key == new_power_user_key,
                power_user_data.credential_hash == node_key,
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
      RemovePowerUser {
        power_user_key_to_remove,
        anchor_node_input_index,
        anchor_node_output_index,
        global_state_ref_input_index,
      } -> {
        let admin = active_admin_from_ref_input(
          self.reference_inputs,
          global_state_ref_input_index,
          global_state_policy_id,
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
          bytearray.length(power_user_key_to_remove) == 28,
          must_be_signed_by_credential(self, admin),
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
              expect _parsed: PowerUser = rem_data
              rem_key == power_user_key_to_remove
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

// ============================================================================
// Tests
// ============================================================================

const t_gs_policy: ByteArray =
  #"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

const t_pu_policy: ByteArray =
  #"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

/// A policy unrelated to the list, sorting before `t_pu_policy`.
const t_foreign_policy: ByteArray =
  #"1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f"

const t_gs_script_hash: ByteArray =
  #"0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d"

const t_pu_script_hash: ByteArray =
  #"d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1"

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

fn t_power_user(
  is_admin: Bool,
  can_mint: Bool,
  can_burn: Bool,
  can_pause: Bool,
  can_force_transfer: Bool,
) -> PowerUser {
  PowerUser {
    credential_hash: t_pu_cred,
    is_admin,
    can_mint,
    can_burn,
    can_pause,
    can_force_transfer,
  }
}

/// A genuine power-user NODE at the list's spend address, carrying the
/// list's NFT, keyed at `t_pu_cred` (i.e. `pu.credential_hash` must be
/// `t_pu_cred` for the asset name to match the datum).
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

/// The same node continued as an OUTPUT — same key, same address, a
/// possibly different `PowerUser` datum. Used by the `ModifyPowerUser`
/// tests, where the input and continuing output must agree on everything
/// except the data.
fn t_pu_node_output(pu: PowerUser) -> Output {
  t_pu_node_input(0, pu).output
}

/// A UTxO sitting at the power-users' own spend address that carries NO
/// power-users-policy token — e.g. value sent there by mistake.
fn t_pu_stray_input(ix: Int) -> Input {
  Input {
    output_reference: t_oref(ix),
    output: Output {
      address: Address {
        payment_credential: Script(t_pu_script_hash),
        stake_credential: None,
      },
      value: from_lovelace(5_000_000),
      datum: NoDatum,
      reference_script: None,
    },
  }
}

/// The power-users ROOT with an empty list.
fn t_pu_root_input(ix: Int) -> Input {
  let element: Element<Data, Data> = Element {
    data: Root { data: builtin.constr_data(0, []) },
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
        from_asset(t_pu_policy, constants.linked_list_root_key, 1),
      ),
      datum: InlineDatum(element),
      reference_script: None,
    },
  }
}

/// The power-users ROOT as an OUTPUT, with a settable link.
fn t_pu_root_output(link: Option<ByteArray>) -> Output {
  let element: Element<Data, Data> = Element {
    data: Root { data: builtin.constr_data(0, []) },
    link,
  }
  Output { ..t_pu_root_input(0).output, datum: InlineDatum(element) }
}

/// The power-users ROOT as an INPUT with a settable link — a remove spends a
/// root that points AT the operator being revoked.
fn t_pu_root_input_linked(ix: Int, link: Option<ByteArray>) -> Input {
  Input { output_reference: t_oref(ix), output: t_pu_root_output(link) }
}

/// A power-user node output keyed at an arbitrary `key` — `t_pu_node_input`
/// is hardwired to `t_pu_cred`, but an insert must produce a node at the key
/// the redeemer names.
fn t_pu_new_node_output_with_credential(
  key: ByteArray,
  credential_hash: ByteArray,
) -> Output {
  let pu = PowerUser {
    credential_hash,
    is_admin: False,
    can_mint: False,
    can_burn: False,
    can_pause: False,
    can_force_transfer: False,
  }
  let element: Element<Data, PowerUser> = Element {
    data: Node { data: pu },
    link: None,
  }
  Output {
    address: Address {
      payment_credential: Script(t_pu_script_hash),
      stake_credential: None,
    },
    value: merge(
      from_lovelace(2_000_000),
      from_asset(t_pu_policy, t_ll_asset_name(key), 1),
    ),
    datum: InlineDatum(element),
    reference_script: None,
  }
}

fn t_pu_new_node_output(key: ByteArray) -> Output {
  t_pu_new_node_output_with_credential(key, key)
}

fn t_gs_datum(deactivated: Bool) -> GlobalStateDatum {
  GlobalStateDatum {
    global_state_script_credential_hash: #"9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a",
    transfers_paused: False,
    deactivated,
    mintable_amount: 1_000_000_000,
    admin_credential_hash: t_admin,
    power_user_linked_list_policy_id: t_pu_policy,
    denylist_linked_list_policy_id: #"",
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

/// A plain UTxO used as the one-shot genesis nonce.
fn t_nonce_input(ix: Int) -> Input {
  Input {
    output_reference: t_oref(ix),
    output: Output {
      address: Address {
        payment_credential: VerificationKey(t_admin),
        stake_credential: None,
      },
      value: from_lovelace(5_000_000),
      datum: NoDatum,
      reference_script: None,
    },
  }
}

// ── Guard 1: the spend gate binds to the UTxO actually being spent ─────────

/// POSITIVE control. A genuine node spend under `StateTransition`, with a
/// genuine power-users mint/burn present — the ordinary shape of every
/// insert/remove's element-side spend. Must still succeed.
test power_users_spend_accepts_a_genuine_node_spend_alongside_a_mutation() {
  let no_datum: Option<Data> = None
  let tx = Transaction {
    ..t_base_tx(),
    inputs: [
      t_pu_node_input(0, t_power_user(False, False, False, False, False)),
    ],
    mint: from_asset(t_pu_policy, t_ll_asset_name(t_pu_cred), 1),
  }
  power_users_validator.spend(
    t_gs_policy,
    no_datum,
    StateTransition,
    t_oref(0),
    tx,
  )
}

/// THE GUARD under test. A UTxO sitting at the power-users address with NO
/// power-users-policy token — not list state at all — spent under
/// `StateTransition` while a genuine power-users mint/burn happens elsewhere
/// in the very same transaction. `spend_for_adding_or_removing_an_element`
/// asks only "does the mint field carry this policy anywhere", so without a
/// check on the spent UTxO itself its value could be swept out alongside any
/// real insert/remove. The validator reads the list policy off ITS OWN spent
/// input, which must hold lovelace plus exactly one NFT; this one holds only
/// lovelace, so the derivation traps — hence `fail`, written `… || True` so
/// that a validator merely returning False cannot pass it.
test power_users_spend_rejects_a_stray_no_token_utxo_swept_alongside_a_mutation() fail {
  let no_datum: Option<Data> = None
  let tx = Transaction {
    ..t_base_tx(),
    inputs: [t_pu_stray_input(0)],
    mint: from_asset(t_pu_policy, t_ll_asset_name(t_pu_cred), 1),
  }
  power_users_validator.spend(
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
// (`power_users_spend_accepts_a_genuine_node_spend_alongside_a_mutation`) with
// only the spent node's value changed. The derivation traps on any shape but
// lovelace plus one NFT, so each is written `… || True`: a validator that
// merely returns False cannot pass it, only a trap can.

/// The control's node with `extra` merged into its value.
fn t_pu_node_with(extra: Assets) -> Input {
  let node = t_pu_node_input(0, t_power_user(False, False, False, False, False))
  Input {
    ..node,
    output: Output { ..node.output, value: merge(node.output.value, extra) },
  }
}

fn t_run_pu_state_transition(own_input: Input) -> Bool {
  let no_datum: Option<Data> = None
  power_users_validator.spend(
    t_gs_policy,
    no_datum,
    StateTransition,
    t_oref(0),
    Transaction {
      ..t_base_tx(),
      inputs: [own_input],
      mint: from_asset(t_pu_policy, t_ll_asset_name(t_pu_cred), 1),
    },
  )
}

/// A second policy beside the list NFT. It sorts before the list policy, so a
/// derivation reading the first token's policy would pick it.
test power_users_spend_refuses_an_own_input_with_two_policies() fail {
  t_run_pu_state_transition(
    t_pu_node_with(from_asset(t_foreign_policy, t_ll_asset_name(t_pu_cred), 1)),
  ) || True
}

/// A second asset name under the list policy.
test power_users_spend_refuses_an_own_input_with_two_names_of_one_policy() fail {
  t_run_pu_state_transition(
    t_pu_node_with(from_asset(t_pu_policy, t_ll_asset_name(t_key_28), 1)),
  ) || True
}

/// The list NFT at quantity 2.
test power_users_spend_refuses_an_own_input_with_quantity_two() fail {
  t_run_pu_state_transition(
    t_pu_node_with(from_asset(t_pu_policy, t_ll_asset_name(t_pu_cred), 1)),
  ) || True
}

/// A UTxO at the list address holding an unrelated policy's NFT, spent under
/// `StateTransition` beside a mint of that unrelated policy: accepted. This is
/// harmless. The spend reads the unrelated policy off the UTxO, so its own
/// mint decides the spend, not this list's; and every reader names the list
/// policy, so such a UTxO is never list state.
test power_users_spend_accepts_a_foreign_utxo_under_its_own_mint() {
  let no_datum: Option<Data> = None
  let node = t_pu_node_input(0, t_power_user(False, False, False, False, False))
  let foreign_input = Input {
    ..node,
    output: Output {
      ..node.output,
      value: merge(
        from_lovelace(2_000_000),
        from_asset(t_foreign_policy, t_ll_asset_name(t_pu_cred), 1),
      ),
    },
  }
  power_users_validator.spend(
    t_gs_policy,
    no_datum,
    StateTransition,
    t_oref(0),
    Transaction {
      ..t_base_tx(),
      inputs: [foreign_input],
      mint: from_asset(t_foreign_policy, t_ll_asset_name(t_key_28), 1),
    },
  )
}

// ── Guard 2: node keys must be exactly 28 bytes ─────────────────────────────

fn t_pu_insert_tx(key: ByteArray) -> Transaction {
  Transaction {
    ..t_base_tx(),
    inputs: [t_pu_root_input(0)],
    reference_inputs: [t_gs_utxo(0, t_gs_datum(False))],
    mint: from_asset(t_pu_policy, t_ll_asset_name(key), 1),
    outputs: [t_pu_root_output(Some(key)), t_pu_new_node_output(key)],
    extra_signatories: [t_admin],
  }
}

fn t_run_pu_add(key: ByteArray, tx: Transaction) -> Bool {
  mint.mint(
    t_gs_policy,
    t_oref(99),
    t_pu_script_hash,
    AddPowerUser {
      new_power_user_key: key,
      anchor_node_output_index: 0,
      appended_node_output_index: 1,
      global_state_ref_input_index: 0,
    },
    t_pu_policy,
    tx,
  )
}

/// POSITIVE control for the insert length checks below — everything else
/// about `t_pu_insert_tx` is exactly what the negatives reuse, differing
/// only in the key's length.
test power_users_insert_accepts_a_28_byte_key() {
  t_run_pu_add(t_key_28, t_pu_insert_tx(t_key_28))
}

test power_users_insert_rejects_a_mismatched_credential_hash() fail {
  let tx = Transaction {
    ..t_pu_insert_tx(t_key_28),
    outputs: [
      t_pu_root_output(Some(t_key_28)),
      t_pu_new_node_output_with_credential(t_key_28, t_pu_cred),
    ],
  }
  t_run_pu_add(t_key_28, tx)
}

/// THE GUARD under test, one byte short. `bytearray.length(new_power_user_key)
/// == 28` is the FIRST conjunct of the branch's `and { }`, so it
/// short-circuits before `insert_ascending` ever runs. Returns False, hence
/// `!`.
test power_users_insert_rejects_a_27_byte_key() {
  !t_run_pu_add(t_key_27, t_pu_insert_tx(t_key_27))
}

/// Same guard, one byte long.
test power_users_insert_rejects_a_29_byte_key() {
  !t_run_pu_add(t_key_29, t_pu_insert_tx(t_key_29))
}

fn t_pu_remove_tx(key: ByteArray) -> Transaction {
  Transaction {
    ..t_base_tx(),
    inputs: [
      t_pu_root_input_linked(0, Some(key)),
      Input { output_reference: t_oref(1), output: t_pu_new_node_output(key) },
    ],
    reference_inputs: [t_gs_utxo(0, t_gs_datum(False))],
    mint: from_asset(t_pu_policy, t_ll_asset_name(key), -1),
    outputs: [t_pu_root_output(None)],
    extra_signatories: [t_admin],
  }
}

fn t_run_pu_remove(key: ByteArray, tx: Transaction) -> Bool {
  mint.mint(
    t_gs_policy,
    t_oref(99),
    t_pu_script_hash,
    RemovePowerUser {
      power_user_key_to_remove: key,
      anchor_node_input_index: 0,
      anchor_node_output_index: 0,
      global_state_ref_input_index: 0,
    },
    t_pu_policy,
    tx,
  )
}

/// POSITIVE control for the remove length checks below.
test power_users_remove_accepts_a_28_byte_key() {
  t_run_pu_remove(t_key_28, t_pu_remove_tx(t_key_28))
}

/// THE GUARD under test on the Remove branch, one byte short. Same
/// short-circuit reasoning as the insert case: the length conjunct is
/// first, so `remove` never runs. Returns False, hence `!`.
test power_users_remove_rejects_a_27_byte_key() {
  !t_run_pu_remove(t_key_27, t_pu_remove_tx(t_key_27))
}

/// Same guard, one byte long.
test power_users_remove_rejects_a_29_byte_key() {
  !t_run_pu_remove(t_key_29, t_pu_remove_tx(t_key_29))
}

// ── ModifyPowerUser branch coverage ─────────────────────────────────────────

fn t_pu_modify_tx(old_pu: PowerUser, new_pu: PowerUser) -> Transaction {
  Transaction {
    ..t_base_tx(),
    inputs: [t_pu_node_input(0, old_pu)],
    outputs: [t_pu_node_output(new_pu)],
    reference_inputs: [t_gs_utxo(0, t_gs_datum(False))],
    extra_signatories: [t_admin],
  }
}

fn t_run_pu_modify(wanted: PowerUser, tx: Transaction) -> Bool {
  let no_datum: Option<Data> = None
  power_users_validator.spend(
    t_gs_policy,
    no_datum,
    ModifyPowerUser {
      own_input_index: 0,
      own_output_index: 0,
      wanted_user_state: wanted,
      global_state_ref_input_index: 0,
    },
    t_oref(0),
    tx,
  )
}

/// POSITIVE control. Admin-signed, and the continuing output's datum equals
/// exactly the redeemer's `wanted_user_state`. The ordinary role-grant flow.
test power_user_modify_accepts_an_admin_signed_change_matching_the_wanted_state() {
  let old_pu = t_power_user(False, False, False, False, False)
  let new_pu = PowerUser { ..old_pu, can_mint: True }
  t_run_pu_modify(new_pu, t_pu_modify_tx(old_pu, new_pu))
}

test power_user_modify_rejects_a_mismatched_credential_hash() fail {
  let old_pu = t_power_user(False, False, False, False, False)
  let new_pu = PowerUser { ..old_pu, credential_hash: t_key_28, can_mint: True }
  t_run_pu_modify(new_pu, t_pu_modify_tx(old_pu, new_pu))
}

/// Without the admin's signature, a role change must be rejected — otherwise
/// anyone could grant themselves (or anyone else) any role. `must_be_signed_
/// by_credential` is the FIRST conjunct of the branch's `and { }`, so it
/// short-circuits before `spend_for_updating_elements_data` ever runs.
/// Returns False, hence `!`.
test power_user_modify_rejects_a_missing_admin_signature() {
  let old_pu = t_power_user(False, False, False, False, False)
  let new_pu = PowerUser { ..old_pu, can_mint: True }
  !t_run_pu_modify(
    new_pu,
    Transaction { ..t_pu_modify_tx(old_pu, new_pu), extra_signatories: [] },
  )
}

/// THE GUARD under test: the continuing output's ACTUAL datum
/// (`can_burn: True`) disagrees with the redeemer's claimed
/// `wanted_user_state` (`can_mint: True`) — an admin could otherwise declare
/// one role change and grant a different one. The mismatch is caught inside
/// the library's `spend_for_updating_elements_data`, whose
/// `additional_validations` callback returns `power_user_data ==
/// wanted_user_state` — False here — and the library wraps that call in
/// `expect additional_validations(...)`, which TRAPS on False. Hence `fail`,
/// not `!`.
test power_user_modify_rejects_an_output_datum_that_disagrees_with_the_wanted_state() fail {
  let old_pu = t_power_user(False, False, False, False, False)
  let claimed_new_pu = PowerUser { ..old_pu, can_mint: True }
  let actual_new_pu = PowerUser { ..old_pu, can_burn: True }
  t_run_pu_modify(claimed_new_pu, t_pu_modify_tx(old_pu, actual_new_pu))
}

// ── Init / Deinit branch coverage ───────────────────────────────────────────

/// `Init` — genesis. The nonce UTxO must be spent and no list element may
/// exist yet.
test power_users_init_succeeds_on_the_nonce_utxo() {
  mint.mint(
    t_gs_policy,
    t_oref(50),
    t_pu_script_hash,
    Init { root_output_index: 0 },
    t_pu_policy,
    Transaction {
      ..t_base_tx(),
      inputs: [t_nonce_input(50)],
      mint: from_asset(t_pu_policy, constants.linked_list_root_key, 1),
      outputs: [t_pu_root_output(None), t_gs_utxo(0, t_gs_datum(False)).output],
    },
  )
}

/// Without the one-shot nonce input, genesis must fail — otherwise anyone
/// could create a second, parallel power-users list and point a deployment
/// at it. The library's `init` guards this with `expect nonce_validated`,
/// which TRAPS, hence `fail`.
test power_users_init_rejects_a_missing_nonce() fail {
  mint.mint(
    t_gs_policy,
    t_oref(50),
    t_pu_script_hash,
    Init { root_output_index: 0 },
    t_pu_policy,
    Transaction {
      ..t_base_tx(),
      inputs: [],
      mint: from_asset(t_pu_policy, constants.linked_list_root_key, 1),
      outputs: [t_pu_root_output(None), t_gs_utxo(0, t_gs_datum(False)).output],
    },
  )
}

/// `Deinit` — burning the root. Admin-signed, on an empty list, and only once
/// the protocol has been deactivated: the root can never be re-created (`Init`
/// is nonce-gated to a UTxO spent at genesis) and `AddPowerUser` needs an
/// existing element as its anchor, so burning it while the token is live would
/// permanently destroy every operator role — mint, burn, pause, unpause,
/// seizure and sanctions alike.
test power_users_deinit_succeeds_for_the_admin_after_deactivation() {
  mint.mint(
    t_gs_policy,
    t_oref(99),
    t_pu_script_hash,
    Deinit { global_state_ref_input_index: 0 },
    t_pu_policy,
    Transaction {
      ..t_base_tx(),
      inputs: [t_pu_root_input(0)],
      reference_inputs: [t_gs_utxo(0, t_gs_datum(True))],
      mint: from_asset(t_pu_policy, constants.linked_list_root_key, -1),
      extra_signatories: [t_admin],
    },
  )
}

/// THE ATTACK the `deactivated` gate exists for: the same admin-signed
/// `Deinit` against a LIVE protocol. `gs.deactivated?` is the first conjunct
/// of the branch's `and { }`, so the validator returns False — hence `!`.
test power_users_deinit_rejects_a_live_protocol() {
  !mint.mint(
    t_gs_policy,
    t_oref(99),
    t_pu_script_hash,
    Deinit { global_state_ref_input_index: 0 },
    t_pu_policy,
    Transaction {
      ..t_base_tx(),
      inputs: [t_pu_root_input(0)],
      reference_inputs: [t_gs_utxo(0, t_gs_datum(False))],
      mint: from_asset(t_pu_policy, constants.linked_list_root_key, -1),
      extra_signatories: [t_admin],
    },
  )
}

/// Unsigned by the admin, the root cannot be burnt — otherwise anyone could
/// destroy the operator list once the protocol was decommissioned. Returns
/// False, hence `!`.
test power_users_deinit_rejects_a_missing_admin_signature() {
  !mint.mint(
    t_gs_policy,
    t_oref(99),
    t_pu_script_hash,
    Deinit { global_state_ref_input_index: 0 },
    t_pu_policy,
    Transaction {
      ..t_base_tx(),
      inputs: [t_pu_root_input(0)],
      reference_inputs: [t_gs_utxo(0, t_gs_datum(True))],
      mint: from_asset(t_pu_policy, constants.linked_list_root_key, -1),
    },
  )
}

// Non-upgradeable: must keep reading a GlobalState datum a future version
// extended with trailing fields (see decode_global_state_core).
test power_users_insert_accepts_a_global_state_with_trailing_fields() {
  t_run_pu_add(
    t_key_28,
    tests.with_trailing_gs_fields(t_pu_insert_tx(t_key_28), t_gs_policy),
  )
}

// ── Init — bound to the genesis GlobalState ──────────────────────────────────
//
// The GlobalState minted alongside must name THIS list; its id is immutable
// afterwards, so a mismatch would leave every role on this list unreachable.

fn t_run_pu_init(outputs: List<Output>) -> Bool {
  mint.mint(
    t_gs_policy,
    t_oref(50),
    t_pu_script_hash,
    Init { root_output_index: 0 },
    t_pu_policy,
    Transaction {
      ..t_base_tx(),
      inputs: [t_nonce_input(50)],
      mint: from_asset(t_pu_policy, constants.linked_list_root_key, 1),
      outputs,
    },
  )
}

test power_users_init_rejects_a_global_state_naming_another_list() {
  !t_run_pu_init(
    [
      t_pu_root_output(None),
      t_gs_utxo(
        0,
        GlobalStateDatum {
          ..t_gs_datum(False),
          power_user_linked_list_policy_id: #"0101010101010101010101010101010101010101010101010101010101",
        },
      ).output,
    ],
  )
}

// No GlobalState created in this transaction: nothing to bind to, so genesis
// cannot proceed (the lookup traps, hence `fail`).
test power_users_init_rejects_without_a_genesis_global_state() fail {
  t_run_pu_init([t_pu_root_output(None)])
}

// Frozen core: both GlobalState read paths (the admin read and Deinit's) keep
// working when a later logic reshapes every field after 0–4.
test power_users_insert_accepts_a_global_state_with_a_reshaped_tail() {
  t_run_pu_add(
    t_key_28,
    tests.with_reshaped_gs_tail(t_pu_insert_tx(t_key_28), t_gs_policy),
  )
}

test power_users_deinit_accepts_a_global_state_with_a_reshaped_tail() {
  mint.mint(
    t_gs_policy,
    t_oref(99),
    t_pu_script_hash,
    Deinit { global_state_ref_input_index: 0 },
    t_pu_policy,
    tests.with_reshaped_gs_tail(
      Transaction {
        ..t_base_tx(),
        inputs: [t_pu_root_input(0)],
        reference_inputs: [t_gs_utxo(0, t_gs_datum(True))],
        mint: from_asset(t_pu_policy, constants.linked_list_root_key, -1),
        extra_signatories: [t_admin],
      },
      t_gs_policy,
    ),
  )
}

// The admin read must treat a malformed `deactivated` as an error, never as
// "live" (a lenient Bool read would let this insert through).
test power_users_insert_rejects_a_malformed_deactivated_flag() fail {
  t_run_pu_add(
    t_key_28,
    tests.with_malformed_gs_deactivated(t_pu_insert_tx(t_key_28), t_gs_policy),
  )
}

// ── Add: the node key must match the redeemer ────────────────────────────────
const t_other_key: ByteArray =
  #"06060606060606060606060606060606060606060606060606060606"

test pu_add_rejects_a_node_keyed_other_than_the_redeemer() fail {
  t_run_pu_add(t_key_28, t_pu_insert_tx(t_other_key))
}

// ── A list NFT never leaves the list script ─────────────────────────────────
//
// One refusal per path through which a power-users NFT is minted, moved or
// kept. Each is an accepted fixture above with only the NFT's destination
// changed; its accepted control is named in its comment. A `fail` test here
// is written `… || True`, so a validator that merely returns False cannot
// pass it — only a trap can.

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

fn t_at_script(output: Output, script_hash: ByteArray) -> Output {
  Output {
    ..output,
    address: Address {
      payment_credential: Script(script_hash),
      stake_credential: None,
    },
  }
}

// Init: control `power_users_init_succeeds_on_the_nonce_utxo`, the same
// transaction with the root at the list script.
test power_users_init_refuses_a_root_at_a_wallet() fail {
  t_run_pu_init(
    [
      t_at_wallet(t_pu_root_output(None)),
      t_gs_utxo(0, t_gs_datum(False)).output,
    ],
  ) || True
}

test power_users_init_refuses_a_root_at_another_script() fail {
  t_run_pu_init(
    [
      t_at_script(t_pu_root_output(None), t_gs_script_hash),
      t_gs_utxo(0, t_gs_datum(False)).output,
    ],
  ) || True
}

// The list script's hash under a key credential: the whole credential is
// compared, not just its hash.
test power_users_init_refuses_a_root_at_the_key_hash_of_the_list_script() fail {
  t_run_pu_init(
    [
      Output {
        ..t_pu_root_output(None),
        address: Address {
          payment_credential: VerificationKey(t_pu_script_hash),
          stake_credential: None,
        },
      },
      t_gs_utxo(0, t_gs_datum(False)).output,
    ],
  ) || True
}

// The root at the list script with a stake part: the stake part is free.
test power_users_init_accepts_a_root_with_a_stake_credential() {
  t_run_pu_init(
    [
      Output {
        ..t_pu_root_output(None),
        address: Address {
          payment_credential: Script(t_pu_script_hash),
          stake_credential: Some(Inline(VerificationKey(t_admin))),
        },
      },
      t_gs_utxo(0, t_gs_datum(False)).output,
    ],
  )
}

// AddPowerUser: control `power_users_insert_accepts_a_28_byte_key`. The new
// node must share the anchor's payment credential (the library's insert
// check), so it traps.
test power_users_insert_refuses_a_new_node_at_a_wallet() fail {
  let tx = t_pu_insert_tx(t_key_28)
  t_run_pu_add(
    t_key_28,
    Transaction {
      ..tx,
      outputs: [
        t_pu_root_output(Some(t_key_28)),
        t_at_wallet(t_pu_new_node_output(t_key_28)),
      ],
    },
  ) || True
}

// The continued anchor must keep the anchor's full address (library), so it
// traps.
test power_users_insert_refuses_an_anchor_continuation_at_a_wallet() fail {
  let tx = t_pu_insert_tx(t_key_28)
  t_run_pu_add(
    t_key_28,
    Transaction {
      ..tx,
      outputs: [
        t_at_wallet(t_pu_root_output(Some(t_key_28))),
        t_pu_new_node_output(t_key_28),
      ],
    },
  ) || True
}

// RemovePowerUser: control `power_users_remove_accepts_a_28_byte_key`. The
// continued anchor must keep the anchor's address (library), so it traps.
test power_users_remove_refuses_an_anchor_continuation_at_a_wallet() fail {
  t_run_pu_remove(
    t_key_28,
    Transaction {
      ..t_pu_remove_tx(t_key_28),
      outputs: [t_at_wallet(t_pu_root_output(None))],
    },
  ) || True
}

// The removed node's NFT is paid to a wallet instead of burnt, so nothing of
// this policy is minted and the branch's one-asset mint conjunct returns
// False, hence `!`.
test power_users_remove_refuses_a_removed_node_kept_in_a_wallet() {
  !t_run_pu_remove(
    t_key_28,
    Transaction {
      ..t_pu_remove_tx(t_key_28),
      mint: zero,
      outputs: [
        t_pu_root_output(None),
        t_at_wallet(t_pu_new_node_output(t_key_28)),
      ],
    },
  )
}

// The same, with another node NFT minted in place of the burn so that this
// policy still runs. The library requires the removal to burn exactly the
// removed node's NFT, so it traps.
test power_users_remove_refuses_a_removed_node_kept_under_another_list_mint() fail {
  t_run_pu_remove(
    t_key_28,
    Transaction {
      ..t_pu_remove_tx(t_key_28),
      mint: from_asset(t_pu_policy, t_ll_asset_name(t_other_key), 1),
      outputs: [
        t_pu_root_output(None),
        t_at_wallet(t_pu_new_node_output(t_key_28)),
      ],
    },
  ) || True
}

// The same, burning another node's NFT instead: the quantity is right, so
// only the library's burnt-name check refuses it, by trapping. In-process
// only: no input carries that NFT, so the ledger could not balance the burn.
test power_users_remove_refuses_burning_another_node_in_place_of_the_removed_one() fail {
  t_run_pu_remove(
    t_key_28,
    Transaction {
      ..t_pu_remove_tx(t_key_28),
      mint: from_asset(t_pu_policy, t_ll_asset_name(t_other_key), -1),
      outputs: [
        t_pu_root_output(None),
        t_at_wallet(t_pu_new_node_output(t_key_28)),
      ],
    },
  ) || True
}

// Deinit: control `power_users_deinit_succeeds_for_the_admin_after_deactivation`.
fn t_pu_deinit_tx() -> Transaction {
  Transaction {
    ..t_base_tx(),
    inputs: [t_pu_root_input(0)],
    reference_inputs: [t_gs_utxo(0, t_gs_datum(True))],
    mint: from_asset(t_pu_policy, constants.linked_list_root_key, -1),
    extra_signatories: [t_admin],
  }
}

fn t_run_pu_deinit(tx: Transaction) -> Bool {
  mint.mint(
    t_gs_policy,
    t_oref(99),
    t_pu_script_hash,
    Deinit { global_state_ref_input_index: 0 },
    t_pu_policy,
    tx,
  )
}

// The root is paid to a wallet instead of burnt: nothing of this policy is
// minted, so the one-asset mint conjunct returns False, hence `!`.
test power_users_deinit_refuses_a_root_kept_in_a_wallet() {
  !t_run_pu_deinit(
    Transaction {
      ..t_pu_deinit_tx(),
      mint: zero,
      outputs: [t_at_wallet(t_pu_root_input(0).output)],
    },
  )
}

// The same, with a node NFT minted in place of the burn. The library requires
// deinit to burn exactly the root NFT, so it traps.
test power_users_deinit_refuses_a_root_kept_under_another_list_mint() fail {
  t_run_pu_deinit(
    Transaction {
      ..t_pu_deinit_tx(),
      mint: from_asset(t_pu_policy, t_ll_asset_name(t_other_key), 1),
      outputs: [t_at_wallet(t_pu_root_input(0).output)],
    },
  ) || True
}

// The same, burning a node's NFT instead: the quantity is right, so only the
// library's burnt-name check refuses it, by trapping. In-process only: no
// input carries that NFT, so the ledger could not balance the burn.
test power_users_deinit_refuses_burning_a_node_name_in_place_of_the_root() fail {
  t_run_pu_deinit(
    Transaction {
      ..t_pu_deinit_tx(),
      mint: from_asset(t_pu_policy, t_ll_asset_name(t_other_key), -1),
      outputs: [t_at_wallet(t_pu_root_input(0).output)],
    },
  ) || True
}

// The same, minting the root key instead of burning it: the name is right, so
// only the library's burnt-quantity check refuses it, by trapping. In-process
// only: the minted copy needs an output too, which deinit never reads.
test power_users_deinit_refuses_minting_the_root_key_in_place_of_burning_it() fail {
  t_run_pu_deinit(
    Transaction {
      ..t_pu_deinit_tx(),
      mint: from_asset(t_pu_policy, constants.linked_list_root_key, 1),
      outputs: [t_at_wallet(t_pu_root_input(0).output)],
    },
  ) || True
}

// The control with two of the root key burnt instead of one: the name is
// right and the quantity is a burn, so only the library's exact-quantity
// check refuses it, by trapping. In-process only: one root is spent, so the
// ledger could not balance the burn.
test power_users_deinit_refuses_burning_two_of_the_root_key() fail {
  t_run_pu_deinit(
    Transaction {
      ..t_pu_deinit_tx(),
      mint: from_asset(t_pu_policy, constants.linked_list_root_key, -2),
    },
  ) || True
}

// ModifyPowerUser: control
// `power_user_modify_accepts_an_admin_signed_change_matching_the_wanted_state`.
// The library requires the continuation to keep the spent element's address,
// so both trap.
test power_users_modify_refuses_a_continuation_at_a_wallet() fail {
  let old_pu = t_power_user(False, False, False, False, False)
  let new_pu = PowerUser { ..old_pu, can_mint: True }
  t_run_pu_modify(
    new_pu,
    Transaction {
      ..t_pu_modify_tx(old_pu, new_pu),
      outputs: [t_at_wallet(t_pu_node_output(new_pu))],
    },
  ) || True
}

test power_users_modify_refuses_a_continuation_at_another_script() fail {
  let old_pu = t_power_user(False, False, False, False, False)
  let new_pu = PowerUser { ..old_pu, can_mint: True }
  t_run_pu_modify(
    new_pu,
    Transaction {
      ..t_pu_modify_tx(old_pu, new_pu),
      outputs: [t_at_script(t_pu_node_output(new_pu), t_gs_script_hash)],
    },
  ) || True
}

// Two node spends sharing one continuation. Input 0 is the node keyed
// `t_pu_cred`, input 1 the node keyed `t_key_28`; the spend under test is
// input 1's, citing output 0.
fn t_pu_two_node_modify_tx(outputs: List<Output>) -> Transaction {
  Transaction {
    ..t_base_tx(),
    inputs: [
      t_pu_node_input(0, t_power_user(False, False, False, False, False)),
      Input {
        output_reference: t_oref(1),
        output: t_pu_new_node_output(t_key_28),
      },
    ],
    outputs,
    reference_inputs: [t_gs_utxo(0, t_gs_datum(False))],
    extra_signatories: [t_admin],
  }
}

/// The state input 1 is changed to: its own key, `can_mint` granted.
fn t_pu_second_wanted() -> PowerUser {
  PowerUser {
    credential_hash: t_key_28,
    is_admin: False,
    can_mint: True,
    can_burn: False,
    can_pause: False,
    can_force_transfer: False,
  }
}

/// A node output carrying the NFT keyed `nft_key` and the datum
/// `t_pu_second_wanted()`.
fn t_pu_second_wanted_output(nft_key: ByteArray) -> Output {
  let element: Element<Data, PowerUser> = Element {
    data: Node { data: t_pu_second_wanted() },
    link: None,
  }
  Output { ..t_pu_new_node_output(nft_key), datum: InlineDatum(element) }
}

fn t_run_pu_modify_second(tx: Transaction) -> Bool {
  let no_datum: Option<Data> = None
  power_users_validator.spend(
    t_gs_policy,
    no_datum,
    ModifyPowerUser {
      own_input_index: 1,
      own_output_index: 0,
      wanted_user_state: t_pu_second_wanted(),
      global_state_ref_input_index: 0,
    },
    t_oref(1),
    tx,
  )
}

/// POSITIVE control: input 1's own continuation at the list script, with its
/// own NFT.
test power_users_modify_accepts_a_second_spend_with_its_own_continuation() {
  t_run_pu_modify_second(
    t_pu_two_node_modify_tx([t_pu_second_wanted_output(t_key_28)]),
  )
}

/// Output 0 carries input 0's NFT (`t_pu_cred`), so both spends would cite
/// it, and input 1's NFT goes to a wallet. Output 0's datum is input 1's
/// wanted state, keyed `t_key_28`, so this spend's own credential check
/// passes and only the library's NFT-preservation check refuses it, by
/// trapping. (In a full attack, output 0 would also have to satisfy input 0's
/// spend, whose credential check refuses this datum as well.)
test power_users_modify_refuses_two_spends_sharing_one_continuation() fail {
  t_run_pu_modify_second(
    t_pu_two_node_modify_tx(
      [
        t_pu_second_wanted_output(t_pu_cred),
        t_at_wallet(t_pu_second_wanted_output(t_key_28)),
      ],
    ),
  ) || True
}
