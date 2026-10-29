use aiken/builtin
use aiken/collection/list
use cardano/address.{Credential, Script, VerificationKey}
use cardano/assets.{quantity_of}
use cardano/certificate.{Certificate, RegisterCredential, UnregisterCredential}
use cardano/transaction.{Input, Output, Transaction, placeholder}
use constants
use tests/global_state_fixtures.{
  t_datum, t_gs_logic, t_gs_policy, t_out_ref, t_output,
}
use types/approval.{ApprovalProxyRedeemer}
use types/global_state.{GlobalStateDatum, gs_core_from_ref_input}
use utils.{must_run_script_withdrawal}

/// The permanent OWNER of every pending transfer of the two-step transfer
/// approval.
///
/// A pending transfer is a programmable-base UTxO whose stake credential is
/// `Script(<this script's hash>)`. The CIP-113 base layer authorises a `Script`
/// owner by its withdraw-0 (`programmable_logic/owner.ak`), so no pending
/// transfer moves unless this handler accepts — and all it does is hand the
/// decision on, so that the rules can be replaced without moving a single
/// pending UTxO:
///
///   this proxy → the GlobalState logic (core field 0), action
///   `DelegateApproval` → the approval logic `approval_logic_hash` names.
///
/// Permanent by construction: its hash IS the vault address, so it can never be
/// redeployed for the UTxOs it owns. It therefore reads only the frozen core
/// (`gs_core_from_ref_input`), never the logic-owned tail where the approval
/// pointer lives — that read happens in the replaceable GlobalState logic.
///
/// The checks, and why each is load-bearing:
/// - GlobalState is a REFERENCE input, and NO input holds the GlobalState NFT.
///   In a transaction that spends GlobalState — `MintSecurity` above all, the
///   one action allowed to move the security token — field 0's withdrawal is
///   present under a spend redeemer, and nothing about the approval would be
///   checked. Refusing a spent GlobalState here does not rely on the ledger
///   keeping inputs and reference inputs disjoint (from protocol version 11
///   only the Plutus V3 context enforces that).
/// - Not deactivated: a decommissioned protocol settles nothing.
/// - (Field 0 is never this script — it would satisfy itself — but that is the
///   GlobalState logic's to keep: genesis and `RotateGlobalStateScript` refuse
///   it. Not re-checked here.)
/// - Field 0's withdraw-0 runs. With GlobalState unspent, a correct GlobalState
///   logic can only pass through `DelegateApproval` (invariant 12 of
///   `global_state_logic`), which in turn requires the approval logic.
validator approval_proxy(global_state_policy_id: ByteArray) {
  withdraw(
    redeemer: ApprovalProxyRedeemer,
    credential: Credential,
    self: Transaction,
  ) {
    // A withdrawal credential may be a verification key, so this is a real
    // assertion, not a formality.
    expect Script(_) = credential
    let global_state_spent = list.any(
      self.inputs,
      fn(input) {
        quantity_of(
          input.output.value,
          global_state_policy_id,
          constants.global_state_asset_name,
        ) > 0
      },
    )
    let core = gs_core_from_ref_input(
      self.reference_inputs,
      redeemer.global_state_ref_input_index,
      global_state_policy_id,
    )
    and {
      !global_state_spent?,
      !core.deactivated?,
      must_run_script_withdrawal(self, core.global_state_script_credential_hash)?,
    }
  }

  // Whitelist RegisterCredential only — see minting_logic_script for rationale.
  // A rubber-stamp publish would let anyone de-register this credential, and
  // no pending transfer could move until it was re-registered.
  publish(_r: Data, c: Certificate, _s: Transaction) {
    when c is {
      RegisterCredential { .. } -> True
      _ -> False
    }
  }

  else(_) {
    fail
  }
}

// ============================================================================
// Tests
// ============================================================================

const p_own: ByteArray =
  #"b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0"

fn p_gs_ref(datum: GlobalStateDatum) -> Input {
  Input { output_reference: t_out_ref(0), output: t_output(datum) }
}

fn p_tx(datum: GlobalStateDatum) -> Transaction {
  Transaction {
    ..placeholder,
    reference_inputs: [p_gs_ref(datum)],
    withdrawals: [Pair(Script(p_own), 0), Pair(Script(t_gs_logic), 0)],
  }
}

fn p_run(tx: Transaction) -> Bool {
  approval_proxy.withdraw(
    t_gs_policy,
    ApprovalProxyRedeemer { global_state_ref_input_index: 0 },
    Script(p_own),
    tx,
  )
}

test proxy_accepts_when_the_global_state_logic_runs() {
  p_run(p_tx(t_datum(False, False)))
}

test proxy_rejects_without_the_global_state_logic() {
  !p_run(
    Transaction {
      ..p_tx(t_datum(False, False)),
      withdrawals: [Pair(Script(p_own), 0)],
    },
  )
}

test proxy_rejects_a_spent_global_state() {
  // The MintSecurity bypass: GlobalState spent (so field 0's withdrawal is
  // there under a spend redeemer) and also referenced. Only the input scan
  // refuses it.
  let tx = p_tx(t_datum(False, False))
  !p_run(Transaction { ..tx, inputs: [p_gs_ref(t_datum(False, False))] })
}

test proxy_rejects_when_deactivated() {
  !p_run(p_tx(t_datum(True, True)))
}

test proxy_rejects_a_reference_input_without_the_nft() fail {
  let gs = p_gs_ref(t_datum(False, False))
  p_run(
    Transaction {
      ..p_tx(t_datum(False, False)),
      reference_inputs: [
        Input {
          ..gs,
          output: Output { ..gs.output, value: assets.from_lovelace(2_000_000) },
        },
      ],
    },
  )
}

test proxy_rejects_key_credential() fail {
  approval_proxy.withdraw(
    t_gs_policy,
    ApprovalProxyRedeemer { global_state_ref_input_index: 0 },
    VerificationKey(p_own),
    p_tx(t_datum(False, False)),
  )
}

test proxy_publish_accepts_registration_only() {
  and {
    approval_proxy.publish(
      t_gs_policy,
      builtin.constr_data(0, []),
      RegisterCredential { credential: Script(p_own), deposit: Never },
      placeholder,
    ),
    !approval_proxy.publish(
      t_gs_policy,
      builtin.constr_data(0, []),
      UnregisterCredential { credential: Script(p_own), refund: Never },
      placeholder,
    ),
  }
}
