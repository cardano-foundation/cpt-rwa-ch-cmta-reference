use aiken/builtin
use aiken/collection/list
use approval_gate
use cardano/address.{
  Address, Credential, Inline, Script, StakeCredential, VerificationKey,
}
use cardano/assets.{from_asset, from_lovelace, merge}
use cardano/certificate.{Certificate, RegisterCredential, UnregisterCredential}
use cardano/transaction.{
  InlineDatum, Input, NoDatum, Output, OutputReference, Transaction, placeholder,
}
use tests/global_state_fixtures.{
  t_admin, t_datum, t_gs_logic, t_gs_policy, t_operator, t_operator_entry,
  t_out_ref, t_output, t_pu_ll_policy, t_pu_script,
}
use types/approval.{
  ApprovalRedeemer, Approve, Cancel, Close, PendingTransfer, Reject,
  SettlementAction,
}
use types/global_state.{
  GlobalStateDatum, GlobalStateLocation, GlobalStateReferenced, GlobalStateSpent,
  approval_view_from_location,
}
use utils

/// The REPLACEABLE rules of the two-step transfer approval — all of them.
///
/// GlobalState's `approval_logic_hash` names this script. Its withdraw-0 is
/// required in two places:
/// - by the transfer logic, in EVERY transaction it validates while
///   `approval_required` is on;
/// - by the GlobalState logic's `DelegateApproval`, which the permanent
///   `approval_proxy` requires whenever a pending transfer is spent.
///
/// The transfer logic knows nothing about the gate beyond that: it skips the
/// vault as a party (no KYC, no denylist) and refuses vault outputs while the
/// switch is off. Everything else is here. Both recognise the VAULT the same
/// way: every UTxO whose stake credential is `Inline(Script(proxy))`. On EVERY
/// run, whatever the redeemer says — the redeemer only carries where
/// GlobalState is and the per-input decisions, so no redeemer can switch a
/// check off:
///
/// 1. THRESHOLD. With the switch on, a transaction spending a holder's
///    security tokens may move at most `approval_threshold` of them, net, to
///    other credentials. Anything more must go to the vault.
/// 2. NO MIXING. A holder's security-token input never shares a transaction
///    with a vault input (any vault input, ADA-only included): a settlement
///    must not carry a holder's own tokens past the threshold.
/// 3. BIND every new pending transfer (output at the vault holding the token):
///    an inline `PendingTransfer` naming the transaction's sole holder as
///    `sender`, stating exactly the security quantity held (> 0), with nothing
///    else beside it but ADA, and neither party this script or the proxy. Other
///    free credentials (the GlobalState logic, a retired approval logic) are
///    not refused as recipient: like any destination, that is for wallets and
///    the approver to refuse (owner decision 2026-10-27).
/// 4. SETTLE every vault input with exactly one action, matched positionally,
///    paired to its own output at a strictly increasing index. The paired
///    output carries every token of the input exactly and at least its
///    lovelace, with no datum or reference script, at the programmable base,
///    owned by `recipient` (Approve) or `sender` (Reject, Cancel). Approve and
///    Reject need the GlobalState ADMIN or an operator holding `can_approve`
///    (its power-user entry named by the redeemer, signed with its KEY); Close
///    needs the admin; Cancel needs the sender only — never the admin or an
///    operator, whatever the switch says.
///
/// It runs only while it is the installed approval logic, so a retired
/// instance's withdrawal is never free. It refuses to run when no input holds a
/// token of the issuance policy (the CIP-68 reference NFT included — a metadata
/// update runs the transfer logic) and no vault input is spent. Outputs are
/// not counted: a transaction whose only policy tokens are in its outputs is a
/// pure mint, and nothing demands this script there.
///
/// What it deliberately does NOT do: KYC, denylist, pause. The transfer logic
/// applies them to every ordinary party. The vault is no party: the original
/// sender is not re-vetted at settlement and the recipient is vetted only when
/// it is paid — the signature of the admin or of a `can_approve` operator is
/// the sanctions screen for a release (owner decision D6, 2026-10-27; the
/// operator role 2026-10-28).
///
/// Replacing it: compile a new instance and `RotateApprovalLogic` in
/// GlobalState. Pending transfers follow, because the proxy that owns them
/// delegates to whatever GlobalState names. This script is the ONLY place the
/// threshold is enforced: a successor that skips it switches the threshold
/// off. See `GlobalStateDatum.approval_logic_hash` for the deployment
/// requirements.
validator approval_logic(
  /// The permanent approval proxy's hash: the owner of every pending transfer.
  approval_proxy_hash: ByteArray,
  /// The GlobalState NFT policy: authenticates the GlobalState this logic
  /// reads its admin, switch and threshold from. `RotateApprovalLogic` never
  /// runs the new logic, so a wrong value here is caught only off-chain — the
  /// post-rotation smoke tests.
  global_state_policy_id: ByteArray,
  /// The power-user list's spend script: an approving operator's entry must
  /// still sit there, so removing an operator takes its approval power away.
  /// A wrong value only shuts the operator path off (the entry check traps);
  /// the admin path is unaffected.
  power_user_list_script_hash: ByteArray,
  issuance_policy_id: ByteArray,
  security_asset_name: ByteArray,
  /// Where `Close` sends the lovelace of a stray vault UTxO. Never owned by
  /// this script or the proxy, or Close would only recreate junk.
  close_payout: Address,
) {
  withdraw(
    redeemer: ApprovalRedeemer,
    credential: Credential,
    self: Transaction,
  ) {
    // A withdrawal credential may be a verification key, so this is a real
    // assertion, not a formality.
    expect Script(own_hash) = credential
    let own = Script(own_hash)
    let proxy = Script(approval_proxy_hash)
    // A pending transfer is recognised by its owner alone, as the transfer
    // logic recognises it: the CIP-113 base layer keeps every token of the
    // policy at the programmable base, so no payment-credential check is
    // needed (and none can be got wrong).
    let vault_owner = Some(Inline(proxy))

    // Authenticated by the NFT. A reference input on every settlement (the
    // proxy refuses a spent GlobalState); spent only in a holder transaction
    // that also spends GlobalState — either way the pre-transaction state.
    // Only the core and the gate fields are decoded.
    let gs = approval_view_from_location(
      self.inputs,
      self.reference_inputs,
      redeemer.global_state_location,
      global_state_policy_id,
    )

    // Parameter sanity, checked at every use because a parameterised script
    // cannot check its parameters at deployment. Only `close_payout` can be
    // checked here: a wrong `approval_proxy_hash`, `issuance_policy_id` or
    // `security_asset_name` passes every run and switches the gate off. Those
    // are caught only off-chain — the deployment checklist and the
    // post-rotation smoke tests (README).
    let parameters_ok = and {
      close_payout.payment_credential != own,
      close_payout.payment_credential != proxy,
      close_payout.stake_credential != Some(Inline(own)),
      close_payout.stake_credential != Some(Inline(proxy)),
    }

    // The admin approves (Approve and Reject also accept a `can_approve`
    // operator, below). Never a credential whose consent anyone can produce:
    // this script, the proxy and the GlobalState logic all run in every
    // settlement, and `must_be_signed_by_credential` accepts a withdrawal.
    // Evaluated only for Approve, Reject and Close — Cancel never depends on
    // the admin's configuration.
    let admin_signed = fn() {
      let admin = gs.core.admin_credential_hash
      and {
        admin != own_hash,
        admin != approval_proxy_hash,
        admin != gs.core.global_state_script_credential_hash,
        utils.must_be_signed_by_credential(self, admin),
      }
    }

    // One pass: does any token of the policy move, is a vault UTxO spent, and
    // what does each holder spend?
    let scan = approval_gate.scan_inputs(
      self.inputs,
      proxy,
      issuance_policy_id,
      security_asset_name,
    )
    let holder_input_seen = scan.holdings != []

    // 1. The threshold: only a holder's own tokens move without approval. A
    //    settlement is the approval (and cannot carry a holder's tokens, 2.).
    let within_threshold = if gs.approval_required && holder_input_seen {
      approval_gate.net_movement_to_others(
        scan.holdings,
        self.outputs,
        proxy,
        issuance_policy_id,
        security_asset_name,
      ) <= gs.approval_threshold
    } else {
      True
    }

    // 3. Bind every new pending transfer (a vault output holding the token).
    let all_bound = list.all(
      self.outputs,
      fn(output) {
        if output.address.stake_credential == vault_owner {
          let quantity = assets.quantity_of(
            output.value,
            issuance_policy_id,
            security_asset_name,
          )
          if quantity > 0 {
            bound(
              output,
              quantity,
              approval_gate.sole_holder(scan.holdings),
              own,
              proxy,
              issuance_policy_id,
              security_asset_name,
            )
          } else {
            True
          }
        } else {
          True
        }
      },
    )

    // Approve and Reject: the admin OR a `can_approve` operator. Close: the
    // admin. Each computed once per run (a closure passed down would
    // re-evaluate for every vault input) and only when an action needs it, so
    // Cancel never reads the admin or the operator entry, and Close never the
    // operator entry; the admin is tried first.
    let approver_signed = list.any(
      redeemer.actions,
      fn(action) {
        when action.decision is {
          Approve | Reject -> True
          _ -> False
        }
      },
    ) && (
      admin_signed() || approval_gate.operator_approved(
        redeemer.approver_ref_input_index,
        gs.core.power_user_linked_list_policy_id,
        power_user_list_script_hash,
        self,
      )
    )
    let closer_signed = list.any(
      redeemer.actions,
      fn(action) { action.decision == Close },
    ) && admin_signed()

    // 4. Settle every pending transfer spent.
    let all_settled = settle_all(
      self.inputs,
      redeemer.actions,
      self.outputs,
      0,
      vault_owner,
      own,
      proxy,
      close_payout,
      approver_signed,
      closer_signed,
      self,
    )

    and {
      parameters_ok?,
      // Only the installed logic runs: a retired one is never free.
      (own_hash == gs.approval_logic_hash)?,
      // Never for nothing.
      (scan.policy_input_seen || scan.vault_input_seen)?,
      // 2. No mixing.
      !(holder_input_seen && scan.vault_input_seen)?,
      within_threshold?,
      all_bound?,
      all_settled?,
    }
  }

  // Whitelist RegisterCredential only — see minting_logic_script for rationale.
  // A rubber-stamp publish would let anyone de-register this credential and
  // stop every request and settlement until it was re-registered.
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

/// A new pending transfer is well-formed. Every check is load-bearing, because
/// settlement moves exactly what the UTxO holds to the party its datum names:
/// - the datum must name the transaction's ONE holder as sender — otherwise a
///   request could claim to come from someone else, and their Cancel would
///   take the tokens;
/// - `amount` must equal the security quantity held and nothing but ADA may
///   sit beside it — the register attributes the UTxO by its datum;
/// - neither party may be this script or the proxy: their withdrawals can be
///   produced by anyone (the other free credentials: see the header, 3.).
fn bound(
  output: Output,
  quantity: Int,
  sole_sender: Option<Credential>,
  own: Credential,
  proxy: Credential,
  issuance_policy_id: ByteArray,
  security_asset_name: ByteArray,
) -> Bool {
  expect Some(sender) = sole_sender
  expect InlineDatum(raw) = output.datum
  expect pending: PendingTransfer = raw
  and {
    pending.sender == sender,
    pending.amount == quantity,
    assets.without_lovelace(output.value) == from_asset(
      issuance_policy_id,
      security_asset_name,
      quantity,
    ),
    pending.sender != own,
    pending.sender != proxy,
    pending.recipient != own,
    pending.recipient != proxy,
  }
}

/// Walk the inputs; every vault input consumes the next action. `outputs` is
/// what is left of the transaction's outputs from index `next_index` on, so
/// each paired output is reached from where the previous one was, never from
/// the head.
fn settle_all(
  inputs: List<Input>,
  actions: List<SettlementAction>,
  outputs: List<Output>,
  next_index: Int,
  vault_owner: Option<StakeCredential>,
  own: Credential,
  proxy: Credential,
  close_payout: Address,
  approver_signed: Bool,
  closer_signed: Bool,
  self: Transaction,
) -> Bool {
  when inputs is {
    // No surplus actions: each one must have settled a vault input.
    [] -> actions == []
    [input, ..rest] ->
      if input.output.address.stake_credential == vault_owner {
        expect [action, ..rest_actions] = actions
        and {
          // Strictly increasing: no output pays two inputs.
          action.output_index >= next_index,
          {
            expect [paired, ..later] = list.drop(
              outputs,
              action.output_index - next_index,
            )
            and {
              settle_one(
                input.output,
                paired,
                action,
                own,
                proxy,
                close_payout,
                approver_signed,
                closer_signed,
                self,
              ),
              settle_all(
                rest,
                rest_actions,
                later,
                action.output_index + 1,
                vault_owner,
                own,
                proxy,
                close_payout,
                approver_signed,
                closer_signed,
                self,
              ),
            }
          },
        }
      } else {
        settle_all(
          rest,
          actions,
          outputs,
          next_index,
          vault_owner,
          own,
          proxy,
          close_payout,
          approver_signed,
          closer_signed,
          self,
        )
      }
  }
}

fn settle_one(
  vault_utxo: Output,
  paired: Output,
  action: SettlementAction,
  own: Credential,
  proxy: Credential,
  close_payout: Address,
  approver_signed: Bool,
  closer_signed: Bool,
  self: Transaction,
) -> Bool {
  // The whole value moves and arrives as a plain holding: every non-ADA asset
  // exactly, and AT LEAST the lovelace. Not lovelace equality: the paired
  // output drops the datum, which frees only ~70 bytes of min-ADA headroom, so
  // a rise in `coinsPerUTxOByte` would otherwise make every pending transfer
  // unsettleable. The CIP-113 base layer made the same choice for seizure
  // residuals (issue #96). A top-up comes from the fee payer and settles
  // nothing else: output indices still strictly increase.
  let moves_everything = and {
    assets.without_lovelace(paired.value) == assets.without_lovelace(
      vault_utxo.value,
    ),
    assets.lovelace_of(paired.value) >= assets.lovelace_of(vault_utxo.value),
    paired.datum == NoDatum,
    paired.reference_script == None,
  }

  // Owned by `owner`, still inside the programmable-logic base.
  let delivered_to = fn(owner: Credential) {
    paired.address == Address(
      vault_utxo.address.payment_credential,
      Some(Inline(owner)),
    )
  }

  // Soft cast: as strict as `expect`, but yields None instead of trapping, so
  // an undecodable datum can reach the `Close` branch.
  let pending = when vault_utxo.datum is {
    InlineDatum(raw) ->
      if raw is p: PendingTransfer {
        Some(p)
      } else {
        None
      }
    _ -> None
  }

  and {
    moves_everything,
    when pending is {
      // A datum naming a free credential as a party is never a real request
      // (binding refuses to create one). The sender is checked always — a
      // free sender would "authorise" its own Cancel — the recipient only where
      // it is paid, so a bad recipient cannot also block Reject and Cancel.
      Some(p) -> and {
          p.sender != own,
          p.sender != proxy,
          when action.decision is {
            Approve -> and {
                p.recipient != own,
                p.recipient != proxy,
                approver_signed,
                delivered_to(p.recipient),
              }
            Reject -> and {
                approver_signed,
                delivered_to(p.sender),
              }
            Cancel -> and {
                approval_gate.credential_authorised(self, p.sender),
                delivered_to(p.sender),
              }
            // A well-formed request is never closed — it is settled.
            Close -> False
          },
        }
      None ->
        when action.decision is {
          Close -> and {
              closer_signed,
              // Lovelace only: tokens never sit under an unreadable datum
              // (binding), and this keeps Close from ever moving one.
              assets.without_lovelace(vault_utxo.value) == assets.zero,
              paired.address == close_payout,
            }
          _ -> False
        }
    },
  }
}

// ============================================================================
// Tests
// ============================================================================

const l_own: ByteArray =
  #"e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5"

const l_proxy: ByteArray =
  #"b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0"

const l_plb: ByteArray =
  #"05050505050505050505050505050505050505050505050505050505"

const l_policy: ByteArray =
  #"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"

const l_sec: ByteArray = "SEC"

const l_sender: ByteArray =
  #"0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a"

const l_recipient: ByteArray =
  #"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"

const l_other: ByteArray =
  #"0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c"

const l_k1: ByteArray =
  #"11111111111111111111111111111111111111111111111111111111"

const l_treasury: ByteArray =
  #"ad01ad01ad01ad01ad01ad01ad01ad01ad01ad01ad01ad01ad01ad01"

fn l_payout() -> Address {
  Address(VerificationKey(l_treasury), None)
}

fn l_ref(ix: Int) -> OutputReference {
  OutputReference {
    transaction_id: #"0000000000000000000000000000000000000000000000000000000000000000",
    output_index: ix,
  }
}

fn l_pending(amount: Int) -> PendingTransfer {
  PendingTransfer {
    sender: VerificationKey(l_sender),
    recipient: VerificationKey(l_recipient),
    amount,
  }
}

fn l_value(amount: Int) {
  merge(from_lovelace(2_000_000), from_asset(l_policy, l_sec, amount))
}

fn l_vault_utxo(amount: Int, datum: Data) -> Output {
  Output {
    address: approval_gate.vault_address(l_plb, l_proxy),
    value: l_value(amount),
    datum: InlineDatum(datum),
    reference_script: None,
  }
}

fn l_vault_input(ix: Int, amount: Int) -> Input {
  Input {
    output_reference: l_ref(ix),
    output: l_vault_utxo(amount, l_pending(amount)),
  }
}

fn l_holding(owner: ByteArray, amount: Int) -> Output {
  Output {
    address: Address(Script(l_plb), Some(Inline(VerificationKey(owner)))),
    value: l_value(amount),
    datum: NoDatum,
    reference_script: None,
  }
}

fn l_holder_input(ix: Int, owner: ByteArray, amount: Int) -> Input {
  Input { output_reference: l_ref(ix), output: l_holding(owner, amount) }
}

/// GlobalState as this logic sees it in the fixtures: approval switched on at
/// threshold 0, this script installed as the approval logic, `t_admin` the
/// admin.
fn l_gs(required: Bool, threshold: Int) -> GlobalStateDatum {
  GlobalStateDatum {
    ..t_datum(False, False),
    approval_required: required,
    approval_threshold: threshold,
    approval_logic_hash: l_own,
  }
}

/// GlobalState as a reference input, at index 0.
fn l_gs_ref(datum: GlobalStateDatum) -> Input {
  Input { output_reference: t_out_ref(99), output: t_output(datum) }
}

fn l_tx(
  inputs: List<Input>,
  outputs: List<Output>,
  signers: List<ByteArray>,
) -> Transaction {
  Transaction {
    ..placeholder,
    inputs,
    reference_inputs: [l_gs_ref(l_gs(True, 0))],
    outputs,
    extra_signatories: signers,
    withdrawals: [Pair(Script(l_own), 0)],
  }
}

/// The same transaction with another GlobalState reference input.
fn with_gs(tx: Transaction, datum: GlobalStateDatum) -> Transaction {
  Transaction { ..tx, reference_inputs: [l_gs_ref(datum)] }
}

const l_gs_at_0: GlobalStateLocation =
  GlobalStateReferenced { global_state_ref_input_index: 0 }

fn l_run(actions: List<SettlementAction>, tx: Transaction) -> Bool {
  l_run_with(l_payout(), actions, tx)
}

fn l_run_with(
  payout: Address,
  actions: List<SettlementAction>,
  tx: Transaction,
) -> Bool {
  approval_logic.withdraw(
    l_proxy,
    t_gs_policy,
    t_pu_script,
    l_policy,
    l_sec,
    payout,
    ApprovalRedeemer {
      global_state_location: l_gs_at_0,
      actions,
      approver_ref_input_index: None,
    },
    Script(l_own),
    tx,
  )
}

fn act(output_index: Int, decision) -> SettlementAction {
  SettlementAction { output_index, decision }
}

const approvers: List<ByteArray> = [t_admin]

// ── Lock: binding new pending transfers ──────────────────────────────────────

fn l_request(datum: Data, amount: Int) -> Transaction {
  l_tx(
    [l_holder_input(10, l_sender, amount)],
    [l_vault_utxo(amount, datum)],
    [l_sender],
  )
}

test lock_accepts_a_bound_request() {
  l_run([], l_request(l_pending(1_000), 1_000))
}

test lock_accepts_a_request_with_change() {
  l_run(
    [],
    l_tx(
      [l_holder_input(10, l_sender, 1_500)],
      [l_vault_utxo(1_000, l_pending(1_000)), l_holding(l_sender, 500)],
      [l_sender],
    ),
  )
}

test lock_rejects_a_datum_naming_another_sender() {
  !l_run(
    [],
    l_request(
      PendingTransfer { ..l_pending(1_000), sender: VerificationKey(l_other) },
      1_000,
    ),
  )
}

test lock_rejects_an_understated_amount() {
  !l_run([], l_request(l_pending(1), 1_000))
}

test lock_rejects_extra_assets_beside_the_token() {
  let tx = l_request(l_pending(1_000), 1_000)
  let out = l_vault_utxo(1_000, l_pending(1_000))
  !l_run(
    [],
    Transaction {
      ..tx,
      outputs: [
        Output { ..out, value: merge(out.value, from_asset(l_other, "X", 1)) },
      ],
    },
  )
}

test lock_rejects_a_missing_datum() fail {
  let out = l_vault_utxo(1_000, l_pending(1_000))
  l_run(
    [],
    Transaction {
      ..l_request(l_pending(1_000), 1_000),
      outputs: [Output { ..out, datum: NoDatum }],
    },
  )
}

test lock_rejects_a_malformed_datum() fail {
  l_run([], l_request(builtin.constr_data(0, []), 1_000))
}

test lock_rejects_two_senders() fail {
  // Whose request would it be?
  l_run(
    [],
    l_tx(
      [l_holder_input(10, l_sender, 600), l_holder_input(11, l_other, 400)],
      [l_vault_utxo(1_000, l_pending(1_000))],
      [l_sender, l_other],
    ),
  )
}

test lock_rejects_a_free_credential_as_recipient() {
  and {
    !l_run(
      [],
      l_request(
        PendingTransfer { ..l_pending(1_000), recipient: Script(l_proxy) },
        1_000,
      ),
    ),
    !l_run(
      [],
      l_request(
        PendingTransfer { ..l_pending(1_000), recipient: Script(l_own) },
        1_000,
      ),
    ),
  }
}

test lock_binds_whatever_the_redeemer_says() {
  // A request carrying a settle-shaped redeemer: there are no vault inputs, so
  // a surplus action is refused, and the unbound output is refused anyway.
  !l_run([act(0, Approve)], l_request(l_pending(1), 1_000))
}

test logic_refuses_to_run_for_nothing() {
  // No input holds a token of the policy and no vault UTxO is spent.
  and {
    // A pure mint: policy tokens in outputs only. Nothing demands this logic
    // there, so it does not run.
    !l_run(
      [],
      Transaction {
        ..l_tx([], [l_holding(l_recipient, 500)], []),
        mint: from_asset(l_policy, l_sec, 500),
      },
    ),
    !l_run(
      [],
      l_tx(
        [
          Input {
            output_reference: l_ref(10),
            output: Output { ..l_holding(l_sender, 0), value: from_lovelace(5) },
          },
        ],
        [Output { ..l_holding(l_other, 0), value: from_lovelace(5) }],
        [],
      ),
    ),
    // An ADA-only output at the vault does not count either.
    !l_run(
      [],
      l_tx(
        [],
        [
          Output {
            ..l_vault_utxo(0, l_pending(0)),
            value: from_lovelace(2_000_000),
          },
        ],
        [],
      ),
    ),
  }
}

// ── Settle: Approve / Reject / Cancel ────────────────────────────────────────

test settle_approve_delivers_to_recipient() {
  l_run(
    [act(0, Approve)],
    l_tx([l_vault_input(0, 100)], [l_holding(l_recipient, 100)], approvers),
  )
}

test settle_reject_returns_to_sender() {
  l_run(
    [act(0, Reject)],
    l_tx([l_vault_input(0, 100)], [l_holding(l_sender, 100)], approvers),
  )
}

test settle_cancel_returns_to_sender() {
  l_run(
    [act(0, Cancel)],
    l_tx([l_vault_input(0, 100)], [l_holding(l_sender, 100)], [l_sender]),
  )
}

test settle_cancel_by_a_script_sender_uses_its_withdrawal() {
  let script_sender = #"5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c"
  let datum = PendingTransfer {
    ..l_pending(100),
    sender: Script(script_sender),
  }
  let input = Input {
    output_reference: l_ref(0),
    output: l_vault_utxo(100, datum),
  }
  let back = Output {
    ..l_holding(l_sender, 100),
    address: Address(Script(l_plb), Some(Inline(Script(script_sender)))),
  }
  let tx = l_tx([input], [back], [])
  and {
    l_run(
      [act(0, Cancel)],
      Transaction {
        ..tx,
        withdrawals: [Pair(Script(l_own), 0), Pair(Script(script_sender), 0)],
      },
    ),
    // A signature by the same hash is a different party.
    !l_run(
      [act(0, Cancel)],
      Transaction { ..tx, extra_signatories: [script_sender] },
    ),
  }
}

test settle_batch_of_two() {
  l_run(
    [act(0, Approve), act(1, Reject)],
    l_tx(
      [l_vault_input(0, 100), l_vault_input(1, 40)],
      [l_holding(l_recipient, 100), l_holding(l_sender, 40)],
      approvers,
    ),
  )
}

test settle_batch_skips_unrelated_outputs() {
  // Paired outputs need not be adjacent: a fee payer's change may sit between.
  let change = l_holding(l_other, 0)
  l_run(
    [act(1, Approve), act(3, Reject)],
    l_tx(
      [l_vault_input(0, 100), l_vault_input(1, 40)],
      [change, l_holding(l_recipient, 100), change, l_holding(l_sender, 40)],
      approvers,
    ),
  )
}

test settle_rejects_decreasing_output_indices() {
  !l_run(
    [act(1, Approve), act(0, Reject)],
    l_tx(
      [l_vault_input(0, 100), l_vault_input(1, 40)],
      [l_holding(l_sender, 40), l_holding(l_recipient, 100)],
      approvers,
    ),
  )
}

test vault_is_recognised_by_its_owner_alone() fail {
  // A pending transfer is whatever the proxy owns, whatever the payment
  // credential says: matching the full address made a logic built with
  // another programmable-base hash see no vault input, settle nothing, and
  // let anyone take every pending transfer with the switch off. Now the vault
  // input finds no action and the run traps.
  let elsewhere = Input {
    ..l_vault_input(0, 100),
    output: Output {
      ..l_vault_utxo(100, l_pending(100)),
      address: Address(Script(l_other), Some(Inline(Script(l_proxy)))),
    },
  }
  l_run(
    [],
    with_gs(l_tx([elsewhere], [l_holding(l_other, 100)], []), l_gs(False, 0)),
  )
}

test parameters_reject_a_close_payout_owned_by_a_free_credential() {
  let tx = l_tx(
    [l_vault_input(0, 100)],
    [l_holding(l_recipient, 100)],
    approvers,
  )
  and {
    !l_run_with(
      approval_gate.vault_address(l_plb, l_proxy),
      [act(0, Approve)],
      tx,
    ),
    !l_run_with(Address(Script(l_own), None), [act(0, Approve)], tx),
  }
}

// ── Settle: destination and value ────────────────────────────────────────────

test settle_approve_rejected_to_the_wrong_party() {
  and {
    !l_run(
      [act(0, Approve)],
      l_tx([l_vault_input(0, 100)], [l_holding(l_sender, 100)], approvers),
    ),
    !l_run(
      [act(0, Approve)],
      l_tx([l_vault_input(0, 100)], [l_holding(l_other, 100)], approvers),
    ),
  }
}

test settle_cancel_rejected_to_the_recipient() {
  !l_run(
    [act(0, Cancel)],
    l_tx([l_vault_input(0, 100)], [l_holding(l_recipient, 100)], [l_sender]),
  )
}

test settle_cancel_rejected_without_the_sender() {
  !l_run(
    [act(0, Cancel)],
    l_tx([l_vault_input(0, 100)], [l_holding(l_sender, 100)], approvers),
  )
}

test settle_rejected_when_a_token_is_short_or_added() {
  let out = l_holding(l_recipient, 100)
  and {
    !l_run(
      [act(0, Approve)],
      l_tx([l_vault_input(0, 100)], [l_holding(l_recipient, 99)], approvers),
    ),
    !l_run(
      [act(0, Approve)],
      l_tx(
        [l_vault_input(0, 100)],
        [
          Output {
            ..out,
            value: merge(out.value, from_asset(l_policy, l_sec, 1)),
          },
        ],
        approvers,
      ),
    ),
  }
}

test settle_accepts_a_lovelace_top_up_and_refuses_a_shortfall() {
  let out = l_holding(l_recipient, 100)
  and {
    l_run(
      [act(0, Approve)],
      l_tx(
        [l_vault_input(0, 100)],
        [Output { ..out, value: merge(out.value, from_lovelace(500_000)) }],
        approvers,
      ),
    ),
    !l_run(
      [act(0, Approve)],
      l_tx(
        [l_vault_input(0, 100)],
        [
          Output {
            ..out,
            value: merge(
              from_lovelace(1_000_000),
              from_asset(l_policy, l_sec, 100),
            ),
          },
        ],
        approvers,
      ),
    ),
  }
}

test settle_rejected_when_the_output_leaves_the_plb() {
  let out = l_holding(l_sender, 100)
  !l_run(
    [act(0, Cancel)],
    l_tx(
      [l_vault_input(0, 100)],
      [
        Output {
          ..out,
          address: Address(
            VerificationKey(l_sender),
            Some(Inline(VerificationKey(l_sender))),
          ),
        },
      ],
      [l_sender],
    ),
  )
}

test settle_rejected_when_the_output_keeps_a_datum_or_script() {
  let out = l_holding(l_recipient, 100)
  and {
    !l_run(
      [act(0, Approve)],
      l_tx(
        [l_vault_input(0, 100)],
        [Output { ..out, datum: InlineDatum(l_pending(100)) }],
        approvers,
      ),
    ),
    !l_run(
      [act(0, Approve)],
      l_tx(
        [l_vault_input(0, 100)],
        [Output { ..out, reference_script: Some(l_own) }],
        approvers,
      ),
    ),
  }
}

test settle_to_the_proxy_recreates_an_unbound_request() fail {
  // Paying a request out to the proxy lands back at the vault: a new
  // token-holding vault output in a transaction with no holder sender, so
  // binding traps (`sole_holder` is None). The settle-side recipient
  // guard is a second, defensive line behind it.
  let to_proxy = PendingTransfer {
    ..l_pending(100),
    recipient: Script(l_proxy),
  }
  l_run(
    [act(0, Approve)],
    l_tx(
      [
        Input {
          output_reference: l_ref(0),
          output: l_vault_utxo(100, to_proxy),
        },
      ],
      [Output { ..l_vault_utxo(100, to_proxy), datum: NoDatum }],
      approvers,
    ),
  )
}

test settle_refuses_a_request_naming_a_free_credential() {
  // Approve to this script's own credential: anyone can produce its
  // withdrawal, so tokens it owned would be free to take.
  let to_own = PendingTransfer { ..l_pending(100), recipient: Script(l_own) }
  let from_own = PendingTransfer { ..l_pending(0), sender: Script(l_own) }
  and {
    !l_run(
      [act(0, Approve)],
      l_tx(
        [
          Input {
            output_reference: l_ref(0),
            output: l_vault_utxo(100, to_own),
          },
        ],
        [
          Output {
            ..l_holding(l_recipient, 100),
            address: Address(Script(l_plb), Some(Inline(Script(l_own)))),
          },
        ],
        approvers,
      ),
    ),
    // Junk vault UTxO "authorising" its own Cancel through this withdrawal.
    !l_run(
      [act(0, Cancel)],
      l_tx(
        [
          Input {
            output_reference: l_ref(0),
            output: Output {
              ..l_vault_utxo(0, from_own),
              value: from_lovelace(3_000_000),
            },
          },
        ],
        [
          Output {
            ..l_holding(l_sender, 0),
            address: Address(Script(l_plb), Some(Inline(Script(l_own)))),
            value: from_lovelace(3_000_000),
          },
        ],
        [],
      ),
    ),
  }
}

// ── Settle: pairing ──────────────────────────────────────────────────────────

test settle_rejects_one_output_for_two_inputs() {
  !l_run(
    [act(0, Approve), act(0, Approve)],
    l_tx(
      [l_vault_input(0, 100), l_vault_input(1, 100)],
      [l_holding(l_recipient, 100)],
      approvers,
    ),
  )
}

test settle_rejects_a_missing_action() fail {
  l_run(
    [act(0, Approve)],
    l_tx(
      [l_vault_input(0, 100), l_vault_input(1, 100)],
      [l_holding(l_recipient, 100), l_holding(l_recipient, 100)],
      approvers,
    ),
  )
}

test settle_rejects_a_surplus_action() {
  !l_run(
    [act(0, Approve), act(1, Approve)],
    l_tx(
      [l_vault_input(0, 100)],
      [l_holding(l_recipient, 100), l_holding(l_recipient, 100)],
      approvers,
    ),
  )
}

test settle_cancels_a_token_free_residual() {
  // Full-drain seizure residual: no token, datum intact.
  let residual = Input {
    output_reference: l_ref(0),
    output: Output {
      ..l_vault_utxo(100, l_pending(100)),
      value: from_lovelace(2_000_000),
    },
  }
  let back = Output {
    ..l_holding(l_sender, 0),
    value: from_lovelace(2_000_000),
  }
  and {
    l_run([act(0, Cancel)], l_tx([residual], [back], [l_sender])),
    !l_run([act(0, Cancel)], l_tx([residual], [back], [])),
  }
}

// ── Close ────────────────────────────────────────────────────────────────────

fn l_stray(datum: Data) -> Input {
  Input {
    output_reference: l_ref(0),
    output: Output { ..l_vault_utxo(0, datum), value: from_lovelace(3_000_000) },
  }
}

fn l_to_payout() -> Output {
  Output {
    address: l_payout(),
    value: from_lovelace(3_000_000),
    datum: NoDatum,
    reference_script: None,
  }
}

test close_sweeps_undecodable_lovelace_to_the_payout() {
  l_run(
    [act(0, Close)],
    l_tx([l_stray(builtin.constr_data(9, []))], [l_to_payout()], approvers),
  )
}

test close_rejected_without_the_admin() {
  !l_run(
    [act(0, Close)],
    l_tx([l_stray(builtin.constr_data(9, []))], [l_to_payout()], [l_k1]),
  )
}

test close_rejected_for_a_wellformed_request() {
  !l_run(
    [act(0, Close)],
    l_tx([l_stray(l_pending(0))], [l_to_payout()], approvers),
  )
}

test close_rejected_when_tokens_are_held() {
  let input = Input {
    output_reference: l_ref(0),
    output: l_vault_utxo(100, builtin.constr_data(9, [])),
  }
  !l_run(
    [act(0, Close)],
    l_tx([input], [Output { ..l_to_payout(), value: l_value(100) }], approvers),
  )
}

test close_rejected_to_another_address() {
  !l_run(
    [act(0, Close)],
    l_tx(
      [l_stray(builtin.constr_data(9, []))],
      [
        Output {
          ..l_to_payout(),
          address: Address(VerificationKey(l_k1), None),
        },
      ],
      approvers,
    ),
  )
}

test close_and_cancel_agree_on_a_malformed_nested_credential() {
  // Right outer shape, but `sender` is not a Credential: it reads as "not a
  // PendingTransfer", so Close applies and Cancel does not.
  let bad = builtin.constr_data(
    0,
    [
      builtin.constr_data(7, [builtin.b_data(l_sender)]),
      builtin.constr_data(0, [builtin.b_data(l_recipient)]),
      builtin.i_data(0),
    ],
  )
  and {
    l_run([act(0, Close)], l_tx([l_stray(bad)], [l_to_payout()], approvers)),
    !l_run(
      [act(0, Cancel)],
      l_tx(
        [l_stray(bad)],
        [Output { ..l_holding(l_sender, 0), value: from_lovelace(3_000_000) }],
        [l_sender],
      ),
    ),
  }
}

// ── Misc ─────────────────────────────────────────────────────────────────────

test logic_rejects_key_credential() fail {
  approval_logic.withdraw(
    l_proxy,
    t_gs_policy,
    t_pu_script,
    l_policy,
    l_sec,
    l_payout(),
    ApprovalRedeemer {
      global_state_location: l_gs_at_0,
      actions: [],
      approver_ref_input_index: None,
    },
    VerificationKey(l_own),
    l_request(l_pending(10), 10),
  )
}

test logic_publish_accepts_registration_only() {
  and {
    approval_logic.publish(
      l_proxy,
      t_gs_policy,
      t_pu_script,
      l_policy,
      l_sec,
      l_payout(),
      builtin.constr_data(0, []),
      RegisterCredential { credential: Script(l_own), deposit: Never },
      placeholder,
    ),
    !approval_logic.publish(
      l_proxy,
      t_gs_policy,
      t_pu_script,
      l_policy,
      l_sec,
      l_payout(),
      builtin.constr_data(0, []),
      UnregisterCredential { credential: Script(l_own), refund: Never },
      placeholder,
    ),
  }
}

test settle_a_bad_recipient_does_not_block_reject_or_cancel() {
  // A request whose recipient is a free credential cannot be approved, but
  // the sender still gets the tokens back.
  let to_own = PendingTransfer { ..l_pending(100), recipient: Script(l_own) }
  let input = Input {
    output_reference: l_ref(0),
    output: l_vault_utxo(100, to_own),
  }
  and {
    l_run(
      [act(0, Reject)],
      l_tx([input], [l_holding(l_sender, 100)], approvers),
    ),
    l_run(
      [act(0, Cancel)],
      l_tx([input], [l_holding(l_sender, 100)], [l_sender]),
    ),
  }
}

// ── GlobalState: admin, installed logic, location ────────────────────────────

fn l_run_at(
  location: GlobalStateLocation,
  actions: List<SettlementAction>,
  tx: Transaction,
) -> Bool {
  approval_logic.withdraw(
    l_proxy,
    t_gs_policy,
    t_pu_script,
    l_policy,
    l_sec,
    l_payout(),
    ApprovalRedeemer {
      global_state_location: location,
      actions,
      approver_ref_input_index: None,
    },
    Script(l_own),
    tx,
  )
}

fn l_approve(signed: List<ByteArray>) -> Transaction {
  l_tx([l_vault_input(0, 100)], [l_holding(l_recipient, 100)], signed)
}

fn l_reject(signed: List<ByteArray>) -> Transaction {
  l_tx([l_vault_input(0, 100)], [l_holding(l_sender, 100)], signed)
}

test settle_needs_the_global_state_admin() {
  and {
    l_run([act(0, Approve)], l_approve([t_admin])),
    !l_run([act(0, Approve)], l_approve([l_other])),
    !l_run([act(0, Approve)], l_approve([])),
    l_run([act(0, Reject)], l_reject([t_admin])),
    !l_run([act(0, Reject)], l_reject([l_other])),
    l_run(
      [act(0, Close)],
      l_tx([l_stray(builtin.constr_data(9, []))], [l_to_payout()], [t_admin]),
    ),
    !l_run(
      [act(0, Close)],
      l_tx([l_stray(builtin.constr_data(9, []))], [l_to_payout()], [l_other]),
    ),
  }
}

test admin_never_a_free_credential() {
  // Every one of these runs (or can run) in a settlement: as the admin, its
  // withdrawal or a signature by its hash would approve for anyone.
  let as_admin = fn(admin) {
    with_gs(
      Transaction {
        ..l_approve([admin]),
        withdrawals: [
          Pair(Script(l_own), 0),
          Pair(Script(l_proxy), 0),
          Pair(Script(t_gs_logic), 0),
        ],
      },
      GlobalStateDatum { ..l_gs(True, 0), admin_credential_hash: admin },
    )
  }
  and {
    // Positive control: the same shape with a genuine admin.
    l_run([act(0, Approve)], as_admin(t_admin)),
    !l_run([act(0, Approve)], as_admin(l_own)),
    !l_run([act(0, Approve)], as_admin(l_proxy)),
    !l_run([act(0, Approve)], as_admin(t_gs_logic)),
  }
}

test retired_logic_never_runs() {
  // GlobalState names another approval logic: this one is retired.
  let cancel = l_reject([l_sender])
  and {
    l_run([act(0, Cancel)], cancel),
    !l_run(
      [act(0, Cancel)],
      with_gs(
        cancel,
        GlobalStateDatum {
          ..l_gs(True, 0),
          approval_logic_hash: #"51515151515151515151515151515151515151515151515151515151",
        },
      ),
    ),
  }
}

test cancel_needs_no_admin_and_works_switched_off() {
  // Regression guard: Cancel never reads the admin or the switch, even when
  // the admin is misconfigured.
  let cancel = l_reject([l_sender])
  and {
    l_run([act(0, Cancel)], with_gs(cancel, l_gs(False, 0))),
    l_run(
      [act(0, Cancel)],
      with_gs(
        cancel,
        GlobalStateDatum { ..l_gs(True, 0), admin_credential_hash: l_own },
      ),
    ),
  }
}

test cancel_by_a_script_sender_needs_its_withdrawal() {
  let script_sender = #"5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c"
  let input = Input {
    output_reference: l_ref(0),
    output: l_vault_utxo(
      100,
      PendingTransfer { ..l_pending(100), sender: Script(script_sender) },
    ),
  }
  let back = Output {
    ..l_holding(l_sender, 100),
    address: Address(Script(l_plb), Some(Inline(Script(script_sender)))),
  }
  !l_run([act(0, Cancel)], l_tx([input], [back], [t_admin]))
}

test global_state_reference_without_the_nft_is_refused() fail {
  let gs = l_gs_ref(l_gs(True, 0))
  l_run(
    [act(0, Cancel)],
    Transaction {
      ..l_reject([l_sender]),
      reference_inputs: [
        Input {
          ..gs,
          output: Output { ..gs.output, value: from_lovelace(2_000_000) },
        },
      ],
    },
  )
}

fn l_gs_input(datum: GlobalStateDatum) -> Input {
  Input { output_reference: t_out_ref(98), output: t_output(datum) }
}

const l_gs_spent_at_0: GlobalStateLocation =
  GlobalStateSpent { global_state_input_index: 0 }

test global_state_spent_location_reads_the_pre_state() {
  // A holder transaction that also spends GlobalState: the threshold of the
  // spent (pre-transaction) datum applies.
  let tx = fn(threshold) {
    Transaction {
      ..l_tx(
        [l_gs_input(l_gs(True, threshold)), l_holder_input(10, l_sender, 1_000)],
        [l_holding(l_recipient, 1_000)],
        [l_sender],
      ),
      reference_inputs: [],
    }
  }
  and {
    l_run_at(l_gs_spent_at_0, [], tx(1_000)),
    !l_run_at(l_gs_spent_at_0, [], tx(999)),
  }
}

test global_state_spent_location_without_the_nft_is_refused() fail {
  let gs = l_gs_input(l_gs(True, 1_000))
  l_run_at(
    l_gs_spent_at_0,
    [],
    Transaction {
      ..l_tx(
        [
          Input {
            ..gs,
            output: Output { ..gs.output, value: from_lovelace(2_000_000) },
          },
          l_holder_input(10, l_sender, 1_000),
        ],
        [l_holding(l_recipient, 1_000)],
        [l_sender],
      ),
      reference_inputs: [],
    },
  )
}

// ── Threshold (moved from the transfer logic) ────────────────────────────────

/// A holder transaction under GlobalState's switch and threshold.
fn l_holder_tx(
  required: Bool,
  threshold: Int,
  inputs: List<Input>,
  outputs: List<Output>,
) -> Bool {
  l_run(
    [],
    with_gs(l_tx(inputs, outputs, [l_sender]), l_gs(required, threshold)),
  )
}

test threshold_zero_rejects_a_direct_transfer() {
  let ins = [l_holder_input(10, l_sender, 1_000)]
  let outs = [l_holding(l_recipient, 1_000)]
  and {
    l_holder_tx(False, 0, ins, outs),
    !l_holder_tx(True, 0, ins, outs),
  }
}

test threshold_is_inclusive() {
  let ins = [l_holder_input(10, l_sender, 1_000)]
  let outs = [l_holding(l_recipient, 1_000)]
  and {
    l_holder_tx(True, 1_000, ins, outs),
    !l_holder_tx(True, 999, ins, outs),
  }
}

test threshold_ignored_with_the_switch_off() {
  l_holder_tx(
    False,
    0,
    [l_holder_input(10, l_sender, 1_000_000)],
    [l_holding(l_recipient, 1_000_000)],
  )
}

test threshold_does_not_count_change_back_to_the_sender() {
  let ins = [l_holder_input(10, l_sender, 1_000)]
  let outs = [l_holding(l_recipient, 300), l_holding(l_sender, 700)]
  and {
    l_holder_tx(True, 300, ins, outs),
    !l_holder_tx(True, 299, ins, outs),
  }
}

test threshold_sums_every_recipient() {
  // Two recipients of 300 each: 600 moved, although neither leg exceeds 500.
  let ins = [l_holder_input(10, l_sender, 1_000)]
  let outs = [
    l_holding(l_recipient, 300),
    l_holding(l_other, 300),
    l_holding(l_sender, 400),
  ]
  and {
    l_holder_tx(True, 600, ins, outs),
    !l_holder_tx(True, 500, ins, outs),
  }
}

test threshold_counts_a_recipient_that_adds_a_dust_input() {
  // The recipient adds 1 of its own and becomes a "sender": still a net gain
  // of 1000.
  let ins = [
    l_holder_input(10, l_sender, 1_000),
    l_holder_input(12, l_recipient, 1),
  ]
  let outs = [l_holding(l_recipient, 1_001)]
  and {
    l_holder_tx(True, 1_000, ins, outs),
    !l_holder_tx(True, 999, ins, outs),
  }
}

test threshold_allows_a_net_zero_two_sender_transaction() {
  let ins = [
    l_holder_input(10, l_sender, 400),
    l_holder_input(12, l_recipient, 600),
  ]
  and {
    l_holder_tx(
      True,
      0,
      ins,
      [l_holding(l_recipient, 600), l_holding(l_sender, 400)],
    ),
    !l_holder_tx(
      True,
      0,
      ins,
      [l_holding(l_recipient, 601), l_holding(l_sender, 399)],
    ),
  }
}

test threshold_counts_minted_outputs_as_movement() {
  let tx = fn(threshold) {
    with_gs(
      Transaction {
        ..l_tx(
          [l_holder_input(10, l_sender, 1_000)],
          [l_holding(l_sender, 1_000), l_holding(l_recipient, 500)],
          [l_sender],
        ),
        mint: from_asset(l_policy, l_sec, 500),
      },
      l_gs(True, threshold),
    )
  }
  and {
    l_run([], tx(500)),
    !l_run([], tx(499)),
  }
}

const l_cip68_name: ByteArray = #"000643b04d657461"

fn l_cip68(owner: ByteArray) -> Output {
  Output {
    ..l_holding(owner, 0),
    value: merge(
      from_lovelace(2_000_000),
      from_asset(l_policy, l_cip68_name, 1),
    ),
  }
}

test threshold_ignores_a_metadata_token_input() {
  let ins = [
    l_holder_input(10, l_sender, 1_000),
    Input { output_reference: l_ref(20), output: l_cip68(l_sender) },
  ]
  let outs = [l_holding(l_recipient, 1_000), l_cip68(l_sender)]
  and {
    l_holder_tx(True, 1_000, ins, outs),
    !l_holder_tx(True, 999, ins, outs),
  }
}

test metadata_update_runs_the_logic() {
  // Only the CIP-68 reference NFT moves: the transfer logic demands this
  // logic while approval is on, so it must accept.
  l_holder_tx(
    True,
    0,
    [Input { output_reference: l_ref(20), output: l_cip68(l_sender) }],
    [l_cip68(l_sender)],
  )
}

test request_to_the_vault_is_accepted_above_the_threshold() {
  l_holder_tx(
    True,
    0,
    [l_holder_input(10, l_sender, 1_000)],
    [l_vault_utxo(1_000, l_pending(1_000))],
  )
}

test request_plus_direct_leg_counts_only_the_direct_leg() {
  let ins = [l_holder_input(10, l_sender, 1_100)]
  let outs = [
    l_vault_utxo(1_000, l_pending(1_000)),
    l_holding(l_recipient, 100),
  ]
  and {
    l_holder_tx(True, 100, ins, outs),
    !l_holder_tx(True, 99, ins, outs),
  }
}

test settlement_is_not_subject_to_the_threshold() {
  // Approve of 100 at threshold 0: the settlement IS the approval.
  l_run([act(0, Approve)], with_gs(l_approve([t_admin]), l_gs(True, 0)))
}

// ── Mixing (moved from the transfer logic) ───────────────────────────────────

fn l_mixed(required: Bool, holder: Bool, vault_input: Input) -> Bool {
  let holder_in = if holder {
    [l_holder_input(5, l_sender, 7)]
  } else {
    []
  }
  let holder_out = if holder {
    [l_holding(l_sender, 7)]
  } else {
    []
  }
  l_run(
    [act(0, Cancel)],
    with_gs(
      l_tx(
        [vault_input, ..holder_in],
        [
          Output { ..l_holding(l_sender, 100), value: vault_input.output.value },
          ..holder_out
        ],
        [l_sender],
      ),
      l_gs(required, 1_000_000),
    ),
  )
}

test mixing_rejected_with_the_switch_on() {
  and {
    l_mixed(True, False, l_vault_input(0, 100)),
    !l_mixed(True, True, l_vault_input(0, 100)),
  }
}

test mixing_rejected_with_the_switch_off() {
  and {
    l_mixed(False, False, l_vault_input(0, 100)),
    !l_mixed(False, True, l_vault_input(0, 100)),
  }
}

test mixing_rejected_with_an_ada_only_vault_input() {
  // A token-free residual is still a vault input: a holder transaction cannot
  // ride along with its Cancel.
  let residual = Input {
    output_reference: l_ref(0),
    output: Output {
      ..l_vault_utxo(100, l_pending(100)),
      value: from_lovelace(2_000_000),
    },
  }
  and {
    l_mixed(True, False, residual),
    !l_mixed(True, True, residual),
  }
}

// ── Approve and Reject by a `can_approve` operator ──────────────────────────
// GlobalState at reference index 0 names the fixtures' power-user list; the
// operator's entry is at reference index 1. The admin never signs here.

fn with_operator_entry(tx: Transaction, can_approve: Bool) -> Transaction {
  Transaction {
    ..tx,
    reference_inputs: [
      l_gs_ref(
        GlobalStateDatum {
          ..l_gs(True, 0),
          power_user_linked_list_policy_id: t_pu_ll_policy,
        },
      ),
      Input {
        output_reference: t_out_ref(98),
        output: t_operator_entry(can_approve),
      },
    ],
  }
}

fn l_run_by(
  index: Option<Int>,
  actions: List<SettlementAction>,
  tx: Transaction,
) -> Bool {
  approval_logic.withdraw(
    l_proxy,
    t_gs_policy,
    t_pu_script,
    l_policy,
    l_sec,
    l_payout(),
    ApprovalRedeemer {
      global_state_location: l_gs_at_0,
      actions,
      approver_ref_input_index: index,
    },
    Script(l_own),
    tx,
  )
}

test operator_with_can_approve_approves_and_rejects() {
  and {
    l_run_by(
      Some(1),
      [act(0, Approve)],
      with_operator_entry(l_approve([t_operator]), True),
    ),
    l_run_by(
      Some(1),
      [act(0, Reject)],
      with_operator_entry(l_reject([t_operator]), True),
    ),
    // Without the role, the same transactions are refused.
    !l_run_by(
      Some(1),
      [act(0, Approve)],
      with_operator_entry(l_approve([t_operator]), False),
    ),
    !l_run_by(
      Some(1),
      [act(0, Reject)],
      with_operator_entry(l_reject([t_operator]), False),
    ),
  }
}

test operator_cannot_close() {
  let close = fn(signer) {
    with_operator_entry(
      l_tx([l_stray(builtin.constr_data(9, []))], [l_to_payout()], [signer]),
      True,
    )
  }
  and {
    // Positive control: the admin closes the same stray UTxO.
    l_run_by(Some(1), [act(0, Close)], close(t_admin)),
    !l_run_by(Some(1), [act(0, Close)], close(t_operator)),
  }
}

test cancel_ignores_the_operator_index() {
  // Index 0 is GlobalState, not a list entry: reading it would trap.
  l_run_by(
    Some(0),
    [act(0, Cancel)],
    with_operator_entry(l_reject([l_sender]), True),
  )
}

test admin_approval_ignores_the_operator_index() {
  // The admin signed: the operator entry (index 0 would trap) is never read.
  l_run_by(
    Some(0),
    [act(0, Approve)],
    with_operator_entry(l_approve([t_admin]), True),
  )
}
