use cardano/address.{Credential}
use types/global_state.{GlobalStateLocation}

/// The inline datum of a PENDING TRANSFER — a programmable-base UTxO owned by
/// the permanent `approval_proxy` (its stake credential is
/// `Script(approval_proxy)`).
///
/// Written by the sender in the request transaction and bound there by the
/// approval logic (sender == the transaction's sole holder sender, amount ==
/// the security-token quantity the output holds, recipient is no free
/// credential). Never re-written: a pending transfer is settled in one step and
/// the paired output carries no datum.
///
/// Frozen in practice: every approval logic ever installed must settle the
/// UTxOs earlier ones bound. "Pending transfers follow an approval-logic
/// rotation" holds while this type is kept; changing it means draining every
/// pending transfer first. Only the approval logic reads it — the transfer
/// logic treats the vault as no party and never decodes it.
pub type PendingTransfer {
  /// The holder that parked the tokens. Full `Credential`: a key and a script
  /// sharing a hash are different holders.
  sender: Credential,
  /// Who receives the tokens on Approve. Vetted (KYC + denylist) only when it
  /// is paid, at settlement — the vault is no party at the request.
  recipient: Credential,
  /// The security-token quantity the UTxO held when it was created.
  amount: Int,
}

/// What happens to ONE pending transfer.
pub type SettlementDecision {
  /// GlobalState admin or a `can_approve` operator (key signature): every
  /// token and at least the lovelace go to `recipient`.
  Approve
  /// GlobalState admin or a `can_approve` operator (key signature): every
  /// token and at least the lovelace go back to `sender`.
  Reject
  /// `sender`, at any time (decision D3), never the admin or an operator and
  /// whatever the switch says — within the ordinary transfer rules: a Cancel
  /// that returns tokens runs the transfer logic, so it waits out a pause and
  /// needs the sender to pass the denylist (and receiver KYC, if required) as
  /// the payee.
  Cancel
  /// GlobalState admin: sweep a vault UTxO that holds ONLY lovelace and whose
  /// datum is not a `PendingTransfer` (anyone can pay ADA to any address in any
  /// shape) to the approval logic's `close_payout` address.
  Close
}

pub type SettlementAction {
  /// Index into `outputs` of this vault input's paired output.
  output_index: Int,
  decision: SettlementDecision,
}

/// Withdraw redeemer of `approval_logic`. Carries where GlobalState is and the
/// per-input actions: the logic binds every new vault output and settles every
/// vault input on EVERY run, whatever the redeemer says, so no redeemer can
/// turn a check off.
pub type ApprovalRedeemer {
  /// Where GlobalState is: its admin (or a `can_approve` operator) approves,
  /// its switch and threshold gate holder transactions. A reference input on
  /// every settlement (the proxy refuses a spent GlobalState); spent only in a
  /// holder transaction that also spends GlobalState.
  global_state_location: GlobalStateLocation,
  /// One action per vault input, in transaction-input order. Output indices
  /// must be strictly increasing, so no output settles two inputs.
  actions: List<SettlementAction>,
  /// Where the approving operator's power-user list entry is among the
  /// REFERENCE inputs, when an operator holding `can_approve` (not the admin)
  /// approves or rejects. `None` on the admin path. Read only when the
  /// transaction Approves or Rejects and the admin did not sign.
  approver_ref_input_index: Option<Int>,
}

/// Withdraw redeemer of the permanent `approval_proxy`: where GlobalState is.
/// It must be a REFERENCE input — the proxy refuses any transaction that spends
/// GlobalState.
pub type ApprovalProxyRedeemer {
  global_state_ref_input_index: Int,
}
