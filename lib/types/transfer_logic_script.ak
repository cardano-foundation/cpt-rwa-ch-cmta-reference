use types/global_state.{GlobalStateLocation}
use types/party_action.{PartyAction}

/// Transfer-logic withdraw redeemer.
///
/// - `global_state_location` — where the GS UTxO is; provides pause flag, TEL,
///   denylist policy id.
/// - `actions_for_each_input` — one KYC proof + denylist element index per
///   unique sender, ordered to match the aggregated-senders order.
/// - `destination_actions` — one KYC proof + denylist element index per unique
///   destination, ordered to match the aggregated-destinations order. Both the
///   KYC attestation and the denylist gate are required on receive.
///   Rationale: Swiss CO Art. 973e (DLT Act) requires the issuer to perform
///   obligations only to a named creditor in the ledger; eWpG §14 requires the
///   issuer to maintain a register of identified holders; and
///   industry-standard regulated-securities designs (ERC-3643; CMTAT with
///   RuleWhitelist) gate both sender and recipient. Requiring a destination
///   proof on regular transfers matches all three.
///
/// A denylist element index names either a covering node (the party is not
/// listed) or the party's own node (the party is partially frozen). See
/// `absence.party_permitted`.
pub type TransferLogicScriptWithdrawRedeemer {
  /// WHERE GlobalState is, not just which reference input it is.
  ///
  /// This validator only READS the datum, so it has no reason to dictate which
  /// list the UTxO sits in — and dictating it is not free. Conway rejects a
  /// transaction whose `inputs` and `reference_inputs` overlap, so while this
  /// field was a bare `global_state_ref_input_index` no transfer of the
  /// security token could occur in any transaction that also SPENDS
  /// GlobalState: not alongside a mint, not alongside a burn, not alongside an
  /// admin action. That is the same defect that made the burn unbuildable
  /// through `third_party_transfer_logic_script`, caught here before it cost a
  /// second on-chain failure rather than after.
  global_state_location: GlobalStateLocation,
  actions_for_each_input: List<PartyAction>,
  destination_actions: List<PartyAction>,
}
