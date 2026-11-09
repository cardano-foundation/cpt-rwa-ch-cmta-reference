use types/kyc_proof.{KycProof}

/// The compliance action for one party: one per unique stake credential on a
/// side of the transaction (the senders or the destinations of a transfer,
/// the destinations of a seizure or a mint), matched to the parties
/// positionally by `compliance.verify_parties`.
///
/// - `proof` — a KYC proof bound to the party. Checked only when the
///   GlobalState flag for that side (`requires_sender_kyc` /
///   `requires_receiver_kyc`) is set.
/// - `denylist_ref_input_index` — the reference input holding the party's
///   denylist element, always checked: a covering node (the party is not
///   listed) or the party's own node (partially frozen; a sender must then
///   pay at least the frozen amount back to itself, a receiver is admitted).
///
/// One type for every side and every path. There used to be four
/// field-for-field identical copies (`TransferLogicScriptAction`,
/// `TransferLogicScriptDestinationAction`, `ThirdPartyDestinationAction`,
/// `MintingLogicDestinationAction`); Plutus data is positional, so merging
/// them does not change a redeemer's encoding.
pub type PartyAction {
  proof: KycProof,
  denylist_ref_input_index: Int,
}
