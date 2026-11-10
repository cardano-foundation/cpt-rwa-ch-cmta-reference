use types/global_state.{GlobalStateLocation}

/// Where this token's CIP-113 registry node is to be found.
///
/// The three locations are exactly the transaction shapes in which the
/// minting proxy (validators/minting_logic_script.ak) runs. The node is
/// always addressed by index, never located by search (see
/// `utils.derive_issuance_policy_id_from_registry_node`).
///
/// When this token's node is merely the COVERING node of another token's
/// registry insert, the base layer requires no run of this proxy (it requires
/// the withdraw-0 of the token being inserted) and forbids minting this
/// token's policy (the registry spend handler refuses any mint of the spent
/// node's key), so no location is needed for that shape.
pub type RegistryNodeLocation {
  /// Steady-state mint and burn (the minting authority's `MintBurn`). The node
  /// already exists as a UTxO and is supplied as a reference input.
  ///
  /// Index into `transaction.reference_inputs`.
  NodeReferenced { registry_node_ref_input_index: Int }
  /// The CIP-113 registry insert of this token's node (the minting
  /// authority's `Register`). The base layer requires this proxy's withdraw-0
  /// there, and the node is an OUTPUT of the inserting transaction. A first
  /// mint of the token in the same transaction is allowed by the base layer,
  /// and it is debited like any other mint. This repository's minting
  /// authority refuses any supply in `Register`, so with it installed first
  /// issuance is always a separate `MintBurn`.
  ///
  /// Index into `transaction.outputs`. An insert emits two registry-node
  /// outputs (the new node and the re-emitted covering node); only the new
  /// node names this proxy, so an index at the covering node traps.
  NodeInserted { registry_node_output_index: Int }
  /// The CIP-113 in-place update of this token's node (the minting
  /// authority's `UpgradeRegistryNode`). The base layer forbids minting this
  /// token's policy in that transaction, so the minted amount is always 0.
  ///
  /// Index into `transaction.inputs`.
  NodeSpent { registry_node_input_index: Int }
}

/// Withdraw redeemer for validators/minting_logic_script.ak, the permanent
/// minting proxy.
///
/// - `global_state_location`: where the GlobalState UTxO is. Either location
///   serves the delegation check, but it MUST be `GlobalStateSpent` whenever
///   this transaction mints or burns the security token, because the proxy
///   then checks the continuing GlobalState output.
/// - `registry_node_location`: where this token's registry node is; the
///   issuance policy id is derived from it.
/// - `global_state_output_index`: index into `transaction.outputs` of the
///   continuing GlobalState output. Read only when the security token is
///   minted or burned; otherwise any value is accepted.
pub type MintingLogicScriptWithdrawRedeemer {
  global_state_location: GlobalStateLocation,
  registry_node_location: RegistryNodeLocation,
  global_state_output_index: Int,
}
