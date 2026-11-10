use types/global_state.{GlobalStateLocation}
use types/party_action.{PartyAction}

/// Withdraw redeemer for validators/minting_authority.ak — the swappable
/// minting authority named by `GlobalStateDatum.minting_script_credential_
/// hash` (admin-rotatable via `RotateMintingScript`).
///
/// minting_logic_script.ak (the permanent, CIP-113-registered proxy) requires
/// this validator's withdraw-0 to be present for any transaction that moves
/// the security token's supply, but hands this validator NOTHING
/// pre-verified — this redeemer carries everything needed to decide, and
/// every input is independently re-resolved and re-checked here.
///
/// `MintBurn` never reads the registry at all: the issuance policy it
/// polices is pinned at compile time, and the base layer already
/// authenticates whichever registry node invoked this withdraw-0 in the
/// first place. The other two variants still resolve a registry node —
/// `Register` through `self.outputs`, because the node does not exist as a
/// UTxO yet (it is being created), `UpgradeRegistryNode` because IT is the
/// one path that may rewrite the node — for CIP-113 structural invariants
/// only they enforce.
pub type MintingAuthorityWithdrawRedeemer {
  /// Steady state: the registry node already exists as a UTxO and is
  /// supplied as a reference input.
  MintBurn {
    /// Index into `self.inputs` — the same GlobalState UTxO the proxy
    /// resolves (shared, transaction-wide data; a wrong index just fails the
    /// NFT check).
    global_state_input_index: Int,
    power_user_node_ref_input_index: Int,
    /// Amount minted (signed: positive for mint, negative for burn).
    minted_amount: Int,
    /// One action per unique destination stake credential among outputs
    /// carrying the security token. Only consulted when `minted_amount > 0`
    /// (burns have no destinations); ordered to match the aggregated
    /// unique-destinations order. CMTAT v3.2.0 refuses to mint to a frozen
    /// address (core) or to a non-allowlisted one (Allowlist variant); this
    /// is the eUTxO equivalent.
    destination_actions: List<PartyAction>,
  }
  /// The CIP-113 registration that creates this token's registry node. The
  /// node is reached through `self.outputs`, because at insert time it is an
  /// output of this very transaction rather than a pre-existing UTxO. The
  /// GlobalState admin alone authorises it, and the protocol must not be
  /// deactivated.
  ///
  /// Name rules, decided by `security_asset_name` alone: a `(100)`-labelled
  /// name is always refused; a CIP-68 user-token name (`(222)`, `(333)` or
  /// `(444)`) needs a body of at least one byte; a plain name must not be
  /// empty.
  ///
  /// Mint rule, in both directions and scoped to the issuance policy: a plain
  /// name mints NOTHING under it; a CIP-68 name mints EXACTLY its reference NFT
  /// (`cip68.reference_name(security_asset_name)`), quantity 1, into exactly
  /// one well-formed carrier output. Supply is never minted here — the first
  /// supply is a later `MintBurn`. Mints under other policies are not
  /// constrained.
  Register {
    /// Index into `self.outputs` — the registry node being created. An
    /// insert emits TWO registry-node outputs (the new node and the
    /// re-emitted covering node), so the index alone does not identify ours;
    /// the identity assertion against the proxy's hash disambiguates.
    registry_node_output_index: Int,
    /// WHERE GlobalState is — read for the deactivation flag and the admin
    /// credential only. A location for the same reason as
    /// `UpgradeRegistryNode`: no supply changes, so nothing here depends on
    /// the GS spend validator running, and a registration should not be
    /// barred from a transaction that also spends GlobalState.
    global_state_location: GlobalStateLocation,
  }
  /// The CIP-113 UPGRADE path for the OTHER logic scripts.
  ///
  /// `registry_spend`'s in-place update branch (the `None` case, when no
  /// registry NFT is minted) lets a node's `transfer_logic_script`,
  /// `third_party_transfer_logic_script`, `unfracking_logic_script` and
  /// `global_state_cs` be rewritten, while `key`, `next` and
  /// `minting_logic_script` stay frozen forever
  /// (`is_field_updated_registry_node`). It gates that on
  /// `pairs.has_key(self.withdrawals, spent_node.minting_logic_script)` —
  /// i.e. on the permanent proxy, which delegates here. So this validator is
  /// the sole authority over whether this token's transfer rules may change.
  ///
  /// The base layer already guarantees, for this shape: exactly one registry
  /// node output (`expect [cont]`), the frozen fields unchanged, and that
  /// this token's own asset is neither minted nor burned in the same
  /// transaction (`expect !mint_has_policy(self.mint, spent_node.key)`).
  /// What it does NOT constrain is our deployment's own invariants — it
  /// happily lets `global_state_cs` be re-pointed away from our GlobalState
  /// and `unfracking_logic_script` be switched on — so those are re-asserted
  /// here, and fields 3 and 4 must name exactly the transfer and seizure
  /// scripts the authority was built with (F08).
  UpgradeRegistryNode {
    /// Index into `self.inputs` — this token's registry node, being spent.
    registry_node_input_index: Int,
    /// Index into `self.outputs` — the continuing node.
    registry_node_output_index: Int,
    /// WHERE GlobalState is — read for the admin credential and the upgrade
    /// lock, nothing more. Deliberately a location rather than a fixed
    /// reference index: this variant makes no claim that depends on the GS
    /// spend validator having run, so pinning it to one list would only forbid
    /// upgrading a registry node in the same transaction that spends
    /// GlobalState (Conway rejects the overlap). Contrast `MintBurn` above,
    /// whose bare `global_state_input_index` is load-bearing: it MUST spend,
    /// or `MintSecurity` never runs and the supply cap goes unenforced. The
    /// type carries that distinction.
    global_state_location: GlobalStateLocation,
  }
}
