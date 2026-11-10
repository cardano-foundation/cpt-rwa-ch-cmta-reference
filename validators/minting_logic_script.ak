use aiken/builtin
use aiken/collection/dict
use aiken/collection/list
use aiken/interval.{Interval, IntervalBound, NegativeInfinity, PositiveInfinity}
use aiken/primitive/bytearray
use cardano/address.{Address, Credential, Script, VerificationKey}
use cardano/assets.{from_asset, from_lovelace, merge, without_lovelace, zero}
use cardano/certificate.{Certificate, RegisterCredential, UnregisterCredential}
use cardano/transaction.{
  InlineDatum, Input, NoDatum, Output, OutputReference, Transaction,
}
use cardano/value
use constants
use tests
use types/global_state.{
  GlobalStateCore, GlobalStateDatum, GlobalStateLocation, GlobalStateReferenced,
  GlobalStateSpent, decode_global_state_core, gs_core_from_output,
  idx_deactivated, idx_mintable_amount, set_mintable_amount,
}
use types/minting_logic_script.{
  MintingLogicScriptWithdrawRedeemer, NodeInserted, NodeReferenced, NodeSpent,
  RegistryNodeLocation,
}
use utils.{must_run_script_withdrawal}

/// The permanent, CIP-113-registered PROXY for this token's minting path.
///
/// Every registry node's `minting_logic_script` field is frozen to this
/// script's hash forever, and the token's own issuance policy id is derived
/// from that hash — so nothing in this file can ever change after deployment
/// without minting a different token. It therefore decides two things, and
/// only two:
///
/// - WHO: delegation. It resolves GlobalState, reads which script is
///   currently the minting authority, and requires that script to be running
///   in this transaction.
/// - HOW MUCH: the supply debit. Every mint or burn of `security_asset_name`
///   under this token's issuance policy is debited from GlobalState's
///   `mintable_amount` in the same transaction. GlobalState must be spent,
///   and its continuing output keeps its address and non-ADA value and
///   carries the input datum with exactly one field written: `mintable_amount`
///   minus the minted amount (a burn raises it), never below zero.
///
/// Everything else — WHO may mint, TO WHOM, which asset names, the CIP-113
/// registration's structural invariants, the admin gate, power-user roles,
/// KYC, denylist, and the guard against riding along on a registry-node
/// update — lives in validators/minting_authority.ak, which the admin can
/// replace at any time via `RotateMintingScript`. Pause is not consulted
/// here. Maximum upgradability, by construction: the only thing that can
/// never be fixed is this file, so this file decides as little as possible.
///
/// WHY THE ISSUANCE POLICY ID IS DERIVED, NEVER PINNED. That policy id is the
/// hash of the CIP-113 issuance template applied to THIS script's hash, so a
/// compile-time pin would be circular. Every run instead resolves this
/// token's registry node from the redeemer and reads its key through
/// `utils.derive_issuance_policy_id_from_registry_node`, which requires a
/// genuine registry node naming this script at field 2. That is sound
/// because of two CIP-113 invariants of the pinned base layer, cited here
/// rather than re-created: the registry derives a node's key from its field 2,
/// and keys are unique. Any change of the CIP-113 version must re-verify both.
///
/// THE EXACT GUARANTEE. Every mint or burn of the security token is debited
/// in the same transaction, whatever authority or GlobalState logic is
/// installed. It is NOT a claim that no rotation can touch the cap: a write of
/// `mintable_amount` outside a mint or burn is a cap amendment, governed by
/// the installed GlobalState logic.
///
/// ACCEPTED RESIDUES.
/// - Other asset names under the issuance policy are not counted. Restricting
///   names is the authority's rule; a replacement authority that drops it is
///   the admin's choice, and such an authority could already mint the real
///   token to unvetted destinations.
/// - Deliberate lock-in: in a transaction that mints or burns the token no
///   other GlobalState datum field may change, appended fields included. A
///   field that must change on every mint (a circulating-supply counter, for
///   example) is therefore impossible for this token version.
///
/// THE PARAMETERS. `global_state_policy_id` authenticates GlobalState,
/// `registry_policy_id` authenticates the registry node, and
/// `security_asset_name` is the one name whose supply is debited. The name
/// makes this script's hash, and so the issuance policy id, name-dependent.
/// There is no cycle, because the name is fixed before any build — but every
/// script of a deployment must be built with byte-identical name bytes.
///
/// The corollary, stated plainly because it is the price of that design: a
/// replacement authority inherits the FULL burden of correctness for every
/// rule except the delegation and the supply debit. Nothing here will catch
/// its mistakes. See the "INVARIANTS ANY REPLACEMENT AUTHORITY MUST PRESERVE"
/// note in validators/minting_authority.ak.
validator minting_logic_validator(
  global_state_policy_id: ByteArray,
  registry_policy_id: ByteArray,
  security_asset_name: ByteArray,
) {
  /// The redeemer says where three things are: GlobalState, this token's
  /// registry node, and (read only when the security token is minted or
  /// burned) the continuing GlobalState output. Every decision about the
  /// transaction's content belongs to the authority (see
  /// types/minting_authority.ak); see types/minting_logic_script.ak for the
  /// transaction shape each node location serves.
  withdraw(
    redeemer: MintingLogicScriptWithdrawRedeemer,
    credential: Credential,
    self: Transaction,
  ) {
    expect Script(own_hash) = credential

    // This token's registry node, addressed by index in whichever list the
    // transaction shape puts it. The derivation traps unless it is a genuine
    // registry node naming `own_hash` at field 2, so a wrong location only
    // traps.
    let node_output: Output = when redeemer.registry_node_location is {
      NodeReferenced { registry_node_ref_input_index } ->
        utils.safe_list_at(self.reference_inputs, registry_node_ref_input_index).output
      NodeInserted { registry_node_output_index } ->
        utils.safe_list_at(self.outputs, registry_node_output_index)
      NodeSpent { registry_node_input_index } ->
        utils.safe_list_at(self.inputs, registry_node_input_index).output
    }
    let issuance_policy_id = utils.derive_issuance_policy_id_from_registry_node(
      node_output,
      registry_policy_id,
      own_hash,
      constants.minting_logic_script_registry_node_index,
    )
    // Only the security asset under this token's own issuance policy is
    // counted: other policies are not this token, and other names under it are
    // the authority's rule (see the accepted residues above).
    let delta = value.quantity_of(
      assets.to_value(self.mint),
      issuance_policy_id,
      security_asset_name,
    )

    // Resolved INLINE rather than through a shared location helper such as
    // `resolve_global_state` (which also decodes the full v1 layout, where
    // this script must read only the frozen core).
    //
    // This one file may not change its compiled bytes after launch. Its hash
    // is frozen into this token's registry node, and the token's issuance
    // policy id is derived from it — so a different hash is a different
    // token, and every already-issued one becomes unreachable. Going through
    // the shared helper was measured to move the hash (6defc595… ->
    // b6e4e07a…): same behaviour, different UPLC. The redeemer TYPES are
    // shared, because a type name is not compiled; the resolution is not. Do
    // not "tidy" this into the helper without re-checking the hash.
    //
    // The compiled bytes also include every shared function and constant this
    // file calls: `utils.derive_issuance_policy_id_from_registry_node`,
    // `utils.safe_list_at`, `utils.must_run_script_withdrawal`,
    // `utils.replace_data_field` (through `set_mintable_amount`),
    // `gs_core_from_output`, `decode_global_state_core` and
    // `GlobalStateCore`, `set_mintable_amount`, and the constants
    // `constants.minting_logic_script_registry_node_index` and
    // `constants.global_state_asset_name` (with the `idx_mintable_amount` and
    // `gs_core_field_count` they rely on), as well as the stdlib functions they
    // use. After launch, editing any of them changes this hash and so the
    // token. Before launch the hash changed deliberately: (a) when the
    // frozen-core layout changed its reads (2026-10-15, and again when
    // `mintable_amount` moved into the core), and (b) when the supply debit
    // was added.
    let gs_output: Output = when redeemer.global_state_location is {
      GlobalStateSpent { global_state_input_index } ->
        utils.safe_list_at(self.inputs, global_state_input_index).output
      GlobalStateReferenced { global_state_ref_input_index } ->
        utils.safe_list_at(self.reference_inputs, global_state_ref_input_index).output
    }
    // NFT presence is what makes this the real GlobalState rather than a
    // datum an attacker fabricated to name an authority they control. Only the
    // frozen core is read: this script can never be redeployed, so it must not
    // depend on the part of the datum a later GlobalState logic may reshape.
    let gs_datum: GlobalStateCore = gs_core_from_output(
      gs_output,
      global_state_policy_id,
    )

    and {
      // Decline if the protocol is deactivated
      (gs_datum.deactivated == False)?,
      // Self-authorisation footgun: this withdraw-0 is, by construction,
      // always present while this code is running, so an authority hash
      // equal to `own_hash` would be trivially self-satisfying. No
      // circularity concern — `own_hash` is a runtime value from
      // `credential`, not a compile-time parameter.
      (gs_datum.minting_script_credential_hash != own_hash)?,
      // Deliberately `must_run_script_withdrawal`, NOT
      // `must_be_signed_by_credential`: the latter also accepts a bare key
      // signature, which would satisfy this gate without the authority
      // script ever executing — and since this proxy checks nothing else
      // about authorisation, that would be a total bypass of every
      // authorisation rule the token has. Only a genuine withdraw-0 proves
      // the authority's own logic ran and approved this specific transaction.
      must_run_script_withdrawal(self, gs_datum.minting_script_credential_hash)?,
      // The supply debit. Nothing of the security token moves: no counter to
      // check, exactly as before the debit existed.
      if delta == 0 {
        True
      } else {
        // A mint or burn: GlobalState must be SPENT, or this traps. Only a
        // spend has a continuing output in which the debit can be written.
        expect GlobalStateSpent { .. } = redeemer.global_state_location
        let gs_continuing = utils.safe_list_at(
          self.outputs,
          redeemer.global_state_output_index,
        )
        expect InlineDatum(in_raw) = gs_output.datum
        expect InlineDatum(out_raw) = gs_continuing.datum
        let remaining = gs_datum.mintable_amount - delta
        // The continuing output stays where GlobalState was and carries the
        // same tokens (its NFT among them); only its lovelace may move.
        let same_address = gs_continuing.address == gs_output.address
        let same_tokens = without_lovelace(gs_continuing.value) == without_lovelace(
          gs_output.value,
        )
        // The input datum with field 5 alone rewritten, compared as Data so
        // that every other field — core, tail and appended — is pinned too.
        let only_the_counter_moved = builtin.equals_data(
          set_mintable_amount(builtin.unconstr_fields(in_raw), remaining),
          out_raw,
        )
        and {
          (remaining >= 0)?,
          same_address?,
          same_tokens?,
          only_the_counter_moved?,
        }
      },
    }
  }

  // Whitelist RegisterCredential only. Rejecting UnregisterCredential prevents
  // a ~2 ADA griefing DoS: a rubber-stamp publish would allow anyone to
  // de-register this script's stake credential, which would brick every
  // withdraw-zero mint/burn until re-registered. Also rejects delegation and
  // DRep/committee cert types — this credential exists solely for withdraw-0.
  // Tradeoff: the stake credential becomes permanent (2 ADA locked forever).
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
// Tests — the validator makes two decisions, and these cover exactly those:
// the delegation (can the gate be satisfied by anything other than the
// currently-named authority genuinely running?) and the supply debit (is every
// mint or burn of the security token debited from `mintable_amount` in the
// same transaction, with nothing else written?).
//
//   test foo()                     -> ACCEPTS.
//   test foo() { !run_withdraw.. } -> REJECTS by returning False (a `?`
//                                     conjunct).
//   test foo() fail { run_withdraw(..) || True }
//                                  -> TRAPS (an `expect` or an index). The
//                                     `|| True` makes a False return pass the
//                                     body, so only a trap fails it.
// ============================================================================

const test_gs_policy_id: ByteArray =
  #"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

// The CIP-113 registry policy: the registry node NFT's policy and the node
// address's payment credential.
const test_registry_policy_id: ByteArray =
  #"c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1"

const test_security_asset_name: ByteArray = "SEC"

// This proxy's own credential, as the ledger passes it to `withdraw`.
const test_minting_logic_hash: ByteArray =
  #"f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1"

// This token's issuance policy id: the key of its registry node.
const test_issuance_policy_id: ByteArray =
  #"e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1"

// The currently-active minting authority (validators/minting_authority.ak),
// as named by GlobalState.minting_script_credential_hash.
const test_minting_authority_hash: ByteArray =
  #"06060606060606060606060606060606060606060606060606060606"

// A second, distinct authority — what `RotateMintingScript` points
// GlobalState at. Used to prove rotation actually re-points the delegation.
const test_new_minting_authority_hash: ByteArray =
  #"07070707070707070707070707070707070707070707070707070707"

// Another token's minting proxy, named at field 2 of another token's node.
const test_other_proxy_hash: ByteArray =
  #"f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9"

// Another token's issuance policy id: the key of the covering node in the
// registration fixtures. Sorts below `test_issuance_policy_id`.
const test_other_issuance_policy_id: ByteArray =
  #"01010101010101010101010101010101010101010101010101010101"

// A GlobalState logic other than the installed one (datum field 0).
const test_other_gs_logic_hash: ByteArray =
  #"9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b"

// A policy that is not this token's issuance policy.
const test_foreign_policy_id: ByteArray =
  #"fafafafafafafafafafafafafafafafafafafafafafafafafafafafa"

fn test_out_ref(ix: Int) -> OutputReference {
  OutputReference {
    transaction_id: #"0000000000000000000000000000000000000000000000000000000000000000",
    output_index: ix,
  }
}

// ── CIP-113 registry node ────────────────────────────────────────────────────

/// Faithful mirror of the CIP-113 registry node layout. Field order is
/// load-bearing: minting=2, transfer=3, third-party=4, unfracking=5, gs_cs=6.
type RegNode {
  key: ByteArray,
  next: ByteArray,
  minting_logic_script: Credential,
  transfer_logic_script: Credential,
  third_party_transfer_logic_script: Credential,
  unfracking_logic_script: Credential,
  global_state_cs: ByteArray,
}

/// THIS token's node: keyed by its issuance policy id, naming this proxy at
/// field 2.
fn genuine_node() -> RegNode {
  RegNode {
    key: test_issuance_policy_id,
    next: #"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    minting_logic_script: Script(test_minting_logic_hash),
    transfer_logic_script: Script(
      #"f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2",
    ),
    third_party_transfer_logic_script: Script(
      #"f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3",
    ),
    unfracking_logic_script: VerificationKey(#""),
    global_state_cs: test_gs_policy_id,
  }
}

/// A node UTxO as CIP-113 produces it: at the registry address, holding ADA
/// and exactly one registry NFT named by the node's key, with an inline datum.
fn registry_node_output(node: RegNode) -> Output {
  Output {
    address: Address {
      payment_credential: Script(test_registry_policy_id),
      stake_credential: None,
    },
    value: merge(
      from_lovelace(2_000_000),
      from_asset(test_registry_policy_id, node.key, 1),
    ),
    datum: InlineDatum(node),
    reference_script: None,
  }
}

/// This token's node as a reference input (the steady-state shape), at an out
/// ref distinct from GlobalState's.
fn registry_node_input() -> Input {
  Input {
    output_reference: test_out_ref(3),
    output: registry_node_output(genuine_node()),
  }
}

// ── GlobalState ──────────────────────────────────────────────────────────────

fn make_gs_datum(authority: ByteArray, deactivated: Bool) -> GlobalStateDatum {
  GlobalStateDatum {
    global_state_script_credential_hash: #"9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a",
    transfers_paused: False,
    deactivated,
    mintable_amount: 1_000_000,
    admin_credential_hash: #"",
    power_user_linked_list_policy_id: #"",
    denylist_linked_list_policy_id: #"",
    security_info: builtin.constr_data(0, []),
    trusted_entity_vkeys: [],
    member_root_hash: #"",
    requires_sender_kyc: False,
    requires_receiver_kyc: False,
    network_id: 1,
    minting_script_credential_hash: authority,
    upgrades_locked: False,
  }
}

/// A GlobalState UTxO carrying `datum`, which is any Data so that fixtures can
/// append fields or retype one.
fn gs_output_of(datum: Data) -> Output {
  Output {
    address: Address {
      payment_credential: Script(test_gs_policy_id),
      stake_credential: None,
    },
    value: merge(
      from_lovelace(2_000_000),
      from_asset(test_gs_policy_id, constants.global_state_asset_name, 1),
    ),
    datum: InlineDatum(datum),
    reference_script: None,
  }
}

fn gs_input_of(datum: Data) -> Input {
  Input { output_reference: test_out_ref(0), output: gs_output_of(datum) }
}

fn make_gs_output(authority: ByteArray, deactivated: Bool) -> Output {
  gs_output_of(make_gs_datum(authority, deactivated))
}

fn make_gs_input(authority: ByteArray, deactivated: Bool) -> Input {
  gs_input_of(make_gs_datum(authority, deactivated))
}

fn base_tx() -> Transaction {
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

// GS spent (the mint/burn shape), with the named authority's withdraw-0
// present or absent, and this token's node as reference input 0.
fn spent_tx(authority: ByteArray, withdrawal: Option<ByteArray>) -> Transaction {
  Transaction {
    ..base_tx(),
    inputs: [make_gs_input(authority, False)],
    reference_inputs: [registry_node_input()],
    withdrawals: when withdrawal is {
      Some(h) -> [Pair(Script(h), 0)]
      None -> []
    },
  }
}

// GS referenced (reference input 0), this token's node at reference input 1,
// and the named authority's withdraw-0.
fn referenced_tx(gs_datum: GlobalStateDatum) -> Transaction {
  Transaction {
    ..base_tx(),
    reference_inputs: [gs_input_of(gs_datum), registry_node_input()],
    withdrawals: [Pair(Script(gs_datum.minting_script_credential_hash), 0)],
  }
}

fn run_withdraw(redeemer: MintingLogicScriptWithdrawRedeemer, tx: Transaction) {
  minting_logic_validator.withdraw(
    test_gs_policy_id,
    test_registry_policy_id,
    test_security_asset_name,
    redeemer,
    Script(test_minting_logic_hash),
    tx,
  )
}

fn redeemer_of(
  global_state_location: GlobalStateLocation,
  registry_node_location: RegistryNodeLocation,
  global_state_output_index: Int,
) -> MintingLogicScriptWithdrawRedeemer {
  MintingLogicScriptWithdrawRedeemer {
    global_state_location,
    registry_node_location,
    global_state_output_index,
  }
}

// The `spent_tx` shape: GS input 0, node reference input 0, GS output 0.
fn spent_redeemer() -> MintingLogicScriptWithdrawRedeemer {
  redeemer_of(
    GlobalStateSpent { global_state_input_index: 0 },
    NodeReferenced { registry_node_ref_input_index: 0 },
    0,
  )
}

// The `referenced_tx` shape: GS reference input 0, node reference input 1.
fn referenced_redeemer() -> MintingLogicScriptWithdrawRedeemer {
  redeemer_of(
    GlobalStateReferenced { global_state_ref_input_index: 0 },
    NodeReferenced { registry_node_ref_input_index: 1 },
    0,
  )
}

// ── the delegation gate ──────────────────────────────────────────────────────

test succeeds_when_the_named_authority_runs() {
  run_withdraw(
    spent_redeemer(),
    spent_tx(test_minting_authority_hash, Some(test_minting_authority_hash)),
  )
}

test succeeds_when_global_state_is_only_referenced() {
  // A structural registration references GS rather than spending it. The
  // proxy accepts either while nothing of the security token is minted —
  // deciding which is appropriate for the operation at hand is the
  // authority's job, not this validator's.
  run_withdraw(
    referenced_redeemer(),
    referenced_tx(make_gs_datum(test_minting_authority_hash, False)),
  )
}

test fails_without_the_authority_withdrawal() {
  // Delegation is this validator's only authorisation decision: with no
  // authority running, nothing else here could possibly authorise anything.
  !run_withdraw(spent_redeemer(), spent_tx(test_minting_authority_hash, None))
}

test fails_when_the_authority_is_merely_signed_for() {
  // The gate must accept ONLY a real withdraw-0 of the named script, never a
  // bare signature — `must_be_signed_by_credential` treats the two as
  // interchangeable, which here would let the authority be skipped entirely
  // and, since this proxy checks nothing else about authorisation, bypass
  // every authorisation rule the token has.
  !run_withdraw(
    spent_redeemer(),
    Transaction {
      ..spent_tx(test_minting_authority_hash, None),
      extra_signatories: [test_minting_authority_hash],
    },
  )
}

test fails_when_a_different_script_runs() {
  // An unrelated script's withdraw-0 is not the named authority's.
  !run_withdraw(
    spent_redeemer(),
    spent_tx(test_minting_authority_hash, Some(test_new_minting_authority_hash)),
  )
}

test fails_when_the_authority_is_this_proxy_itself() {
  // Self-authorisation footgun: this withdraw-0 is always present while this
  // code runs, so `own_hash` as the authority would be free.
  !run_withdraw(
    spent_redeemer(),
    spent_tx(test_minting_logic_hash, Some(test_minting_logic_hash)),
  )
}

// ── the upgrade property ─────────────────────────────────────────────────────

test superseded_authority_stops_working_after_rotation() {
  // Which script satisfies the gate is read live from GlobalState on every
  // transaction, so rotating `minting_script_credential_hash` genuinely
  // re-points the delegation — otherwise a superseded (e.g. compromised)
  // authority would keep working forever and "rotation" would be cosmetic.
  !run_withdraw(
    spent_redeemer(),
    spent_tx(test_new_minting_authority_hash, Some(test_minting_authority_hash)),
  )
}

test rotated_authority_starts_working() {
  // Positive mirror of the test above, same GlobalState.
  run_withdraw(
    spent_redeemer(),
    spent_tx(
      test_new_minting_authority_hash,
      Some(test_new_minting_authority_hash),
    ),
  )
}

// ── GlobalState authentication ───────────────────────────────────────────────

test fails_when_global_state_is_forged() fail {
  // Without the NFT check an attacker could supply any UTxO carrying a
  // GlobalState-shaped datum that names an authority they control, and the
  // gate would happily delegate to it.
  let forged = Output {
    ..make_gs_output(test_new_minting_authority_hash, False),
    value: from_lovelace(2_000_000),
  }
  run_withdraw(
    spent_redeemer(),
    Transaction {
      ..base_tx(),
      inputs: [Input { output_reference: test_out_ref(0), output: forged }],
      reference_inputs: [registry_node_input()],
      withdrawals: [Pair(Script(test_new_minting_authority_hash), 0)],
    },
  ) || True
}

test fails_when_index_points_at_a_non_global_state_utxo() fail {
  let unrelated = Output {
    address: Address {
      payment_credential: Script(test_gs_policy_id),
      stake_credential: None,
    },
    value: from_lovelace(2_000_000),
    datum: NoDatum,
    reference_script: None,
  }
  run_withdraw(
    spent_redeemer(),
    Transaction {
      ..spent_tx(test_minting_authority_hash, Some(test_minting_authority_hash)),
      inputs: [Input { output_reference: test_out_ref(1), output: unrelated }],
    },
  ) || True
}

// ── publish handler ──────────────────────────────────────────────────────────

test publish_accepts_credential_registration() {
  minting_logic_validator.publish(
    test_gs_policy_id,
    test_registry_policy_id,
    test_security_asset_name,
    builtin.constr_data(0, []),
    RegisterCredential {
      credential: Script(test_minting_logic_hash),
      deposit: Never,
    },
    base_tx(),
  )
}

test publish_rejects_credential_deregistration() {
  // Pins the anti-griefing rule the handler documents: a rubber-stamp publish
  // would let anyone de-register this script's stake credential for ~2 ADA,
  // bricking every withdraw-0 mint and burn until it was re-registered.
  !minting_logic_validator.publish(
    test_gs_policy_id,
    test_registry_policy_id,
    test_security_asset_name,
    builtin.constr_data(0, []),
    UnregisterCredential {
      credential: Script(test_minting_logic_hash),
      refund: Never,
    },
    base_tx(),
  )
}

// The proxy can never be upgraded, so it must keep reading a GlobalState datum
// that a future version extended with trailing fields (see decode_global_state_core).
test succeeds_when_global_state_has_trailing_fields() {
  run_withdraw(
    spent_redeemer(),
    tests.with_trailing_gs_fields(
      spent_tx(test_minting_authority_hash, Some(test_minting_authority_hash)),
      test_gs_policy_id,
    ),
  )
}

// Frozen core: a later GlobalState logic may reshape every field after 0–5;
// this permanent script reads only the core, so it keeps working.
test succeeds_when_global_state_has_a_reshaped_tail() {
  run_withdraw(
    spent_redeemer(),
    tests.with_reshaped_gs_tail(
      spent_tx(test_minting_authority_hash, Some(test_minting_authority_hash)),
      test_gs_policy_id,
    ),
  )
}

// `deactivated` must be a real Bool. `Constr(2, [])` is neither False nor
// True; a lenient read (`builtin.unconstr_index(..) == 1`) would take it as
// "not deactivated" and let a mint through — the core decoder traps instead.
test fails_when_deactivated_is_not_a_bool() fail {
  let tx = spent_tx(
    test_minting_authority_hash,
    Some(test_minting_authority_hash),
  )
  expect [gs_in] = tx.inputs
  expect InlineDatum(raw) = gs_in.output.datum
  let bad = builtin.constr_data(
    0,
    utils.replace_data_field(
      builtin.unconstr_fields(raw),
      idx_deactivated,
      builtin.constr_data(2, []),
    ),
  )
  run_withdraw(
    spent_redeemer(),
    Transaction {
      ..tx,
      inputs: [
        Input {
          ..gs_in,
          output: Output { ..gs_in.output, datum: InlineDatum(bad) },
        },
      ],
    },
  ) || True
}

// ── Deactivation ─────────────────────────────────────────────────────────────
/// The permanent proxy refuses a deactivated protocol on its own.
test proxy_fails_when_deactivated() {
  !run_withdraw(
    referenced_redeemer(),
    referenced_tx(make_gs_datum(test_minting_authority_hash, True)),
  )
}

// ── the supply debit ─────────────────────────────────────────────────────────
//
// Each fixture below passes every delegation conjunct; each negative is
// refused by exactly the one debit check its name gives, and pairs with a
// positive built from the same helpers.

fn gs_with_headroom(mintable_amount: Int) -> GlobalStateDatum {
  GlobalStateDatum {
    ..make_gs_datum(test_minting_authority_hash, False),
    mintable_amount,
  }
}

/// `datum` with `mintable_amount` lowered by `amount` (raised for a burn).
fn debited(datum: GlobalStateDatum, amount: Int) -> GlobalStateDatum {
  GlobalStateDatum { ..datum, mintable_amount: datum.mintable_amount - amount }
}

/// `datum` as Data, with `extra` appended after its last field.
fn with_appended(datum: GlobalStateDatum, extra: List<Data>) -> Data {
  let raw: Data = datum
  builtin.constr_data(0, list.concat(builtin.unconstr_fields(raw), extra))
}

fn sec_mint(quantity: Int) -> assets.Assets {
  from_asset(test_issuance_policy_id, test_security_asset_name, quantity)
}

/// The mint/burn shape: GS spent (input 0) carrying `in_datum`, its
/// continuing output (output 0) carrying `out_datum`, this token's node at
/// reference input 0, and `quantity` of the security token minted under its
/// issuance policy. The authority `in_datum` names runs.
fn mint_tx(in_datum: Data, out_datum: Data, quantity: Int) -> Transaction {
  let authority = decode_global_state_core(in_datum).minting_script_credential_hash
  Transaction {
    ..base_tx(),
    inputs: [gs_input_of(in_datum)],
    reference_inputs: [registry_node_input()],
    outputs: [gs_output_of(out_datum)],
    mint: sec_mint(quantity),
    withdrawals: [Pair(Script(authority), 0)],
  }
}

test mint_debits_the_counter_by_the_minted_amount() {
  let d = gs_with_headroom(1_000_000)
  run_withdraw(spent_redeemer(), mint_tx(d, debited(d, 100), 100))
}

test burn_credits_the_counter_by_the_burned_amount() {
  let d = gs_with_headroom(1_000_000)
  run_withdraw(spent_redeemer(), mint_tx(d, debited(d, -100), -100))
}

test mint_to_exactly_zero_headroom_succeeds() {
  let d = gs_with_headroom(100)
  run_withdraw(spent_redeemer(), mint_tx(d, debited(d, 100), 100))
}

test mint_without_the_debit_fails() {
  !run_withdraw(
    spent_redeemer(),
    Transaction {
      ..spent_tx(test_minting_authority_hash, Some(test_minting_authority_hash)),
      mint: from_asset(test_issuance_policy_id, "SEC", 100),
      outputs: [make_gs_output(test_minting_authority_hash, False)],
    },
  )
}

test mint_with_a_wrong_debit_fails() {
  let d = gs_with_headroom(1_000_000)
  !run_withdraw(spent_redeemer(), mint_tx(d, debited(d, 99), 100))
}

test mint_beyond_the_headroom_fails() {
  // The output carries exactly the debited value, -1, so only the headroom
  // check refuses.
  let d = gs_with_headroom(50)
  !run_withdraw(spent_redeemer(), mint_tx(d, debited(d, 51), 51))
}

test mint_that_changes_another_core_field_fails() {
  let d = gs_with_headroom(1_000_000)
  !run_withdraw(
    spent_redeemer(),
    mint_tx(
      d,
      GlobalStateDatum {
        ..debited(d, 100),
        admin_credential_hash: #"0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a",
      },
      100,
    ),
  )
}

test mint_that_changes_a_tail_field_fails() {
  let d = gs_with_headroom(1_000_000)
  !run_withdraw(
    spent_redeemer(),
    mint_tx(
      d,
      GlobalStateDatum { ..debited(d, 100), transfers_paused: True },
      100,
    ),
  )
}

test mint_that_changes_an_appended_field_fails() {
  let d = gs_with_headroom(1_000_000)
  !run_withdraw(
    spent_redeemer(),
    mint_tx(
      with_appended(d, [builtin.i_data(42), builtin.b_data(#"cafe")]),
      with_appended(
        debited(d, 100),
        [builtin.i_data(43), builtin.b_data(#"cafe")],
      ),
      100,
    ),
  )
}

test mint_keeps_appended_fields_unchanged() {
  let d = gs_with_headroom(1_000_000)
  run_withdraw(
    spent_redeemer(),
    mint_tx(
      with_appended(d, [builtin.i_data(42), builtin.b_data(#"cafe")]),
      with_appended(
        debited(d, 100),
        [builtin.i_data(42), builtin.b_data(#"cafe")],
      ),
      100,
    ),
  )
}

/// The burn direction of `mint_without_the_debit_fails`: 100 are burned and
/// the output datum equals the input datum, so the counter is not credited.
/// Only the counter check refuses.
test burn_without_the_credit_fails() {
  let d = gs_with_headroom(1_000_000)
  !run_withdraw(spent_redeemer(), mint_tx(d, d, -100))
}

test burn_with_global_state_only_referenced_fails() fail {
  // The burn direction of the test below: GS is a reference input, yet the
  // outputs hold, at the redeemer's output index, a copy of the GS output
  // credited by exactly the 100 burned. Only the spent-location requirement
  // traps.
  let d = gs_with_headroom(1_000_000)
  run_withdraw(
    referenced_redeemer(),
    Transaction {
      ..referenced_tx(d),
      outputs: [gs_output_of(debited(d, -100))],
      mint: sec_mint(-100),
    },
  ) || True
}

test mint_with_global_state_only_referenced_fails() fail {
  // GS is a reference input, yet the outputs hold, at the redeemer's output
  // index, a copy of the GS output with the exact debit (same address, same
  // NFT). Every other check would pass; only the spent-location requirement
  // traps.
  let d = gs_with_headroom(1_000_000)
  run_withdraw(
    referenced_redeemer(),
    Transaction {
      ..referenced_tx(d),
      outputs: [gs_output_of(debited(d, 100))],
      mint: sec_mint(100),
    },
  ) || True
}

test mint_that_moves_global_state_fails() {
  let d = gs_with_headroom(1_000_000)
  let tx = mint_tx(d, debited(d, 100), 100)
  expect [out] = tx.outputs
  !run_withdraw(
    spent_redeemer(),
    Transaction {
      ..tx,
      outputs: [
        Output {
          ..out,
          address: Address {
            payment_credential: Script(test_other_proxy_hash),
            stake_credential: None,
          },
        },
      ],
    },
  )
}

test mint_that_changes_global_state_tokens_fails() {
  let d = gs_with_headroom(1_000_000)
  let tx = mint_tx(d, debited(d, 100), 100)
  expect [out] = tx.outputs
  !run_withdraw(
    spent_redeemer(),
    Transaction {
      ..tx,
      outputs: [
        Output {
          ..out,
          value: merge(out.value, from_asset(test_foreign_policy_id, "X", 1)),
        },
      ],
    },
  )
}

test mint_accepts_an_ada_top_up_on_global_state() {
  let d = gs_with_headroom(1_000_000)
  let tx = mint_tx(d, debited(d, 100), 100)
  expect [out] = tx.outputs
  run_withdraw(
    spent_redeemer(),
    Transaction {
      ..tx,
      outputs: [
        Output { ..out, value: merge(out.value, from_lovelace(3_000_000)) },
      ],
    },
  )
}

test rotated_permissive_authority_cannot_skip_the_debit() {
  // Whatever authority is installed (here a rotated one, standing in for any
  // replacement that approves everything), the counter must still move.
  let d = GlobalStateDatum {
    ..gs_with_headroom(1_000_000),
    minting_script_credential_hash: test_new_minting_authority_hash,
  }
  !run_withdraw(spent_redeemer(), mint_tx(d, d, 100))
}

test rotated_permissive_global_state_logic_cannot_skip_the_debit() {
  // Whatever GlobalState logic is installed (field 0 names another logic, and
  // it runs), a mint that RAISES the counter is refused here.
  let d = GlobalStateDatum {
    ..gs_with_headroom(1_000_000),
    global_state_script_credential_hash: test_other_gs_logic_hash,
  }
  let tx = mint_tx(d, debited(d, -100), 100)
  !run_withdraw(
    spent_redeemer(),
    Transaction {
      ..tx,
      withdrawals: [
        Pair(Script(test_minting_authority_hash), 0),
        Pair(Script(test_other_gs_logic_hash), 0),
      ],
    },
  )
}

// ── the registry node locations ──────────────────────────────────────────────

/// The covering node of the registration fixtures, as spent: another token's
/// node, naming another proxy, whose `next` is where this token's node goes.
fn covering_node() -> RegNode {
  RegNode {
    ..genuine_node(),
    key: test_other_issuance_policy_id,
    minting_logic_script: Script(test_other_proxy_hash),
  }
}

/// The CIP-113 insert of this token's node, as the base layer requires it:
/// the covering node spent and re-emitted with `next` = the new key (output 0),
/// this token's new node (output 1), one registry NFT named by the new key
/// minted, plus `extra_mint`. GS is referenced and the authority runs.
fn registration_tx(extra_mint: assets.Assets) -> Transaction {
  let covering = covering_node()
  Transaction {
    ..base_tx(),
    inputs: [
      Input {
        output_reference: test_out_ref(4),
        output: registry_node_output(covering),
      },
    ],
    reference_inputs: [
      gs_input_of(make_gs_datum(test_minting_authority_hash, False)),
    ],
    outputs: [
      registry_node_output(
        RegNode { ..covering, next: test_issuance_policy_id },
      ),
      registry_node_output(genuine_node()),
    ],
    mint: merge(
      from_asset(test_registry_policy_id, test_issuance_policy_id, 1),
      extra_mint,
    ),
    withdrawals: [Pair(Script(test_minting_authority_hash), 0)],
  }
}

fn registration_redeemer(
  registry_node_output_index: Int,
) -> MintingLogicScriptWithdrawRedeemer {
  redeemer_of(
    GlobalStateReferenced { global_state_ref_input_index: 0 },
    NodeInserted { registry_node_output_index },
    0,
  )
}

test registration_with_the_node_inserted_and_global_state_referenced_succeeds() {
  // A CIP-68 registration mints the reference NFT under the issuance policy:
  // not the security asset, so nothing is debited and GS may be referenced.
  run_withdraw(
    registration_redeemer(1),
    registration_tx(
      from_asset(
        test_issuance_policy_id,
        bytearray.concat(#"000643b0", "SEC"),
        1,
      ),
    ),
  )
}

test registration_index_at_the_covering_node_fails() fail {
  // The covering node is a genuine registry node, but it names another proxy.
  run_withdraw(
    registration_redeemer(0),
    registration_tx(
      from_asset(
        test_issuance_policy_id,
        bytearray.concat(#"000643b0", "SEC"),
        1,
      ),
    ),
  ) || True
}

/// The registration with a first mint of the security token: GS is spent
/// (input 1, after the covering node), its continuing output is output 2.
fn first_mint_registration_tx(out_datum: GlobalStateDatum) -> Transaction {
  let d = gs_with_headroom(1_000_000)
  let tx = registration_tx(sec_mint(100))
  Transaction {
    ..tx,
    inputs: list.concat(
      tx.inputs,
      [Input { ..gs_input_of(d), output_reference: test_out_ref(5) }],
    ),
    reference_inputs: [],
    outputs: list.concat(tx.outputs, [gs_output_of(out_datum)]),
  }
}

fn first_mint_redeemer() -> MintingLogicScriptWithdrawRedeemer {
  redeemer_of(
    GlobalStateSpent { global_state_input_index: 1 },
    NodeInserted { registry_node_output_index: 1 },
    2,
  )
}

test first_mint_in_the_registration_transaction_is_debited() {
  run_withdraw(
    first_mint_redeemer(),
    first_mint_registration_tx(debited(gs_with_headroom(1_000_000), 100)),
  )
}

test first_mint_in_the_registration_transaction_without_the_debit_fails() {
  !run_withdraw(
    first_mint_redeemer(),
    first_mint_registration_tx(gs_with_headroom(1_000_000)),
  )
}

test upgrade_with_the_node_spent_succeeds() {
  // The CIP-113 in-place update: this token's node is spent and continues
  // with a re-pointed transfer logic. The base layer forbids minting this
  // token here, so nothing is debited and GS may be referenced.
  run_withdraw(
    redeemer_of(
      GlobalStateReferenced { global_state_ref_input_index: 0 },
      NodeSpent { registry_node_input_index: 0 },
      0,
    ),
    Transaction {
      ..base_tx(),
      inputs: [registry_node_input()],
      reference_inputs: [
        gs_input_of(make_gs_datum(test_minting_authority_hash, False)),
      ],
      outputs: [
        registry_node_output(
          RegNode {
            ..genuine_node(),
            transfer_logic_script: Script(
              #"f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4",
            ),
          },
        ),
      ],
      withdrawals: [Pair(Script(test_minting_authority_hash), 0)],
    },
  )
}

test node_naming_another_proxy_fails() fail {
  // A genuine-shaped node (registry address, one registry NFT named by its
  // key) whose field 2 names another proxy is not this token's node.
  let tx = spent_tx(
    test_minting_authority_hash,
    Some(test_minting_authority_hash),
  )
  run_withdraw(
    spent_redeemer(),
    Transaction {
      ..tx,
      reference_inputs: [
        Input {
          output_reference: test_out_ref(3),
          output: registry_node_output(
            RegNode {
              ..genuine_node(),
              minting_logic_script: Script(test_other_proxy_hash),
            },
          ),
        },
      ],
    },
  ) || True
}

test node_location_at_a_non_node_utxo_fails() fail {
  // The same node datum and address, without the registry NFT.
  let tx = spent_tx(
    test_minting_authority_hash,
    Some(test_minting_authority_hash),
  )
  let node = registry_node_input()
  run_withdraw(
    spent_redeemer(),
    Transaction {
      ..tx,
      reference_inputs: [
        Input {
          ..node,
          output: Output { ..node.output, value: from_lovelace(2_000_000) },
        },
      ],
    },
  ) || True
}

// ── what is counted ──────────────────────────────────────────────────────────

test only_the_issuance_policy_counts() {
  // The security asset's name under a foreign policy is not this token.
  run_withdraw(
    referenced_redeemer(),
    Transaction {
      ..referenced_tx(make_gs_datum(test_minting_authority_hash, False)),
      mint: from_asset(test_foreign_policy_id, test_security_asset_name, 100),
    },
  )
}

/// The deliberate residue: another name under the issuance policy is not
/// counted. Restricting the names minted under it is the authority's rule.
test other_names_under_the_issuance_policy_are_not_counted() {
  run_withdraw(
    referenced_redeemer(),
    Transaction {
      ..referenced_tx(make_gs_datum(test_minting_authority_hash, False)),
      mint: from_asset(test_issuance_policy_id, "OTHER", 100),
    },
  )
}

test delta_zero_with_global_state_spent_checks_no_counter() {
  // GS spent, nothing minted and no outputs at all: the continuing output is
  // never looked for.
  run_withdraw(
    spent_redeemer(),
    Transaction {
      ..spent_tx(test_minting_authority_hash, Some(test_minting_authority_hash)),
      outputs: [],
      mint: zero,
    },
  )
}

// A permanent reader traps on a retyped core field: `mintable_amount` as bytes
// is refused by the core decoder even when nothing is minted.
test proxy_traps_on_a_non_int_mintable_amount() fail {
  let raw: Data = make_gs_datum(test_minting_authority_hash, False)
  let bad = builtin.constr_data(
    0,
    utils.replace_data_field(
      builtin.unconstr_fields(raw),
      idx_mintable_amount,
      builtin.b_data(#"00"),
    ),
  )
  run_withdraw(
    spent_redeemer(),
    Transaction {
      ..spent_tx(test_minting_authority_hash, Some(test_minting_authority_hash)),
      inputs: [gs_input_of(bad)],
    },
  ) || True
}
