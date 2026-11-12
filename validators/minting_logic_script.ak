use aiken/builtin
use aiken/collection/dict
use aiken/interval.{Interval, IntervalBound, NegativeInfinity, PositiveInfinity}
use cardano/address.{Address, Credential, Script}
use cardano/assets.{from_asset, from_lovelace, merge, zero}
use cardano/certificate.{Certificate, RegisterCredential, UnregisterCredential}
use cardano/transaction.{
  InlineDatum, Input, NoDatum, Output, OutputReference, Transaction,
}
use constants
use tests
use tests/global_state_fixtures.{t_datum}
use types/global_state.{
  GlobalStateCore, GlobalStateDatum, GlobalStateLocation, GlobalStateReferenced,
  GlobalStateSpent, gs_core_from_output, idx_deactivated,
}
use utils.{must_run_script_withdrawal}

/// The permanent, CIP-113-registered PROXY for this token's minting path.
///
/// Every registry node's `minting_logic_script` field is frozen to this
/// script's hash forever, and the token's own issuance policy id is derived
/// from that hash — so nothing in this file can ever change after deployment
/// without minting a different token. It therefore decides the delegation
/// and nothing else: it resolves GlobalState, reads which script is currently
/// the minting authority, and requires that script to be running in this
/// transaction. That is the whole validator.
///
/// EVERY substantive rule — the supply debit of `mintable_amount`, power-user
/// roles, KYC, denylist, mint destinations, which asset names may be minted,
/// the CIP-113 registration's structural invariants, the admin gate, and the
/// guard against riding along on a registry-node update — lives in
/// validators/minting_authority.ak, which the admin can replace at any time
/// via `RotateMintingScript`. Maximum upgradability, by construction: the only
/// thing that can never be fixed is this file, so this file decides as little
/// as possible.
///
/// WHY THE SUPPLY DEBIT IS DELIBERATELY NOT HERE. This file's hash is the
/// token's issuance policy id, so a defect in a rule written here could never
/// be fixed. The authority can be rotated. Until `LockUpgrades` the admin can
/// already set the cap with `SetMintableAmount`; after `LockUpgrades`,
/// `RotateMintingScript` is closed and the installed authority, its debit
/// included, is permanent too.
///
/// The corollary, stated plainly because it is the price of that design: a
/// replacement authority inherits the FULL burden of correctness. Nothing
/// here will catch its mistakes. See the "INVARIANTS ANY REPLACEMENT
/// AUTHORITY MUST PRESERVE" note in validators/minting_authority.ak.
validator minting_logic_validator(global_state_policy_id: ByteArray) {
  /// The redeemer is exactly `GlobalStateLocation` — the proxy needs one thing
  /// from the caller, where to find GlobalState, and every other decision
  /// belongs to the authority (see types/minting_authority.ak). The shared
  /// type is the single encoding of "which list is GlobalState in" for every
  /// validator where the choice is free.
  withdraw(
    redeemer: GlobalStateLocation,
    credential: Credential,
    self: Transaction,
  ) {
    expect Script(own_hash) = credential

    // Resolved INLINE rather than through a shared location helper such as
    // `resolve_global_state` (which also decodes the full v1 layout, where
    // this script must read only the frozen core).
    //
    // This one file may not change its compiled bytes after launch. Its hash
    // is frozen into this token's registry node, and the token's issuance
    // policy id is derived from it — so a different hash is a different
    // token, and every already-issued one becomes unreachable. Going through
    // the shared helper was measured to move the hash (6defc595… ->
    // b6e4e07a…): same behaviour, different UPLC. The redeemer TYPE is
    // shared, because a type name is not compiled; the resolution is not. Do
    // not "tidy" this into the helper without re-checking the hash.
    //
    // The compiled bytes also include every shared function and constant this
    // file calls: `utils.safe_list_at`, `utils.must_run_script_withdrawal`,
    // `gs_core_from_output` / `decode_global_state_core` / `GlobalStateCore`,
    // and `constants.global_state_asset_name` with the `gs_core_field_count`
    // it is read alongside, as well as the stdlib functions they use. After
    // launch, editing any of them changes this hash and so the token. Before
    // launch the hash changed deliberately when the frozen-core layout changed
    // its reads (2026-10-15, and again when `mintable_amount` moved into the
    // core and back out of it).
    let gs_output: Output = when redeemer is {
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
      // script ever executing — and since this proxy checks nothing else at
      // all, that would be a total bypass of every rule the token has. Only
      // a genuine withdraw-0 proves the authority's own logic ran and
      // approved this specific transaction.
      must_run_script_withdrawal(self, gs_datum.minting_script_credential_hash)?,
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
// Tests — the whole validator is one delegation decision, so these cover
// exactly that: can the gate be satisfied by anything other than the
// currently-named authority genuinely running?
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

// This proxy's own credential, as the ledger passes it to `withdraw`.
const test_minting_logic_hash: ByteArray =
  #"f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1"

// The currently-active minting authority (validators/minting_authority.ak),
// as named by GlobalState.minting_script_credential_hash.
const test_minting_authority_hash: ByteArray =
  #"06060606060606060606060606060606060606060606060606060606"

// A second, distinct authority — what `RotateMintingScript` points
// GlobalState at. Used to prove rotation actually re-points the delegation.
const test_new_minting_authority_hash: ByteArray =
  #"07070707070707070707070707070707070707070707070707070707"

fn test_out_ref(ix: Int) -> OutputReference {
  OutputReference {
    transaction_id: #"0000000000000000000000000000000000000000000000000000000000000000",
    output_index: ix,
  }
}

// ── GlobalState ──────────────────────────────────────────────────────────────

// The shared v1 fixture, with no admin and `authority` as the minting
// authority.
fn make_gs_datum(authority: ByteArray, deactivated: Bool) -> GlobalStateDatum {
  GlobalStateDatum {
    ..t_datum(False, deactivated),
    admin_credential_hash: #"",
    minting_script_credential_hash: authority,
  }
}

/// A GlobalState UTxO carrying `datum`, which is any Data so that fixtures can
/// retype a field.
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
// present or absent.
fn spent_tx(authority: ByteArray, withdrawal: Option<ByteArray>) -> Transaction {
  Transaction {
    ..base_tx(),
    inputs: [make_gs_input(authority, False)],
    withdrawals: when withdrawal is {
      Some(h) -> [Pair(Script(h), 0)]
      None -> []
    },
  }
}

// GS referenced (reference input 0), and the named authority's withdraw-0.
fn referenced_tx(gs_datum: GlobalStateDatum) -> Transaction {
  Transaction {
    ..base_tx(),
    reference_inputs: [gs_input_of(gs_datum)],
    withdrawals: [Pair(Script(gs_datum.minting_script_credential_hash), 0)],
  }
}

fn run_withdraw(redeemer: GlobalStateLocation, tx: Transaction) {
  minting_logic_validator.withdraw(
    test_gs_policy_id,
    redeemer,
    Script(test_minting_logic_hash),
    tx,
  )
}

// The `spent_tx` shape: GS input 0.
fn spent_redeemer() -> GlobalStateLocation {
  GlobalStateSpent { global_state_input_index: 0 }
}

// The `referenced_tx` shape: GS reference input 0.
fn referenced_redeemer() -> GlobalStateLocation {
  GlobalStateReferenced { global_state_ref_input_index: 0 }
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
  // proxy accepts either — deciding which is appropriate for the operation
  // at hand is the authority's job, not this validator's.
  run_withdraw(
    referenced_redeemer(),
    referenced_tx(make_gs_datum(test_minting_authority_hash, False)),
  )
}

test fails_without_the_authority_withdrawal() {
  // This is the entire validator: with no authority running, nothing else
  // here could possibly authorise anything.
  !run_withdraw(spent_redeemer(), spent_tx(test_minting_authority_hash, None))
}

test fails_when_the_authority_is_merely_signed_for() {
  // The gate must accept ONLY a real withdraw-0 of the named script, never a
  // bare signature — `must_be_signed_by_credential` treats the two as
  // interchangeable, which here would let the authority be skipped entirely
  // and, since this proxy checks nothing else, bypass every rule the token
  // has.
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

// This permanent script reads only the core (fields 0–4), so it keeps working
// whatever follows it.
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
