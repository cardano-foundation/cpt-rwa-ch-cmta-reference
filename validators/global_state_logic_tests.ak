//// Tests for `global_state_logic` (global_state_logic.ak).
////
//// A separate module because most of them run the full spend path, the proxy
//// AND the logic together (`run_spend`), and Aiken lets only a module without
//// validators import validator modules.

use aiken/builtin
use aiken/collection/list
use aiken/collection/pairs
use aiken/primitive/bytearray
use aiken_design_patterns/linked_list.{Element, Node}
use cardano/address.{Address, Credential, Script, VerificationKey}
use cardano/assets.{Value, from_asset, from_lovelace, merge}
use cardano/certificate.{RegisterCredential, UnregisterCredential}
use cardano/transaction.{InlineDatum, Input, Mint, NoDatum, Output, Transaction}
use constants
use global_state_logic as v_logic
use global_state_proxy as v_proxy
use tests/global_state_fixtures.{
  rotated, t_admin, t_data_of_raw_length, t_datum, t_dl_ll_policy, t_gs_logic,
  t_gs_policy, t_gs_script_hash, t_many_entities, t_metadata_len_at_cap,
  t_metadata_len_over_cap, t_minting_script, t_new_gs_logic, t_out_ref, t_output,
  t_pu_ll_policy, t_reference_script, t_root32, t_security_info_len_at_cap,
  t_security_info_len_over_cap, t_tx, t_vkey_10,
}
use types/global_state.{
  AddTrustedEntity, DeactivateContract, GlobalStateDatum,
  GlobalStateSpendRedeemer, LockUpgrades, MintSecurity, ModifySecurityInfo,
  PauseTransfers, RemoveTrustedEntity, RotateAdmin, RotateGlobalStateScript,
  RotateMintingScript, SetMintableAmount, SetRequiresReceiverKyc,
  SetRequiresSenderKyc, TrustedEntityMetadata, UpdateMemberRootHash,
  UpdateTrustedEntity, idx_mintable_amount, set_security_info,
}
use types/power_users.{PowerUser}
use utils

// ============================================================================
// Fixtures and runners used only by the logic tests
// ============================================================================

const t_issuance_policy: ByteArray =
  #"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

// The power-users SPEND validator's hash, where the PauseTransfers tests put
// the operator's list node.
const t_pu_script_hash: ByteArray =
  #"d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1"

const t_new_admin: ByteArray =
  #"1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c"

const t_sec_name: ByteArray = "SEC"

const t_new_minting_script: ByteArray =
  #"ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

fn t_output_with_reference_script(datum: GlobalStateDatum) -> Output {
  Output { ..t_output(datum), reference_script: Some(t_reference_script) }
}

fn deactivate_redeemer() -> GlobalStateSpendRedeemer {
  GlobalStateSpendRedeemer {
    global_state_output_index: 0,
    action: DeactivateContract,
  }
}

// A GlobalState spend as the ledger runs it: the proxy on the spent UTxO and
// the logic its field 0 names, whose withdraw-0 is added here. The ledger hands
// a spend validator the datum of the input it spends, while the logic reads it
// from the transaction — so the input at `t_out_ref(0)` is given `input_datum`,
// exactly the pairing the old single spend validator received.
fn run_spend(
  input_datum: GlobalStateDatum,
  redeemer: GlobalStateSpendRedeemer,
  tx: Transaction,
) -> Bool {
  let input_data: Data = input_datum
  let redeemer_data: Data = redeemer
  let logic = input_datum.global_state_script_credential_hash
  let tx = Transaction {
    ..tx,
    inputs: list.map(
      tx.inputs,
      fn(input) {
        if input.output_reference == t_out_ref(0) {
          Input {
            ..input,
            output: Output { ..input.output, datum: InlineDatum(input_data) },
          }
        } else {
          input
        }
      },
    ),
    withdrawals: [Pair(Script(logic), 0), ..tx.withdrawals],
  }
  and {
    v_proxy.global_state_proxy.spend(
      Some(input_data),
      redeemer_data,
      t_out_ref(0),
      tx,
    ),
    run_logic(logic, redeemer, tx),
  }
}

fn run_logic(
  logic: ByteArray,
  redeemer: GlobalStateSpendRedeemer,
  tx: Transaction,
) -> Bool {
  v_logic.global_state_logic.withdraw(
    t_sec_name,
    t_issuance_policy,
    t_gs_policy,
    t_pu_script_hash,
    redeemer,
    Script(logic),
    tx,
  )
}

// ── RotateMintingScript — admin-only, single-signature ───────────────────────

fn rotate_minting_script_redeemer(
  new_minting_script_credential_hash: ByteArray,
) -> GlobalStateSpendRedeemer {
  GlobalStateSpendRedeemer {
    global_state_output_index: 0,
    action: RotateMintingScript { new_minting_script_credential_hash },
  }
}

test rotate_minting_script_succeeds_when_admin_signs() {
  // Admin alone is sufficient — note the signatory list holds neither the
  // outgoing nor the incoming authority. Deliberately NOT dual-sig:
  // replacing a buggy or compromised authority has to work precisely when
  // that authority can no longer be trusted to co-sign its own removal.
  let input_datum = t_datum(False, False)
  let output_datum = GlobalStateDatum {
    ..input_datum,
    minting_script_credential_hash: t_new_minting_script,
    upgrades_locked: False,
  }
  run_spend(
    input_datum,
    rotate_minting_script_redeemer(t_new_minting_script),
    t_tx(input_datum, output_datum, [t_admin]),
  )
}

test rotate_minting_script_fails_without_admin_signature() {
  // Deliberately NOT dual-sig: only the admin's signature is checked, so
  // this must fail on a missing ADMIN signature alone — no signature from
  // the outgoing minting script is required or checked at all.
  let input_datum = t_datum(False, False)
  let output_datum = GlobalStateDatum {
    ..input_datum,
    minting_script_credential_hash: t_new_minting_script,
    upgrades_locked: False,
  }
  !run_spend(
    input_datum,
    rotate_minting_script_redeemer(t_new_minting_script),
    t_tx(input_datum, output_datum, []),
  )
}

test rotate_minting_script_cannot_smuggle_another_field_change() {
  // A rotation must change exactly one field. Without the whole-datum
  // equality check an admin-signed rotation would be a carrier for any
  // other datum edit — e.g. silently raising the supply cap alongside it.
  let input_datum = t_datum(False, False)
  let output_datum = GlobalStateDatum {
    ..input_datum,
    minting_script_credential_hash: t_new_minting_script,
    upgrades_locked: False,
    mintable_amount: input_datum.mintable_amount + 1_000_000,
  }
  !run_spend(
    input_datum,
    rotate_minting_script_redeemer(t_new_minting_script),
    t_tx(input_datum, output_datum, [t_admin]),
  )
}

test global_state_spend_rejects_reference_script_on_output() {
  let input_datum = t_datum(False, False)
  let output_datum = GlobalStateDatum {
    ..input_datum,
    minting_script_credential_hash: t_new_minting_script,
    upgrades_locked: False,
  }
  let tx = Transaction {
    ..t_tx(input_datum, output_datum, [t_admin]),
    outputs: [t_output_with_reference_script(output_datum)],
  }
  !run_spend(
    input_datum,
    rotate_minting_script_redeemer(t_new_minting_script),
    tx,
  )
}

test rotate_admin_succeeds_when_both_sign() {
  // Dual-sig by design: requiring the INCOMING admin's signature too proves
  // the new credential is live, so a typo cannot strand the protocol with an
  // admin nobody controls.
  let input_datum = t_datum(False, False)
  let output_datum = GlobalStateDatum {
    ..input_datum,
    admin_credential_hash: t_new_admin,
  }
  run_spend(
    input_datum,
    rotate_admin_redeemer(t_new_admin),
    t_tx(input_datum, output_datum, [t_admin, t_new_admin]),
  )
}

test rotate_admin_fails_without_outgoing_admin_signature() {
  // Blocks silent takeover: whoever holds the new key cannot install it alone.
  let input_datum = t_datum(False, False)
  let output_datum = GlobalStateDatum {
    ..input_datum,
    admin_credential_hash: t_new_admin,
  }
  !run_spend(
    input_datum,
    rotate_admin_redeemer(t_new_admin),
    t_tx(input_datum, output_datum, [t_new_admin]),
  )
}

test rotate_admin_fails_without_incoming_admin_signature() {
  // The lost-key soft-brick guard: the outgoing admin alone cannot hand the
  // protocol to a credential that has not proven it can sign.
  let input_datum = t_datum(False, False)
  let output_datum = GlobalStateDatum {
    ..input_datum,
    admin_credential_hash: t_new_admin,
  }
  !run_spend(
    input_datum,
    rotate_admin_redeemer(t_new_admin),
    t_tx(input_datum, output_datum, [t_admin]),
  )
}

test rotate_admin_cannot_smuggle_another_field_change() {
  let input_datum = t_datum(False, False)
  let output_datum = GlobalStateDatum {
    ..input_datum,
    admin_credential_hash: t_new_admin,
    mintable_amount: input_datum.mintable_amount + 1_000_000,
  }
  !run_spend(
    input_datum,
    rotate_admin_redeemer(t_new_admin),
    t_tx(input_datum, output_datum, [t_admin, t_new_admin]),
  )
}

fn rotate_admin_redeemer(
  new_admin_credential_hash: ByteArray,
) -> GlobalStateSpendRedeemer {
  GlobalStateSpendRedeemer {
    global_state_output_index: 0,
    action: RotateAdmin { new_admin_credential_hash },
  }
}

test rotate_minting_script_fails_when_length_invalid() {
  let input_datum = t_datum(False, False)
  let bad_hash = #"ab"
  let output_datum = GlobalStateDatum {
    ..input_datum,
    minting_script_credential_hash: bad_hash,
    upgrades_locked: False,
  }
  !run_spend(
    input_datum,
    rotate_minting_script_redeemer(bad_hash),
    t_tx(input_datum, output_datum, [t_admin]),
  )
}

test deactivated_input_rejects_rotate_minting_script() fail {
  let input_datum = t_datum(True, True)
  let output_datum = GlobalStateDatum {
    ..input_datum,
    minting_script_credential_hash: t_new_minting_script,
    upgrades_locked: False,
  }
  run_spend(
    input_datum,
    rotate_minting_script_redeemer(t_new_minting_script),
    t_tx(input_datum, output_datum, [t_admin]),
  )
}

// ── LockUpgrades — the one-way upgrade lock ─────────────────────────────────

fn lock_upgrades_redeemer() -> GlobalStateSpendRedeemer {
  GlobalStateSpendRedeemer {
    global_state_output_index: 0,
    action: LockUpgrades,
  }
}

fn t_datum_locked() -> GlobalStateDatum {
  GlobalStateDatum { ..t_datum(False, False), upgrades_locked: True }
}

test lock_upgrades_succeeds_when_admin_signs() {
  let input_datum = t_datum(False, False)
  run_spend(
    input_datum,
    lock_upgrades_redeemer(),
    t_tx(input_datum, t_datum_locked(), [t_admin]),
  )
}

test lock_upgrades_fails_without_admin_signature() {
  let input_datum = t_datum(False, False)
  !run_spend(
    input_datum,
    lock_upgrades_redeemer(),
    t_tx(input_datum, t_datum_locked(), []),
  )
}

test lock_upgrades_is_one_way() {
  // Re-locking is refused, so the action is never a silent no-op...
  let input_datum = t_datum_locked()
  !run_spend(
    input_datum,
    lock_upgrades_redeemer(),
    t_tx(input_datum, t_datum_locked(), [t_admin]),
  )
}

test lock_upgrades_cannot_be_undone() {
  // ...and no action can clear it. Every branch reproduces the datum
  // wholesale via `equals_data`, and only LockUpgrades touches this field —
  // which sets it True — so False is reachable exactly once, at genesis.
  // Attempting to unlock is checked here against LockUpgrades itself; the
  // whole-datum equality is what blocks every other branch from doing it.
  let input_datum = t_datum_locked()
  !run_spend(
    input_datum,
    lock_upgrades_redeemer(),
    t_tx(input_datum, t_datum(False, False), [t_admin]),
  )
}

test lock_upgrades_cannot_smuggle_another_field_change() {
  let input_datum = t_datum(False, False)
  let output_datum = GlobalStateDatum {
    ..t_datum_locked(),
    mintable_amount: input_datum.mintable_amount + 1_000_000,
  }
  !run_spend(
    input_datum,
    lock_upgrades_redeemer(),
    t_tx(input_datum, output_datum, [t_admin]),
  )
}

test rotate_minting_script_fails_once_upgrades_are_locked() {
  // The lock closes the minting-authority upgrade path permanently.
  let input_datum = t_datum_locked()
  let output_datum = GlobalStateDatum {
    ..input_datum,
    minting_script_credential_hash: t_new_minting_script,
  }
  !run_spend(
    input_datum,
    rotate_minting_script_redeemer(t_new_minting_script),
    t_tx(input_datum, output_datum, [t_admin]),
  )
}

// ── DeactivateContract — success + guard on preconditions ────────────────────

test deactivate_succeeds_when_paused_and_admin_signs() {
  let input_datum = t_datum(True, False)
  let output_datum = GlobalStateDatum { ..input_datum, deactivated: True }
  run_spend(
    input_datum,
    deactivate_redeemer(),
    t_tx(input_datum, output_datum, [t_admin]),
  )
}

test deactivate_fails_when_not_paused() {
  // transfers_paused == False → the paused precondition rejects.
  let input_datum = t_datum(False, False)
  let output_datum = GlobalStateDatum { ..input_datum, deactivated: True }
  !run_spend(
    input_datum,
    deactivate_redeemer(),
    t_tx(input_datum, output_datum, [t_admin]),
  )
}

test deactivate_fails_without_admin_signature() {
  let input_datum = t_datum(True, False)
  let output_datum = GlobalStateDatum { ..input_datum, deactivated: True }
  !run_spend(
    input_datum,
    deactivate_redeemer(),
    t_tx(input_datum, output_datum, []),
  )
}

test deactivate_fails_when_output_not_marked_deactivated() {
  // Output keeps deactivated == False → the expected-datum equality fails.
  let input_datum = t_datum(True, False)
  let output_datum = input_datum
  !run_spend(
    input_datum,
    deactivate_redeemer(),
    t_tx(input_datum, output_datum, [t_admin]),
  )
}

// ── DeactivateContract — no_security_token_spent ─────────────────────────
//
// `with_security_token_input`/`with_security_token_output` are defined below,
// alongside the MintSecurity fixtures — Aiken resolves top-level bindings
// module-wide, so the forward reference is fine.

test deactivate_succeeds_when_security_token_absent_from_tx() {
  // Positive control paired with the two negatives below — same fixture as
  // `deactivate_succeeds_when_paused_and_admin_signs`, named here to make the
  // pairing with the guard explicit.
  let input_datum = t_datum(True, False)
  let output_datum = GlobalStateDatum { ..input_datum, deactivated: True }
  run_spend(
    input_datum,
    deactivate_redeemer(),
    t_tx(input_datum, output_datum, [t_admin]),
  )
}

test deactivate_rejects_when_an_input_carries_the_security_token() {
  let input_datum = t_datum(True, False)
  let output_datum = GlobalStateDatum { ..input_datum, deactivated: True }
  !run_spend(
    input_datum,
    deactivate_redeemer(),
    with_security_token_input(t_tx(input_datum, output_datum, [t_admin])),
  )
}

test deactivate_rejects_when_the_security_token_is_minted_into_an_output() {
  let input_datum = t_datum(True, False)
  let output_datum = GlobalStateDatum { ..input_datum, deactivated: True }
  !run_spend(
    input_datum,
    deactivate_redeemer(),
    with_security_token_minted_into_an_output(
      t_tx(input_datum, output_datum, [t_admin]),
    ),
  )
}

// ── Terminal irreversibility — a deactivated GS UTxO cannot be spent at all ──

test deactivated_input_rejects_further_deactivate() fail {
  // Already deactivated → the top-level terminal guard traps.
  let input_datum = t_datum(True, True)
  let output_datum = input_datum
  run_spend(
    input_datum,
    deactivate_redeemer(),
    t_tx(input_datum, output_datum, [t_admin]),
  )
}

test deactivated_input_rejects_modify_security_info() fail {
  // A normally-valid ModifySecurityInfo on a deactivated GS must still be
  // rejected by the terminal guard (proves the guard blocks all non-burn
  // actions, not just DeactivateContract). Without the guard this succeeds.
  let input_datum = t_datum(True, True)
  let new_info: Data = builtin.constr_data(0, [builtin.i_data(7)])
  let input_fields = builtin.unconstr_fields(input_datum)
  expect output_datum: GlobalStateDatum = set_security_info(
    input_fields,
    new_info,
  )
  let redeemer = GlobalStateSpendRedeemer {
    global_state_output_index: 0,
    action: ModifySecurityInfo { new_security_info: new_info },
  }
  run_spend(input_datum, redeemer, t_tx(input_datum, output_datum, [t_admin]))
}

// ── Post-deactivation: burns allowed, mints rejected ────────────────────────

// A MintSecurity transaction: `mint_delta` of the security token (negative =
// burn, positive = mint) plus the issuance-policy Mint redeemer the branch
// requires, on top of the shared GS input/output.
fn t_mintsecurity_tx(
  input_datum: GlobalStateDatum,
  output_datum: GlobalStateDatum,
  mint_delta: Int,
  signatories: List<ByteArray>,
) -> Transaction {
  Transaction {
    ..t_tx(input_datum, output_datum, signatories),
    mint: from_asset(t_issuance_policy, t_sec_name, mint_delta),
    redeemers: [Pair(Mint(t_issuance_policy), builtin.constr_data(0, []))],
  }
}

fn mintsecurity_redeemer() -> GlobalStateSpendRedeemer {
  GlobalStateSpendRedeemer {
    global_state_output_index: 0,
    action: MintSecurity { issuance_policy_redeemer_index: 0 },
  }
}

// ── no_security_token_spent — shared fixtures ───────────────────────────────
//
// Every non-MintSecurity branch composes `no_security_token_spent`. These
// helpers append one extra input, or one extra output, carrying the security
// token to an otherwise-unmodified transaction — reused by every branch's
// guard tests below, and by the MintSecurity positive control that proves
// the branch is deliberately exempt.

const t_wallet_vkey: ByteArray =
  #"77777777777777777777777777777777777777777777777777777777"

fn t_security_token_value() -> Value {
  merge(from_lovelace(2_000_000), from_asset(t_issuance_policy, t_sec_name, 1))
}

/// An extra input carrying one unit of the security token, parked in a plain
/// wallet — proves `no_security_token_spent` rejects the token appearing
/// as an INPUT, independent of which branch or datum is under test.
fn t_security_token_input() -> Input {
  Input {
    output_reference: t_out_ref(9),
    output: Output {
      address: Address {
        payment_credential: VerificationKey(t_wallet_vkey),
        stake_credential: None,
      },
      value: t_security_token_value(),
      datum: NoDatum,
      reference_script: None,
    },
  }
}

/// Same, but as an extra OUTPUT. On its own an output with no matching input
/// is ledger-impossible (value is conserved), so the fixture that uses this
/// also MINTS the unit — the output side is covered by
/// `no_concurrent_security_mint`, not by an output scan.
fn t_security_token_output() -> Output {
  Output {
    address: Address {
      payment_credential: VerificationKey(t_wallet_vkey),
      stake_credential: None,
    },
    value: t_security_token_value(),
    datum: NoDatum,
    reference_script: None,
  }
}

fn with_security_token_input(tx: Transaction) -> Transaction {
  Transaction {
    ..tx,
    inputs: list.concat(tx.inputs, [t_security_token_input()]),
  }
}

/// An extra OUTPUT carrying the unit that `with_security_token_input` spends
/// — a ledger-consistent pass-through, used by the MintSecurity exemption
/// test (the one branch allowed to move the token).
fn with_security_token_output(tx: Transaction) -> Transaction {
  Transaction {
    ..tx,
    outputs: list.concat(tx.outputs, [t_security_token_output()]),
  }
}

/// The only ledger-valid way for the token to appear in an output without
/// being spent is to mint it; `no_concurrent_security_mint` rejects that.
fn with_security_token_minted_into_an_output(tx: Transaction) -> Transaction {
  Transaction {
    ..tx,
    mint: merge(tx.mint, from_asset(t_issuance_policy, t_sec_name, 1)),
    outputs: list.concat(tx.outputs, [t_security_token_output()]),
  }
}

/// The supply-cap branch must change exactly `mintable_amount` and nothing
/// else. It is the highest-value branch to pin: a mint is the one routine
/// operation that legitimately rewrites the datum, so if it could carry a
/// second edit it would be the natural vehicle for one — rotating the admin,
/// clearing a KYC flag or unlocking upgrades under cover of an ordinary
/// issuance. The whole-datum equality is what prevents that; this test is its
/// guard.
test mint_security_cannot_smuggle_another_field_change() {
  let input_datum = t_datum(False, False)
  let mint = 100
  let output_datum = GlobalStateDatum {
    ..input_datum,
    mintable_amount: input_datum.mintable_amount - mint,
    // …plus one edit that has no business riding along.
    admin_credential_hash: t_new_admin,
  }
  !run_spend(
    input_datum,
    mintsecurity_redeemer(),
    t_mintsecurity_tx(input_datum, output_datum, mint, [t_admin]),
  )
}

/// The control: the same transaction WITHOUT the smuggled edit is accepted.
/// Without this, the test above would pass even if the whole branch were
/// broken.
test mint_security_accepts_a_clean_cap_decrement() {
  let input_datum = t_datum(False, False)
  let mint = 100
  let output_datum = GlobalStateDatum {
    ..input_datum,
    mintable_amount: input_datum.mintable_amount - mint,
  }
  run_spend(
    input_datum,
    mintsecurity_redeemer(),
    t_mintsecurity_tx(input_datum, output_datum, mint, [t_admin]),
  )
}

/// The cap must actually be decremented. Here the datum is reproduced
/// unchanged while 100 tokens are issued, which would leave headroom for the
/// full original cap on top of live supply — the simplest form of the
/// inflation this branch exists to prevent.
test mint_security_rejects_a_cap_that_does_not_decrement() {
  let input_datum = t_datum(False, False)
  let output_datum = input_datum
  !run_spend(
    input_datum,
    mintsecurity_redeemer(),
    t_mintsecurity_tx(input_datum, output_datum, 100, [t_admin]),
  )
}

test deactivated_input_rejects_burn() fail {
  // Deactivation is fully terminal: even a burn (negative security-mint) is
  // rejected by the terminal guard — no token-level update of any kind after
  // deactivation, so an immobilised (frozen-as-is) state stays exactly as-is.
  let input_datum = t_datum(True, True)
  let burn = -100
  let output_datum = GlobalStateDatum {
    ..input_datum,
    mintable_amount: input_datum.mintable_amount - burn,
  }
  run_spend(
    input_datum,
    mintsecurity_redeemer(),
    t_mintsecurity_tx(input_datum, output_datum, burn, [t_admin]),
  )
}

test deactivated_input_rejects_mint() fail {
  // No minting after deactivation — a positive security-mint on a deactivated
  // GS is rejected by the terminal guard (traps).
  let input_datum = t_datum(True, True)
  let mint = 100
  let output_datum = GlobalStateDatum {
    ..input_datum,
    mintable_amount: input_datum.mintable_amount - mint,
  }
  run_spend(
    input_datum,
    mintsecurity_redeemer(),
    t_mintsecurity_tx(input_datum, output_datum, mint, [t_admin]),
  )
}

test live_contract_still_allows_mint() {
  // Sanity: a normal (non-deactivated) mint still works — the burn-only guard
  // only bites once deactivated.
  let input_datum = t_datum(False, False)
  let mint = 100
  let output_datum = GlobalStateDatum {
    ..input_datum,
    mintable_amount: input_datum.mintable_amount - mint,
  }
  run_spend(
    input_datum,
    mintsecurity_redeemer(),
    t_mintsecurity_tx(input_datum, output_datum, mint, [t_admin]),
  )
}

/// MintSecurity is deliberately EXEMPT from `no_security_token_spent` — it
/// is the one branch that legitimately mints, burns, and otherwise moves the
/// token. On top of the ordinary mint-delta this transaction ALSO carries an
/// unrelated security-token input and output — exactly the shape every other
/// branch's negative controls below reject — and the branch still succeeds.
test mint_security_allows_security_token_input_and_output() {
  let input_datum = t_datum(False, False)
  let mint = 100
  let output_datum = GlobalStateDatum {
    ..input_datum,
    mintable_amount: input_datum.mintable_amount - mint,
  }
  let tx = t_mintsecurity_tx(input_datum, output_datum, mint, [t_admin])
    |> with_security_token_input
    |> with_security_token_output
  run_spend(input_datum, mintsecurity_redeemer(), tx)
}

// ── PauseTransfers — the power-user gate and its list-address pin ───────────
//
// The address pin this branch carries matters more here than in the swappable
// consumers: a GlobalState logic is replaced only by an admin rotation,
// so the assertion is the primary defence rather than a belt-and-braces one.
// Keep all three tests together — the positive control is what makes the two
// negatives meaningful.

const t_pause_pu_cred: ByteArray =
  #"0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c"

/// The datum used by the pause tests — `t_datum` leaves the list policy ids
/// empty, which no real deployment does.
fn t_pause_datum(transfers_paused: Bool) -> GlobalStateDatum {
  GlobalStateDatum {
    ..t_datum(transfers_paused, False),
    power_user_linked_list_policy_id: t_pu_ll_policy,
    denylist_linked_list_policy_id: t_dl_ll_policy,
  }
}

/// A power-user node with `can_pause`, at `payment` — varied so the address
/// pin can be exercised in both directions.
fn t_pu_node_at(payment: Credential) -> Input {
  let pu = PowerUser {
    credential_hash: t_pause_pu_cred,
    is_admin: False,
    can_mint: False,
    can_burn: False,
    can_pause: True,
    can_force_transfer: False,
  }
  let element: Element<Data, PowerUser> = Element {
    data: Node { data: pu },
    link: None,
  }
  Input {
    output_reference: t_out_ref(5),
    output: Output {
      address: Address { payment_credential: payment, stake_credential: None },
      value: merge(
        from_lovelace(2_000_000),
        from_asset(
          t_pu_ll_policy,
          bytearray.concat(
            constants.linked_list_node_key_prefix,
            t_pause_pu_cred,
          ),
          1,
        ),
      ),
      datum: InlineDatum(element),
      reference_script: None,
    },
  }
}

fn t_pause_tx(node: Input) -> Transaction {
  Transaction {
    ..t_tx(t_pause_datum(False), t_pause_datum(True), [t_pause_pu_cred]),
    reference_inputs: [node],
  }
}

fn t_pause_redeemer() -> GlobalStateSpendRedeemer {
  GlobalStateSpendRedeemer {
    global_state_output_index: 0,
    action: PauseTransfers {
      transfers_paused: True,
      power_user_node_ref_input_index: 0,
    },
  }
}

/// The positive control. Without it the two negatives below would also pass
/// if the branch were broken outright.
test pause_succeeds_for_a_can_pause_power_user_in_the_list() {
  run_spend(
    t_pause_datum(False),
    t_pause_redeemer(),
    t_pause_tx(t_pu_node_at(Script(t_pu_script_hash))),
  )
}

/// The GlobalState logic's withdrawal is in every pause transaction, and
/// `must_be_signed_by_credential` accepts a withdrawal as a signature: a
/// `can_pause` operator whose credential IS the installed logic hash would be
/// satisfied by anyone. Here the operator does not sign; only the logic's
/// withdrawal (added by `run_spend`) is present.
test pause_rejects_an_operator_that_is_the_global_state_logic() {
  let input_datum = GlobalStateDatum {
    ..t_pause_datum(False),
    global_state_script_credential_hash: t_pause_pu_cred,
  }
  !run_spend(
    input_datum,
    t_pause_redeemer(),
    Transaction {
      ..t_tx(
        input_datum,
        GlobalStateDatum { ..input_datum, transfers_paused: True },
        [],
      ),
      reference_inputs: [t_pu_node_at(Script(t_pu_script_hash))],
    },
  )
}

/// The same node, same NFT, same datum — parked at a SCRIPT address
/// that is not the power-users list. `expect ... == power_user_list_script_hash`
/// traps, hence `fail`.
test pause_fails_when_the_power_user_node_is_at_the_wrong_script() fail {
  run_spend(
    t_pause_datum(False),
    t_pause_redeemer(),
    t_pause_tx(t_pu_node_at(Script(t_gs_script_hash))),
  )
}

/// The reachable shape: the node NFT carried out of the list into a private
/// wallet, where element authentication would otherwise still accept whatever
/// role flags its holder writes. The `expect Script(..)` pattern match traps on
/// a `VerificationKey` credential.
test pause_fails_when_the_power_user_node_is_in_a_wallet() fail {
  run_spend(
    t_pause_datum(False),
    t_pause_redeemer(),
    t_pause_tx(
      t_pu_node_at(
        VerificationKey(
          #"0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e",
        ),
      ),
    ),
  )
}

// ── PauseTransfers — no_security_token_spent ─────────────────────────────

test pause_succeeds_when_security_token_absent_from_tx() {
  // Positive control paired with the two negatives below — same fixture as
  // `pause_succeeds_for_a_can_pause_power_user_in_the_list`.
  run_spend(
    t_pause_datum(False),
    t_pause_redeemer(),
    t_pause_tx(t_pu_node_at(Script(t_pu_script_hash))),
  )
}

test pause_rejects_when_an_input_carries_the_security_token() {
  !run_spend(
    t_pause_datum(False),
    t_pause_redeemer(),
    with_security_token_input(
      t_pause_tx(t_pu_node_at(Script(t_pu_script_hash))),
    ),
  )
}

test pause_rejects_when_the_security_token_is_minted_into_an_output() {
  !run_spend(
    t_pause_datum(False),
    t_pause_redeemer(),
    with_security_token_minted_into_an_output(
      t_pause_tx(t_pu_node_at(Script(t_pu_script_hash))),
    ),
  )
}

// ── PauseTransfers — value_preserved ────────────────────────────────────────
// `value_preserved` compares the input and continuing output without their
// lovelace: every non-ADA asset must be identical, and ADA is free in either
// direction. The two tests below pin both halves.

const t_foreign_policy: ByteArray =
  #"ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

/// Rebuild the continuing GlobalState output (index 0, what every redeemer
/// names) with a transformed value; everything else is untouched.
fn with_gs_output_value(tx: Transaction, f: fn(Value) -> Value) -> Transaction {
  expect [gs_out, ..rest] = tx.outputs
  Transaction {
    ..tx,
    outputs: [Output { ..gs_out, value: f(gs_out.value) }, ..rest],
  }
}

/// ADA top-up on the control UTxO is allowed (lovelace is not compared).
test pause_succeeds_when_the_continuing_output_is_topped_up_with_ada() {
  run_spend(
    t_pause_datum(False),
    t_pause_redeemer(),
    with_gs_output_value(
      t_pause_tx(t_pu_node_at(Script(t_pu_script_hash))),
      fn(v) { merge(v, from_lovelace(1_000_000)) },
    ),
  )
}

/// A foreign asset smuggled into the continuing output changes the non-ADA
/// asset set, which `value_preserved` requires to be identical — rejected as a
/// clean `False` (`value_preserved` is a `Bool` conjunct), hence `!run_spend`.
test pause_rejects_a_foreign_asset_added_to_the_continuing_output() {
  !run_spend(
    t_pause_datum(False),
    t_pause_redeemer(),
    with_gs_output_value(
      t_pause_tx(t_pu_node_at(Script(t_pu_script_hash))),
      fn(v) { merge(v, from_asset(t_foreign_policy, "X", 1)) },
    ),
  )
}

// ============================================================================
// Tests — the seven remaining spend branches: ModifySecurityInfo,
// AddTrustedEntity, RemoveTrustedEntity, UpdateTrustedEntity,
// SetRequiresSenderKyc, SetRequiresReceiverKyc, UpdateMemberRootHash
// ============================================================================
//
// None of these seven branches contains an `expect` inside its `and { .. }`
// block — every condition (signature, length, has_key, ..) is a plain Bool
// combined with `and`, so a violated precondition or a missing signature
// makes `run_spend` return False. It never traps. So unlike the
// `deactivated_input_rejects_*` / `pause_fails_when_*` tests above, none of
// the negatives below are `fail`-annotated.
//
// `deactivated_input_rejects_modify_security_info` (above) remains the only
// terminal-guard test touching one of these seven branches — it is not
// duplicated here.

/// 32-byte trusted-entity vkeys, chosen so their byte-wise ascending order is
/// obvious: 05 < 10 < 20 < 30 < 40.
const t_vkey_05: ByteArray =
  #"0505050505050505050505050505050505050505050505050505050505050505"

const t_vkey_20: ByteArray =
  #"2020202020202020202020202020202020202020202020202020202020202020"

const t_vkey_30: ByteArray =
  #"3030303030303030303030303030303030303030303030303030303030303030"

const t_vkey_40: ByteArray =
  #"4040404040404040404040404040404040404040404040404040404040404040"

/// Deliberately not 32 bytes.
const t_vkey_bad_length: ByteArray = #"aabb"

/// Trusted-entity fixture: two entries already sorted ascending, so tests can
/// exercise insertion, removal, renaming and duplicate/absence checks against
/// a non-trivial starting list.
fn t_tel_datum() -> GlobalStateDatum {
  GlobalStateDatum {
    ..t_datum(False, False),
    trusted_entity_vkeys: [
      Pair(t_vkey_10, builtin.i_data(1)),
      Pair(t_vkey_30, builtin.i_data(3)),
    ],
  }
}

// ── ModifySecurityInfo — admin-only; no shape or value precondition ────────

fn modify_security_info_redeemer(
  new_security_info: Data,
) -> GlobalStateSpendRedeemer {
  GlobalStateSpendRedeemer {
    global_state_output_index: 0,
    action: ModifySecurityInfo { new_security_info },
  }
}

test modify_security_info_succeeds_when_admin_signs() {
  let input_datum = t_datum(False, False)
  let new_info: Data = builtin.constr_data(0, [builtin.i_data(7)])
  let output_datum = GlobalStateDatum { ..input_datum, security_info: new_info }
  run_spend(
    input_datum,
    modify_security_info_redeemer(new_info),
    t_tx(input_datum, output_datum, [t_admin]),
  )
}

test modify_security_info_fails_without_admin_signature() {
  let input_datum = t_datum(False, False)
  let new_info: Data = builtin.constr_data(0, [builtin.i_data(7)])
  let output_datum = GlobalStateDatum { ..input_datum, security_info: new_info }
  !run_spend(
    input_datum,
    modify_security_info_redeemer(new_info),
    t_tx(input_datum, output_datum, []),
  )
}

test modify_security_info_cannot_smuggle_another_field_change() {
  let input_datum = t_datum(False, False)
  let new_info: Data = builtin.constr_data(0, [builtin.i_data(7)])
  let output_datum = GlobalStateDatum {
    ..input_datum,
    security_info: new_info,
    mintable_amount: input_datum.mintable_amount + 1_000_000,
  }
  !run_spend(
    input_datum,
    modify_security_info_redeemer(new_info),
    t_tx(input_datum, output_datum, [t_admin]),
  )
}

test modify_security_info_accepts_an_arbitrary_data_shape() {
  // `security_info` is opaque, unconstrained `Data` — an admin-signed update
  // to a plain integer (not even a Constr) is accepted exactly like a
  // Constr-shaped one; there is no on-chain shape check to violate.
  let input_datum = t_datum(False, False)
  let new_info: Data = builtin.i_data(42)
  let output_datum = GlobalStateDatum { ..input_datum, security_info: new_info }
  run_spend(
    input_datum,
    modify_security_info_redeemer(new_info),
    t_tx(input_datum, output_datum, [t_admin]),
  )
}

// ── ModifySecurityInfo — datum growth cap ───────────────────────────────────

test modify_security_info_succeeds_at_the_size_cap() {
  let input_datum = t_datum(False, False)
  let new_info = t_data_of_raw_length(t_security_info_len_at_cap)
  let output_datum = GlobalStateDatum { ..input_datum, security_info: new_info }
  run_spend(
    input_datum,
    modify_security_info_redeemer(new_info),
    t_tx(input_datum, output_datum, [t_admin]),
  )
}

test modify_security_info_rejects_one_byte_over_the_size_cap() {
  let input_datum = t_datum(False, False)
  let new_info = t_data_of_raw_length(t_security_info_len_over_cap)
  let output_datum = GlobalStateDatum { ..input_datum, security_info: new_info }
  !run_spend(
    input_datum,
    modify_security_info_redeemer(new_info),
    t_tx(input_datum, output_datum, [t_admin]),
  )
}

// ── AddTrustedEntity — 32-byte vkey, no duplicate, sorted insertion ────────

fn add_trusted_entity_redeemer(
  vkey: ByteArray,
  metadata: TrustedEntityMetadata,
) -> GlobalStateSpendRedeemer {
  GlobalStateSpendRedeemer {
    global_state_output_index: 0,
    action: AddTrustedEntity { vkey, metadata },
  }
}

test add_trusted_entity_succeeds_when_admin_signs() {
  let input_datum = t_tel_datum()
  let output_datum = GlobalStateDatum {
    ..input_datum,
    trusted_entity_vkeys: [
      Pair(t_vkey_10, builtin.i_data(1)),
      Pair(t_vkey_20, builtin.i_data(2)),
      Pair(t_vkey_30, builtin.i_data(3)),
    ],
  }
  run_spend(
    input_datum,
    add_trusted_entity_redeemer(t_vkey_20, builtin.i_data(2)),
    t_tx(input_datum, output_datum, [t_admin]),
  )
}

test add_trusted_entity_fails_without_admin_signature() {
  let input_datum = t_tel_datum()
  let output_datum = GlobalStateDatum {
    ..input_datum,
    trusted_entity_vkeys: [
      Pair(t_vkey_10, builtin.i_data(1)),
      Pair(t_vkey_20, builtin.i_data(2)),
      Pair(t_vkey_30, builtin.i_data(3)),
    ],
  }
  !run_spend(
    input_datum,
    add_trusted_entity_redeemer(t_vkey_20, builtin.i_data(2)),
    t_tx(input_datum, output_datum, []),
  )
}

test add_trusted_entity_fails_when_vkey_wrong_length() {
  // `t_vkey_bad_length` is 2 bytes, not 32 — `bytearray.length(vkey) == 32`
  // is the only assertion this violates: the output below is the exact
  // insertion the branch itself would compute, so equals_data would
  // otherwise pass.
  let input_datum = t_tel_datum()
  let updated_entities = pairs.insert_by_ascending_key(
    input_datum.trusted_entity_vkeys,
    t_vkey_bad_length,
    builtin.i_data(9),
    bytearray.compare,
  )
  let output_datum = GlobalStateDatum {
    ..input_datum,
    trusted_entity_vkeys: updated_entities,
  }
  !run_spend(
    input_datum,
    add_trusted_entity_redeemer(t_vkey_bad_length, builtin.i_data(9)),
    t_tx(input_datum, output_datum, [t_admin]),
  )
}

test add_trusted_entity_fails_when_vkey_already_present() {
  // t_vkey_10 is already in the fixture's list — `!has_key` is the only
  // assertion this violates. The output is what a naive (unguarded) insert
  // would produce: a second Pair keyed on the same vkey, which is exactly
  // the corruption this precondition exists to prevent.
  let input_datum = t_tel_datum()
  let updated_entities = pairs.insert_by_ascending_key(
    input_datum.trusted_entity_vkeys,
    t_vkey_10,
    builtin.i_data(99),
    bytearray.compare,
  )
  let output_datum = GlobalStateDatum {
    ..input_datum,
    trusted_entity_vkeys: updated_entities,
  }
  !run_spend(
    input_datum,
    add_trusted_entity_redeemer(t_vkey_10, builtin.i_data(99)),
    t_tx(input_datum, output_datum, [t_admin]),
  )
}

test add_trusted_entity_cannot_smuggle_another_field_change() {
  let input_datum = t_tel_datum()
  let output_datum = GlobalStateDatum {
    ..input_datum,
    trusted_entity_vkeys: [
      Pair(t_vkey_10, builtin.i_data(1)),
      Pair(t_vkey_20, builtin.i_data(2)),
      Pair(t_vkey_30, builtin.i_data(3)),
    ],
    mintable_amount: input_datum.mintable_amount + 1_000_000,
  }
  !run_spend(
    input_datum,
    add_trusted_entity_redeemer(t_vkey_20, builtin.i_data(2)),
    t_tx(input_datum, output_datum, [t_admin]),
  )
}

test add_trusted_entity_inserts_smaller_vkey_in_sorted_order() {
  // t_vkey_05 sorts BEFORE every existing entry. The expected output below
  // is written out explicitly in ascending order — not computed by calling
  // the same production helper the branch uses — so a broken sort insertion
  // in the validator itself would actually be caught here.
  let input_datum = t_tel_datum()
  let output_datum = GlobalStateDatum {
    ..input_datum,
    trusted_entity_vkeys: [
      Pair(t_vkey_05, builtin.i_data(0)),
      Pair(t_vkey_10, builtin.i_data(1)),
      Pair(t_vkey_30, builtin.i_data(3)),
    ],
  }
  run_spend(
    input_datum,
    add_trusted_entity_redeemer(t_vkey_05, builtin.i_data(0)),
    t_tx(input_datum, output_datum, [t_admin]),
  )
}

// ── AddTrustedEntity — datum growth caps ────────────────────────────────────

fn t_full_tel_datum(count: Int) -> GlobalStateDatum {
  GlobalStateDatum {
    ..t_datum(False, False),
    trusted_entity_vkeys: t_many_entities(count),
  }
}

test add_trusted_entity_succeeds_when_resulting_length_is_at_the_cap() {
  let input_datum = t_full_tel_datum(constants.max_trusted_entities - 1)
  let new_vkey = bytearray.from_int_big_endian(
    constants.max_trusted_entities,
    32,
  )
  let updated_entities = pairs.insert_by_ascending_key(
    input_datum.trusted_entity_vkeys,
    new_vkey,
    builtin.i_data(0),
    bytearray.compare,
  )
  let output_datum = GlobalStateDatum {
    ..input_datum,
    trusted_entity_vkeys: updated_entities,
  }
  run_spend(
    input_datum,
    add_trusted_entity_redeemer(new_vkey, builtin.i_data(0)),
    t_tx(input_datum, output_datum, [t_admin]),
  )
}

test add_trusted_entity_rejects_when_resulting_length_exceeds_the_cap() {
  let input_datum = t_full_tel_datum(constants.max_trusted_entities)
  let new_vkey = bytearray.from_int_big_endian(
    constants.max_trusted_entities + 1,
    32,
  )
  let updated_entities = pairs.insert_by_ascending_key(
    input_datum.trusted_entity_vkeys,
    new_vkey,
    builtin.i_data(0),
    bytearray.compare,
  )
  let output_datum = GlobalStateDatum {
    ..input_datum,
    trusted_entity_vkeys: updated_entities,
  }
  !run_spend(
    input_datum,
    add_trusted_entity_redeemer(new_vkey, builtin.i_data(0)),
    t_tx(input_datum, output_datum, [t_admin]),
  )
}

test add_trusted_entity_succeeds_when_metadata_is_at_the_size_cap() {
  let input_datum = t_tel_datum()
  let metadata = t_data_of_raw_length(t_metadata_len_at_cap)
  let updated_entities = pairs.insert_by_ascending_key(
    input_datum.trusted_entity_vkeys,
    t_vkey_20,
    metadata,
    bytearray.compare,
  )
  let output_datum = GlobalStateDatum {
    ..input_datum,
    trusted_entity_vkeys: updated_entities,
  }
  run_spend(
    input_datum,
    add_trusted_entity_redeemer(t_vkey_20, metadata),
    t_tx(input_datum, output_datum, [t_admin]),
  )
}

test add_trusted_entity_rejects_metadata_one_byte_over_the_size_cap() {
  let input_datum = t_tel_datum()
  let metadata = t_data_of_raw_length(t_metadata_len_over_cap)
  let updated_entities = pairs.insert_by_ascending_key(
    input_datum.trusted_entity_vkeys,
    t_vkey_20,
    metadata,
    bytearray.compare,
  )
  let output_datum = GlobalStateDatum {
    ..input_datum,
    trusted_entity_vkeys: updated_entities,
  }
  !run_spend(
    input_datum,
    add_trusted_entity_redeemer(t_vkey_20, metadata),
    t_tx(input_datum, output_datum, [t_admin]),
  )
}

// ── RemoveTrustedEntity — vkey must be present ──────────────────────────────

fn remove_trusted_entity_redeemer(vkey: ByteArray) -> GlobalStateSpendRedeemer {
  GlobalStateSpendRedeemer {
    global_state_output_index: 0,
    action: RemoveTrustedEntity { vkey },
  }
}

test remove_trusted_entity_succeeds_when_admin_signs() {
  let input_datum = t_tel_datum()
  let output_datum = GlobalStateDatum {
    ..input_datum,
    trusted_entity_vkeys: [Pair(t_vkey_30, builtin.i_data(3))],
  }
  run_spend(
    input_datum,
    remove_trusted_entity_redeemer(t_vkey_10),
    t_tx(input_datum, output_datum, [t_admin]),
  )
}

test remove_trusted_entity_fails_without_admin_signature() {
  let input_datum = t_tel_datum()
  let output_datum = GlobalStateDatum {
    ..input_datum,
    trusted_entity_vkeys: [Pair(t_vkey_30, builtin.i_data(3))],
  }
  !run_spend(
    input_datum,
    remove_trusted_entity_redeemer(t_vkey_10),
    t_tx(input_datum, output_datum, []),
  )
}

test remove_trusted_entity_fails_when_vkey_absent() {
  // t_vkey_20 is not present in the fixture's list at all — `has_key` is the
  // only assertion this violates; the output reproduces the input list
  // unchanged, which is what the branch's own `list.filter` would compute
  // for an absent key (a no-op), so nothing else here is what rejects it.
  let input_datum = t_tel_datum()
  let output_datum = GlobalStateDatum {
    ..input_datum,
    trusted_entity_vkeys: input_datum.trusted_entity_vkeys,
  }
  !run_spend(
    input_datum,
    remove_trusted_entity_redeemer(t_vkey_20),
    t_tx(input_datum, output_datum, [t_admin]),
  )
}

test remove_trusted_entity_cannot_smuggle_another_field_change() {
  let input_datum = t_tel_datum()
  let output_datum = GlobalStateDatum {
    ..input_datum,
    trusted_entity_vkeys: [Pair(t_vkey_30, builtin.i_data(3))],
    mintable_amount: input_datum.mintable_amount + 1_000_000,
  }
  !run_spend(
    input_datum,
    remove_trusted_entity_redeemer(t_vkey_10),
    t_tx(input_datum, output_datum, [t_admin]),
  )
}

// ── RemoveTrustedEntity — no_security_token_spent ────────────────────────

test remove_trusted_entity_succeeds_when_security_token_absent_from_tx() {
  let input_datum = t_tel_datum()
  let output_datum = GlobalStateDatum {
    ..input_datum,
    trusted_entity_vkeys: [Pair(t_vkey_30, builtin.i_data(3))],
  }
  run_spend(
    input_datum,
    remove_trusted_entity_redeemer(t_vkey_10),
    t_tx(input_datum, output_datum, [t_admin]),
  )
}

test remove_trusted_entity_rejects_when_an_input_carries_the_security_token() {
  let input_datum = t_tel_datum()
  let output_datum = GlobalStateDatum {
    ..input_datum,
    trusted_entity_vkeys: [Pair(t_vkey_30, builtin.i_data(3))],
  }
  !run_spend(
    input_datum,
    remove_trusted_entity_redeemer(t_vkey_10),
    with_security_token_input(t_tx(input_datum, output_datum, [t_admin])),
  )
}

test remove_trusted_entity_rejects_when_the_security_token_is_minted_into_an_output() {
  let input_datum = t_tel_datum()
  let output_datum = GlobalStateDatum {
    ..input_datum,
    trusted_entity_vkeys: [Pair(t_vkey_30, builtin.i_data(3))],
  }
  !run_spend(
    input_datum,
    remove_trusted_entity_redeemer(t_vkey_10),
    with_security_token_minted_into_an_output(
      t_tx(input_datum, output_datum, [t_admin]),
    ),
  )
}

// ── UpdateTrustedEntity — old present, new free (unless renaming to self), new 32 bytes ──

fn update_trusted_entity_redeemer(
  old_vkey: ByteArray,
  new_vkey: ByteArray,
  new_metadata: TrustedEntityMetadata,
) -> GlobalStateSpendRedeemer {
  GlobalStateSpendRedeemer {
    global_state_output_index: 0,
    action: UpdateTrustedEntity { old_vkey, new_vkey, new_metadata },
  }
}

test update_trusted_entity_succeeds_when_admin_signs() {
  // Rename t_vkey_10 -> t_vkey_20, with new metadata.
  let input_datum = t_tel_datum()
  let output_datum = GlobalStateDatum {
    ..input_datum,
    trusted_entity_vkeys: [
      Pair(t_vkey_20, builtin.i_data(20)),
      Pair(t_vkey_30, builtin.i_data(3)),
    ],
  }
  run_spend(
    input_datum,
    update_trusted_entity_redeemer(t_vkey_10, t_vkey_20, builtin.i_data(20)),
    t_tx(input_datum, output_datum, [t_admin]),
  )
}

test update_trusted_entity_fails_without_admin_signature() {
  let input_datum = t_tel_datum()
  let output_datum = GlobalStateDatum {
    ..input_datum,
    trusted_entity_vkeys: [
      Pair(t_vkey_20, builtin.i_data(20)),
      Pair(t_vkey_30, builtin.i_data(3)),
    ],
  }
  !run_spend(
    input_datum,
    update_trusted_entity_redeemer(t_vkey_10, t_vkey_20, builtin.i_data(20)),
    t_tx(input_datum, output_datum, []),
  )
}

test update_trusted_entity_fails_when_old_vkey_absent() {
  // t_vkey_40 is not present — `old_exists` is the only assertion this
  // violates. new_clash_ok, the length check and the signature all hold, and
  // the output is exactly what `without_old` + `insert_by_ascending_key`
  // compute (filtering an absent key is a no-op), so equals_data would
  // otherwise also pass.
  let input_datum = t_tel_datum()
  let output_datum = GlobalStateDatum {
    ..input_datum,
    trusted_entity_vkeys: [
      Pair(t_vkey_10, builtin.i_data(1)),
      Pair(t_vkey_20, builtin.i_data(20)),
      Pair(t_vkey_30, builtin.i_data(3)),
    ],
  }
  !run_spend(
    input_datum,
    update_trusted_entity_redeemer(t_vkey_40, t_vkey_20, builtin.i_data(20)),
    t_tx(input_datum, output_datum, [t_admin]),
  )
}

test update_trusted_entity_fails_when_new_vkey_collides_with_another_entry() {
  // Renaming t_vkey_10 -> t_vkey_30 collides with the OTHER existing entry —
  // `new_clash_ok` is the only assertion this violates. The output is what
  // `without_old` (removes t_vkey_10) followed by the branch's own
  // `insert_by_ascending_key(.., t_vkey_30, ..)` actually computes: a
  // duplicate-keyed list, which is exactly the corruption this precondition
  // exists to prevent.
  let input_datum = t_tel_datum()
  let without_old = list.filter(
    input_datum.trusted_entity_vkeys,
    fn(p) { p.1st != t_vkey_10 },
  )
  let updated_entities = pairs.insert_by_ascending_key(
    without_old,
    t_vkey_30,
    builtin.i_data(30),
    bytearray.compare,
  )
  let output_datum = GlobalStateDatum {
    ..input_datum,
    trusted_entity_vkeys: updated_entities,
  }
  !run_spend(
    input_datum,
    update_trusted_entity_redeemer(t_vkey_10, t_vkey_30, builtin.i_data(30)),
    t_tx(input_datum, output_datum, [t_admin]),
  )
}

test update_trusted_entity_fails_when_new_vkey_wrong_length() {
  // t_vkey_bad_length is 2 bytes — `bytearray.length(new_vkey) == 32` is the
  // only assertion this violates. old_exists and new_clash_ok both hold
  // (bad_length is absent from the list), and the output is exactly what
  // the branch's own without_old + insert_by_ascending_key compute.
  let input_datum = t_tel_datum()
  let without_old = list.filter(
    input_datum.trusted_entity_vkeys,
    fn(p) { p.1st != t_vkey_10 },
  )
  let updated_entities = pairs.insert_by_ascending_key(
    without_old,
    t_vkey_bad_length,
    builtin.i_data(9),
    bytearray.compare,
  )
  let output_datum = GlobalStateDatum {
    ..input_datum,
    trusted_entity_vkeys: updated_entities,
  }
  !run_spend(
    input_datum,
    update_trusted_entity_redeemer(
      t_vkey_10,
      t_vkey_bad_length,
      builtin.i_data(9),
    ),
    t_tx(input_datum, output_datum, [t_admin]),
  )
}

test update_trusted_entity_cannot_smuggle_another_field_change() {
  let input_datum = t_tel_datum()
  let output_datum = GlobalStateDatum {
    ..input_datum,
    trusted_entity_vkeys: [
      Pair(t_vkey_20, builtin.i_data(20)),
      Pair(t_vkey_30, builtin.i_data(3)),
    ],
    mintable_amount: input_datum.mintable_amount + 1_000_000,
  }
  !run_spend(
    input_datum,
    update_trusted_entity_redeemer(t_vkey_10, t_vkey_20, builtin.i_data(20)),
    t_tx(input_datum, output_datum, [t_admin]),
  )
}

// ── UpdateTrustedEntity — datum growth cap ──────────────────────────────────

test update_trusted_entity_succeeds_when_new_metadata_is_at_the_size_cap() {
  let input_datum = t_tel_datum()
  let new_metadata = t_data_of_raw_length(t_metadata_len_at_cap)
  let output_datum = GlobalStateDatum {
    ..input_datum,
    trusted_entity_vkeys: [
      Pair(t_vkey_20, new_metadata),
      Pair(t_vkey_30, builtin.i_data(3)),
    ],
  }
  run_spend(
    input_datum,
    update_trusted_entity_redeemer(t_vkey_10, t_vkey_20, new_metadata),
    t_tx(input_datum, output_datum, [t_admin]),
  )
}

test update_trusted_entity_rejects_new_metadata_one_byte_over_the_size_cap() {
  let input_datum = t_tel_datum()
  let new_metadata = t_data_of_raw_length(t_metadata_len_over_cap)
  let output_datum = GlobalStateDatum {
    ..input_datum,
    trusted_entity_vkeys: [
      Pair(t_vkey_20, new_metadata),
      Pair(t_vkey_30, builtin.i_data(3)),
    ],
  }
  !run_spend(
    input_datum,
    update_trusted_entity_redeemer(t_vkey_10, t_vkey_20, new_metadata),
    t_tx(input_datum, output_datum, [t_admin]),
  )
}

// ── SetRequiresSenderKyc — admin-only; guards against writing the sibling flag ──

fn set_requires_sender_kyc_redeemer(enabled: Bool) -> GlobalStateSpendRedeemer {
  GlobalStateSpendRedeemer {
    global_state_output_index: 0,
    action: SetRequiresSenderKyc { enabled },
  }
}

test set_requires_sender_kyc_succeeds_when_admin_signs() {
  let input_datum = t_datum(False, False)
  let output_datum = GlobalStateDatum {
    ..input_datum,
    requires_sender_kyc: True,
  }
  run_spend(
    input_datum,
    set_requires_sender_kyc_redeemer(True),
    t_tx(input_datum, output_datum, [t_admin]),
  )
}

test set_requires_sender_kyc_fails_without_admin_signature() {
  let input_datum = t_datum(False, False)
  let output_datum = GlobalStateDatum {
    ..input_datum,
    requires_sender_kyc: True,
  }
  !run_spend(
    input_datum,
    set_requires_sender_kyc_redeemer(True),
    t_tx(input_datum, output_datum, []),
  )
}

test set_requires_sender_kyc_rejects_flipping_the_other_flag() {
  // Index-transposition guard: the redeemer asks to set the SENDER flag, but
  // the output instead flips requires_receiver_kyc and leaves
  // requires_sender_kyc at its input value — the whole-datum equality must
  // catch a write landing on the wrong field index.
  let input_datum = t_datum(False, False)
  let output_datum = GlobalStateDatum {
    ..input_datum,
    requires_receiver_kyc: True,
  }
  !run_spend(
    input_datum,
    set_requires_sender_kyc_redeemer(True),
    t_tx(input_datum, output_datum, [t_admin]),
  )
}

test set_requires_sender_kyc_cannot_smuggle_another_field_change() {
  let input_datum = t_datum(False, False)
  let output_datum = GlobalStateDatum {
    ..input_datum,
    requires_sender_kyc: True,
    mintable_amount: input_datum.mintable_amount + 1_000_000,
  }
  !run_spend(
    input_datum,
    set_requires_sender_kyc_redeemer(True),
    t_tx(input_datum, output_datum, [t_admin]),
  )
}

// ── SetRequiresSenderKyc — no_security_token_spent ───────────────────────

test set_requires_sender_kyc_succeeds_when_security_token_absent_from_tx() {
  let input_datum = t_datum(False, False)
  let output_datum = GlobalStateDatum {
    ..input_datum,
    requires_sender_kyc: True,
  }
  run_spend(
    input_datum,
    set_requires_sender_kyc_redeemer(True),
    t_tx(input_datum, output_datum, [t_admin]),
  )
}

test set_requires_sender_kyc_rejects_when_an_input_carries_the_security_token() {
  let input_datum = t_datum(False, False)
  let output_datum = GlobalStateDatum {
    ..input_datum,
    requires_sender_kyc: True,
  }
  !run_spend(
    input_datum,
    set_requires_sender_kyc_redeemer(True),
    with_security_token_input(t_tx(input_datum, output_datum, [t_admin])),
  )
}

test set_requires_sender_kyc_rejects_when_the_security_token_is_minted_into_an_output() {
  let input_datum = t_datum(False, False)
  let output_datum = GlobalStateDatum {
    ..input_datum,
    requires_sender_kyc: True,
  }
  !run_spend(
    input_datum,
    set_requires_sender_kyc_redeemer(True),
    with_security_token_minted_into_an_output(
      t_tx(input_datum, output_datum, [t_admin]),
    ),
  )
}

// ── SetRequiresReceiverKyc — admin-only; guards against writing the sibling flag ──

fn set_requires_receiver_kyc_redeemer(enabled: Bool) -> GlobalStateSpendRedeemer {
  GlobalStateSpendRedeemer {
    global_state_output_index: 0,
    action: SetRequiresReceiverKyc { enabled },
  }
}

test set_requires_receiver_kyc_succeeds_when_admin_signs() {
  let input_datum = t_datum(False, False)
  let output_datum = GlobalStateDatum {
    ..input_datum,
    requires_receiver_kyc: True,
  }
  run_spend(
    input_datum,
    set_requires_receiver_kyc_redeemer(True),
    t_tx(input_datum, output_datum, [t_admin]),
  )
}

test set_requires_receiver_kyc_fails_without_admin_signature() {
  let input_datum = t_datum(False, False)
  let output_datum = GlobalStateDatum {
    ..input_datum,
    requires_receiver_kyc: True,
  }
  !run_spend(
    input_datum,
    set_requires_receiver_kyc_redeemer(True),
    t_tx(input_datum, output_datum, []),
  )
}

test set_requires_receiver_kyc_rejects_flipping_the_other_flag() {
  // Same transposition guard, other direction: the redeemer asks to set the
  // RECEIVER flag, but the output instead flips requires_sender_kyc.
  let input_datum = t_datum(False, False)
  let output_datum = GlobalStateDatum {
    ..input_datum,
    requires_sender_kyc: True,
  }
  !run_spend(
    input_datum,
    set_requires_receiver_kyc_redeemer(True),
    t_tx(input_datum, output_datum, [t_admin]),
  )
}

test set_requires_receiver_kyc_cannot_smuggle_another_field_change() {
  let input_datum = t_datum(False, False)
  let output_datum = GlobalStateDatum {
    ..input_datum,
    requires_receiver_kyc: True,
    mintable_amount: input_datum.mintable_amount + 1_000_000,
  }
  !run_spend(
    input_datum,
    set_requires_receiver_kyc_redeemer(True),
    t_tx(input_datum, output_datum, [t_admin]),
  )
}

// ── UpdateMemberRootHash — new root must be empty or exactly 32 bytes ──────

fn update_member_root_hash_redeemer(
  new_member_root_hash: ByteArray,
) -> GlobalStateSpendRedeemer {
  GlobalStateSpendRedeemer {
    global_state_output_index: 0,
    action: UpdateMemberRootHash { new_member_root_hash },
  }
}

test update_member_root_hash_succeeds_with_32_byte_root_when_admin_signs() {
  let input_datum = t_datum(False, False)
  let output_datum = GlobalStateDatum {
    ..input_datum,
    member_root_hash: t_root32,
  }
  run_spend(
    input_datum,
    update_member_root_hash_redeemer(t_root32),
    t_tx(input_datum, output_datum, [t_admin]),
  )
}

test update_member_root_hash_fails_without_admin_signature() {
  let input_datum = t_datum(False, False)
  let output_datum = GlobalStateDatum {
    ..input_datum,
    member_root_hash: t_root32,
  }
  !run_spend(
    input_datum,
    update_member_root_hash_redeemer(t_root32),
    t_tx(input_datum, output_datum, []),
  )
}

test update_member_root_hash_fails_when_length_invalid() {
  // 2 bytes — neither empty nor 32 — is the only assertion this violates;
  // mirrors sanitise_rejects_bad_root_hash_length but exercised through the
  // spend branch rather than genesis sanitisation.
  let input_datum = t_datum(False, False)
  let bad_root = #"aabb"
  let output_datum = GlobalStateDatum {
    ..input_datum,
    member_root_hash: bad_root,
  }
  !run_spend(
    input_datum,
    update_member_root_hash_redeemer(bad_root),
    t_tx(input_datum, output_datum, [t_admin]),
  )
}

test update_member_root_hash_cannot_smuggle_another_field_change() {
  let input_datum = t_datum(False, False)
  let output_datum = GlobalStateDatum {
    ..input_datum,
    member_root_hash: t_root32,
    mintable_amount: input_datum.mintable_amount + 1_000_000,
  }
  !run_spend(
    input_datum,
    update_member_root_hash_redeemer(t_root32),
    t_tx(input_datum, output_datum, [t_admin]),
  )
}

test update_member_root_hash_accepts_clearing_back_to_empty() {
  // The other valid length, 0 bytes (no membership tree yet), is accepted
  // just like 32 — the positive control that gives the wrong-length negative
  // above its meaning: both endpoints of the "empty or 32" precondition are
  // exercised, not just the one that happens to be non-empty.
  let input_datum = GlobalStateDatum {
    ..t_datum(False, False),
    member_root_hash: t_root32,
  }
  let output_datum = GlobalStateDatum { ..input_datum, member_root_hash: #"" }
  run_spend(
    input_datum,
    update_member_root_hash_redeemer(#""),
    t_tx(input_datum, output_datum, [t_admin]),
  )
}

// ── UpdateMemberRootHash — no_security_token_spent ───────────────────────

test update_member_root_hash_succeeds_when_security_token_absent_from_tx() {
  let input_datum = t_datum(False, False)
  let output_datum = GlobalStateDatum {
    ..input_datum,
    member_root_hash: t_root32,
  }
  run_spend(
    input_datum,
    update_member_root_hash_redeemer(t_root32),
    t_tx(input_datum, output_datum, [t_admin]),
  )
}

test update_member_root_hash_rejects_when_an_input_carries_the_security_token() {
  let input_datum = t_datum(False, False)
  let output_datum = GlobalStateDatum {
    ..input_datum,
    member_root_hash: t_root32,
  }
  !run_spend(
    input_datum,
    update_member_root_hash_redeemer(t_root32),
    with_security_token_input(t_tx(input_datum, output_datum, [t_admin])),
  )
}

test update_member_root_hash_rejects_when_the_security_token_is_minted_into_an_output() {
  let input_datum = t_datum(False, False)
  let output_datum = GlobalStateDatum {
    ..input_datum,
    member_root_hash: t_root32,
  }
  !run_spend(
    input_datum,
    update_member_root_hash_redeemer(t_root32),
    with_security_token_minted_into_an_output(
      t_tx(input_datum, output_datum, [t_admin]),
    ),
  )
}

// ── SetMintableAmount — admin-only, bounded, closed by LockUpgrades ──────────
//
// Every negative below is a one-change copy of a passing positive: the output
// datum always equals the input with `mintable_amount` set to the redeemer's
// value, so only the guard under test can be what rejects it.

fn set_mintable_amount_redeemer(
  new_mintable_amount: Int,
) -> GlobalStateSpendRedeemer {
  GlobalStateSpendRedeemer {
    global_state_output_index: 0,
    action: SetMintableAmount { new_mintable_amount },
  }
}

/// Input `input_datum`, output identical except `mintable_amount = value`,
/// redeemer naming the same `value`.
fn t_set_mintable_tx(
  input_datum: GlobalStateDatum,
  value: Int,
  signatories: List<ByteArray>,
) -> Transaction {
  t_tx(
    input_datum,
    GlobalStateDatum { ..input_datum, mintable_amount: value },
    signatories,
  )
}

test set_mintable_amount_succeeds_when_admin_signs_raise() {
  let input_datum = t_datum(False, False)
  let value = input_datum.mintable_amount + 5_000_000
  run_spend(
    input_datum,
    set_mintable_amount_redeemer(value),
    t_set_mintable_tx(input_datum, value, [t_admin]),
  )
}

test set_mintable_amount_succeeds_when_admin_signs_lower() {
  let input_datum = t_datum(False, False)
  let value = input_datum.mintable_amount - 1
  run_spend(
    input_datum,
    set_mintable_amount_redeemer(value),
    t_set_mintable_tx(input_datum, value, [t_admin]),
  )
}

test set_mintable_amount_succeeds_to_zero() {
  let input_datum = t_datum(False, False)
  run_spend(
    input_datum,
    set_mintable_amount_redeemer(0),
    t_set_mintable_tx(input_datum, 0, [t_admin]),
  )
}

test set_mintable_amount_rejects_negative() {
  let input_datum = t_datum(False, False)
  !run_spend(
    input_datum,
    set_mintable_amount_redeemer(-1),
    t_set_mintable_tx(input_datum, -1, [t_admin]),
  )
}

test set_mintable_amount_fails_without_admin_signature() {
  let input_datum = t_datum(False, False)
  !run_spend(
    input_datum,
    set_mintable_amount_redeemer(42),
    t_set_mintable_tx(input_datum, 42, []),
  )
}

test set_mintable_amount_fails_with_non_admin_signature() {
  let input_datum = t_datum(False, False)
  !run_spend(
    input_datum,
    set_mintable_amount_redeemer(42),
    t_set_mintable_tx(input_datum, 42, [t_new_admin]),
  )
}

// Positive control for the locked negative: identical except the lock.
test set_mintable_amount_succeeds_when_upgrades_unlocked() {
  let input_datum = GlobalStateDatum {
    ..t_datum_locked(),
    upgrades_locked: False,
  }
  run_spend(
    input_datum,
    set_mintable_amount_redeemer(42),
    t_set_mintable_tx(input_datum, 42, [t_admin]),
  )
}

test set_mintable_amount_fails_once_upgrades_are_locked() {
  // LockUpgrades makes the cap final, like the mint/transfer rules.
  let input_datum = t_datum_locked()
  !run_spend(
    input_datum,
    set_mintable_amount_redeemer(42),
    t_set_mintable_tx(input_datum, 42, [t_admin]),
  )
}

test set_mintable_amount_output_must_match_redeemer() {
  let input_datum = t_datum(False, False)
  !run_spend(
    input_datum,
    set_mintable_amount_redeemer(42),
    t_set_mintable_tx(input_datum, 43, [t_admin]),
  )
}

test set_mintable_amount_cannot_smuggle_another_field_change() {
  let input_datum = t_datum(False, False)
  let output_datum = GlobalStateDatum {
    ..input_datum,
    mintable_amount: 42,
    transfers_paused: True,
  }
  !run_spend(
    input_datum,
    set_mintable_amount_redeemer(42),
    t_tx(input_datum, output_datum, [t_admin]),
  )
}

test set_mintable_amount_succeeds_when_security_token_absent_from_tx() {
  // Positive control paired with the three security-token negatives below.
  let input_datum = t_datum(False, False)
  run_spend(
    input_datum,
    set_mintable_amount_redeemer(42),
    t_set_mintable_tx(input_datum, 42, [t_admin]),
  )
}

test set_mintable_amount_rejects_concurrent_security_mint() {
  // Load-bearing here: without it a mint could ride along on a cap write
  // without being decremented from the cap.
  let input_datum = t_datum(False, False)
  !run_spend(
    input_datum,
    set_mintable_amount_redeemer(42),
    with_security_token_minted_into_an_output(
      t_set_mintable_tx(input_datum, 42, [t_admin]),
    ),
  )
}

test set_mintable_amount_rejects_concurrent_security_burn() {
  // Mint field only (no token input), so `no_concurrent_security_mint` is the
  // sole guard that can reject it.
  let input_datum = t_datum(False, False)
  let tx = t_set_mintable_tx(input_datum, 42, [t_admin])
  !run_spend(
    input_datum,
    set_mintable_amount_redeemer(42),
    Transaction { ..tx, mint: from_asset(t_issuance_policy, t_sec_name, -1) },
  )
}

test set_mintable_amount_rejects_security_token_spent() {
  let input_datum = t_datum(False, False)
  !run_spend(
    input_datum,
    set_mintable_amount_redeemer(42),
    with_security_token_input(t_set_mintable_tx(input_datum, 42, [t_admin])),
  )
}

test set_mintable_amount_rejects_a_foreign_asset_added_to_the_continuing_output() {
  let input_datum = t_datum(False, False)
  !run_spend(
    input_datum,
    set_mintable_amount_redeemer(42),
    with_gs_output_value(
      t_set_mintable_tx(input_datum, 42, [t_admin]),
      fn(v) { merge(v, from_asset(t_foreign_policy, "X", 1)) },
    ),
  )
}

test set_mintable_amount_rejects_changed_output_address() {
  let input_datum = t_datum(False, False)
  let tx = t_set_mintable_tx(input_datum, 42, [t_admin])
  expect [gs_out, ..rest] = tx.outputs
  let moved = Output {
    ..gs_out,
    address: Address {
      payment_credential: Script(t_new_minting_script),
      stake_credential: None,
    },
  }
  !run_spend(
    input_datum,
    set_mintable_amount_redeemer(42),
    Transaction { ..tx, outputs: [moved, ..rest] },
  )
}

test set_mintable_amount_rejects_reference_script_on_output() {
  let input_datum = t_datum(False, False)
  let output_datum = GlobalStateDatum { ..input_datum, mintable_amount: 42 }
  !run_spend(
    input_datum,
    set_mintable_amount_redeemer(42),
    Transaction {
      ..t_tx(input_datum, output_datum, [t_admin]),
      outputs: [t_output_with_reference_script(output_datum)],
    },
  )
}

test deactivated_input_rejects_set_mintable_amount() fail {
  // Terminal `expect !deactivated` traps before dispatch.
  let input_datum = t_datum(True, True)
  run_spend(
    input_datum,
    set_mintable_amount_redeemer(42),
    t_set_mintable_tx(input_datum, 42, [t_admin]),
  )
}

// ── Burns after SetMintableAmount — headroom semantics ───────────────────────
//
// The GlobalState validator never sees circulating supply, only headroom: a
// MintSecurity spend writes `mintable_amount - minted`, and a burn mints a
// NEGATIVE quantity. So a cap of 0, or one set below what is already in
// circulation (indistinguishable on chain), never blocks a burn — and every
// burn hands its quantity back as headroom that can be minted again.

test burn_succeeds_when_mintable_amount_is_zero() {
  let input_datum = GlobalStateDatum {
    ..t_datum(False, False),
    mintable_amount: 0,
  }
  let output_datum = GlobalStateDatum { ..input_datum, mintable_amount: 100 }
  run_spend(
    input_datum,
    mintsecurity_redeemer(),
    t_mintsecurity_tx(input_datum, output_datum, -100, [t_admin]),
  )
}

test mint_rejected_when_mintable_amount_is_zero() {
  let input_datum = GlobalStateDatum {
    ..t_datum(False, False),
    mintable_amount: 0,
  }
  let output_datum = GlobalStateDatum { ..input_datum, mintable_amount: -1 }
  !run_spend(
    input_datum,
    mintsecurity_redeemer(),
    t_mintsecurity_tx(input_datum, output_datum, 1, [t_admin]),
  )
}

// After a burn of 100 at a zero cap, exactly the burned 100 may be re-minted…
test mint_up_to_burned_headroom_succeeds_after_zero_cap() {
  let input_datum = GlobalStateDatum {
    ..t_datum(False, False),
    mintable_amount: 100,
  }
  let output_datum = GlobalStateDatum { ..input_datum, mintable_amount: 0 }
  run_spend(
    input_datum,
    mintsecurity_redeemer(),
    t_mintsecurity_tx(input_datum, output_datum, 100, [t_admin]),
  )
}

// …and not one unit more.
test mint_beyond_burned_headroom_rejected_after_zero_cap() {
  let input_datum = GlobalStateDatum {
    ..t_datum(False, False),
    mintable_amount: 100,
  }
  let output_datum = GlobalStateDatum { ..input_datum, mintable_amount: -1 }
  !run_spend(
    input_datum,
    mintsecurity_redeemer(),
    t_mintsecurity_tx(input_datum, output_datum, 101, [t_admin]),
  )
}

// ── global_state_logic — installed-logic, admin and credential guards ────────

fn lock_tx() -> Transaction {
  let tx = t_tx(
    t_datum(False, False),
    GlobalStateDatum { ..t_datum(False, False), upgrades_locked: True },
    [t_admin],
  )
  tx
}

test logic_runs_an_action_when_it_is_field_0() {
  run_logic(t_gs_logic, lock_upgrades_redeemer(), lock_tx())
}

// A logic that is not (or no longer) field 0 never acts on GlobalState.
test logic_fails_when_it_is_not_field_0() fail {
  run_logic(t_new_gs_logic, lock_upgrades_redeemer(), lock_tx())
}

test logic_fails_when_admin_is_its_own_hash() fail {
  let input_datum = GlobalStateDatum {
    ..t_datum(False, False),
    admin_credential_hash: t_gs_logic,
  }
  run_spend(
    input_datum,
    lock_upgrades_redeemer(),
    t_tx(
      input_datum,
      GlobalStateDatum { ..input_datum, upgrades_locked: True },
      [],
    ),
  )
}

// The logic reads only a SPENT GlobalState: one that is merely referenced
// is not there for it to find.
test logic_fails_when_global_state_is_only_referenced() fail {
  let tx = lock_tx()
  run_logic(
    t_gs_logic,
    lock_upgrades_redeemer(),
    Transaction { ..tx, inputs: [], reference_inputs: tx.inputs },
  )
}

test logic_accepts_register_credential() {
  v_logic.global_state_logic.publish(
    t_sec_name,
    t_issuance_policy,
    t_gs_policy,
    t_pu_script_hash,
    builtin.constr_data(0, []),
    RegisterCredential { credential: Script(t_gs_logic), deposit: Never },
    lock_tx(),
  )
}

test logic_rejects_unregister_credential() {
  !v_logic.global_state_logic.publish(
    t_sec_name,
    t_issuance_policy,
    t_gs_policy,
    t_pu_script_hash,
    builtin.constr_data(0, []),
    UnregisterCredential { credential: Script(t_gs_logic), refund: Never },
    lock_tx(),
  )
}

test rotate_minting_script_to_the_gs_logic_fails() {
  let input_datum = t_datum(False, False)
  !run_spend(
    input_datum,
    rotate_minting_script_redeemer(t_gs_logic),
    t_tx(
      input_datum,
      GlobalStateDatum {
        ..input_datum,
        minting_script_credential_hash: t_gs_logic,
      },
      [t_admin],
    ),
  )
}

test rotate_admin_to_the_gs_logic_fails() {
  let input_datum = t_datum(False, False)
  !run_spend(
    input_datum,
    rotate_admin_redeemer(t_gs_logic),
    t_tx(
      input_datum,
      GlobalStateDatum { ..input_datum, admin_credential_hash: t_gs_logic },
      [t_admin, t_gs_logic],
    ),
  )
}

// ── RotateGlobalStateScript — replace the logic, both sides ──────────────────
//
// `t_rotate_tx` builds a rotation that passes on both sides: admin signs, the
// output is the input with field 0 := `t_new_gs_logic`, and both logics'
// withdrawals are present. Every negative is a one-change copy.

fn rotate_gs_redeemer(new: ByteArray) -> GlobalStateSpendRedeemer {
  GlobalStateSpendRedeemer {
    global_state_output_index: 0,
    action: RotateGlobalStateScript { new_global_state_script_hash: new },
  }
}

fn both_withdrawals() -> Pairs<Credential, Int> {
  [Pair(Script(t_gs_logic), 0), Pair(Script(t_new_gs_logic), 0)]
}

fn t_rotate_tx_from(
  input_datum: GlobalStateDatum,
  output_datum: GlobalStateDatum,
  signatories: List<ByteArray>,
) -> Transaction {
  Transaction {
    ..t_tx(input_datum, output_datum, signatories),
    withdrawals: both_withdrawals(),
  }
}

fn t_rotate_tx(output_datum: GlobalStateDatum) -> Transaction {
  t_rotate_tx_from(t_datum(False, False), output_datum, [t_admin])
}

fn t_rotated_datum() -> GlobalStateDatum {
  rotated(t_datum(False, False), t_new_gs_logic)
}

fn with_raw_output(tx: Transaction, raw: Data) -> Transaction {
  Transaction {
    ..tx,
    outputs: [
      Output { ..t_output(t_datum(False, False)), datum: InlineDatum(raw) },
    ],
  }
}

fn outgoing(new: ByteArray, tx: Transaction) -> Bool {
  run_logic(t_gs_logic, rotate_gs_redeemer(new), tx)
}

fn incoming(tx: Transaction) -> Bool {
  run_logic(t_new_gs_logic, rotate_gs_redeemer(t_new_gs_logic), tx)
}

test rotate_gs_logic_succeeds_when_admin_signs() {
  let tx = t_rotate_tx(t_rotated_datum())
  let input_data: Data = t_datum(False, False)
  and {
    v_proxy.global_state_proxy.spend(
      Some(input_data),
      builtin.constr_data(0, []),
      t_out_ref(0),
      tx,
    ),
    outgoing(t_new_gs_logic, tx),
    incoming(tx),
  }
}

test rotate_gs_logic_fails_without_admin_signature() {
  !outgoing(
    t_new_gs_logic,
    t_rotate_tx_from(t_datum(False, False), t_rotated_datum(), []),
  )
}

test rotate_gs_logic_fails_once_upgrades_are_locked() {
  let input_datum = t_datum_locked()
  !outgoing(
    t_new_gs_logic,
    t_rotate_tx_from(
      input_datum,
      rotated(input_datum, t_new_gs_logic),
      [t_admin],
    ),
  )
}

test deactivated_input_rejects_rotate_gs_logic() fail {
  let input_datum = t_datum(True, True)
  outgoing(
    t_new_gs_logic,
    t_rotate_tx_from(
      input_datum,
      rotated(input_datum, t_new_gs_logic),
      [t_admin],
    ),
  )
}

test rotate_gs_logic_fails_without_the_new_withdrawal() {
  !outgoing(
    t_new_gs_logic,
    Transaction {
      ..t_rotate_tx(t_rotated_datum()),
      withdrawals: [Pair(Script(t_gs_logic), 0)],
    },
  )
}

test rotate_gs_logic_fails_when_the_new_logic_is_merely_signed_for() {
  !outgoing(
    t_new_gs_logic,
    Transaction {
      ..t_rotate_tx(t_rotated_datum()),
      withdrawals: [Pair(Script(t_gs_logic), 0)],
      extra_signatories: [t_admin, t_new_gs_logic],
    },
  )
}

// Self-rotation by the installed logic, admin-signed: refused, so it can never
// be used to rewrite the datum unchecked.
test rotate_to_the_current_logic_fails_with_admin() {
  let output_datum = GlobalStateDatum {
    ..t_datum(False, False),
    mintable_amount: 999_999_999,
  }
  !outgoing(t_gs_logic, t_rotate_tx(output_datum))
}

// The same with no signature at all — the takeover shape.
test incoming_side_rejects_self_rotation() {
  let output_datum = GlobalStateDatum {
    ..t_datum(False, False),
    admin_credential_hash: t_new_admin,
    upgrades_locked: False,
    mintable_amount: 999_999_999,
  }
  !outgoing(
    t_gs_logic,
    t_rotate_tx_from(t_datum(False, False), output_datum, []),
  )
}

test rotate_gs_logic_fails_to_the_minting_script() {
  let tx = Transaction {
    ..t_rotate_tx(rotated(t_datum(False, False), t_minting_script)),
    withdrawals: [
      Pair(Script(t_gs_logic), 0),
      Pair(Script(t_minting_script), 0),
    ],
  }
  !outgoing(t_minting_script, tx)
}

test rotation_fails_when_new_logic_equals_the_admin() {
  let tx = Transaction {
    ..t_rotate_tx(rotated(t_datum(False, False), t_admin)),
    withdrawals: [Pair(Script(t_gs_logic), 0), Pair(Script(t_admin), 0)],
  }
  !outgoing(t_admin, tx)
}

test rotate_gs_logic_fails_on_a_short_hash() {
  let tx = Transaction {
    ..t_rotate_tx(rotated(t_datum(False, False), #"2b2b")),
    withdrawals: [Pair(Script(t_gs_logic), 0), Pair(Script(#"2b2b"), 0)],
  }
  !outgoing(#"2b2b", tx)
}

test rotate_gs_logic_fails_when_field_0_is_not_the_named_logic() {
  !outgoing(
    t_new_gs_logic,
    t_rotate_tx(rotated(t_datum(False, False), t_new_minting_script)),
  )
}

test rotate_gs_logic_fails_when_the_nft_leaves_the_proxy() {
  let tx = t_rotate_tx(t_rotated_datum())
  let moved = Output {
    ..t_output(t_rotated_datum()),
    address: Address {
      payment_credential: Script(t_new_gs_logic),
      stake_credential: None,
    },
  }
  !outgoing(t_new_gs_logic, Transaction { ..tx, outputs: [moved] })
}

test rotate_gs_logic_fails_when_deactivated_changes() {
  !outgoing(
    t_new_gs_logic,
    t_rotate_tx(GlobalStateDatum { ..t_rotated_datum(), deactivated: True }),
  )
}

test rotate_gs_logic_fails_when_the_admin_changes() {
  !outgoing(
    t_new_gs_logic,
    t_rotate_tx(
      GlobalStateDatum {
        ..t_rotated_datum(),
        admin_credential_hash: t_new_admin,
      },
    ),
  )
}

test rotate_gs_logic_fails_when_the_power_users_list_changes() {
  !outgoing(
    t_new_gs_logic,
    t_rotate_tx(
      GlobalStateDatum {
        ..t_rotated_datum(),
        power_user_linked_list_policy_id: t_pu_ll_policy,
      },
    ),
  )
}

test rotate_gs_logic_fails_when_the_minting_script_changes() {
  !outgoing(
    t_new_gs_logic,
    t_rotate_tx(
      GlobalStateDatum {
        ..t_rotated_datum(),
        minting_script_credential_hash: t_new_minting_script,
      },
    ),
  )
}

// A retyped known field would make the frozen readers trap for good.
test rotate_gs_logic_fails_when_the_output_is_not_readable() fail {
  let raw: Data = t_rotated_datum()
  let fields = utils.replace_data_field(
    builtin.unconstr_fields(raw),
    idx_mintable_amount,
    builtin.b_data(#"00"),
  )
  outgoing(
    t_new_gs_logic,
    with_raw_output(
      t_rotate_tx(t_rotated_datum()),
      builtin.constr_data(0, fields),
    ),
  )
}

test rotate_gs_logic_fails_with_a_concurrent_security_mint() {
  !outgoing(
    t_new_gs_logic,
    Transaction {
      ..t_rotate_tx(t_rotated_datum()),
      mint: from_asset(t_issuance_policy, t_sec_name, 1),
    },
  )
}

test rotate_gs_logic_fails_when_the_security_token_is_spent() {
  !outgoing(
    t_new_gs_logic,
    with_security_token_input(t_rotate_tx(t_rotated_datum())),
  )
}

test rotate_gs_logic_fails_with_a_reference_script_on_the_output() {
  !outgoing(
    t_new_gs_logic,
    Transaction {
      ..t_rotate_tx(t_rotated_datum()),
      outputs: [t_output_with_reference_script(t_rotated_datum())],
    },
  )
}

// "Don't block updates": the outgoing logic leaves every other field, and any
// appended field, to the new logic.
test rotate_gs_logic_outgoing_allows_another_field_to_change() {
  outgoing(
    t_new_gs_logic,
    t_rotate_tx(GlobalStateDatum { ..t_rotated_datum(), mintable_amount: 7 }),
  )
}

test rotate_gs_logic_outgoing_allows_an_appended_field() {
  let raw: Data = t_rotated_datum()
  outgoing(
    t_new_gs_logic,
    with_raw_output(
      t_rotate_tx(t_rotated_datum()),
      builtin.constr_data(
        0,
        list.concat(builtin.unconstr_fields(raw), [builtin.i_data(1)]),
      ),
    ),
  )
}

// ── incoming side (this version being installed) ─────────────────────────────

test rotate_gs_logic_incoming_accepts_only_field_0_rewritten() {
  incoming(t_rotate_tx(t_rotated_datum()))
}

test rotate_gs_logic_incoming_rejects_another_change() {
  !incoming(
    t_rotate_tx(GlobalStateDatum { ..t_rotated_datum(), mintable_amount: 7 }),
  )
}

test incoming_side_rejects_a_non_nft_output() {
  let tx = t_rotate_tx(t_rotated_datum())
  !incoming(
    Transaction {
      ..tx,
      outputs: [
        Output {
          ..t_output(t_rotated_datum()),
          value: from_lovelace(2_000_000),
        },
      ],
    },
  )
}

// The installed logic is ALWAYS the outgoing side, whatever the redeemer
// claims: a self-rotation that changes nothing still needs the admin and is
// still refused as a no-op. (Chosen by the redeemer instead, this would be
// taken as the incoming side, whose equality check alone would accept it.)
test self_rotation_without_changes_is_refused() {
  !outgoing(
    t_gs_logic,
    t_rotate_tx_from(t_datum(False, False), t_datum(False, False), []),
  )
}

// Named in the output but not in the redeemer: each logic gets its own
// redeemer, and the incoming side acts only on one naming it.
test incoming_side_rejects_a_redeemer_naming_another_logic() {
  !run_logic(
    t_new_gs_logic,
    rotate_gs_redeemer(t_new_minting_script),
    t_rotate_tx(t_rotated_datum()),
  )
}

// A logic that is neither installed nor the one named never acts.
test rotation_fails_for_a_bystander_logic() {
  !run_logic(
    t_new_gs_logic,
    rotate_gs_redeemer(t_new_minting_script),
    t_rotate_tx(rotated(t_datum(False, False), t_new_minting_script)),
  )
}

test rotate_gs_logic_incoming_fails_when_admin_is_its_own_hash() fail {
  let input_datum = GlobalStateDatum {
    ..t_datum(False, False),
    admin_credential_hash: t_new_gs_logic,
  }
  incoming(
    t_rotate_tx_from(
      input_datum,
      rotated(input_datum, t_new_gs_logic),
      [t_new_gs_logic],
    ),
  )
}

// ── after a rotation ─────────────────────────────────────────────────────────

// The installed logic governs the rotated datum: an ordinary action under it
// succeeds, and the previous logic can no longer act.
test rotated_logic_runs_the_next_action() {
  let input_datum = t_rotated_datum()
  run_spend(
    input_datum,
    GlobalStateSpendRedeemer {
      global_state_output_index: 0,
      action: SetRequiresSenderKyc { enabled: True },
    },
    t_tx(
      input_datum,
      GlobalStateDatum { ..input_datum, requires_sender_kyc: True },
      [t_admin],
    ),
  )
}

test previous_logic_cannot_act_after_a_rotation() fail {
  let input_datum = t_rotated_datum()
  run_logic(
    t_gs_logic,
    GlobalStateSpendRedeemer {
      global_state_output_index: 0,
      action: SetRequiresSenderKyc { enabled: True },
    },
    t_tx(
      input_datum,
      GlobalStateDatum { ..input_datum, requires_sender_kyc: True },
      [t_admin],
    ),
  )
}

// Fields a later logic appended survive this version's writes.
fn appended(datum: GlobalStateDatum) -> Data {
  let raw: Data = datum
  builtin.constr_data(
    0,
    list.concat(builtin.unconstr_fields(raw), [builtin.b_data(#"ff")]),
  )
}

fn kyc_tx_raw(input_raw: Data, output_raw: Data) -> Transaction {
  let tx = t_tx(t_datum(False, False), t_datum(False, False), [t_admin])
  Transaction {
    ..tx,
    inputs: [
      Input {
        output_reference: t_out_ref(0),
        output: Output {
          ..t_output(t_datum(False, False)),
          datum: InlineDatum(input_raw),
        },
      },
    ],
    outputs: [
      Output {
        ..t_output(t_datum(False, False)),
        datum: InlineDatum(output_raw),
      },
    ],
  }
}

fn kyc_redeemer() -> GlobalStateSpendRedeemer {
  GlobalStateSpendRedeemer {
    global_state_output_index: 0,
    action: SetRequiresSenderKyc { enabled: True },
  }
}

test an_action_keeps_an_appended_field() {
  run_logic(
    t_gs_logic,
    kyc_redeemer(),
    kyc_tx_raw(
      appended(t_datum(False, False)),
      appended(
        GlobalStateDatum { ..t_datum(False, False), requires_sender_kyc: True },
      ),
    ),
  )
}

test an_action_cannot_drop_an_appended_field() {
  !run_logic(
    t_gs_logic,
    kyc_redeemer(),
    kyc_tx_raw(
      appended(t_datum(False, False)),
      GlobalStateDatum { ..t_datum(False, False), requires_sender_kyc: True },
    ),
  )
}
