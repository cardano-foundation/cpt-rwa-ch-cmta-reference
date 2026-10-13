//// GlobalState — genesis mint (one-shot).
////
//// The GlobalState is split over three scripts; this file is step 1:
////
////   1. `global_state_mint_validator` (this file): mints the single
////      GlobalState NFT once, from a one-shot UTxO, and places it at the
////      proxy with a sanitised initial datum.
////   2. `global_state_proxy` (global_state_proxy.ak): the permanent address
////      of the NFT. It only reads datum field 0 and requires that script's
////      withdraw-0 in the same transaction.
////   3. `global_state_logic` (global_state_logic.ak): the withdraw-0 script
////      named by field 0. Every rule for changing the GlobalState lives
////      there, and `RotateGlobalStateScript` replaces it without moving the
////      NFT.
////
//// Hash dependencies (no cycles): proxy (no parameters) → mint (takes the
//// proxy hash) → logic (takes the mint policy id); field 0 names the logic.

use aiken/builtin
use aiken/collection/list
use aiken/primitive/bytearray
use cardano/address.{Address, Inline, Script, VerificationKey}
use cardano/assets.{
  PolicyId, Value, from_asset, from_lovelace, merge, quantity_of,
}
use cardano/transaction.{
  InlineDatum, Input, NoDatum, Output, OutputReference, Transaction, find_input,
}
use constants
use tests/global_state_fixtures.{
  rotated, t_admin, t_data_of_raw_length, t_dl_ll_policy, t_gs_logic,
  t_gs_policy, t_gs_script_hash, t_many_entities, t_metadata_len_at_cap,
  t_metadata_len_over_cap, t_minting_script, t_new_gs_logic, t_pu_ll_policy,
  t_reference_script, t_root32, t_security_info_len_at_cap,
  t_security_info_len_over_cap, t_tx, t_vkey_10,
}
use types/global_state.{GlobalStateDatum, TrustedEntityMetadata}
use utils.{quantity_of_policy_id}

// ============================================================================
// Sanitisation helpers (used by mint validator at genesis)
// ============================================================================

fn walk_strictly_ascending(
  prev: ByteArray,
  rest: Pairs<ByteArray, TrustedEntityMetadata>,
) -> Bool {
  when rest is {
    [] -> True
    [head, ..tail] -> {
      let k = head.1st
      and {
        bytearray.length(k) == 32,
        builtin.less_than_bytearray(prev, k),
        walk_strictly_ascending(k, tail),
      }
    }
  }
}

fn is_sorted_no_dup_vkeys(
  entries: Pairs<ByteArray, TrustedEntityMetadata>,
) -> Bool {
  when entries is {
    [] -> True
    [head, ..tail] -> {
      let k = head.1st
      and {
        bytearray.length(k) == 32,
        walk_strictly_ascending(k, tail),
      }
    }
  }
}

/// Every trusted entity's metadata, individually, within
/// `constants.max_trusted_entity_metadata_bytes` once CBOR-serialised.
fn all_metadata_within_bound(
  entries: Pairs<ByteArray, TrustedEntityMetadata>,
) -> Bool {
  list.all(
    entries,
    fn(entry) {
      bytearray.length(builtin.serialise_data(entry.2nd)) <= constants.max_trusted_entity_metadata_bytes
    },
  )
}

fn sanitise_initial_datum(datum: GlobalStateDatum, self_mint: Value) -> Bool {
  let root_len = bytearray.length(datum.member_root_hash)
  and {
    !datum.transfers_paused,
    // A born-deactivated protocol would be permanently unspendable at genesis.
    !datum.deactivated,
    datum.mintable_amount >= 0,
    bytearray.length(datum.admin_credential_hash) == 28,
    bytearray.length(datum.minting_script_credential_hash) == 28,
    // The GlobalState logic (field 0) is a delegate credential like the
    // minting authority: well-formed, and never doubling as the authority or
    // the admin — its withdrawal is in every GlobalState transaction and
    // `must_be_signed_by_credential` would accept it for either.
    bytearray.length(datum.global_state_script_credential_hash) == 28,
    datum.global_state_script_credential_hash != datum.minting_script_credential_hash,
    datum.global_state_script_credential_hash != datum.admin_credential_hash,
    // Born unlocked. Locking is a single admin transaction away, so a
    // deployment that wants immutability from day one loses nothing — but a
    // token that started locked could never be corrected at all.
    !datum.upgrades_locked,
    // network_id is IMMUTABLE and must fit the 1-byte field encoded into every
    // KYC-attestation payload (0–255). An out-of-range value would silently and
    // permanently disable attestation-based transfers.
    datum.network_id >= 0,
    datum.network_id <= 255,
    // member_root_hash must be empty (no membership tree yet) or a 32-byte
    // blake2b-256 digest; any other length makes `mpf.from_root` trap on every
    // membership-proof transfer.
    or {
      root_len == 0,
      root_len == 32,
    },
    // power_users LL root and denylist LL root must be minted in this tx
    quantity_of_policy_id(self_mint, datum.power_user_linked_list_policy_id) >= 1,
    quantity_of_policy_id(self_mint, datum.denylist_linked_list_policy_id) >= 1,
    // The two lists must not be the same list. If the ids were equal,
    // every power-user node would double as a denylist node — and since a
    // power-user node's link is unconstrained by the denylist's ordering, the
    // sanctions list would be satisfiable from day one and never bind. No v1
    // action changes either field (the power-users id is also pinned across
    // logic rotations; the denylist id is the new logic's to keep), so this is
    // the only chance to catch it.
    //
    // The length checks are the same defence one step earlier: a malformed id
    // can never name a real minting policy, so the corresponding list would be
    // permanently un-initialisable. Off-chain must additionally verify both ids
    // against the compiled list-validator hashes before signing genesis — that
    // binding is not checkable here.
    datum.power_user_linked_list_policy_id != datum.denylist_linked_list_policy_id,
    bytearray.length(datum.power_user_linked_list_policy_id) == 28,
    bytearray.length(datum.denylist_linked_list_policy_id) == 28,
    is_sorted_no_dup_vkeys(datum.trusted_entity_vkeys),
    // Datum growth caps — defence in depth, see `constants.max_*` doc
    // comment. Enforced once here at genesis, and again on every spend
    // branch able to grow the same field afterwards.
    list.length(datum.trusted_entity_vkeys) <= constants.max_trusted_entities,
    bytearray.length(builtin.serialise_data(datum.security_info)) <= constants.max_security_info_bytes,
    all_metadata_within_bound(datum.trusted_entity_vkeys),
  }
}

// ============================================================================
// Mint validator
// ============================================================================
// Only used at genesis to mint the global_state NFT with the initial datum.
// Verifies the following:
// - The one-and-only global_state NFT is being minted, and goes to the output.
// - That output sits at `global_state_proxy` (its payment credential). The
//   proxy is unparameterised, so its hash is known before genesis with no
//   circular dependency; the logic it delegates to is named by datum field 0.
// - The initial datum is well-formed (basic field checks + trusted entity vkey list is sorted and has no duplicates + power user ll and denylist ll roots are minted).
// The stake part of the address is left free; choose it deliberately — every
// logic action preserves the full address afterwards, so it is permanent.
validator global_state_mint_validator(
  tx0: ByteArray,
  index0: Int,
  /// Hash of `global_state_proxy` (global_state_proxy.ak), the NFT's permanent home.
  global_state_proxy_hash: ByteArray,
) {
  mint(_redeemer: Data, policy_id: PolicyId, self: Transaction) {
    let one_time_utxo = OutputReference(tx0, index0)
    //we won't use input_present, we just need it to be there, otherwise error
    expect Some(_input_present) = find_input(self.inputs, one_time_utxo)

    let output_parameters = list.expect_find(
      self.outputs,
      fn(output) {
        assets.has_nft_strict(
          output.value,
          policy_id,
          constants.global_state_asset_name,
        )
      },
    )

    expect InlineDatum(output_datum_raw) = output_parameters.datum
    expect output_datum: GlobalStateDatum = output_datum_raw

    and {
      // No other asset names under this policy are minted alongside the NFT.
      quantity_of_policy_id(self.mint, policy_id) == 1,
      // Exactly one global_state NFT is minted.
      quantity_of(self.mint, policy_id, constants.global_state_asset_name) == 1,
      // GlobalState is state, not script storage.
      output_parameters.reference_script == None,
      // Born at the proxy — the SCRIPT, never a key with the same bytes. Every
      // logic action keeps it there afterwards.
      output_parameters.address.payment_credential == Script(
        global_state_proxy_hash,
      ),
      // The proxy refuses to delegate to itself anyway; refusing it here keeps
      // a genesis that could never be spent from landing at all.
      output_datum.global_state_script_credential_hash != global_state_proxy_hash,
      //Initial datum is well-formed (sort, no duplicates, correct field widths,
      //LL root NFTs also minted in this tx).
      sanitise_initial_datum(output_datum, self.mint),
    }
  }

  else(_) {
    fail
  }
}

// ============================================================================
// Tests
// ============================================================================

test sanitise_rejects_genesis_that_is_born_locked() {
  // A token locked at birth could never be corrected at all; locking is one
  // admin transaction away, so nothing is lost by refusing it here.
  let datum = GlobalStateDatum {
    ..sanitise_datum(#"", 1),
    upgrades_locked: True,
  }
  !sanitise_initial_datum(datum, sanitise_mint())
}

// ── F-18: genesis KYC-config validation ─────────────────────────────────────

fn sanitise_datum(
  member_root_hash: ByteArray,
  network_id: Int,
) -> GlobalStateDatum {
  GlobalStateDatum {
    global_state_script_credential_hash: t_gs_logic,
    transfers_paused: False,
    deactivated: False,
    mintable_amount: 1_000,
    admin_credential_hash: t_admin,
    power_user_linked_list_policy_id: t_pu_ll_policy,
    denylist_linked_list_policy_id: t_dl_ll_policy,
    security_info: builtin.constr_data(0, []),
    trusted_entity_vkeys: [],
    member_root_hash,
    requires_sender_kyc: False,
    requires_receiver_kyc: False,
    network_id,
    minting_script_credential_hash: t_minting_script,
    upgrades_locked: False,
  }
}

fn sanitise_mint() -> Value {
  merge(
    from_asset(t_pu_ll_policy, constants.linked_list_root_key, 1),
    from_asset(t_dl_ll_policy, constants.linked_list_root_key, 1),
  )
}

test sanitise_accepts_valid_config() {
  sanitise_initial_datum(sanitise_datum(#"", 1), sanitise_mint())
}

test sanitise_accepts_32_byte_root() {
  sanitise_initial_datum(sanitise_datum(t_root32, 2), sanitise_mint())
}

test sanitise_rejects_network_id_above_255() {
  !sanitise_initial_datum(sanitise_datum(#"", 256), sanitise_mint())
}

test sanitise_rejects_negative_network_id() {
  !sanitise_initial_datum(sanitise_datum(#"", -1), sanitise_mint())
}

test sanitise_rejects_bad_root_hash_length() {
  // 2 bytes — neither empty nor 32.
  !sanitise_initial_datum(sanitise_datum(#"aabb", 1), sanitise_mint())
}

// ── Datum growth caps — genesis ─────────────────────────────────────────────

test sanitise_accepts_trusted_entity_count_at_the_cap() {
  let d = GlobalStateDatum {
    ..sanitise_datum(#"", 1),
    trusted_entity_vkeys: t_many_entities(constants.max_trusted_entities),
  }
  sanitise_initial_datum(d, sanitise_mint())
}

test sanitise_rejects_trusted_entity_count_over_the_cap() {
  let d = GlobalStateDatum {
    ..sanitise_datum(#"", 1),
    trusted_entity_vkeys: t_many_entities(constants.max_trusted_entities + 1),
  }
  !sanitise_initial_datum(d, sanitise_mint())
}

test sanitise_accepts_security_info_at_the_size_cap() {
  let d = GlobalStateDatum {
    ..sanitise_datum(#"", 1),
    security_info: t_data_of_raw_length(t_security_info_len_at_cap),
  }
  sanitise_initial_datum(d, sanitise_mint())
}

test sanitise_rejects_security_info_one_byte_over_the_size_cap() {
  let d = GlobalStateDatum {
    ..sanitise_datum(#"", 1),
    security_info: t_data_of_raw_length(t_security_info_len_over_cap),
  }
  !sanitise_initial_datum(d, sanitise_mint())
}

test sanitise_accepts_trusted_entity_metadata_at_the_size_cap() {
  let d = GlobalStateDatum {
    ..sanitise_datum(#"", 1),
    trusted_entity_vkeys: [
      Pair(t_vkey_10, t_data_of_raw_length(t_metadata_len_at_cap)),
    ],
  }
  sanitise_initial_datum(d, sanitise_mint())
}

test sanitise_rejects_trusted_entity_metadata_one_byte_over_the_size_cap() {
  let d = GlobalStateDatum {
    ..sanitise_datum(#"", 1),
    trusted_entity_vkeys: [
      Pair(t_vkey_10, t_data_of_raw_length(t_metadata_len_over_cap)),
    ],
  }
  !sanitise_initial_datum(d, sanitise_mint())
}

// ── Genesis sanitisation negatives ──────────────────────────────────────────

test sanitise_rejects_negative_mintable_amount() {
  let d = GlobalStateDatum { ..sanitise_datum(#"", 1), mintable_amount: -1 }
  !sanitise_initial_datum(d, sanitise_mint())
}

test sanitise_rejects_short_admin_credential_hash() {
  let d = GlobalStateDatum {
    ..sanitise_datum(#"", 1),
    admin_credential_hash: #"ab",
  }
  !sanitise_initial_datum(d, sanitise_mint())
}

test sanitise_rejects_short_minting_script_credential_hash() {
  let d = GlobalStateDatum {
    ..sanitise_datum(#"", 1),
    minting_script_credential_hash: #"ab",
  }
  !sanitise_initial_datum(d, sanitise_mint())
}

test sanitise_rejects_born_paused() {
  let d = GlobalStateDatum { ..sanitise_datum(#"", 1), transfers_paused: True }
  !sanitise_initial_datum(d, sanitise_mint())
}

test sanitise_rejects_born_deactivated() {
  let d = GlobalStateDatum { ..sanitise_datum(#"", 1), deactivated: True }
  !sanitise_initial_datum(d, sanitise_mint())
}

// ── Genesis mint validator ───────────────────────────────────────────────────

const t_mint_tx0: ByteArray =
  #"9999999999999999999999999999999999999999999999999999999999999999"

const t_mint_index0: Int = 0

const t_mint_receiver_vkey: ByteArray =
  #"88888888888888888888888888888888888888888888888888888888"

/// Invokes `global_state_mint_validator.mint` end-to-end, fixing the
/// compile-time one-shot UTxO reference (`t_mint_tx0`/`t_mint_index0`) and
/// the (unused) redeemer so each test only has to vary `policy_id` and `self`.
fn run_mint(policy_id: PolicyId, self: Transaction) -> Bool {
  global_state_mint_validator.mint(
    t_mint_tx0,
    t_mint_index0,
    t_gs_script_hash,
    builtin.constr_data(0, []),
    policy_id,
    self,
  )
}

/// The one-shot nonce UTxO the mint validator requires as an input.
fn t_nonce_input() -> Input {
  Input {
    output_reference: OutputReference {
      transaction_id: t_mint_tx0,
      output_index: t_mint_index0,
    },
    output: Output {
      address: Address {
        payment_credential: VerificationKey(t_mint_receiver_vkey),
        stake_credential: None,
      },
      value: from_lovelace(2_000_000),
      datum: NoDatum,
      reference_script: None,
    },
  }
}

/// The output carrying the freshly-minted global_state NFT plus a datum.
fn t_mint_output(datum: GlobalStateDatum) -> Output {
  Output {
    address: Address {
      payment_credential: Script(t_gs_script_hash),
      stake_credential: None,
    },
    value: merge(
      from_lovelace(2_000_000),
      from_asset(t_gs_policy, constants.global_state_asset_name, 1),
    ),
    datum: InlineDatum(datum),
    reference_script: None,
  }
}

fn t_mint_output_with_reference_script(datum: GlobalStateDatum) -> Output {
  Output { ..t_mint_output(datum), reference_script: Some(t_reference_script) }
}

/// A plain output carrying no asset of `t_gs_policy` at all.
fn t_mint_plain_output() -> Output {
  Output {
    address: Address {
      payment_credential: VerificationKey(t_mint_receiver_vkey),
      stake_credential: None,
    },
    value: from_lovelace(2_000_000),
    datum: NoDatum,
    reference_script: None,
  }
}

fn t_mint_tx(
  inputs: List<Input>,
  outputs: List<Output>,
  mint: Value,
) -> Transaction {
  Transaction {
    ..t_tx(sanitise_datum(#"", 1), sanitise_datum(#"", 1), []),
    inputs,
    outputs,
    mint,
  }
}

test global_state_mint_succeeds_with_nonce_and_sanitised_datum() {
  let datum = sanitise_datum(#"", 1)
  let mint = merge(
    from_asset(t_gs_policy, constants.global_state_asset_name, 1),
    sanitise_mint(),
  )
  run_mint(
    t_gs_policy,
    t_mint_tx([t_nonce_input()], [t_mint_output(datum)], mint),
  )
}

test global_state_mint_rejects_reference_script_on_output() {
  let datum = sanitise_datum(#"", 1)
  let mint = merge(
    from_asset(t_gs_policy, constants.global_state_asset_name, 1),
    sanitise_mint(),
  )
  !run_mint(
    t_gs_policy,
    t_mint_tx(
      [t_nonce_input()],
      [t_mint_output_with_reference_script(datum)],
      mint,
    ),
  )
}

test global_state_mint_fails_without_nonce_input() fail {
  // The one-time UTxO `find_input` must locate is absent from `self.inputs`
  // — `expect Some(_input_present) = find_input(..)` traps.
  let datum = sanitise_datum(#"", 1)
  let mint = merge(
    from_asset(t_gs_policy, constants.global_state_asset_name, 1),
    sanitise_mint(),
  )
  run_mint(t_gs_policy, t_mint_tx([], [t_mint_output(datum)], mint))
}

test global_state_mint_rejects_second_asset_name_under_policy() {
  // A second asset name minted under the same policy, carried by a SEPARATE
  // output — the primary NFT output is untouched, so `list.expect_find`
  // still locates it without trapping; `quantity_of_policy_id(self.mint,
  // policy_id) == 1` is the only assertion this violates.
  let datum = sanitise_datum(#"", 1)
  let mint = merge(
    merge(
      from_asset(t_gs_policy, constants.global_state_asset_name, 1),
      from_asset(t_gs_policy, "Other", 1),
    ),
    sanitise_mint(),
  )
  !run_mint(
    t_gs_policy,
    t_mint_tx(
      [t_nonce_input()],
      [t_mint_output(datum), t_mint_plain_output()],
      mint,
    ),
  )
}

test global_state_mint_rejects_nft_quantity_of_two() {
  // The NFT-carrying output still holds exactly 1 unit (so `list.expect_find`
  // does not trap), but `self.mint` carries 2 units of the same asset name —
  // `quantity_of(self.mint, policy_id, asset_name) == 1` is the check this
  // violates.
  let datum = sanitise_datum(#"", 1)
  let mint = merge(
    from_asset(t_gs_policy, constants.global_state_asset_name, 2),
    sanitise_mint(),
  )
  !run_mint(
    t_gs_policy,
    t_mint_tx([t_nonce_input()], [t_mint_output(datum)], mint),
  )
}

test global_state_mint_fails_when_no_output_carries_the_nft() fail {
  // No output in the transaction carries the NFT at all — `list.expect_find`
  // recurses past the end of `self.outputs` and traps.
  let mint = merge(
    from_asset(t_gs_policy, constants.global_state_asset_name, 1),
    sanitise_mint(),
  )
  run_mint(
    t_gs_policy,
    t_mint_tx([t_nonce_input()], [t_mint_plain_output()], mint),
  )
}

/// One list must not double as the other. `sanitise_mint()` mints both
/// roots under distinct policies, so with the datum ids made equal the mint
/// check still passes and the new inequality assertion is what rejects it.
/// Both fields are immutable after genesis, so this is the only chance.
test sanitise_rejects_identical_list_policies() {
  let d = sanitise_datum(#"", 1)
  !sanitise_initial_datum(
    GlobalStateDatum { ..d, denylist_linked_list_policy_id: t_pu_ll_policy },
    sanitise_mint(),
  )
}

/// A malformed policy id can never name a real minting policy, so the
/// corresponding list would be permanently un-initialisable.
///
/// The mint is built to carry a root under the malformed id as well, so the
/// pre-existing "both roots minted here" check PASSES and the new length check
/// is the only thing that can reject this datum.
test sanitise_rejects_short_list_policy_id() {
  let d = sanitise_datum(#"", 1)
  let short_policy = #"aabb"
  !sanitise_initial_datum(
    GlobalStateDatum { ..d, denylist_linked_list_policy_id: short_policy },
    merge(
      from_asset(t_pu_ll_policy, constants.linked_list_root_key, 1),
      from_asset(short_policy, constants.linked_list_root_key, 1),
    ),
  )
}

// ── genesis — the NFT is born at the proxy ───────────────────────────────────

fn genesis_with(output: Output) -> Bool {
  let mint = merge(
    from_asset(t_gs_policy, constants.global_state_asset_name, 1),
    sanitise_mint(),
  )
  run_mint(t_gs_policy, t_mint_tx([t_nonce_input()], [output], mint))
}

test global_state_mint_fails_when_the_nft_is_not_at_the_proxy() {
  !genesis_with(
    Output {
      ..t_mint_output(sanitise_datum(#"", 1)),
      address: Address {
        payment_credential: Script(t_new_gs_logic),
        stake_credential: None,
      },
    },
  )
}

test global_state_mint_fails_when_the_nft_goes_to_a_key_with_the_proxy_bytes() {
  !genesis_with(
    Output {
      ..t_mint_output(sanitise_datum(#"", 1)),
      address: Address {
        payment_credential: VerificationKey(t_gs_script_hash),
        stake_credential: None,
      },
    },
  )
}

test global_state_mint_allows_any_stake_credential() {
  genesis_with(
    Output {
      ..t_mint_output(sanitise_datum(#"", 1)),
      address: Address {
        payment_credential: Script(t_gs_script_hash),
        stake_credential: Some(Inline(VerificationKey(t_admin))),
      },
    },
  )
}

test global_state_mint_fails_when_field_0_is_the_proxy() {
  !genesis_with(
    t_mint_output(rotated(sanitise_datum(#"", 1), t_gs_script_hash)),
  )
}

test sanitise_rejects_a_short_global_state_logic() {
  !sanitise_initial_datum(
    rotated(sanitise_datum(#"", 1), #"9a9a"),
    sanitise_mint(),
  )
}

test sanitise_rejects_a_global_state_logic_equal_to_the_minting_script() {
  !sanitise_initial_datum(
    rotated(sanitise_datum(#"", 1), t_minting_script),
    sanitise_mint(),
  )
}

test sanitise_rejects_a_global_state_logic_equal_to_the_admin() {
  !sanitise_initial_datum(
    rotated(sanitise_datum(#"", 1), t_admin),
    sanitise_mint(),
  )
}
