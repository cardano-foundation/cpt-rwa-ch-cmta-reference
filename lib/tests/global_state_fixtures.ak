//// Shared test fixtures for the GlobalState validator modules
//// (global_state.ak, global_state_proxy.ak, global_state_logic_tests.ak).
//// Test-only: nothing here is used by validator code.

use aiken/builtin
use aiken/collection/dict
use aiken/collection/list
use aiken/interval.{Interval, IntervalBound, NegativeInfinity, PositiveInfinity}
use aiken/primitive/bytearray
use cardano/address.{Address, Script}
use cardano/assets.{Value, from_asset, from_lovelace, merge, zero}
use cardano/transaction.{
  InlineDatum, Input, Output, OutputReference, Transaction,
}
use constants
use types/global_state.{GlobalStateDatum, TrustedEntityMetadata}

// ── One GlobalState UTxO at the proxy, and a transaction spending it ────────

pub const t_gs_policy: ByteArray =
  #"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

pub const t_admin: ByteArray =
  #"cccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

// `global_state_proxy`'s hash: where the NFT lives.
pub const t_gs_script_hash: ByteArray =
  #"dddddddddddddddddddddddddddddddddddddddddddddddddddddddd"

// The installed GlobalState logic — datum field 0 in every fixture.
pub const t_gs_logic: ByteArray =
  #"9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a"

pub const t_minting_script: ByteArray =
  #"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"

pub const t_reference_script: ByteArray = #"4e4d01000033222220051200120011"

pub fn t_out_ref(ix: Int) -> OutputReference {
  OutputReference {
    transaction_id: #"0000000000000000000000000000000000000000000000000000000000000000",
    output_index: ix,
  }
}

pub fn t_datum(transfers_paused: Bool, deactivated: Bool) -> GlobalStateDatum {
  GlobalStateDatum {
    global_state_script_credential_hash: t_gs_logic,
    transfers_paused,
    deactivated,
    mintable_amount: 1_000_000,
    admin_credential_hash: t_admin,
    power_user_linked_list_policy_id: #"",
    denylist_linked_list_policy_id: #"",
    security_info: builtin.constr_data(0, []),
    trusted_entity_vkeys: [],
    member_root_hash: #"",
    requires_sender_kyc: False,
    requires_receiver_kyc: False,
    network_id: 1,
    minting_script_credential_hash: t_minting_script,
    upgrades_locked: False,
  }
}

pub fn t_gs_value() -> Value {
  merge(
    from_lovelace(2_000_000),
    from_asset(t_gs_policy, constants.global_state_asset_name, 1),
  )
}

pub fn t_input(datum: GlobalStateDatum) -> Input {
  Input {
    output_reference: t_out_ref(0),
    output: Output {
      address: Address {
        payment_credential: Script(t_gs_script_hash),
        stake_credential: None,
      },
      value: t_gs_value(),
      datum: InlineDatum(datum),
      reference_script: None,
    },
  }
}

pub fn t_output(datum: GlobalStateDatum) -> Output {
  Output {
    address: Address {
      payment_credential: Script(t_gs_script_hash),
      stake_credential: None,
    },
    value: t_gs_value(),
    datum: InlineDatum(datum),
    reference_script: None,
  }
}

pub fn t_tx(
  input_datum: GlobalStateDatum,
  output_datum: GlobalStateDatum,
  signatories: List<ByteArray>,
) -> Transaction {
  Transaction {
    inputs: [t_input(input_datum)],
    reference_inputs: [],
    outputs: [t_output(output_datum)],
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
    extra_signatories: signatories,
    redeemers: [],
    datums: dict.empty,
    id: #"0000000000000000000000000000000000000000000000000000000000000000",
    votes: [],
    proposal_procedures: [],
    current_treasury_amount: None,
    treasury_donation: None,
  }
}

// ── Genesis datum ────────────────────────────────────────────────────────────

pub const t_pu_ll_policy: ByteArray =
  #"11111111111111111111111111111111111111111111111111111111"

pub const t_dl_ll_policy: ByteArray =
  #"22222222222222222222222222222222222222222222222222222222"

pub const t_root32: ByteArray =
  #"3333333333333333333333333333333333333333333333333333333333333333"

// ── Datum size caps (genesis sanitisation and the logic's growth checks) ──────

/// `count` strictly-ascending 32-byte vkeys (big-endian encoding of 1..count,
/// so ascending order is guaranteed automatically), each paired with trivial
/// metadata — used to exercise the trusted-entity list length cap without
/// hand-writing dozens of fixtures.
pub fn t_many_entities(count: Int) -> Pairs<ByteArray, TrustedEntityMetadata> {
  list.map(
    list.range(1, count),
    fn(i) { Pair(bytearray.from_int_big_endian(i, 32), builtin.i_data(i)) },
  )
}

/// An arbitrary `Data` value (a plain byte string) whose serialised (CBOR)
/// size, in bytes, is a function of `raw_len`. Plutus Data serialises a
/// ByteArray longer than 64 bytes as an indefinite-length, 64-byte-chunked
/// byte string, so the size is not simply `raw_len` plus a fixed constant.
/// The `t_*_len_at_cap` / `t_*_len_over_cap` constants below were chosen so
/// this lands the serialised size exactly on, or one byte over, the two
/// size bounds the GlobalState tests exercise.
pub fn t_data_of_raw_length(raw_len: Int) -> Data {
  builtin.b_data(bytearray.from_int_big_endian(0, raw_len))
}

pub const t_security_info_len_at_cap: Int = 3969

pub const t_security_info_len_over_cap: Int = 3970

pub const t_metadata_len_at_cap: Int = 494

pub const t_metadata_len_over_cap: Int = 495

pub const t_vkey_10: ByteArray =
  #"1010101010101010101010101010101010101010101010101010101010101010"

// ── RotateGlobalStateScript ─────────────────────────────────────────────────

pub const t_new_gs_logic: ByteArray =
  #"2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b"

pub fn rotated(datum: GlobalStateDatum, logic: ByteArray) -> GlobalStateDatum {
  GlobalStateDatum { ..datum, global_state_script_credential_hash: logic }
}
