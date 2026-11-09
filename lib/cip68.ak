use aiken/builtin
use aiken/collection/dict.{Dict}
use aiken/collection/list
use aiken/primitive/bytearray
use cardano/address.{Address, Script}
use cardano/assets.{
  AssetName, Assets, PolicyId, from_asset, from_lovelace, merge, to_dict, tokens,
}
use cardano/transaction.{InlineDatum, NoDatum, Output}
use constants
use types/cip68.{Cip68Datum}

/// Does `asset_name` carry one of the protected CIP-67 label prefixes?
///
/// One comparison against one constant. There is exactly one CIP-68 metadata
/// label, `(100)`, so this is not a set membership test — and the slice width is
/// the FIXED `constants.cip68_protected_prefix_length` rather than the prefix's
/// measured length. Both matter because this runs once per token of the issuance
/// policy per output on the transfer path. The constant is held to that length
/// by `cip68_protected_prefix_has_the_fixed_length` below.
///
/// `bytearray.take` on a name shorter than the slice returns the whole (short)
/// name, which cannot equal a four-byte prefix — so a malformed or truncated
/// asset name is simply unprotected rather than a trap.
pub fn is_protected(asset_name: ByteArray) -> Bool {
  bytearray.take(asset_name, constants.cip68_protected_prefix_length) == constants.cip68_protected_prefix
}

/// Does `value` carry any protected token under `issuance_policy_id`?
///
/// Scoped to the one policy on purpose: a UTxO may legitimately hold anything
/// else, and enumerating a whole `Value` would make this cost grow with assets
/// this deployment has no opinion about.
pub fn value_has_protected(value: Assets, issuance_policy_id: PolicyId) -> Bool {
  tokens(value, issuance_policy_id)
    |> dict.to_pairs
    |> list.any(fn(entry) { is_protected(entry.1st) })
}

/// Is `output` a well-formed CIP-68 metadata UTxO — ADA plus exactly one
/// protected token, carrying a correctly shaped datum?
///
/// TRAPS rather than returning False. Every caller wants the transaction
/// rejected, and a trap names the assertion that failed in the trace, which a
/// bare `False` does not.
///
/// Three separate things are asserted, and each earns its place:
///
///   * **Value is ADA + this policy, nothing else.** A metadata UTxO that also
///     held security tokens would carry value through a path that treats it as
///     metadata — the compliance scans are all scoped to the security asset
///     name and would never look at it. A foreign policy's token is refused for
///     the same reason it is refused on a list element: it makes the UTxO
///     something other than what its name says it is.
///   * **Exactly one, and protected.** "Reference token" at quantity two is not
///     an NFT, and a non-protected name here means the caller located the wrong
///     output.
///   * **The datum decodes as `Cip68Datum`** — constructor 0, three fields,
///     `metadata` a map and `version` an integer. Contents are not inspected;
///     see the type's doc comment for why.
///
/// The ADA entry is DROPPED rather than compared. A `Value` is keyed by policy
/// id, ADA's is the empty bytestring so it always sorts first, and every UTxO
/// carries lovelace — so `dict.expect_tail` is both cheaper than an equality
/// check and no weaker. The same invariant the linked-list library's element
/// authentication and CIP-113's own `validate_directory_node_output` rely on.
/// Exactly one policy may remain after the drop.
pub fn output_is_well_formed(
  output: Output,
  issuance_policy_id: PolicyId,
) -> Bool {
  expect [Pair(policy, names)] = output.value
    |> to_dict
    |> dict.expect_tail
    |> dict.to_pairs
  expect policy == issuance_policy_id

  expect [Pair(asset_name, 1)] = dict.to_pairs(names)
  expect is_protected(asset_name)

  expect InlineDatum(raw_datum) = output.datum
  expect _well_shaped: Cip68Datum = raw_datum

  True
}

/// Assert the CIP-68 shape IF `policy_tokens` contains a protected name.
///
/// Takes the ALREADY-EXTRACTED token dict rather than the output's whole value,
/// so a caller walking outputs pays one policy lookup for both questions it has
/// — "is this a destination?" and "does this carry metadata?". On the transfer
/// hot path that keeps the added cost to one prefix comparison per token of the
/// policed policy, which for an ordinary transfer is a single comparison.
pub fn enforce_if_protected(
  policy_tokens: Dict<AssetName, Int>,
  output: Output,
  issuance_policy_id: PolicyId,
) -> Bool {
  if dict.to_pairs(policy_tokens)
    |> list.any(fn(entry) { is_protected(entry.1st) }) {
    output_is_well_formed(output, issuance_policy_id)
  } else {
    True
  }
}

// ============================================================================
// Tests
// ============================================================================

/// A `(100)` reference-token name is protected, whatever follows the label.
test cip68_label_100_is_protected() {
  is_protected(#"000643b04d792d546f6b656e") == True
}

/// The `(333)` fungible-token label — the shape a security token uses — must
/// NOT be protected, or every transfer and seizure of it would be refused.
test cip68_label_333_is_not_protected() {
  is_protected(#"0014df104d792d546f6b656e") == False
}

/// A name shorter than a label cannot match, and must not trap.
test cip68_short_name_is_not_protected() {
  is_protected(#"0006") == False
}

/// TRIPWIRE for the fixed slice width. `is_protected` compares a
/// `cip68_protected_prefix_length`-byte slice, so a prefix of any other length
/// would match nothing at all and leave metadata tokens silently unprotected — a
/// hole no other test would notice, because every test would simply see "not
/// protected" and agree. Change one constant without the other and this fails
/// instead of the security property.
test cip68_protected_prefix_has_the_fixed_length() {
  bytearray.length(constants.cip68_protected_prefix) == constants.cip68_protected_prefix_length
}

// ── output_is_well_formed ────────────────────────────────────────────────────
//
// "Only ADA + the CIP-68 token, and a correctly shaped datum." Each negative
// below is paired with the positive control above it, built from the same
// fixture, so a test cannot pass because the whole path is broken.

const t_policy: PolicyId =
  #"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"

const t_other_policy: PolicyId =
  #"cccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

const t_ref_name: ByteArray = #"000643b04d657461"

const t_sec_name: ByteArray = #"0014df104d657461"

fn t_datum() -> Data {
  let d = Cip68Datum {
    metadata: [],
    version: 1,
    extra: builtin.constr_data(0, []),
  }
  let raw: Data = d
  raw
}

fn t_output(value: Assets, datum: Data) -> Output {
  Output {
    address: Address {
      payment_credential: Script(t_policy),
      stake_credential: None,
    },
    value,
    datum: InlineDatum(datum),
    reference_script: None,
  }
}

fn t_ref_value() -> Assets {
  merge(from_lovelace(2_000_000), from_asset(t_policy, t_ref_name, 1))
}

/// POSITIVE CONTROL: ADA + exactly one reference token + a CIP-68 datum.
test cip68_output_accepts_the_canonical_shape() {
  output_is_well_formed(t_output(t_ref_value(), t_datum()), t_policy)
}

/// Co-located with the security token — the shape rule exists to stop exactly
/// this, since a metadata UTxO holding value would move under the transfer
/// gates as if it were value.
test cip68_output_rejects_a_co_located_security_token() fail {
  output_is_well_formed(
    t_output(
      merge(t_ref_value(), from_asset(t_policy, t_sec_name, 5)),
      t_datum(),
    ),
    t_policy,
  )
}

/// Co-located with a foreign policy's token.
test cip68_output_rejects_a_foreign_policy_token() fail {
  output_is_well_formed(
    t_output(
      merge(t_ref_value(), from_asset(t_other_policy, "X", 1)),
      t_datum(),
    ),
    t_policy,
  )
}

/// Quantity must be exactly one — a "reference token" at quantity 2 is not an NFT.
test cip68_output_rejects_quantity_two() fail {
  output_is_well_formed(
    t_output(
      merge(from_lovelace(2_000_000), from_asset(t_policy, t_ref_name, 2)),
      t_datum(),
    ),
    t_policy,
  )
}

/// A datum that is not the CIP-68 three-field constructor.
test cip68_output_rejects_a_malformed_datum() fail {
  output_is_well_formed(
    t_output(t_ref_value(), builtin.constr_data(0, [])),
    t_policy,
  )
}

/// No inline datum at all.
test cip68_output_rejects_a_missing_datum() fail {
  output_is_well_formed(
    Output { ..t_output(t_ref_value(), t_datum()), datum: NoDatum },
    t_policy,
  )
}

/// A datum with the right field COUNT but the wrong constructor tag. CIP-68
/// fixes the tag at 0 (`#6.121`), and a `Constr 1` record is a different type
/// to any reader — so the shape check must not accept it merely because three
/// fields are present.
test cip68_output_rejects_a_wrong_constructor_tag() fail {
  let wrong_tag = builtin.constr_data(
    1,
    [builtin.map_data([]), builtin.i_data(1), builtin.constr_data(0, [])],
  )
  output_is_well_formed(t_output(t_ref_value(), wrong_tag), t_policy)
}

/// Right tag and field count, but `metadata` is an integer rather than a map.
/// The field TYPES are part of the shape; without this the check would only be
/// counting fields.
test cip68_output_rejects_non_map_metadata() fail {
  let wrong_types = builtin.constr_data(
    0,
    [builtin.i_data(42), builtin.i_data(1), builtin.constr_data(0, [])],
  )
  output_is_well_formed(t_output(t_ref_value(), wrong_types), t_policy)
}
