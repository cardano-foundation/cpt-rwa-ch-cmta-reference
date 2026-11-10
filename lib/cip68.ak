use aiken/builtin
use aiken/collection/dict.{Dict}
use aiken/primitive/bytearray
use cardano/address.{Address, Script}
use cardano/assets.{
  AssetName, Assets, PolicyId, from_asset, from_lovelace, merge, quantity_of,
  to_dict, tokens,
}
use cardano/transaction.{InlineDatum, NoDatum, Output}
use constants
use types/cip68.{Cip68Datum}

/// The CIP-68 reference (`(100)`) NFT name of `asset_name`, or `None` when
/// `asset_name` is not a CIP-68 user-token name.
///
/// A name is a CIP-68 user-token name exactly when its first
/// `constants.cip67_label_length` bytes are one of the three user-token
/// labels — `(222)`, `(333)` or `(444)`. The label is compared byte for byte,
/// with no CIP-67 parsing: these three constants are the whole set. Its
/// reference name is the `(100)` label followed by the same body.
///
/// The body length plays no part here: a bare label (empty body) is still
/// detected, and maps to the bare `(100)` label. Whether such a name is
/// acceptable is a registration rule, kept in the minting authority, so that
/// every caller agrees on which names ARE CIP-68.
///
/// `None` for everything else: a plain name, the `(100)` reference label
/// itself, `""`, and any name shorter than a label. `bytearray.take` on a name
/// shorter than the slice returns the whole (short) name, which cannot equal a
/// four-byte label — so a truncated name is simply plain rather than a trap.
///
/// This is the only place a reference name is built.
pub fn reference_name(asset_name: ByteArray) -> Option<ByteArray> {
  let label = bytearray.take(asset_name, constants.cip67_label_length)
  if or {
    label == constants.cip68_nft_label,
    label == constants.cip68_ft_label,
    label == constants.cip68_rft_label,
  } {
    Some(
      bytearray.concat(
        constants.cip68_reference_label,
        bytearray.drop(asset_name, constants.cip67_label_length),
      ),
    )
  } else {
    None
  }
}

/// Does `value` carry the exact name `reference_name` under
/// `issuance_policy_id`?
///
/// Scoped to the one policy and the one name on purpose: a UTxO may
/// legitimately hold anything else, and enumerating a whole `Value` would make
/// this cost grow with assets this deployment has no opinion about.
pub fn value_has_reference(
  value: Assets,
  issuance_policy_id: PolicyId,
  reference_name: ByteArray,
) -> Bool {
  quantity_of(value, issuance_policy_id, reference_name) > 0
}

/// Is `output` a well-formed CIP-68 metadata UTxO — ADA plus exactly one
/// `reference_name` token, carrying a correctly shaped datum?
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
///   * **Exactly one, and exactly `reference_name`.** "Reference token" at
///     quantity two is not an NFT, and any other name here means the caller
///     located the wrong output.
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
  reference_name: ByteArray,
) -> Bool {
  expect [Pair(policy, names)] = output.value
    |> to_dict
    |> dict.expect_tail
    |> dict.to_pairs
  expect policy == issuance_policy_id

  expect [Pair(asset_name, 1)] = dict.to_pairs(names)
  expect asset_name == reference_name

  expect InlineDatum(raw_datum) = output.datum
  expect _well_shaped: Cip68Datum = raw_datum

  True
}

/// Assert the CIP-68 shape IF `policy_tokens` holds the exact key
/// `reference_name`.
///
/// Takes the ALREADY-EXTRACTED token dict rather than the output's whole value,
/// so a caller walking outputs pays one policy lookup for both questions it has
/// — "is this a destination?" and "does this carry the reference NFT?". On the
/// transfer hot path that keeps the added cost to one key lookup per output.
///
/// Keyed on the exact name: another `(100)`-labelled name under the same
/// policy is not this token's metadata, and is not checked here.
pub fn enforce_if_reference(
  policy_tokens: Dict<AssetName, Int>,
  output: Output,
  issuance_policy_id: PolicyId,
  reference_name: ByteArray,
) -> Bool {
  if dict.has_key(policy_tokens, reference_name) {
    output_is_well_formed(output, issuance_policy_id, reference_name)
  } else {
    True
  }
}

// ============================================================================
// Tests
// ============================================================================

// ── reference_name ──────────────────────────────────────────────────────────

/// `(222)` + body maps to `(100)` + the same body.
test cip68_reference_name_maps_the_222_label() {
  reference_name(#"000de1404d657461") == Some(#"000643b04d657461")
}

/// `(333)` + body maps to `(100)` + the same body.
test cip68_reference_name_maps_the_333_label() {
  reference_name(#"0014df104d657461") == Some(#"000643b04d657461")
}

/// `(444)` + body maps to `(100)` + the same body.
test cip68_reference_name_maps_the_444_label() {
  reference_name(#"001bc2804d657461") == Some(#"000643b04d657461")
}

/// Detection does not depend on the body length: a bare label is a CIP-68
/// name, and maps to the bare `(100)` label. Rejecting it is a registration
/// rule, not this function's.
test cip68_reference_name_detects_a_bare_label() {
  reference_name(#"0014df10") == Some(#"000643b0")
}

/// A plain name has no reference NFT.
test cip68_reference_name_is_none_for_a_plain_name() {
  reference_name("SEC") == None
}

/// The `(100)` label is the reference label, not a user-token label, so a
/// `(100)` name has no reference name of its own.
test cip68_reference_name_is_none_for_the_reference_label() {
  reference_name(#"000643b04d657461") == None
}

/// A name shorter than a label, or empty, cannot match, and must not trap.
test cip68_reference_name_is_none_for_a_short_or_empty_name() {
  and {
    reference_name(#"0014df") == None,
    reference_name(#"") == None,
  }
}

/// TRIPWIRE for the fixed slice width. `reference_name` compares and drops a
/// `cip67_label_length`-byte slice, so a label of any other length would match
/// nothing at all, or splice the wrong body — a hole no other test would
/// notice. Change one constant without the others and this fails instead of
/// the security property.
test cip68_labels_have_the_fixed_length() {
  and {
    bytearray.length(constants.cip68_reference_label) == constants.cip67_label_length,
    bytearray.length(constants.cip68_nft_label) == constants.cip67_label_length,
    bytearray.length(constants.cip68_ft_label) == constants.cip67_label_length,
    bytearray.length(constants.cip68_rft_label) == constants.cip67_label_length,
  }
}

// ── output_is_well_formed ────────────────────────────────────────────────────
//
// "Only ADA + exactly the reference token, and a correctly shaped datum." Each
// negative
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

/// `(100)` + "Y": a reference-labelled name with another body.
const t_other_ref_name: ByteArray = #"000643b059"

fn t_other_ref_value() -> Assets {
  merge(from_lovelace(2_000_000), from_asset(t_policy, t_other_ref_name, 1))
}

/// POSITIVE CONTROL: ADA + exactly one reference token + a CIP-68 datum.
test cip68_output_accepts_the_canonical_shape() {
  output_is_well_formed(
    t_output(t_ref_value(), t_datum()),
    t_policy,
    t_ref_name,
  )
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
    t_ref_name,
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
    t_ref_name,
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
    t_ref_name,
  )
}

/// A datum that is not the CIP-68 three-field constructor.
test cip68_output_rejects_a_malformed_datum() fail {
  output_is_well_formed(
    t_output(t_ref_value(), builtin.constr_data(0, [])),
    t_policy,
    t_ref_name,
  )
}

/// No inline datum at all.
test cip68_output_rejects_a_missing_datum() fail {
  output_is_well_formed(
    Output { ..t_output(t_ref_value(), t_datum()), datum: NoDatum },
    t_policy,
    t_ref_name,
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
  output_is_well_formed(
    t_output(t_ref_value(), wrong_tag),
    t_policy,
    t_ref_name,
  )
}

/// Right tag and field count, but `metadata` is an integer rather than a map.
/// The field TYPES are part of the shape; without this the check would only be
/// counting fields.
test cip68_output_rejects_non_map_metadata() fail {
  let wrong_types = builtin.constr_data(
    0,
    [builtin.i_data(42), builtin.i_data(1), builtin.constr_data(0, [])],
  )
  output_is_well_formed(
    t_output(t_ref_value(), wrong_types),
    t_policy,
    t_ref_name,
  )
}

/// The only token is a `(100)` name, but not the reference name the caller
/// derived: another body. A `(100)` label alone does not make an output this
/// token's metadata. POSITIVE CONTROL: `cip68_output_accepts_the_canonical_shape`,
/// whose output differs in exactly the asset name.
test cip68_output_rejects_a_wrong_body_reference() fail {
  output_is_well_formed(
    t_output(t_other_ref_value(), t_datum()),
    t_policy,
    t_ref_name,
  )
}

// ── enforce_if_reference ─────────────────────────────────────────────────────

/// A `(100)` name under the policed policy that is NOT the exact reference
/// name is not checked at all, even on a malformed output. This pins the
/// exact-name residue: protection is keyed on the derived name only.
test cip68_enforce_if_reference_ignores_a_non_matching_reference_label() {
  let output = t_output(t_other_ref_value(), builtin.constr_data(0, []))
  enforce_if_reference(
    tokens(output.value, t_policy),
    output,
    t_policy,
    t_ref_name,
  )
}

/// The exact reference name on a malformed output is checked, and traps.
/// Differs from the test above in exactly the asset name.
test cip68_enforce_if_reference_checks_the_exact_reference() fail {
  let output = t_output(t_ref_value(), builtin.constr_data(0, []))
  enforce_if_reference(
    tokens(output.value, t_policy),
    output,
    t_policy,
    t_ref_name,
  )
}
