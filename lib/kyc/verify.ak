use aiken/builtin
use aiken/collection/dict
use aiken/collection/pairs
use aiken/crypto.{blake2b_224, verify_ed25519_signature}
use aiken/interval.{
  Finite, Interval, IntervalBound, NegativeInfinity, PositiveInfinity,
}
use aiken/merkle_patricia_forestry as mpf
use aiken/primitive/bytearray
use cardano/address.{Credential, Script, VerificationKey}
use cardano/assets
use cardano/transaction.{Transaction}
use types/global_state.{GlobalStateDatum}
use types/kyc_proof.{
  Cip30Attestation, Cip30AttestationProof, KycProof, Membership, MembershipProof,
  credential_type_key, credential_type_script, issuer_vkey_length,
  max_protected_header_length, offset_credential_type, offset_network_id,
  offset_security_policy_id, offset_user_kyc_tier, offset_user_pkh,
  offset_valid_until_ms, payload_length, signature_length, tier_invalid,
  width_security_policy_id, width_user_pkh, width_valid_until_ms,
}
use utils

/// The rules of the signed 67-byte claim: it must bind exactly this holder
/// (hash AND credential type), a valid tier, this policy and network, and a
/// deadline no earlier than the transaction's (finite) upper bound.
pub fn verify_payload(
  payload: ByteArray,
  expected_credential: Credential,
  security_policy_id: ByteArray,
  network_id: Int,
  tx: Transaction,
) -> Bool {
  if bytearray.length(payload) != payload_length {
    False
  } else {
    let payload_user_pkh = bytearray.slice(
      payload,
      offset_user_pkh,
      offset_user_pkh + width_user_pkh - 1,
    )
    let payload_tier = builtin.index_bytearray(payload, offset_user_kyc_tier)
    let payload_ttl = bytearray.to_int_big_endian(
      bytearray.slice(
        payload,
        offset_valid_until_ms,
        offset_valid_until_ms + width_valid_until_ms - 1,
      ),
    )
    let payload_policy = bytearray.slice(
      payload,
      offset_security_policy_id,
      offset_security_policy_id + width_security_policy_id - 1,
    )
    let payload_network = builtin.index_bytearray(payload, offset_network_id)
    let payload_credential_type = builtin.index_bytearray(
      payload,
      offset_credential_type,
    )
    let ttl_ok = when tx.validity_range.upper_bound.bound_type is {
      Finite(tx_upper) -> tx_upper <= payload_ttl
      _ -> False
    }
    and {
      payload_user_pkh == utils.credential_hash(expected_credential),
      payload_credential_type == utils.credential_type_byte(expected_credential),
      payload_tier != tier_invalid,
      ttl_ok,
      payload_policy == security_policy_id,
      payload_network == network_id,
    }
  }
}

/// CBOR byte string: minimal head + bytes. Only used for lengths < 256, which
/// the callers guarantee (protected header ≤ 255; payload 67 or 28).
fn cbor_bytes(value: ByteArray) -> ByteArray {
  let size = builtin.length_of_bytearray(value)
  let head = if size < 24 {
    builtin.cons_bytearray(64 + size, #"")
  } else {
    builtin.cons_bytearray(0x58, builtin.cons_bytearray(size, #""))
  }
  builtin.append_bytearray(head, value)
}

/// The COSE (RFC 8152 §4.4) `Sig_structure` a CIP-30 wallet signs:
/// `["Signature1", protected, external_aad = h'', payload]`.
pub fn cip30_signed_message(
  protected_header: ByteArray,
  signed_payload: ByteArray,
) -> ByteArray {
  builtin.append_bytearray(
    // array(4), text(10) "Signature1"
    #"846a5369676e617475726531",
    builtin.append_bytearray(
      cbor_bytes(protected_header),
      builtin.append_bytearray(#"40", cbor_bytes(signed_payload)),
    ),
  )
}

/// Verify a trusted issuer's CIP-30 `signData` attestation from its parts.
///
/// True iff: lengths are sane (non-empty protected header ≤ 255 bytes,
/// 64-byte signature, 32-byte key); the key is a trusted issuer; the claim
/// passes `verify_payload` (which also requires the 67-byte length); and the issuer's Ed25519 signature verifies
/// over the rebuilt `Sig_structure` — over `blake2b_224(claim)` when `hashed`.
///
/// The protected header is deliberately NOT parsed: authorisation is the
/// trusted key, and the claim itself binds holder, policy, network and expiry.
/// That makes ANY `signData` by a trusted key over a valid claim (or its hash)
/// an attestation — so issuer keys must be dedicated to issuance (see the
/// integration guide). Cheap checks precede the hash and the Ed25519 builtin.
pub fn verify_cip30_attestation_proof(
  proof: Cip30AttestationProof,
  expected_credential: Credential,
  gs_datum: GlobalStateDatum,
  security_policy_id: ByteArray,
  network_id: Int,
  tx: Transaction,
) -> Bool {
  let header_length = bytearray.length(proof.protected_header)
  let lengths_ok = and {
    header_length > 0,
    header_length <= max_protected_header_length,
    bytearray.length(proof.signature) == signature_length,
    bytearray.length(proof.issuer_vkey) == issuer_vkey_length,
  }
  if !lengths_ok {
    False
  } else if !pairs.has_key(gs_datum.trusted_entity_vkeys, proof.issuer_vkey) {
    False
  } else if !verify_payload(
    proof.payload,
    expected_credential,
    security_policy_id,
    network_id,
    tx,
  ) {
    False
  } else {
    let signed_payload = if proof.hashed {
      blake2b_224(proof.payload)
    } else {
      proof.payload
    }
    verify_ed25519_signature(
      proof.issuer_vkey,
      cip30_signed_message(proof.protected_header, signed_payload),
      proof.signature,
    )
  }
}

/// Encode a millisecond timestamp as an 8-byte big-endian ByteArray.
pub fn encode_valid_until(ms: Int) -> ByteArray {
  bytearray.from_int_big_endian(ms, 8)
}

/// Build the MPF LEAF KEY for a membership entry.
///
/// `credential_type_byte ‖ hash` (29 bytes), not the bare 28-byte hash, so
/// a key credential and a script credential sharing a hash are DIFFERENT leaves
/// and cannot inherit each other's membership.
pub fn membership_leaf_key(credential: Credential) -> ByteArray {
  bytearray.concat(
    bytearray.from_int_big_endian(utils.credential_type_byte(credential), 1),
    utils.credential_hash(credential),
  )
}

/// Build the MPF LEAF VALUE for a membership entry.
///
/// `valid_until_ms(8) ‖ security_policy_id(28) ‖ network_id(1)` — the same
/// three bindings the attestation payload carries, so the two proof types are
/// genuinely interchangeable. Previously the value was the TTL alone, which left
/// a membership root portable between deployments and across networks.
pub fn membership_leaf_value(
  valid_until_ms: Int,
  security_policy_id: ByteArray,
  network_id: Int,
) -> ByteArray {
  bytearray.concat(
    bytearray.concat(encode_valid_until(valid_until_ms), security_policy_id),
    bytearray.from_int_big_endian(network_id, 1),
  )
}

/// Verify a Merkle Patricia Forestry membership proof for a given holder.
///
/// Returns True iff:
///   1. `proof.pkh` matches the expected credential's hash — a redundant but
///      cheap sanity binding; the authoritative key is derived below.
///   2. Tx validity upper bound is Finite and <= proof.valid_until_ms — the
///      membership has not expired relative to the transaction deadline.
///   3. `membership_leaf_key(expected_credential) → membership_leaf_value(...)`
///      is a valid leaf in the MPF tree committed to by `member_root_hash`.
///
/// Pure function — all state flows through arguments.
///
/// This variant commits to exactly what the attestation payload commits to: the
/// holder's credential CONSTRUCTOR as well as its hash (leaf key), and the
/// security policy id and network id (leaf value). An earlier revision bound
/// neither policy nor network, so two deployments sharing a membership root
/// accepted each other's proofs and a proof was not pinned to a network; and it
/// keyed on a bare hash, so a script credential inherited a verification key's
/// membership. The two proof types must be interchangeable, which means they
/// must bind the same things.
///
/// BREAKING, off-chain must move in LOCKSTEP: the leaf encoding changed on both
/// halves, so every existing membership root must be rebuilt with
/// `membership_leaf_key` / `membership_leaf_value` before
/// `UpdateMemberRootHash` is called. A root built the old way will simply fail
/// every proof — it fails CLOSED, not open.
///
/// KNOWN, UNHANDLED: `ttl_ok` on both proof paths ignores the validity bound's
/// `is_inclusive` flag. At most a 1 ms edge.
pub fn verify_membership_proof(
  proof: MembershipProof,
  expected_credential: Credential,
  gs_datum: GlobalStateDatum,
  security_policy_id: ByteArray,
  network_id: Int,
  tx: Transaction,
) -> Bool {
  and {
    // 1. Proof must reference the correct sender.
    proof.pkh == utils.credential_hash(expected_credential),
    // 2. Tx validity upper bound must be finite and within the membership TTL.
    when tx.validity_range.upper_bound.bound_type is {
      Finite(tx_upper) -> tx_upper <= proof.valid_until_ms
      _ -> False
    },
    // 3. The leaf must exist in the on-chain MPF tree committed to by
    //    member_root_hash. Key and value are derived from the EXPECTED
    //    credential and this deployment's own policy/network — never from the
    //    proof — so a proof cannot select which deployment it belongs to.
    mpf.has(
      mpf.from_root(gs_datum.member_root_hash),
      membership_leaf_key(expected_credential),
      membership_leaf_value(
        proof.valid_until_ms,
        security_policy_id,
        network_id,
      ),
      proof.mpf_proof,
    ),
  }
}

/// Dispatch a KYC proof to the appropriate verifier based on its variant.
///
/// - `Cip30Attestation`: delegates to `verify_cip30_attestation_proof` — a
///   trusted issuer signs, through CIP-30 `signData`, a claim that embeds the
///   user's credential, tier, TTL, security policy and network.
/// - `Membership`: delegates to `verify_membership_proof` — the user PKH and
///   TTL must exist as a leaf in the on-chain MPF membership tree.
///
/// Both variants take the holder's full `Credential`, not a bare hash —
/// the constructor is part of the identity being attested.
///
/// Returns True iff the selected verifier returns True.
/// Pure function — all state flows through arguments.
pub fn verify_kyc_proof(
  proof: KycProof,
  expected_credential: Credential,
  gs_datum: GlobalStateDatum,
  security_policy_id: ByteArray,
  network_id: Int,
  tx: Transaction,
) -> Bool {
  when proof is {
    Membership { membership_proof } ->
      verify_membership_proof(
        membership_proof,
        expected_credential,
        gs_datum,
        security_policy_id,
        network_id,
        tx,
      )
    Cip30Attestation { cip30_proof } ->
      verify_cip30_attestation_proof(
        cip30_proof,
        expected_credential,
        gs_datum,
        security_policy_id,
        network_id,
        tx,
      )
  }
}

// ============================================================================
// Tests
// ============================================================================

// ── Test constants ────────────────────────────────────────────────────────────

// 28-byte payment key hash used across all proof tests.
const test_user_pkh: ByteArray =
  #"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

// 28-byte security token policy ID used in attestation tests.
const test_security_policy_id: ByteArray =
  #"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

// 32-byte Ed25519 verification key representing the trusted issuer. This is
// a GENUINE key, not a placeholder: it is the public half of the fixed-seed
// test key pair. The CIP-30 vectors below are genuine signatures from this
// key.
const test_issuer_vkey: ByteArray =
  #"03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8"

// POSIX millisecond TTL well beyond test_tx_upper.
const test_ttl_ms: Int = 100_000_000

// Transaction validity upper bound strictly below test_ttl_ms.
const test_tx_upper: Int = 50_000_000

// preprod network identifier.
const test_network_id: Int = 1

// ── A raw signature, for the cross-format negative ───────────────────────────
// Genuine Ed25519 signature by the fixed-seed test key (`test_issuer_vkey`)
// over the BARE claim `make_payload(test_user_pkh, 1, test_ttl_ms,
// test_security_policy_id, test_network_id)` — the removed raw format. Kept
// only to prove such a signature is not accepted as a CIP-30 one.
const test_raw_signature_over_the_claim: ByteArray =
  #"e21761b04b625ba34551d8fd4203d0af1087606ff16f7af2aa34164b94e31063947229dde38f53ae65f203006ebd828af8f266fb5ff761c9ce83bf640f12160e"

// ── Test helpers ──────────────────────────────────────────────────────────────

/// Build the 67-byte attestation payload from explicit field values.
/// Layout mirrors the KycProof spec:
/// pkh(28)|tier(1)|ttl(8)|policy(28)|net(1)|cred_type(1).
fn make_payload(
  user_pkh: ByteArray,
  tier: Int,
  ttl_ms: Int,
  security_policy_id: ByteArray,
  network_id: Int,
) -> ByteArray {
  make_payload_for(
    user_pkh,
    tier,
    ttl_ms,
    security_policy_id,
    network_id,
    credential_type_key,
  )
}

/// Same, with the credential-type byte varied — the discriminator is what
/// stops an attestation issued for a verification key being replayed for a
/// script credential sharing its hash.
fn make_payload_for(
  user_pkh: ByteArray,
  tier: Int,
  ttl_ms: Int,
  security_policy_id: ByteArray,
  network_id: Int,
  credential_type: Int,
) -> ByteArray {
  bytearray.concat(
    bytearray.concat(
      bytearray.concat(
        bytearray.concat(
          bytearray.concat(user_pkh, bytearray.from_int_big_endian(tier, 1)),
          encode_valid_until(ttl_ms),
        ),
        security_policy_id,
      ),
      bytearray.from_int_big_endian(network_id, 1),
    ),
    bytearray.from_int_big_endian(credential_type, 1),
  )
}

/// The test holder as a verification-key credential.
fn test_user_cred() -> Credential {
  VerificationKey(test_user_pkh)
}

/// Return a Trusted Entity List containing only test_issuer_vkey.
fn test_tel() -> Pairs<ByteArray, Data> {
  [Pair(test_issuer_vkey, builtin.constr_data(0, []))]
}

/// GlobalStateDatum with the given TEL and an empty membership tree.
fn test_gs_datum_with_tel(
  trusted_keys: Pairs<ByteArray, Data>,
) -> GlobalStateDatum {
  GlobalStateDatum {
    global_state_script_credential_hash: #"9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a",
    transfers_paused: False,
    deactivated: False,
    mintable_amount: 0,
    admin_credential_hash: #"",
    power_user_linked_list_policy_id: #"",
    denylist_linked_list_policy_id: #"",
    security_info: builtin.constr_data(0, []),
    trusted_entity_vkeys: trusted_keys,
    member_root_hash: #"",
    requires_sender_kyc: True,
    requires_receiver_kyc: True,
    network_id: test_network_id,
    minting_script_credential_hash: #"",
    upgrades_locked: False,
    approval_required: False,
    approval_threshold: 0,
    approval_logic_hash: #"a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7",
  }
}

/// GlobalStateDatum with an empty TEL and the given MPF root hash.
fn test_gs_datum_with_root(root: ByteArray) -> GlobalStateDatum {
  GlobalStateDatum {
    global_state_script_credential_hash: #"9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a",
    transfers_paused: False,
    deactivated: False,
    mintable_amount: 0,
    admin_credential_hash: #"",
    power_user_linked_list_policy_id: #"",
    denylist_linked_list_policy_id: #"",
    security_info: builtin.constr_data(0, []),
    trusted_entity_vkeys: [],
    member_root_hash: root,
    requires_sender_kyc: True,
    requires_receiver_kyc: True,
    network_id: test_network_id,
    minting_script_credential_hash: #"",
    upgrades_locked: False,
    approval_required: False,
    approval_threshold: 0,
    approval_logic_hash: #"a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7",
  }
}

/// Transaction whose validity window closes at `upper` ms (Finite upper bound).
fn tx_with_upper_bound(upper: Int) -> Transaction {
  Transaction {
    inputs: [],
    reference_inputs: [],
    outputs: [],
    fee: 0,
    mint: assets.zero,
    certificates: [],
    withdrawals: [],
    validity_range: Interval {
      lower_bound: IntervalBound {
        bound_type: NegativeInfinity,
        is_inclusive: True,
      },
      upper_bound: IntervalBound {
        bound_type: Finite(upper),
        is_inclusive: True,
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

/// Transaction with no deadline (PositiveInfinity upper bound).
fn tx_with_infinite_upper() -> Transaction {
  Transaction {
    inputs: [],
    reference_inputs: [],
    outputs: [],
    fee: 0,
    mint: assets.zero,
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

// ── encode_valid_until ────────────────────────────────────────────────────────

test encode_valid_until_encodes_zero_as_eight_zero_bytes() {
  encode_valid_until(0) == #"0000000000000000"
}

test encode_valid_until_encodes_value_big_endian() {
  // 100_000_000 = 0x05F5E100 — verify 8-byte big-endian layout
  encode_valid_until(100_000_000) == #"0000000005f5e100"
}

// ── verify_payload — the claim rules every attestation enforces ──────────────
// Signature-free, so each rule is pinned on its own; the CIP-30 tests below
// pin the same rules end to end under a genuine signature. (These replace the
// raw-attestation tests removed with the raw format on 2026-10-15.)

fn claim_ok(payload: ByteArray, credential: Credential, tx: Transaction) -> Bool {
  verify_payload(
    payload,
    credential,
    test_security_policy_id,
    test_network_id,
    tx,
  )
}

fn valid_claim() -> ByteArray {
  make_payload(
    test_user_pkh,
    1,
    test_ttl_ms,
    test_security_policy_id,
    test_network_id,
  )
}

test verify_payload_accepts_a_valid_key_claim() {
  claim_ok(valid_claim(), test_user_cred(), tx_with_upper_bound(test_tx_upper))
}

test verify_payload_accepts_a_valid_script_claim() {
  claim_ok(
    make_payload_for(
      test_user_pkh,
      1,
      test_ttl_ms,
      test_security_policy_id,
      test_network_id,
      credential_type_script,
    ),
    Script(test_user_pkh),
    tx_with_upper_bound(test_tx_upper),
  )
}

// The deadline is inclusive: a transaction ending exactly at it is accepted.
test verify_payload_accepts_a_deadline_equal_to_the_upper_bound() {
  claim_ok(valid_claim(), test_user_cred(), tx_with_upper_bound(test_ttl_ms))
}

test verify_payload_rejects_a_short_claim() {
  !claim_ok(#"aabb", test_user_cred(), tx_with_upper_bound(test_tx_upper))
}

test verify_payload_rejects_a_long_claim() {
  !claim_ok(
    bytearray.concat(valid_claim(), #"ff"),
    test_user_cred(),
    tx_with_upper_bound(test_tx_upper),
  )
}

test verify_payload_rejects_another_holder() {
  !claim_ok(
    make_payload(
      #"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
      1,
      test_ttl_ms,
      test_security_policy_id,
      test_network_id,
    ),
    test_user_cred(),
    tx_with_upper_bound(test_tx_upper),
  )
}

test verify_payload_rejects_the_invalid_tier() {
  !claim_ok(
    make_payload(
      test_user_pkh,
      tier_invalid,
      test_ttl_ms,
      test_security_policy_id,
      test_network_id,
    ),
    test_user_cred(),
    tx_with_upper_bound(test_tx_upper),
  )
}

test verify_payload_rejects_an_expired_claim() {
  !claim_ok(
    valid_claim(),
    test_user_cred(),
    tx_with_upper_bound(test_ttl_ms + 1),
  )
}

// No finite upper bound: the deadline cannot be checked, so it is refused.
test verify_payload_rejects_an_unbounded_transaction() {
  !claim_ok(valid_claim(), test_user_cred(), tx_with_infinite_upper())
}

test verify_payload_rejects_another_policy() {
  !claim_ok(
    make_payload(
      test_user_pkh,
      1,
      test_ttl_ms,
      #"ffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
      test_network_id,
    ),
    test_user_cred(),
    tx_with_upper_bound(test_tx_upper),
  )
}

test verify_payload_rejects_another_network() {
  !claim_ok(
    make_payload(
      test_user_pkh,
      1,
      test_ttl_ms,
      test_security_policy_id,
      test_network_id + 1,
    ),
    test_user_cred(),
    tx_with_upper_bound(test_tx_upper),
  )
}

// The credential type is part of the identity: a claim for a key does not
// cover the script with the same hash, nor the other way round.
test verify_payload_rejects_a_key_claim_for_a_script() {
  !claim_ok(
    valid_claim(),
    Script(test_user_pkh),
    tx_with_upper_bound(test_tx_upper),
  )
}

test verify_payload_rejects_a_script_claim_for_a_key() {
  !claim_ok(
    make_payload_for(
      test_user_pkh,
      1,
      test_ttl_ms,
      test_security_policy_id,
      test_network_id,
      credential_type_script,
    ),
    test_user_cred(),
    tx_with_upper_bound(test_tx_upper),
  )
}

// ── Membership leaf encoding ─────────────────────────────────────────────────

/// The two credential forms of one hash must produce DIFFERENT leaf keys,
/// otherwise a script credential inherits a verification key's membership.
test membership_leaf_key_separates_credential_forms() {
  and {
    membership_leaf_key(VerificationKey(test_user_pkh)) != membership_leaf_key(
      Script(test_user_pkh),
    ),
    // …and each is the 1-byte tag followed by the hash, so the tag cannot be
    // confused with the first byte of a hash.
    membership_leaf_key(VerificationKey(test_user_pkh)) == bytearray.concat(
      #"00",
      test_user_pkh,
    ),
    membership_leaf_key(Script(test_user_pkh)) == bytearray.concat(
      #"01",
      test_user_pkh,
    ),
  }
}

/// The leaf value must commit to the policy id and the network id, not
/// just the TTL — otherwise a membership root is portable between deployments
/// and across networks.
test membership_leaf_value_binds_policy_and_network() {
  let other_policy = #"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
  and {
    membership_leaf_value(test_ttl_ms, test_security_policy_id, 1) != membership_leaf_value(
      test_ttl_ms,
      other_policy,
      1,
    ),
    membership_leaf_value(test_ttl_ms, test_security_policy_id, 1) != membership_leaf_value(
      test_ttl_ms,
      test_security_policy_id,
      2,
    ),
    // 8-byte TTL + 28-byte policy + 1-byte network.
    bytearray.length(
      membership_leaf_value(test_ttl_ms, test_security_policy_id, 1),
    ) == 37,
  }
}

// ── verify_membership_proof ───────────────────────────────────────────────────

test membership_fails_when_pkh_mismatch() {
  // proof.pkh != expected_user_pkh → short-circuits before TTL / MPF checks
  let different_pkh = #"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
  let proof = MembershipProof {
    pkh: test_user_pkh,
    valid_until_ms: test_ttl_ms,
    mpf_proof: [],
  }
  !verify_membership_proof(
    proof,
    VerificationKey(different_pkh),
    test_gs_datum_with_root(#""),
    test_security_policy_id,
    test_network_id,
    tx_with_upper_bound(test_tx_upper),
  )
}

test membership_fails_when_ttl_expired() {
  // valid_until_ms = tx_upper - 1 → tx_upper <= valid_until_ms is False
  let expired_ttl = test_tx_upper - 1
  let root = mpf.empty
    |> mpf.insert(
        membership_leaf_key(test_user_cred()),
        membership_leaf_value(
          expired_ttl,
          test_security_policy_id,
          test_network_id,
        ),
        [],
      )
    |> mpf.root()
  let proof = MembershipProof {
    pkh: test_user_pkh,
    valid_until_ms: expired_ttl,
    mpf_proof: [],
  }
  !verify_membership_proof(
    proof,
    test_user_cred(),
    test_gs_datum_with_root(root),
    test_security_policy_id,
    test_network_id,
    tx_with_upper_bound(test_tx_upper),
  )
}

test membership_fails_when_upper_bound_is_infinite() {
  // PositiveInfinity hits the `_ -> False` branch
  let root = mpf.empty
    |> mpf.insert(
        membership_leaf_key(test_user_cred()),
        membership_leaf_value(
          test_ttl_ms,
          test_security_policy_id,
          test_network_id,
        ),
        [],
      )
    |> mpf.root()
  let proof = MembershipProof {
    pkh: test_user_pkh,
    valid_until_ms: test_ttl_ms,
    mpf_proof: [],
  }
  !verify_membership_proof(
    proof,
    test_user_cred(),
    test_gs_datum_with_root(root),
    test_security_policy_id,
    test_network_id,
    tx_with_infinite_upper(),
  )
}

test membership_fails_when_mpf_proof_is_wrong() {
  // pkh and TTL checks pass; empty proof cannot satisfy a real 32-byte root.
  // mpf.from_root requires exactly 32 bytes (blake2b_256 digest size).
  let fake_root = #"0000000000000000000000000000000000000000000000000000000000000000"
  let proof = MembershipProof {
    pkh: test_user_pkh,
    valid_until_ms: test_ttl_ms,
    mpf_proof: [],
  }
  !verify_membership_proof(
    proof,
    test_user_cred(),
    test_gs_datum_with_root(fake_root),
    test_security_policy_id,
    test_network_id,
    tx_with_upper_bound(test_tx_upper),
  )
}

// ── verify_membership_proof — positive controls ───────────────────────────────
// Every negative test above proves the verifier rejects a specific defect —
// none of them proves it can ever accept anything true. These build a REAL
// root with the vendored MPF library itself (never hand-pasted) so the
// verifier is checked against a root nobody could get right by accident.

/// A single-leaf tree containing exactly the expected credential's leaf, with
/// an empty inclusion proof (correct for a one-leaf trie), must verify.
test membership_succeeds_with_a_genuine_single_leaf_root() {
  let root = mpf.empty
    |> mpf.insert(
        membership_leaf_key(test_user_cred()),
        membership_leaf_value(
          test_ttl_ms,
          test_security_policy_id,
          test_network_id,
        ),
        [],
      )
    |> mpf.root()
  let proof = MembershipProof {
    pkh: test_user_pkh,
    valid_until_ms: test_ttl_ms,
    mpf_proof: [],
  }
  verify_membership_proof(
    proof,
    test_user_cred(),
    test_gs_datum_with_root(root),
    test_security_policy_id,
    test_network_id,
    tx_with_upper_bound(test_tx_upper),
  )
}

/// The Script-credential twin: a single-leaf tree built for
/// `Script(test_user_pkh)` (a DIFFERENT leaf key than the VerificationKey
/// form — see `membership_leaf_key_separates_credential_forms`) must verify
/// against that same Script credential.
test membership_succeeds_with_a_genuine_single_leaf_root_for_a_script_credential() {
  let script_cred = Script(test_user_pkh)
  let root = mpf.empty
    |> mpf.insert(
        membership_leaf_key(script_cred),
        membership_leaf_value(
          test_ttl_ms,
          test_security_policy_id,
          test_network_id,
        ),
        [],
      )
    |> mpf.root()
  let proof = MembershipProof {
    pkh: test_user_pkh,
    valid_until_ms: test_ttl_ms,
    mpf_proof: [],
  }
  verify_membership_proof(
    proof,
    script_cred,
    test_gs_datum_with_root(root),
    test_security_policy_id,
    test_network_id,
    tx_with_upper_bound(test_tx_upper),
  )
}

/// Pins that the positive test above passes for the RIGHT reason: the SAME
/// genuine root — built for the VerificationKey form only — does not also
/// satisfy the Script form of the identical hash. `membership_leaf_key`
/// making the two forms different leaves is only meaningful if
/// `verify_membership_proof` actually looks up the right one; this proves it
/// does, using a real library-computed root rather than an empty placeholder.
test membership_genuine_root_rejects_other_credential() {
  let root = mpf.empty
    |> mpf.insert(
        membership_leaf_key(test_user_cred()),
        membership_leaf_value(
          test_ttl_ms,
          test_security_policy_id,
          test_network_id,
        ),
        [],
      )
    |> mpf.root()
  let proof = MembershipProof {
    pkh: test_user_pkh,
    valid_until_ms: test_ttl_ms,
    mpf_proof: [],
  }
  !verify_membership_proof(
    proof,
    Script(test_user_pkh),
    test_gs_datum_with_root(root),
    test_security_policy_id,
    test_network_id,
    tx_with_upper_bound(test_tx_upper),
  )
}

// ── verify_kyc_proof — dispatch ───────────────────────────────────────────────

test kyc_proof_routes_membership_variant() {
  // PKH mismatch → verify_membership_proof returns False,
  // confirming the Membership branch is reached.
  let different_pkh = #"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
  let proof = Membership {
    membership_proof: MembershipProof {
      pkh: test_user_pkh,
      valid_until_ms: test_ttl_ms,
      mpf_proof: [],
    },
  }
  !verify_kyc_proof(
    proof,
    VerificationKey(different_pkh),
    test_gs_datum_with_root(#""),
    test_security_policy_id,
    test_network_id,
    tx_with_upper_bound(test_tx_upper),
  )
}

// ── verify_kyc_proof — dispatch positive controls ─────────────────────────────
// The test above proves routing on the REJECT path — it would pass even if
// `verify_kyc_proof` always returned False. This proves the ACCEPT path is
// reachable through the dispatcher too. (The CIP-30 tests below all run
// through `verify_kyc_proof`, so they cover its routing both ways.)

test kyc_proof_routes_membership_variant_and_accepts_a_genuine_proof() {
  let root = mpf.empty
    |> mpf.insert(
        membership_leaf_key(test_user_cred()),
        membership_leaf_value(
          test_ttl_ms,
          test_security_policy_id,
          test_network_id,
        ),
        [],
      )
    |> mpf.root()
  let proof = Membership {
    membership_proof: MembershipProof {
      pkh: test_user_pkh,
      valid_until_ms: test_ttl_ms,
      mpf_proof: [],
    },
  }
  verify_kyc_proof(
    proof,
    test_user_cred(),
    test_gs_datum_with_root(root),
    test_security_policy_id,
    test_network_id,
    tx_with_upper_bound(test_tx_upper),
  )
}

// Genuine CIP-30 parts, generated off-repository with a public TEST seed. The
// hashed (Ledger-style) vectors were cross-checked when generated: Emurgo's
// cardano-message-signing 1.1.0 (`hash_payload()` + its own Sig_structure)
// produced BYTE-IDENTICAL signatures — Ed25519 is deterministic, so it built
// exactly the same signed bytes.

fn run_cip30(proof: KycProof) -> Bool {
  verify_kyc_proof(
    proof,
    test_user_cred(),
    test_gs_datum_with_tel(test_tel()),
    test_security_policy_id,
    test_network_id,
    tx_with_upper_bound(test_tx_upper),
  )
}

fn cip30(
  protected_header: ByteArray,
  payload: ByteArray,
  hashed: Bool,
  signature: ByteArray,
) -> KycProof {
  Cip30Attestation {
    cip30_proof: Cip30AttestationProof {
      protected_header,
      payload,
      hashed,
      signature,
      issuer_vkey: test_issuer_vkey,
    },
  }
}

fn cip30_unit_valid() -> KycProof {
  cip30(
    #"a201276761646472657373581d6027e38d0e19e3434e33fbd001d3fe04b5b76763f88acd625e0d770b43",
    #"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa010000000005f5e100bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb0100",
    False,
    #"b98e5f45c6b54500cf64d816928f8bd81ec095d85c12e642c4204325df16f06943e6d8a1ae82796f4dd91fe71caa31e7e2cf5356b7a96d7ba1a1bd10482b2b06",
  )
}

fn cip30_unit_hashed_valid() -> KycProof {
  cip30(
    #"a201276761646472657373581d6027e38d0e19e3434e33fbd001d3fe04b5b76763f88acd625e0d770b43",
    #"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa010000000005f5e100bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb0100",
    True,
    #"2a51077b605a1e9610a3aede92105263bb225d843a584d5a14412c234c273f3097fecc734ee44150c688bf59fc0a35ccd4c42de2e140a12cda572475e5faf60a",
  )
}

fn cip30_protected_len_1() -> KycProof {
  cip30(
    #"a0",
    #"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa010000000005f5e100bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb0100",
    False,
    #"e83c0442a80ad5aceb304df48510e8c294d75592a2f20d5dfeca94f47b65995fe619ba62d36057b7ece3cc4003bdbada7e3bca1e65cb37f17e436e2ae6388c03",
  )
}

fn cip30_protected_len_23() -> KycProof {
  cip30(
    #"a161705370707070707070707070707070707070707070",
    #"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa010000000005f5e100bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb0100",
    False,
    #"c5a7453e6ff4b6ea3161f90dce664f15b22e270d48957bd707ba0d46b67179e69560191b6ddf1175fcc83eae4e4ec09f0774c0ecebf20decc70ba9cc7a3fea0f",
  )
}

fn cip30_protected_len_24() -> KycProof {
  cip30(
    #"a16170547070707070707070707070707070707070707070",
    #"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa010000000005f5e100bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb0100",
    False,
    #"a8562bbd33fa07f5092dc9f8bd4dae7b7967c0cede7a8324d5a21595870dfbd546550ca378f697586a1ec81be09531a1900d1039a5858328e10392f00c8d0600",
  )
}

fn cip30_protected_len_255() -> KycProof {
  cip30(
    #"a1617058fa70707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070",
    #"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa010000000005f5e100bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb0100",
    False,
    #"c8c90b9df1cc789918751fe76cef79d9f4054fe9e53c6157d3b87b8fce7a5d9dadc05885c14bef03195a499bbbeadaf87227875dee32ed32e1ce7a3ef3460401",
  )
}

fn cip30_protected_len_0() -> KycProof {
  cip30(
    #"",
    #"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa010000000005f5e100bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb0100",
    False,
    #"fa61c9a25a2c669c8dcb197fc3c55f5f635fe57e0ab42848bf4d697e1aff943a8b8e590856143104739412b0256b9f0a45991b06f801d1fbd4f25171e4b34f0d",
  )
}

fn cip30_protected_len_256() -> KycProof {
  cip30(
    #"a1617058fb7070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070",
    #"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa010000000005f5e100bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb0100",
    False,
    #"010d6ddf6171fdbfac51813b46be9c8cb5376af25deef1250f731c038b146f58c00c9d5788f75ecfb2e338bf24b1a70b36c7e95ef41aa376356662de8990c00f",
  )
}

fn cip30_invalid_tier() -> KycProof {
  cip30(
    #"a201276761646472657373581d6027e38d0e19e3434e33fbd001d3fe04b5b76763f88acd625e0d770b43",
    #"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa000000000005f5e100bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb0100",
    False,
    #"79f95df2f99f53cfe62b35da88e4cba63c9ff5a764d4ec5d20c0266c90d1832ea102a23979291797eb281e72c888e1d1952fac5d50b0e0a49ccf2c1df0d1b30e",
  )
}

fn cip30_expired() -> KycProof {
  cip30(
    #"a201276761646472657373581d6027e38d0e19e3434e33fbd001d3fe04b5b76763f88acd625e0d770b43",
    #"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa010000000002faf07fbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb0100",
    False,
    #"22db94609086fae5f1964e9e0c63c4551fbb919f8b1a1e5cbbdb2a341870604f1de5cce624d7a8ff058ca56f48c0c60203d98aed87203da80ea237c8470ae10c",
  )
}

fn cip30_wrong_holder() -> KycProof {
  cip30(
    #"a201276761646472657373581d6027e38d0e19e3434e33fbd001d3fe04b5b76763f88acd625e0d770b43",
    #"dddddddddddddddddddddddddddddddddddddddddddddddddddddddd010000000005f5e100bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb0100",
    False,
    #"eefa4f374897f19632b974b02346c80843b2300c38f72b134e9ab38d792e0cc198f03422411d9636b6ec59b91dff51cc7fca3e242dc345ad1b674d7aaf20770c",
  )
}

fn cip30_wrong_policy() -> KycProof {
  cip30(
    #"a201276761646472657373581d6027e38d0e19e3434e33fbd001d3fe04b5b76763f88acd625e0d770b43",
    #"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa010000000005f5e100ffffffffffffffffffffffffffffffffffffffffffffffffffffffff0100",
    False,
    #"047d304d3198fde7a4435ed8c9db6a0025248c69de99edffa2696a291d741a361cd89d326cd3c4fb45651cff3ff272bd95954b5d2ad10be5aaf2b9d9365f200c",
  )
}

fn cip30_wrong_kyc_network() -> KycProof {
  cip30(
    #"a201276761646472657373581d6027e38d0e19e3434e33fbd001d3fe04b5b76763f88acd625e0d770b43",
    #"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa010000000005f5e100bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb0200",
    False,
    #"8681b8455b0fc5eda9f66938daca961e66abd50718b4ac22bdd607f1555aeff037439548801476c00e1e7cfaf6aae2a8d5048739603e584ea39512fdc0e8080b",
  )
}

fn cip30_wrong_credential_type() -> KycProof {
  cip30(
    #"a201276761646472657373581d6027e38d0e19e3434e33fbd001d3fe04b5b76763f88acd625e0d770b43",
    #"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa010000000005f5e100bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb0101",
    False,
    #"59b8cf37eb530f20b11e6f423303471088222779586f6463ebc0df361b4e5386dd4da22dad8e93b90201e832abe11381f75dc21377a35a9bc23b02916ec97708",
  )
}

fn with_cip30(
  proof: KycProof,
  edit: fn(Cip30AttestationProof) -> Cip30AttestationProof,
) -> KycProof {
  expect Cip30Attestation { cip30_proof } = proof
  Cip30Attestation { cip30_proof: edit(cip30_proof) }
}

/// Flip the claim's tier byte 0x01 -> 0x02: still a VALID claim (tier != 0),
/// so only the signature check can reject it.
fn bump_tier(p: Cip30AttestationProof) -> Cip30AttestationProof {
  Cip30AttestationProof {
    ..p,
    payload: builtin.cons_bytearray(
      2,
      bytearray.drop(p.payload, offset_user_kyc_tier + 1),
    )
      |> builtin.append_bytearray(
          bytearray.take(p.payload, offset_user_kyc_tier),
          _,
        ),
  }
}

test cip30_accepts_a_genuine_unhashed_proof() {
  run_cip30(cip30_unit_valid())
}

test cip30_accepts_a_genuine_hashed_proof() {
  run_cip30(cip30_unit_hashed_valid())
}

// Protected-header bstr re-wrap boundaries: 40+n for n < 24, 58 n up to 255.
test cip30_accepts_protected_header_length_1() {
  run_cip30(cip30_protected_len_1())
}

test cip30_accepts_protected_header_length_23() {
  run_cip30(cip30_protected_len_23())
}

test cip30_accepts_protected_header_length_24() {
  run_cip30(cip30_protected_len_24())
}

test cip30_accepts_protected_header_length_255() {
  run_cip30(cip30_protected_len_255())
}

// Genuinely signed, but outside the accepted bounds — only the length rule rejects.
test cip30_rejects_a_genuinely_signed_empty_protected_header() {
  !run_cip30(cip30_protected_len_0())
}

test cip30_rejects_a_genuinely_signed_256_byte_protected_header() {
  // Refused by the length bound, before any encoding (cbor_bytes covers < 256).
  !run_cip30(cip30_protected_len_256())
}

test cip30_rejects_an_untrusted_issuer() {
  !verify_kyc_proof(
    cip30_unit_valid(),
    test_user_cred(),
    test_gs_datum_with_tel([]),
    test_security_policy_id,
    test_network_id,
    tx_with_upper_bound(test_tx_upper),
  )
}

// A wrong-length key that IS in the trusted list: only the length rule rejects.
test cip30_rejects_a_trusted_but_wrong_length_key() {
  let short_key = bytearray.take(test_issuer_vkey, 31)
  !verify_kyc_proof(
    with_cip30(
      cip30_unit_valid(),
      fn(p) { Cip30AttestationProof { ..p, issuer_vkey: short_key } },
    ),
    test_user_cred(),
    test_gs_datum_with_tel([Pair(short_key, builtin.constr_data(0, []))]),
    test_security_policy_id,
    test_network_id,
    tx_with_upper_bound(test_tx_upper),
  )
}

// The 67-byte payload length is enforced in the shared `verify_payload`.
test cip30_rejects_a_wrong_length_payload() {
  !run_cip30(
    with_cip30(
      cip30_unit_valid(),
      fn(p) {
        Cip30AttestationProof {
          ..p,
          payload: builtin.append_bytearray(p.payload, #"00"),
        }
      },
    ),
  )
}

test cip30_rejects_a_wrong_length_signature() {
  !run_cip30(
    with_cip30(
      cip30_unit_valid(),
      fn(p) {
        Cip30AttestationProof {
          ..p,
          signature: bytearray.take(p.signature, 63),
        }
      },
    ),
  )
}

// `hashed` is unsigned (unprotected header) — flipping it changes the payload
// slot's length (58 43 vs 58 1c), so it can never re-interpret a signature.
test cip30_rejects_a_hashed_proof_presented_as_unhashed() {
  !run_cip30(
    with_cip30(
      cip30_unit_hashed_valid(),
      fn(p) { Cip30AttestationProof { ..p, hashed: False } },
    ),
  )
}

test cip30_rejects_an_unhashed_proof_presented_as_hashed() {
  !run_cip30(
    with_cip30(
      cip30_unit_valid(),
      fn(p) { Cip30AttestationProof { ..p, hashed: True } },
    ),
  )
}

// Byte flips that keep the claim valid, so only the signature can reject.
test cip30_rejects_a_changed_claim_unhashed() {
  !run_cip30(with_cip30(cip30_unit_valid(), bump_tier))
}

test cip30_rejects_a_changed_claim_hashed() {
  !run_cip30(with_cip30(cip30_unit_hashed_valid(), bump_tier))
}

test cip30_rejects_a_changed_protected_header() {
  // One byte inside the signed address flipped, same length — only the
  // signature check can reject it.
  !run_cip30(
    with_cip30(
      cip30_unit_valid(),
      fn(p) {
        let h = p.protected_header
        Cip30AttestationProof {
          ..p,
          protected_header: builtin.append_bytearray(
            bytearray.take(h, 20),
            builtin.cons_bytearray(
              builtin.index_bytearray(h, 20) + 1,
              bytearray.drop(h, 21),
            ),
          ),
        }
      },
    ),
  )
}

test cip30_rejects_a_changed_signature() {
  !run_cip30(
    with_cip30(
      cip30_unit_valid(),
      fn(p) {
        Cip30AttestationProof {
          ..p,
          signature: builtin.cons_bytearray(0, bytearray.drop(p.signature, 1)),
        }
      },
    ),
  )
}

// Genuine signatures over claims the shared claim rules refuse.
test cip30_rejects_signed_invalid_tier() {
  !run_cip30(cip30_invalid_tier())
}

test cip30_rejects_signed_expired_claim() {
  !run_cip30(cip30_expired())
}

test cip30_rejects_signed_wrong_holder() {
  !run_cip30(cip30_wrong_holder())
}

test cip30_rejects_signed_wrong_policy() {
  !run_cip30(cip30_wrong_policy())
}

test cip30_rejects_signed_wrong_kyc_network() {
  !run_cip30(cip30_wrong_kyc_network())
}

test cip30_rejects_signed_wrong_credential_type() {
  !run_cip30(cip30_wrong_credential_type())
}

// A raw Ed25519 signature over the bare claim (the removed raw format) is not
// a CIP-30 signature: the signed bytes differ, so it never verifies.
test cip30_rejects_a_raw_attestation_signature() {
  // test_raw_signature_over_the_claim is a genuine RAW signature over this claim.
  !run_cip30(
    with_cip30(
      cip30_unit_valid(),
      fn(p) {
        Cip30AttestationProof {
          ..p,
          signature: test_raw_signature_over_the_claim,
        }
      },
    ),
  )
}
