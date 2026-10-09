#!/usr/bin/env node
// Deterministic, genuine CIP-30/CIP-8 COSE vectors. This fixed test seed is
// public and must never be used as an issuer's production signing key.
// Run: node scripts/cip30-test-vectors.mjs
import { createPrivateKey, createPublicKey, sign } from "node:crypto";

const seed = Buffer.from(Array.from({ length: 32 }, (_, i) => i));
const key = createPrivateKey({
  key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]),
  format: "der",
  type: "pkcs8",
});
const vkey = createPublicKey(key).export({ format: "der", type: "spki" }).subarray(-32);
// BLAKE2b-224(vkey), independently reproducible with Python:
// hashlib.blake2b(bytes.fromhex(vkey_hex), digest_size=28).hexdigest()
const issuerPkh = Buffer.from("27e38d0e19e3434e33fbd001d3fe04b5b76763f88acd625e0d770b43", "hex");

// BLAKE2b (RFC 7693), variable output length — Node's crypto has no BLAKE2b-224.
// Cross-checked against Python: hashlib.blake2b(data, digest_size=28).
const M64 = (1n << 64n) - 1n;
const IV = [0x6a09e667f3bcc908n, 0xbb67ae8584caa73bn, 0x3c6ef372fe94f82bn, 0xa54ff53a5f1d36f1n,
  0x510e527fade682d1n, 0x9b05688c2b3e6c1fn, 0x1f83d9abfb41bd6bn, 0x5be0cd19137e2179n];
const SIGMA = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15], [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
  [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4], [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
  [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13], [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
  [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11], [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
  [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5], [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0]];
const rotr = (x, n) => ((x >> BigInt(n)) | (x << BigInt(64 - n))) & M64;
function blake2b(data, outLen) {
  const h = IV.slice();
  h[0] ^= 0x01010000n ^ BigInt(outLen);
  const blocks = Math.max(1, Math.ceil(data.length / 128));
  for (let b = 0; b < blocks; b++) {
    const chunk = Buffer.alloc(128);
    data.copy(chunk, 0, b * 128, Math.min(data.length, (b + 1) * 128));
    const last = b === blocks - 1;
    const t = BigInt(last ? data.length : (b + 1) * 128);
    const m = Array.from({ length: 16 }, (_, i) => chunk.readBigUInt64LE(i * 8));
    const v = [...h, ...IV];
    v[12] ^= t & M64; v[13] ^= t >> 64n;
    if (last) v[14] ^= M64;
    const G = (a, b2, c, d, x, y) => {
      v[a] = (v[a] + v[b2] + x) & M64; v[d] = rotr(v[d] ^ v[a], 32);
      v[c] = (v[c] + v[d]) & M64;       v[b2] = rotr(v[b2] ^ v[c], 24);
      v[a] = (v[a] + v[b2] + y) & M64; v[d] = rotr(v[d] ^ v[a], 16);
      v[c] = (v[c] + v[d]) & M64;       v[b2] = rotr(v[b2] ^ v[c], 63);
    };
    for (let r = 0; r < 12; r++) {
      const s = SIGMA[r % 10];
      G(0, 4, 8, 12, m[s[0]], m[s[1]]); G(1, 5, 9, 13, m[s[2]], m[s[3]]);
      G(2, 6, 10, 14, m[s[4]], m[s[5]]); G(3, 7, 11, 15, m[s[6]], m[s[7]]);
      G(0, 5, 10, 15, m[s[8]], m[s[9]]); G(1, 6, 11, 12, m[s[10]], m[s[11]]);
      G(2, 7, 8, 13, m[s[12]], m[s[13]]); G(3, 4, 9, 14, m[s[14]], m[s[15]]);
    }
    for (let i = 0; i < 8; i++) h[i] ^= v[i] ^ v[i + 8];
  }
  const out = Buffer.alloc(64);
  h.forEach((w, i) => out.writeBigUInt64LE(w, i * 8));
  return out.subarray(0, outLen);
}

function head(major, n) {
  if (n < 24) return Buffer.from([(major << 5) | n]);
  if (n < 256) return Buffer.from([(major << 5) | 24, n]);
  if (n < 65536) return Buffer.from([(major << 5) | 25, n >> 8, n & 255]);
  throw new RangeError(`CBOR item too large: ${n}`);
}
function enc(x) {
  if (Buffer.isBuffer(x)) return Buffer.concat([head(2, x.length), x]);
  if (typeof x === "string") {
    const b = Buffer.from(x);
    return Buffer.concat([head(3, b.length), b]);
  }
  if (typeof x === "number") return head(x >= 0 ? 0 : 1, x >= 0 ? x : -x - 1);
  if (typeof x === "boolean") return Buffer.from([x ? 0xf5 : 0xf4]);
  if (Array.isArray(x)) return Buffer.concat([head(4, x.length), ...x.map(enc)]);
  if (x instanceof Map) {
    return Buffer.concat([head(5, x.size), ...[...x].flatMap(([k, v]) => [enc(k), enc(v)])]);
  }
  throw new TypeError(`unsupported CBOR value: ${typeof x}`);
}
function padded(total) {
  // a1 61 70 <bstr pad>: a one-entry map whose total encoding is exactly `total` bytes.
  for (let n = 0; n < total; n++) {
    const candidate = Buffer.concat([Buffer.from([0xa1, 0x61, 0x70]), enc(Buffer.alloc(n, 0x70))]);
    if (candidate.length === total) return candidate;
  }
  throw new RangeError(`cannot pad protected header to ${total}`);
}
function payload(holder, policy = "bb".repeat(28), network = 1, tier = 1, ttl = 100_000_000, kind = 0) {
  const expiry = Buffer.alloc(8);
  expiry.writeBigUInt64BE(BigInt(ttl));
  return Buffer.concat([Buffer.from(holder, "hex"), Buffer.from([tier]), expiry,
    Buffer.from(policy, "hex"), Buffer.from([network, kind])]);
}
function make({ holder, policy, address, network = 1, tier = 1, ttl = 100_000_000,
  kind = 0, algorithm = -8, keyAlgorithm = -8, keyCurve = 6,
  reordered = false, kid = false, tag = false, hashed = false, protectedLength = null }) {
  const claim = payload(holder, policy, network, tier, ttl, kind);
  // CIP-8 hashed mode (Ledger): the COSE payload — and what is signed — is BLAKE2b-224(claim).
  const signedPayload = hashed ? blake2b(claim, 28) : claim;
  const addressBytes = Buffer.from(address, "hex");
  const protectedMap = new Map(reordered
    ? [["address", addressBytes], [1, algorithm]]
    : [[1, algorithm], ["address", addressBytes]]);
  if (kid) protectedMap.set(4, addressBytes);
  // The on-chain verifier never parses the protected header — it only re-wraps its bytes —
  // so length-boundary vectors use a padded map of an exact total size (0 = absent header).
  const protectedBytes = protectedLength === null ? enc(protectedMap)
    : protectedLength === 0 ? Buffer.alloc(0)
    : protectedLength === 1 ? Buffer.from([0xa0])
    : padded(protectedLength);
  const unprotected = new Map([["hashed", hashed]]);
  const toSign = enc(["Signature1", protectedBytes, Buffer.alloc(0), signedPayload]);
  const signature = sign(null, toSign, key);
  const sign1 = enc([protectedBytes, unprotected, signedPayload, signature]);
  const coseKey = enc(new Map([[1, 1], [3, keyAlgorithm], [-1, keyCurve], [-2, vkey], ...(kid ? [[2, addressBytes]] : [])]));
  return {
    cose_sign1: Buffer.concat([tag ? Buffer.from([0xd2]) : Buffer.alloc(0), sign1]).toString("hex"),
    cose_key: coseKey.toString("hex"),
    // The on-chain proof: extracted parts + the 67-byte claim (the preimage when hashed).
    payload: claim.toString("hex"),
    protected: protectedBytes.toString("hex"),
    hashed,
    signature: signature.toString("hex"),
  };
}
const pkh = issuerPkh.toString("hex");
const address = {
  enterprise: `60${pkh}`,
  base: `00${pkh}${"cc".repeat(28)}`,
  base_script_stake: `20${pkh}${"cc".repeat(28)}`,
  pointer: `40${pkh}010203`,
  reward: `e0${pkh}`,
  wrong_key: `60${"dd".repeat(28)}`,
  wrong_network: `61${pkh}`,
};
const e = address.enterprise;
const cases = {
  unit_valid: make({ holder: "aa".repeat(28), address: e }),
  unit_hashed_valid: make({ holder: "aa".repeat(28), address: e, hashed: true }),
  sender_valid: make({ holder: "0a".repeat(28), policy: "ee".repeat(28), address: e }),
  receiver_valid: make({ holder: "0b".repeat(28), policy: "ee".repeat(28), address: e }),
  receiver_hashed_valid: make({ holder: "0b".repeat(28), policy: "ee".repeat(28), address: e, hashed: true }),
  // Protected-header length boundaries of the on-chain bstr re-wrap (40+n / 58 n / refused).
  protected_len_1: make({ holder: "aa".repeat(28), address: e, protectedLength: 1 }),
  protected_len_23: make({ holder: "aa".repeat(28), address: e, protectedLength: 23 }),
  protected_len_24: make({ holder: "aa".repeat(28), address: e, protectedLength: 24 }),
  protected_len_255: make({ holder: "aa".repeat(28), address: e, protectedLength: 255 }),
  protected_len_0: make({ holder: "aa".repeat(28), address: e, protectedLength: 0 }),
  protected_len_256: make({ holder: "aa".repeat(28), address: e, protectedLength: 256 }),
  // Genuine signatures over claims the verifier must refuse.
  invalid_tier: make({ holder: "aa".repeat(28), address: e, tier: 0 }),
  expired: make({ holder: "aa".repeat(28), address: e, ttl: 49_999_999 }),
  wrong_holder: make({ holder: "dd".repeat(28), address: e }),
  wrong_policy: make({ holder: "aa".repeat(28), address: e, policy: "ff".repeat(28) }),
  wrong_kyc_network: make({ holder: "aa".repeat(28), address: e, network: 2 }),
  wrong_credential_type: make({ holder: "aa".repeat(28), address: e, kind: 1 }),
};
const BLAKE2B_224_SELFTEST = blake2b(Buffer.from("abc"), 28).toString("hex");
function plutusConstr(index, fields) {
  // Plutus Data constructor indices 0..6 use CBOR tags 121..127.
  return Buffer.concat([Buffer.from([0xd8, 121 + index]), head(4, fields.length), ...fields]);
}
function proofBytes(sign1Hex, coseKeyHex, claimHex, rawSignatureHex) {
  const raw = plutusConstr(0, [plutusConstr(0, [
    enc(Buffer.from(claimHex, "hex")), enc(Buffer.from(rawSignatureHex, "hex")), enc(vkey),
  ])]);
  const c = comparable;
  const cip30 = plutusConstr(2, [plutusConstr(0, [
    enc(Buffer.from(c.protected, "hex")), enc(Buffer.from(c.payload, "hex")),
    Buffer.from([0xd8, c.hashed ? 122 : 121, 0x80]),
    enc(Buffer.from(c.signature, "hex")), enc(vkey),
  ])]);
  return { raw_attestation: raw.length, cip30_attestation: cip30.length,
    delta: cip30.length - raw.length };
}
const comparable = cases.sender_valid;
const rawSignature = sign(null, Buffer.from(comparable.payload, "hex"), key).toString("hex");
console.log(JSON.stringify({
  issuer_vkey: vkey.toString("hex"), issuer_pkh: pkh, blake2b_224_abc: BLAKE2B_224_SELFTEST, cases,
  serialized_proof_bytes: proofBytes(comparable.cose_sign1, comparable.cose_key,
    comparable.payload, rawSignature),
}, null, 2));
