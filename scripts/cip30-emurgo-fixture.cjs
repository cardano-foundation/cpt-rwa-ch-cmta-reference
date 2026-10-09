// Externally-built CIP-8 hashed COSE_Sign1, an independent check of cip30-test-vectors.mjs.
// Emurgo's cardano-message-signing (@emurgo/cardano-message-signing-nodejs 1.1.0) builds the
// headers, hashes the payload (hash_payload()) and the Sig_structure (make_data_to_sign()); this
// script only signs those bytes with the same public TEST seed.
//
// Run (install the library OUTSIDE this repo, pass its path):
//   npm install --prefix /tmp/ems @emurgo/cardano-message-signing-nodejs@1.1.0
//   node scripts/cip30-emurgo-fixture.cjs /tmp/ems/node_modules/@emurgo/cardano-message-signing-nodejs
//
// Expect the signatures to be BYTE-IDENTICAL to cip30-test-vectors.mjs's unit_hashed_valid and
// receiver_hashed_valid: Ed25519 is deterministic, so identical bytes mean Emurgo built exactly the
// same Sig_structure — that agreement is the evidence. Protected = COSE_Sign1[0]'s inner bytes.
const MS = require(process.argv[2]);
const { createPrivateKey, sign } = require("node:crypto");
const seed = Buffer.from(Array.from({ length: 32 }, (_, i) => i));
const key = createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]), format: "der", type: "pkcs8" });
function claim(holder, policy) {
  const e = Buffer.alloc(8); e.writeBigUInt64BE(100000000n);
  return Buffer.concat([Buffer.from(holder, "hex"), Buffer.from([1]), e, Buffer.from(policy, "hex"), Buffer.from([1, 0])]);
}
function protectedOf(sign1) {
  let i = sign1[0] === 0x84 ? 1 : 2;                       // optional tag 18 (d2)
  const h = sign1[i], n = h & 31;
  return n < 24 ? sign1.subarray(i + 1, i + 1 + n) : sign1.subarray(i + 2, i + 2 + sign1[i + 1]);
}
const out = {};
for (const [name, holder, policy] of [["unit", "aa".repeat(28), "bb".repeat(28)], ["receiver", "0b".repeat(28), "ee".repeat(28)]]) {
  const c = claim(holder, policy);
  const hm = MS.HeaderMap.new();
  hm.set_algorithm_id(MS.Label.from_algorithm_id(MS.AlgorithmId.EdDSA));
  hm.set_header(MS.Label.new_text("address"), MS.CBORValue.new_bytes(Buffer.from("6027e38d0e19e3434e33fbd001d3fe04b5b76763f88acd625e0d770b43", "hex")));
  const headers = MS.Headers.new(MS.ProtectedHeaderMap.new(hm), MS.HeaderMap.new());
  const builder = MS.COSESign1Builder.new(headers, c, false);
  builder.hash_payload();
  const sig = sign(null, Buffer.from(builder.make_data_to_sign().to_bytes()), key);
  const cose = builder.build(sig);
  const unprot = cose.headers().unprotected();
  const hashedVal = unprot.header(MS.Label.new_text("hashed"));
  out[name] = {
    cose_sign1: Buffer.from(cose.to_bytes()).toString("hex"),
    protected: protectedOf(Buffer.from(cose.to_bytes())).toString("hex"),

    cose_payload: Buffer.from(cose.payload()).toString("hex"),
    hashed_header: hashedVal ? hashedVal.as_special().as_bool() : null,
    payload: c.toString("hex"),
    signature: sig.toString("hex"),
  };
}
console.log(JSON.stringify(out, null, 2));
