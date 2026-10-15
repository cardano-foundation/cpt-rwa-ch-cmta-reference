# Practical integration guide

This guide is for a transaction builder integrating the validators in this repository with a
deployed CIP-113 programmable-token base layer. The [README](../README.md) explains the protocol
and lists the exact script parameter order. The base layer supplies token custody, registry
transactions and owner authorisation; its transaction builder and redeemers depend on the deployed
base-layer version. The examples below describe **this repository's** witnesses and data. They are
Aiken-shaped sketches, not a ready-to-submit SDK or CLI implementation.

## Before building transactions

1. Build and apply every validator's parameters in [README: Parameter order](../README.md#parameter-order).
   Record the applied script hashes, the issuance policy ID, the selected `security_asset_name`,
   the CIP-113 registry policy ID and the deployed base-layer commit. Keep list **policy IDs**
   distinct from list **spend validator hashes**.
2. Select three spendable one-shot inputs: one for GlobalState, one for the power-users root and
   one for the denylist root. The list mint validators' `init_input_out_ref` values and the
   GlobalState mint validator's `tx0`/`index0` must match the inputs actually spent at genesis.
3. Choose the admin credential, initial minting authority script hash, cap, network ID and KYC
   settings. The initial datum must have `transfers_paused = False`, `deactivated = False`,
   `upgrades_locked = False`, a non-negative `mintable_amount`, a 28-byte admin hash, a 28-byte
   authority hash, a network ID from 0 to 255 and an empty or 32-byte `member_root_hash`.
   Trusted-entity vkeys are 32 bytes, sorted and unique. See
   [`GlobalStateDatum`](../lib/types/global_state.ak) and the genesis checks in
   [`global_state.ak`](../validators/global_state.ak).
4. Publish large applied scripts as reference scripts and keep their reference UTxOs available to
   the builder. Register every withdraw-0 script's stake credential before a transaction invokes
   it; see [README: Deployment](../README.md#deployment-reference-scripts).

All `*_index` fields below are **zero-based positions in the final transaction**, after coin
selection and output ordering. Recompute them after a builder inserts change outputs, collateral,
reference inputs or other witnesses. In particular, an index into `inputs` is not an index into
`reference_inputs`; GlobalState must never appear in both lists in one transaction.

## Bootstrap a token

### 1. Mint GlobalState and both list roots together

Spend the three reserved inputs in **one transaction**. Mint exactly one GlobalState NFT under
`global_state.global_state_mint_validator` and initialise both linked lists with the `Init` mint
redeemer from their respective [`MintRedeemer` types](../lib/types/power_users.ak) and
[`denylist` type](../lib/types/denylist.ak). Each `Init { root_output_index }` points to its own
root output. The GlobalState mint validator checks that both root policies mint in this same
transaction; a later transaction for either root is rejected.

Output the GlobalState NFT with an inline `GlobalStateDatum` at `global_state_proxy.global_state_proxy`
(unparameterised; the GlobalState mint takes its hash as `global_state_proxy_hash` and rejects any
other payment credential). Datum **field 0**, `global_state_script_credential_hash`, is the hash of
`global_state_logic.global_state_logic` applied with this deployment's parameters; it must be 28 bytes and
differ from the admin, the minting authority and the proxy. Apply the same
`max_global_state_datum_bytes` (recommended 8192) to the mint and the logic; the serialised genesis
datum must fit under it, and later actions that grow the datum are refused beyond it. Nothing on chain
ties the two values together: assert in the deployment script that they are equal and positive. A
logic cap below the genesis datum's size would refuse every write that grows the datum (adding
trusted entities, larger security info, setting the member root, raising the supply cap, and burns
that lengthen `mintable_amount`'s encoding) until a rotation, which `LockUpgrades` makes impossible.
Before locking, check it with a write that grows the datum, such as adding and then removing a trusted
entity; a same-size write passes whatever the cap. In operation, keep headroom below the cap: a datum
sitting exactly at it refuses even a burn that adds a byte to `mintable_amount`, until the admin
shrinks it. Output each root at its corresponding
list spend validator address. The list mint validators cannot verify those destination addresses,
and nothing on chain can bind field 0 to the compiled logic hash, so compare the applied hashes,
field 0 and output addresses **before signing**. Each list's `Init` rejects a GlobalState output of
this same transaction that names another list (`power_user_linked_list_policy_id` /
`denylist_linked_list_policy_id`). That catches swapped ids and any genesis that initialises the
real lists, but not a datum naming some other policy that mints in the transaction while the real
`Init`s never run — so the off-chain check stays load-bearing: assert that the two list policy IDs
are distinct and equal the compiled list mint hashes. The datum's
`minting_script_credential_hash` must identify the intended current minting authority, not the
permanent proxy.

### 2. Register the five withdrawal credentials

Register the applied stake credential of `global_state_logic` before the first GlobalState action
(its hash is known before genesis, so registering it first is simplest). Then register the
applied stake credentials for `minting_logic_validator` (proxy),
`minting_authority_validator`, `transfer_logic_validator` and
`third_party_transfer_logic_validator`. The first two **must** be registered before the CIP-113
registry insert, because registration runs both withdraw-0 scripts. The latter two must be
registered before transfers or seizures. Each validator's `publish` handler accepts
`RegisterCredential` and refuses deregistration.

### 3. Create an operator and register the CIP-113 node

Add a power-user node with `can_mint = True` if the registration will also issue initial supply.
The admin grants the role through the power-users list. Keep a reference to the new node for mint
transactions. A structural-only registration does not need a minter role.

Insert this token's CIP-113 registry node with `key` = the issuance policy ID derived from the
permanent **proxy** hash (README, What the derived parameters must equal), fields 3 and 4 = exactly
the transfer and third-party logic script credentials the minting authority was built with
(`transfer_logic_script_hash`, `third_party_transfer_logic_script_hash`; anything else, or the two
swapped, is rejected — F08), the deployment's GlobalState policy ID, and the disabled unfracking
credential. The admin signs. The proxy's withdraw redeemer
is `GlobalStateReferenced { global_state_ref_input_index }` for the usual structural-only shape;
the authority's is:

```aiken
RegisterStructural {
  registry_node_output_index,
  global_state_location: GlobalStateReferenced { global_state_ref_input_index },
}
```

`registry_node_output_index` must identify **this token's new node**, not the covering node that
the CIP-113 insert also outputs. Do not mint anything under this issuance policy in a
`RegisterStructural` transaction. [`RegisterMint`](../lib/types/minting_authority.ak) is the
alternative if initial supply is issued during the insert: spend GlobalState, put `MintSecurity`
on the `global_state_logic` withdrawal (see
[How a GlobalState action is submitted](#upgrades-and-operator-checks)), invoke the minting proxy
with `GlobalStateSpent`, and supply the minter node,
`minted_amount` and destination actions as for a normal mint below. Only this registration shape
may also create a single CIP-68 reference NFT. The registry's base-layer redeemers and covering
node proof are version-specific; construct them using the deployed CIP-113 implementation.

## Build a normal transfer

The CIP-113 base layer spends the programmable-base token UTxOs and invokes the registered
`transfer_logic_validator` as a zero-value withdrawal. Include GlobalState as a reference input
for an ordinary transfer, plus a genuine denylist covering-node reference input for every unique
sender and receiver. A covering node's key must be below the holder's hash and its `next` link
above it; the root covers the initial empty list. The node must still sit at the denylist spend
validator address. One node can cover several holders.

For one sender and one destination, the repository's withdrawal redeemer has this shape:

```aiken
TransferLogicScriptWithdrawRedeemer {
  global_state_location: GlobalStateReferenced { global_state_ref_input_index },
  actions_for_each_input: [TransferLogicScriptAction {
    source_proof,
    source_denylist_covering_ref_input_index,
  }],
  destination_actions: [TransferLogicScriptDestinationAction {
    destination_proof,
    destination_denylist_covering_ref_input_index,
  }],
}
```

For example, with `reference_inputs = [GlobalState, denylist_root]`, set
`global_state_ref_input_index = 0` and both covering indices to `1` if the empty denylist root
covers both parties. With one token-bearing sender input and one token-bearing receiver output,
the two action lists each have one entry. Recalculate these positions after finalising the
transaction; the example does not apply once another reference input is inserted ahead of them.

For multiple parties, build one source action per unique **full stake credential** among token
inputs, and one destination action per unique full stake credential among token outputs. Preserve
the first-occurrence order in the transaction input and output lists; the validator matches
actions positionally. Both sides always need denylist absence. The corresponding KYC proof is
checked only when `requires_sender_kyc` or `requires_receiver_kyc` is true. The transaction fails
while paused or deactivated. See the actual schemas in
[`types/transfer_logic_script.ak`](../lib/types/transfer_logic_script.ak).

### The KYC claim

An attestation (`KycProof` variant `Cip30Attestation`, below) is an issuer's signature over exactly
this 67-byte claim; the issuer's 32-byte Ed25519 vkey must be in GlobalState's
`trusted_entity_vkeys`:

```text
credential_hash(28) | tier(1) | valid_until_ms(8, big-endian) |
issuance_policy_id(28) | network_id(1) | credential_type(1)
```

Use credential type `0x00` for a verification-key stake credential or `0x01` for a script stake
credential, and a nonzero tier. The transaction validity range must have a finite upper bound no
later than `valid_until_ms`. The signature must be over the CIP-30 COSE `Sig_structure` wrapping
the claim (next section). A raw Ed25519 signature over the bare claim is **not** accepted — that
format was removed on 2026-10-15.

The alternative `Membership` proof uses an MPF leaf with key
`credential_type(1) | credential_hash(28)` and value
`valid_until_ms(8) | issuance_policy_id(28) | network_id(1)`. Use
[`membership_leaf_key` and `membership_leaf_value`](../lib/kyc/verify.ak) as the encoding reference
and publish its tree root through `UpdateMemberRootHash`. Revoking a tree leaf does not invalidate
an independently issued attestation before that attestation expires.

### Construct an attestation (CIP-30)

`Cip30Attestation` lets an **already trusted issuer** sign the 67-byte claim with any CIP-30
wallet, hardware wallets included. A backend issuer needs no wallet: it can sign the same
`Sig_structure` bytes directly with its key (see the end of this section). The issuer's 32-byte public key must be in GlobalState's
`trusted_entity_vkeys`; a holder signing their own claim grants nothing. The transaction builder
never needs the issuer's private key.

**Keep issuer keys dedicated to issuance.** The validator does not look at the COSE headers
(address, algorithm, kid): the trusted key *is* the authorisation, and the claim binds holder,
policy, network and expiry. So *any* `signData` by a trusted key over a valid claim — or, in
hashed mode, over the BLAKE2b-224 of one — counts as an attestation. Never connect an issuer
wallet to other dApps, and treat the tool that builds the claim as trusted: in hashed mode a
Ledger shows only the hash, so the device cannot confirm what is being attested.

Build the claim as described above, then ask the issuer's wallet to sign it:

```js
const api = await window.cardano[walletName].enable();
// The address whose payment key (or stake key, for a reward address) IS the vkey registered in
// trusted_entity_vkeys. Do not rely on getChangeAddress(): multi-address/HD wallets derive a
// different key per address, and a change address can rotate — every proof would then fail as
// "untrusted issuer".
const addressHex = issuerAddressHex;
const claimHex = buildKycPayload({ /* see "The KYC claim" */ });   // 67 bytes
const { signature, key } = await api.signData(addressHex, claimHex);
```

`signature` is a hex CBOR `COSE_Sign1`, `key` a hex CBOR `COSE_Key`. Extract four parts **off
chain** (any CBOR library):

| Redeemer field | Where it comes from |
|---|---|
| `protected_header` | `COSE_Sign1[0]` — the bytes *inside* the protected bstr, verbatim, never re-encoded |
| `hashed` | the unprotected map (`COSE_Sign1[1]`) entry `"hashed"`; absent means `False` |
| `signature` | `COSE_Sign1[3]` (64 bytes) |
| `issuer_vkey` | `COSE_Key` label `-2` (32 bytes) |
| `payload` | **always your own 67-byte claim** — not `COSE_Sign1[2]` |

`COSE_Sign1` may be wrapped in CBOR tag 18. In hashed mode (`hashed: true`, which Ledger
requires) `COSE_Sign1[2]` holds `blake2b_224(claim)`, not the claim; check off chain that it equals
the hash of the claim you asked to be signed, and put the claim itself in `payload`. If the wallet
returns a detached (`nil`) payload, treat it the same way.

Before submitting, check off chain that `issuer_vkey` is in `trusted_entity_vkeys`; a key mismatch
otherwise surfaces only as a rejected transaction. None of this extraction is trusted. The validator rebuilds the COSE `Sig_structure`
`["Signature1", protected_header, h'', claim or blake2b_224(claim)]` and verifies the issuer's
Ed25519 signature over it, so a wrong extraction can only make the proof fail. Bounds: the protected
header must be 1–255 bytes (wallets produce ≈ 40–60).

```aiken
Cip30Attestation {
  cip30_proof: Cip30AttestationProof {
    protected_header, payload, hashed, signature, issuer_vkey,
  },
}
```

At the Plutus Data boundary this is `Constr(1, [Constr(0, [B(protected_header), B(payload),
Bool(hashed), B(signature), B(issuer_vkey)])])` (`Bool` is `Constr 0 []` / `Constr 1 []`;
`Membership` is `Constr(0, …)` — the indices moved when the raw `Attestation` was removed).

**Backend issuers (no wallet).** Sign the bytes the validator rebuilds,
`["Signature1", protected_header, h'', claim]` as CBOR, with the issuer's Ed25519 key, and submit
`hashed: False`. The protected header is not interpreted on chain beyond its length (1–255 bytes);
a minimal standard header is `a10127` (`{1: -8}`, alg EdDSA), which keeps the proof ≈ 40 bytes
smaller than a wallet's.
[`scripts/cip30-test-vectors.mjs`](../scripts/cip30-test-vectors.mjs) reproducibly generates genuine
vectors with a fixed **test-only** seed, unhashed and hashed.
[`scripts/cip30-emurgo-fixture.cjs`](../scripts/cip30-emurgo-fixture.cjs) rebuilds the hashed
vectors with Emurgo's `cardano-message-signing` 1.1.0 (`hash_payload()`) and yields byte-identical
signatures — an independent check of the CIP-8 hashing and of the `Sig_structure` encoding.

## Mint, burn and forced transfer

For a later mint, spend the GlobalState UTxO at `global_state_proxy` (any spend redeemer; it is
ignored) and continue it at the same address, with its NFT and non-ADA value preserved. Add the
withdrawal of the GlobalState logic named in datum field 0, with redeemer
`GlobalStateSpendRedeemer { global_state_output_index, action: MintSecurity {
issuance_policy_redeemer_index } }`; the inner index points into the transaction's **redeemers**
at `Mint(issuance_policy_id)`. The validator writes the new `mintable_amount` by subtracting the
actual minted security quantity. Include the `can_mint` power-user node as a reference input,
signed by that operator; the CIP-113 registry node is referenced, not spent. Besides the
GlobalState logic, invoke the minting proxy and the minting authority as zero-value withdrawals —
three withdrawals in all:

```aiken
// Proxy withdraw redeemer
GlobalStateSpent { global_state_input_index }

// Minting authority withdraw redeemer
MintBurn {
  global_state_input_index,
  power_user_node_ref_input_index,
  minted_amount,
  destination_actions: [MintingLogicDestinationAction {
    destination_proof,
    destination_denylist_covering_ref_input_index,
  }],
}
```

`minted_amount` must equal the actual signed quantity under `security_asset_name`. Supply
increases require one action per unique token destination, with denylist absence and receiver KYC
when enabled. The authenticated, signing `can_mint` operator may mint to their own stake credential
without a separate KYC proof; their destination still needs denylist absence. Only the security
asset name can be minted in a steady-state `MintBurn` transaction;
the CIP-68 reference NFT is a registration-time artefact.

A burn uses the same GlobalState, proxy and authority shape with a **negative** `minted_amount`,
an operator with `can_burn`, and no mint destination actions. Burning returns cap headroom. It
also spends a programmable-base token UTxO, so satisfy the CIP-113 base layer's required movement
path. During a pause or when the holder cannot pass the ordinary sender gates, route the burn
through `ThirdPartyAct` with a `can_force_transfer` operator as well; `can_burn` alone does not
make that base-layer path buildable. Use `GlobalStateSpent` in any accompanying transfer or
third-party withdrawal redeemer, since GlobalState is spent in this transaction.

A forced transfer invokes `third_party_transfer_logic_validator` with
`ThirdPartyTransferLogicScriptWithdrawRedeemer { global_state_location,
power_user_node_ref_input_index, destination_actions }`. The `can_force_transfer` operator signs;
destinations supply denylist absence and enabled receiver KYC. Source KYC and denylist status are
deliberately overridden, and pause does not block seizure. Against a sanctioned or expired
holder, drain whole UTxOs: the base layer returns a partial UTxO residual to its source, which
then fails this deployment's destination checks. See
[`types/third_party_transfer_logic_script.ak`](../lib/types/third_party_transfer_logic_script.ak).

## Upgrades and operator checks

The admin can change `minting_script_credential_hash` with GlobalState's `RotateMintingScript`.
The permanent proxy will delegate **all** mint, burn and registration decisions to the new
authority. Register its stake credential first. Before switching, verify that the replacement
preserves supply-cap enforcement, GlobalState spending for supply changes, allowed asset names,
registration structure and deactivation rules described at the top of
[`minting_authority.ak`](../validators/minting_authority.ak). Test an unsigned mint and each
power-user role without its authorised signature; each should reject. **No power-user credential,
admin or minting authority may ever equal GlobalState datum field 0** (the GlobalState logic hash):
every GlobalState spend carries that logic's withdrawal, and `must_be_signed_by_credential` accepts
a withdrawal as a signature, so such a role would be exercisable by anyone. All three are guarded
on chain — the admin and minting authority when written, an operator wherever its role is used
(pause, mint/burn, seizure, sanctions) — so a misconfigured role fails closed; still avoid granting one.

To change transfer or third-party logic, first `RotateMintingScript` to a minting authority built
with the new script hash (register its stake credential), because the continuing node must name
exactly the scripts the active authority was built with (F08). Then update this token's CIP-113
registry node with
`UpgradeRegistryNode { registry_node_input_index, registry_node_output_index,
global_state_location }` on the minting authority withdrawal. The admin signs. The authority
pins the node to this issuance policy, retains this deployment's GlobalState and disabled
unfracking setting, and checks `upgrades_locked == False`. Register replacement logic stake
credentials before their first use. This transaction cannot change the token supply.

**How a GlobalState action is submitted.** GlobalState is never governed by its spend script
alone. Spend the GlobalState UTxO at `global_state_proxy` with any redeemer (it is ignored), and add a
withdrawal from the credential in datum field 0 — the current `global_state_logic` — carrying the
`GlobalStateSpendRedeemer { global_state_output_index, action }` described below. Withdraw the
credential's whole reward balance (normally 0, but anyone can top a reward account up). The logic
finds the GlobalState input by its NFT. The proxy's address is shared by every deployment, so
locate GlobalState by the NFT, never by address.

To adjust the supply cap, spend GlobalState with `GlobalStateSpendRedeemer {
global_state_output_index, action: SetMintableAmount { new_mintable_amount } }` (constructor
index 13), signed by the admin. The continuing output must equal the input datum with only
`mintable_amount` replaced by `new_mintable_amount`, which must lie in `[0, 2^63 − 1]`. The value
is absolute remaining headroom, not a delta and not total supply. The transaction must not mint,
burn or spend the security token, so a raise followed by a mint takes two transactions.

To replace the GlobalState logic, apply and verify the new `global_state_logic` build against
the blueprint, register its stake credential in an **earlier** transaction (registering and
withdrawing in one transaction does not work), and dry-run the rotation, one `MintSecurity` and a
rotation back on an emulator or preprod. Then spend GlobalState with `RotateGlobalStateScript {
new_global_state_script_hash }` (constructor index 14) as the redeemer of **both** withdrawals —
the current logic (old field 0) and the new one — signed by the admin. The continuing output stays at
the proxy with the same non-ADA value; its datum has field 0 set to the new hash. The current logic
requires the frozen core (fields 0–4: logic hash, `deactivated`, admin, power-users list policy,
minting-authority hash) to still decode, with constructor 0, and fields 1–4 to be unchanged; the
proxy, the minting proxy and both lists read only the core and can never be redeployed. Everything
after the core is the new logic's to accept, including a completely different layout.
This version, as the new logic, accepts exactly the input datum with field 0 rewritten. The new hash
must differ from the admin and the minting authority. No security token may be minted, burned or
spent in the same transaction. Off-chain readers should read the core (fields 0–4) by position and the rest according to the
installed logic's layout: a later logic may reshape everything after field 4. The v1 layout is
`GlobalStateDatum`; `decode_global_state_core` is the on-chain core reader.

`LockUpgrades` irreversibly closes the authority-rotation, registry-upgrade and GlobalState-logic-rotation
paths, and admin changes to the supply cap, for **later** transactions. A registry upgrade bundled into the same transaction can still read the
unlocked input state and succeed; inspect all redeemers in the locking transaction. Admin-only
GlobalState actions similarly expose their pre-state to a bundled registry operation. Record the
active script hashes, operator credentials, base-layer version and lock transaction as deployment
artifacts. For final retirement, follow the ordered
[decommissioning runbook](security/security-fixes.md#the-decommissioning-runbook-in-order).
