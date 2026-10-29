# Security fixes

An adversarial internal review of this token's compliance layer — the denylist, the KYC gates, and
the transfer, seizure and minting logic — found eleven defects; a re-audit on 2026-08-28 found two
more (12 and 13, both fixed) and a set of items judged
[not to warrant a code change](#acknowledged-and-deliberately-not-changed). Two were critical and reachable by
any wallet with no prior position in the protocol. This document records each one: what was wrong,
why it was wrong, how it was fixed, and why that fix rather than another.

**This is not a third-party audit.** It is a self-review. The formal audit noted in the README is
still outstanding, and this document does not substitute for it.

Every fix is pinned by a test in [`validators/regression.ak`](../../validators/regression.ak). That
file exists so a future edit cannot quietly undo any of this: revert a fix and its test fails.

Every negative test that guards a new check is paired with a **positive control** built from the
same fixtures. That is not ceremony: writing the controls caught four fixture bugs that had left
negative tests passing for the wrong reason — a node datum that could not decode, a node keyed at
the wrong asset name, a list root that did not link to the node being removed, and a test annotated
`!` where the validator actually traps.

---

## Contents

| # | Defect | Severity | Status |
|---|---|---|---|
| [1](#1-the-denylist-absence-proof-compared-against-a-corrupted-key) | The denylist absence proof compared against a corrupted key | **Critical** | Fixed |
| [2](#2-the-transfer-scripts-let-the-caller-choose-which-token-they-policed) | The transfer scripts let the caller choose which token they policed | **Critical** | Fixed |
| [3](#3-a-list-element-was-trusted-wherever-it-sat) | A list element was trusted wherever it sat | High | Fixed |
| [4](#4-the-mint-roles-rested-entirely-on-external-code) | The mint roles rested entirely on external code | High | Fixed |
| [5](#5-pause-does-not-stop-issuance) | Pause does not stop issuance | Medium | **Accepted, by decision** |
| [6](#6-mint-destinations-were-vetted-by-stake-credential-only) | Mint destinations were vetted by stake credential only | Medium | Fixed |
| [7](#7-the-globalstate-utxos-ada-balance-was-unconstrained) | The GlobalState UTxO's ADA balance was unconstrained | Low | **Accepted, by decision** |
| [8](#8-genesis-did-not-sanity-check-the-two-list-policy-ids) | Genesis did not sanity-check the two list policy ids | Low | Fixed |
| [9](#9-credential-type-was-erased-throughout) | Credential type was erased throughout | Low | Fixed |
| [10](#10-the-membership-kyc-variant-bound-neither-policy-nor-network) | The membership KYC variant bound neither policy nor network | Info | Fixed |
| [11](#11-the-power-user-authority-footgun-was-undocumented) | The power-user authority footgun was undocumented | Info | Fixed |
| [12](#12-dismantling-either-linked-list-was-a-one-way-freeze-of-a-live-protocol) | Dismantling either linked list was a one-way freeze of a live protocol | Medium | Fixed |
| [13](#13-cip-68-metadata-tokens-were-governed-by-an-exact-name-not-by-their-kind) | CIP-68 metadata tokens were governed by an exact name, not by their kind | Medium | Fixed |
| [14](#14-registry-fields-3-and-4-accepted-any-script-f08) | Registry fields 3 and 4 accepted any script (F08) | Medium | Fixed |
| [15](#15-genesis-never-ran-the-field-0-logic-and-rotation-accepted-any-script-that-runs) | Genesis never ran the field-0 logic, and rotation accepted any script that runs | — | Fixed |
| [16](#16-the-power-users-list-policy-id-was-held-twice-on-the-mint-path) | The power-users list policy id was held twice on the mint path | — | Fixed |
| [17](#17-partial-freeze-a-denylist-entry-can-freeze-an-amount-not-only-the-whole-holding) | Partial freeze: a denylist entry can freeze an amount | Feature | Added 2026-10-23 |
| [18](#18-two-step-transfer-approval-hazards-closed-before-release) | Two-step transfer approval: hazards closed before release | — | Designed out |

Findings 12 and 13 come from the 2026-08-28 re-audit; 1–11 from the original review; 14 from the
2026-10-15 audit (F08) and 15–16 from the review of PR #29, which assigned them no severity; 17 is a
feature, and 18 the design record of the two-step transfer approval. Then:
[acknowledged and not changed](#acknowledged-and-deliberately-not-changed),
[the linked-list dependency](#the-linked-list-dependency),
[what the base layer guarantees](#what-the-cip-113-base-layer-actually-guarantees),
[what this changes for off-chain](#what-this-changes-for-off-chain),
[what is still open](#what-is-still-open).

---

## The linked-list dependency

`anastasia-labs/aiken-design-patterns` was upgraded **v1.6.0 → v1.8.0** as part of this work. Both
lists — the denylist and the power-users list — are built on it, so its correctness is our
correctness.

What the upgrade changes for security:

| | v1.6.0 | v1.8.0 |
|---|---|---|
| Node `link` returned by `get_element_info` | **double-stripped** — defect 1 | correct (fixed in v1.7.0, commit `c757cb5`) |
| `Root` vs `Node` link encoding | inconsistent | consistent |
| Element address visible to callers | **not exposed at all** | passed to the callback, so it can be pinned |
| Structural input count on insert/remove | not checked — defect 3(b) | enforced by scanning the full `inputs` list |
| Root-only vs node-only reads | caller must `expect Some(key)` | `get_node_element_info` rejects the root structurally |

Two upstream fixes in that window do **not** affect us: `0dfb6ad` (*prevent same node-key namespace
mints*) is in the `advanced` module, which we do not import; `193b1aa` (*disallow ref scripts
attached to elems*) repairs a regression introduced after v1.6.0, so the version we came from was
never exposed.

One packaging wrinkle: v1.8.0's non-test `utils.ak` imports `aiken/fuzz` at module level, and Aiken
v1.1.23 does not resolve a dependency's own manifest. `aiken-lang/fuzz` and
`keyan-m/aiken-scott-utils` are therefore declared explicitly in `aiken.toml`, with a comment saying
why.

The upgrade also made the compliance path measurably **cheaper** — the denylist absence proof
dropped from ~48.6M to ~31.8M CPU units — which matters for the per-party execution cost measured by
the `aiken bench` scaling benches on the transfer and seizure paths (see
[what is still open](#what-is-still-open) and the README's *Execution budget and transaction
sizing* section).

---

## 1. The denylist absence proof compared against a corrupted key

**Severity: critical.** Reachable by any wallet. Broke the sanctions list in *both* directions.

### What was wrong

`anastasia-labs/aiken-design-patterns` **v1.6.0** — the version this project used at the time — was
internally inconsistent about whether a node's `link` field carries the 4-byte `"Node"` asset-name
prefix.

The **write** side does not. `insert_ascending` computes
`new_element_key = bytearray.drop(new_element_asset_name, 4)` and then asserts, against the raw
datum link, that the anchor points at that bare key. So links are stored as **bare keys**.

The **read** side assumes they do. `get_element_info` returns, for a `Node` element:

```aiken
element_link |> option.map(fn(asset_name) { bytearray.drop(asset_name, node_key_prefix_length) })
```

— stripping four bytes from a value that never had them. The parameter name `asset_name` is the
mistaken assumption made visible.

`verify_denylist_absence` used that link. So the absence check was really comparing the target
against `drop(4, successor_key)`.

### Why it was exploitable both ways

The covering-node test is `node.key < target < node.link`. With the link corrupted:

**Sanctioned keys could prove their own absence.** To prove a sanctioned key `S` absent, point at
`S`'s own predecessor `P`. The lower bound `P.key < S` holds — the list is sorted. The upper bound
becomes `S < drop(4, S)`, which reduces to comparing byte 0 of `S` against byte 4. That is true for
**roughly half of all 28-byte credential hashes**, with no grinding at all. An attacker wanting
certainty grinds a stake key until its hash satisfies it — about 2³² hashes, hours on commodity
hardware — and is then permanently immune to being denylisted. Worse, they get an independent ~50%
attempt per node preceding them in the list, so on any realistic denylist a bypass is near-certain.

**Clean holders could be frozen out.** For an unsanctioned holder `X`, the honest covering node `P`
satisfies `P.key < X < P.link` — but if `drop(4, P.link)` sorts below `X`, the proof cannot be
constructed at all. In the extreme (`P.link = 0xaaaaaaaa00…00`, stripping to 24 zero bytes) **no
target can ever be proven absent through that node**, and in an ascending list with unique keys
there is no alternative covering node. The holding is unspendable until an operator happens to
rewrite that link by adding or removing an unrelated entry.

### Why it went unnoticed

Two reasons, both worth internalising.

The existing tests exercised the `covers_key` predicate in isolation with hand-supplied link values.
The bug was not in the predicate — it was in what the caller **fed** the predicate. No amount of
testing at that level would have found it.

And a one-entry denylist behaves correctly, because `get_element_info` returns a `Root` element's
link **unstripped**. Any smoke test on a fresh list passes.

### The fix

**Upgraded the library to v1.8.0, where this is fixed upstream.**

The bug was found independently by the library authors and fixed in commit `c757cb5`, *"fix: link
provision in `get_element_info` — There was one extra cutting off of asset name labels for the link
before provision to the callback."* It first shipped in **v1.7.0**.

`lib/denylist/absence.ak` therefore uses the library's link directly again, with no workaround.

For the record, the interim fix — used before the upgrade — was to discard the library's link and
decode `covering_ref.output.datum` as an `Element` to read the raw link. That was safe because it
read the **same `Output`** the library had already authenticated, so it failed closed. It is gone
now; the clean API is correct.

`Root` behaviour was never affected: the library returned root links unstripped, and the datum holds
the same value.

**Pinned by** `denylisted_key_cannot_prove_its_own_absence`,
`transfer_rejects_a_sanctioned_holder_end_to_end`,
`transfer_accepts_a_clean_holder_with_a_high_successor_link` (the freeze direction — this one
asserts a legitimate transfer **succeeds**), and
`denylist_absence_is_sound_and_complete_over_a_real_list`, which runs a genuine two-node list and
checks the proof in both directions — the end-to-end coverage the module had explicitly deferred.

**Anyone still on v1.6.0 or earlier is affected.** Every consumer of `get_element_info`'s link is
wrong the same way. In this repository only the absence proof read the link — the power-user reads
discard it — which is why this defect had exactly one blast radius: the sanctions list.

---

## 2. The transfer scripts let the caller choose which token they policed

**Severity: critical.** Setup cost: one permissionless registry insert, reusable forever, by anyone.

### What was wrong

Both `transfer_logic_validator` and `third_party_transfer_logic_validator` learned the issuance
policy id they exist to guard from a CIP-113 registry node at a **redeemer-supplied index**, and
authenticated that node with exactly one assertion: *this node names me at field 3* (or field 4).

CIP-113 binds only field 2 (`minting_logic_script`) to the node's key, cryptographically. Fields 3
and 4 are free — the base layer checks only that they are 28 bytes long. This repository's own
comments already said so; the reasoning that a redeemer-chosen node "cannot lie about which policy
it keys" was correct for field 2 and was carried over to fields 3 and 4, where it does not hold.

### The attack

Register a throwaway programmable token — a permissionless CIP-113 insert — whose
`transfer_logic_script` field is *this* deployment's transfer-logic hash, and whose `key` is some
unrelated policy. Include that node as a reference input and point `registry_node_ref_input_index`
at it.

The validator then scans inputs and outputs for `decoy_policy + security_asset_name`, matches
nothing, and both the sender list and the destination list come out empty. `list.indexed_foldr` over
an empty list returns `True`, so the redeemer needs no proofs at all — `actions_for_each_input: []`,
`destination_actions: []`.

The real security token moves with **no denylist check and no KYC check on either side**.

For the seizure variant a `can_force_transfer` power user is still required — but the destination
constraint, which is the entire content of that role's limits, disappears. The "must actually seize
something" check is satisfied with a dust input of the attacker's own decoy token.

The two node indices are genuinely independent, which is what makes this work: the base layer names
*your* registry node in order to decide that *your* transfer logic must run, while your validator
separately reads a **redeemer-chosen** node to decide what to police. Nothing tied the two together.

### The fix

Pin the policy id at compile time. Both validators gained an `expected_issuance_policy_id`
parameter, asserted immediately after derivation, in the `withdraw` handler right after the
registry-node lookup:

- `transfer_logic_validator.withdraw`, `expect issuance_policy_id == expected_issuance_policy_id`
  (`validators/transfer_logic_script.ak:91`)
- `third_party_transfer_logic_validator.withdraw`, the same assertion
  (`validators/third_party_transfer_logic_script.ak:107`)

**There is no circularity.** A registry node's key derives from the *minting* logic hash, never from
these scripts' hashes, so the issuance policy id is known before either script is compiled. The
dependency order is `gs_policy → proxy hash → issuance_policy_id → these scripts`.

The misleading reasoning in `lib/utils.ak` was rewritten to say explicitly that it applies to field
index 2 only, and that every caller passing index 3 or 4 must compare the derived id against a
compile-time expectation.

**Pinned by** `transfer_rejects_a_foreign_registry_node`, `seizure_rejects_a_foreign_registry_node`,
and — as the control that proves the pin did not simply break the path —
`transfer_rejects_a_sanctioned_sender_via_the_genuine_node`.

**Later hardening (2026-08-20):** the registry node is no longer consulted at all on the transfer,
seizure or mint-burn paths — the issuance policy id is pinned at compile time, with no runtime
registry-node derivation or identity check left to bypass. `transfer_rejects_a_foreign_registry_node`
and `seizure_rejects_a_foreign_registry_node` were retired as moot: the decoy-node construction they
guarded against is no longer expressible once the redeemer carries no registry-node index at all.

---

## 3. A list element was trusted wherever it sat

**Severity: high.** Two halves: a primitive, and the reachability that made it usable.

### (a) The primitive — element authentication ignores the address

The library checks the datum shape and that the UTxO holds exactly ADA plus one NFT of the given
policy. **It never looks at the address** — and in v1.6.0 the public helper did not even *expose*
the address, so a consumer could not have checked it. So a single list NFT sitting in a private
wallet authenticates whatever datum its holder writes.

For the denylist that is decisive. The node's *key* is pinned to the NFT's asset name, but the
*link* comes from the datum — so a wallet-held node keyed at `00…00` with `link: None` certifies
absence for **every address on chain**.

For the power-users list it is narrower but still real. The key is pinned, so the signature gate
still binds — but the *role flags* come from the datum, so a revoked operator keeps whichever powers
their old key hash signs for.

### (b) The reachability — how the NFT gets out

Both list `spend` handlers delegate entirely to their mint validator and ask only whether *some*
token of their policy appears in the transaction's mint field. Meanwhile `insert_ascending` inspects
exactly three element UTxOs, and `remove` exactly three.

A **fourth** list node spent alongside a legitimate insert was therefore constrained by nothing at
all. The mint field carries exactly one asset at +1, so that fourth NFT is conserved by the ledger
and must land in some output — and no validator said which. It could go to a wallet.

This needs a privileged transaction author, who is already trusted to sanction or to grant roles.
But an ordinary un-sanctioning is on chain and reversible, whereas this is neither. It also
permanently corrupts the list: the predecessor still links to a key whose UTxO is no longer at the
script, so that entry can never be removed properly.

### The fix

**Reachability first**, because it is the cheaper and more complete half. `lib/utils.ak` gained
`count_inputs_with_policy`, and each mint branch of `validators/denylist.ak` and
`validators/power_users.ak` pins the number of list-policy inputs:

| Branch | Expected list-policy inputs | Why |
|---|---|---|
| `Init` | 0 | genesis — no node exists yet; the root is an *output* |
| `Deinit` | 1 | only the root, and `deinit` already requires an empty list |
| `Add…` | 1 | an insert spends the anchor only; the new node is an *output* |
| `Remove…` | 2 | the anchor and the node being removed |

Outputs need no separate constraint: with inputs pinned and the mint field already restricted to a
single asset, value conservation forces the count, and the library already validates that each
element output holds exactly one NFT of the policy.

**v1.8.0 now enforces these counts itself** — `insert_ascending` and `remove` take the full `inputs`
list and scan it (`validate_singular_authentic_input` / `validate_dual_authentic_inputs`). Our own
counts were kept anyway, deliberately, because the two are **not** equivalent: the library's scanner
only recognises *canonical* elements (exactly ADA plus one list NFT) and silently **ignores** an
input that carries the list policy in any other value shape, whereas ours counts every input bearing
the policy. Element outputs are strictly canonical, so the gap should be unreachable — but a linked
list used as an access-control structure is the wrong place to rely on "should", and the check costs
one fold.

**Then the primitive.** Every place that reads an element for authority now asserts the element's
payment credential is its list's spend-validator hash, threaded in as a compile-time parameter.
Note this hash is **not** the list policy id — the spend and mint validators are separate validators
in the same file and have different hashes.

v1.8.0 added the element's `Address` to the public callback, so the check now lives **inside** the
authentication callback rather than as a separate re-decode. Two places hold it:

- `lib/denylist/absence.ak` — the absence proof, inside its `get_element_info` callback.
- `lib/utils.ak` — `authenticated_power_user`, the single helper every power-user read now goes
  through: the denylist mint, the minting authority, the seizure logic and the GlobalState pause
  branch. It also uses v1.8.0's `get_node_element_info`, which rejects the list ROOT structurally
  rather than via an `expect Some(key)` that each caller could get wrong.

Collapsing four near-identical copies into one helper is the point: three security conditions
(genuine element, is a node, still at the list address) can no longer drift apart between callers.

### Why compile-time parameters, and why all five

The alternative was two new immutable GlobalState datum fields. Parameters were chosen because they
keep the swappable consumers hot-patchable.

The last two sites, in `global_state.spend` and `denylist.mint`, are *not* swappable — adding a
parameter there changes the GlobalState UTxO's address and the denylist policy id respectively.
They were fixed anyway. That makes the whole change redeploy-only, which is the right trade because
nothing is deployed to mainnet, and because in `global_state.spend` the check is the **primary**
defence rather than a belt-and-braces one: that validator cannot be rotated later.

**Pinned by** `denylist_insert_rejects_a_smuggled_extra_node_input`,
`power_user_insert_rejects_a_smuggled_extra_node_input` (each built from a proven-valid insert plus
exactly one extra input, so they isolate the count),
`absence_proof_rejects_a_covering_node_in_a_wallet`,
`wallet_held_power_user_node_cannot_authorise_a_sanction`,
`misplaced_power_user_node_cannot_authorise_a_sanction`, and — in
`validators/global_state_logic_tests.ak` — `pause_fails_when_the_power_user_node_is_in_a_wallet` and
`pause_fails_when_the_power_user_node_is_at_the_wrong_script`, each with a positive control.

The two `*_spend_handler_is_pure_delegation` tests are deliberate records that the `spend` handlers'
`StateTransition` path was **not** changed — the constraint lives in the mint validators, which must
run for any insert or remove. The denylist's later in-place `UpdateDenylistEntry` (§17) runs no mint;
it binds each spend to its own continuation, which must keep the address, the NFT and the link.

---

## 4. The mint roles rested entirely on external code

**Severity: high**, conditional on base-layer behaviour that this repository does not vendor.

### What was wrong

`minting_authority_validator` derived the issuance policy id from a registry node and authenticated
it by "this node names our proxy at field 2". That *is* a cryptographic binding under CIP-113 — but
the guarantee lives entirely in external code that is neither vendored, pinned, nor re-derived here.

If that guarantee ever failed, pointing `registry_node_ref_input_index` at a node naming this
deployment's proxy but keyed to a foreign policy would cascade:

1. the "only the security asset is minted" check inspects the foreign policy — vacuously true;
2. `minted_amount` reads 0 under the foreign policy;
3. `0 > 0` is false, so the branch asks for `can_burn`, **not** `can_mint`;
4. destination checks are skipped entirely.

…while the transaction mints a million of the **real** token to a **sanctioned** address. The supply
cap survives, because GlobalState is still spent — but a `can_burn`-only operator has just created
arbitrary real supply.

### The fix

Do not inherit a control this critical. `minting_authority_validator` gained
`expected_issuance_policy_id`, asserted at every derivation site (all in
`validators/minting_authority.ak`):

- the `MintBurn` branch, immediately after deriving `issuance_policy_id` from the referenced
  registry node (line 183)
- the `UpgradeRegistryNode` branch, on the spent node (the continuing node is already compared
  against it) (line 322)
- inside `verify_registration_structure`, shared by `RegisterMint` and `RegisterStructural`
  (line 609)

Not circular: `gs_policy → proxy hash → issuance_policy_id → this validator`, and this validator is
compiled last precisely because it is the swappable one.

**Pinned by** `mint_rejects_a_registry_node_keyed_to_a_foreign_policy` for the `MintBurn` branch, and
three tests in `validators/minting_authority.ak` — `register_mint_fails_when_node_is_keyed_to_a_foreign_policy`,
`register_structural_fails_when_node_is_keyed_to_a_foreign_policy`,
`upgrade_fails_when_spent_node_is_keyed_to_a_foreign_policy` — for the other three. Each uses a node
that **does** name this deployment's proxy, so the pre-existing identity assertion passes and only
the new pin can reject it.

The base layer was subsequently read and does hold the binding (see
[below](#what-the-cip-113-base-layer-actually-guarantees)). The pin stays: the point is that the
control is now local and survives a base-layer upgrade that weakens it.

---

## 5. Pause does not stop issuance

**Severity: medium. Status: accepted as intended behaviour, and now documented.**

`verify_mint_or_burn` reads `deactivated` but never `transfers_paused`. A `can_mint` power user can
issue new supply, and a `can_burn` power user can destroy it, in the middle of a pause.

This was flagged because the answer was **unwritten**, not because it was necessarily wrong. Both
answers are defensible, and the deployment owner chose: **pause is transfer-only.**

The reasoning, now recorded beside the deactivation check in `validators/minting_authority.ak`:

- It follows the CMTAT *reference implementation*, where `mint` and `burn` go through `_update`
  rather than the pause-checked transfer path.
- It mirrors the exemption `third_party_transfer_logic_script.ak` already documents for forced
  transfers — enforcement availability beats a literal reading of "prevent all transfers". A court-
  or regulator-ordered burn cannot wait for an unpause any more than a seizure can.

Two consequences are accepted knowingly:

1. Position sizes can change while the register is otherwise static. Every such change is still a
   signed, on-chain, power-user-gated, cap-enforced event, so the register stays auditable.
2. A holder minted to during a pause cannot move the tokens until the pause lifts. Off-chain
   issuance procedure must not mint to third parties mid-pause.

If the mandate ever changes, the change is one line, and the code says exactly which line and which
tests to invert.

**Pinned by** `mint_succeeds_while_transfers_are_paused_by_design` and
`burn_succeeds_while_transfers_are_paused_by_design`. These assert *intended* behaviour and are
deliberately left asserting acceptance — **do not "fix" them.**

---

## 6. Mint destinations were vetted by stake credential only

**Severity: medium.**

`verify_mint_destinations` selected outputs by "carries the security asset", then read
`output.address.stake_credential` as the owner identity. Nothing asserted anything about the
**payment** credential. A comment stated that the payment credential "is the shared programmable-logic
base script" rather than checking it.

If the base layer did not independently pin mint destinations, supply minted to a plain wallet would
live outside the programmable base, never be seen by a transfer-logic script again, and be freely
transferable with no KYC, no denylist and no pause — permanently — while still counting against the
cap as though it were regulated. Because it looks identical on chain, the register would not surface
the discrepancy. Plausibly reachable by accident, since the failure is silent.

### The fix

`minting_authority_validator` gained a `plb_script_hash` parameter, and every token-bearing output
must sit behind it — `verify_mint_destinations`, `expect dest_payment == plb_script_hash`
(`validators/minting_authority.ak:817`).

**Extended to the transfer path as well**, but only after reading the base layer. The review
explicitly warned against doing this blind, because a legitimate flow might produce a token-bearing
output outside the base. Having confirmed the base layer forbids escape on transfers too, the pin
was added to both transfer validators' `withdraw` handlers as **defence in depth** — not as the
load-bearing control: `transfer_logic_validator.withdraw`'s sender fold
(`expect src_payment == plb_script_hash`, `validators/transfer_logic_script.ak:150`) and
destination fold (`expect dest_payment == plb_script_hash`,
`validators/transfer_logic_script.ak:185`), and
`third_party_transfer_logic_validator.withdraw`'s destination fold (same assertion,
`validators/third_party_transfer_logic_script.ak:148`). It earns its place because the surrounding
code reads the stake credential *as if* the payment credential were the base script; asserting it
makes that true by construction.

**Pinned by** `mint_rejects_a_destination_outside_the_programmable_logic_base` and
`transfer_rejects_a_destination_outside_the_programmable_logic_base`.

**Later hardening (2026-08-20):** the programmable-base payment-credential pin described above was
removed from the mint path (`verify_mint_destinations`, `reference_nft_output_is_pinned`) and from
the ordinary-transfer path (both the sender and destination folds in
`transfer_logic_validator.withdraw`), in favour of relying directly on the base layer's own custody
guarantees — see the "Minted supply is confined to programmable-base addresses" and "Transfers cannot
move tokens out of the base, and conserve value" rows in
[the base-layer table](#what-the-cip-113-base-layer-actually-guarantees). The pin is **kept** on the
seizure path (`third_party_transfer_logic_validator`), because that guarantee was not independently
verified — see the same table. `mint_rejects_a_destination_outside_the_programmable_logic_base` and
`transfer_rejects_a_destination_outside_the_programmable_logic_base` were retired alongside the
removal, since the payment-credential pin they each pinned no longer exists on those two paths.

**Later hardening (2026-08-21):** the programmable-base payment-credential pin was also removed from
the **seizure path** (`third_party_transfer_logic_validator`), on the same basis — see the "Seizure
(forced-transfer) custody" row in
[the base-layer table](#what-the-cip-113-base-layer-actually-guarantees). The pin is now removed on
**all three** paths: mint, ordinary transfer and seizure.

---

## 7. The GlobalState UTxO's ADA balance was unconstrained

**Severity: low** — the actor is an admin or role-flagged power user, not an outsider.

`value_preserved` compared `without_lovelace` on both sides, and all eleven spend branches compose
that same value. The non-ADA value was pinned; the ADA was free.

The effect: any authorised action also moves the UTxO's ADA freely, in either direction.

**Accepted by decision (2026-08-21), and the check has been removed.** The actions that reach this
line are all signed — by the admin, or by a power user holding the relevant flag — so an ADA
withdrawal from the control UTxO is a privileged operator moving their own working capital, not an
attack. `value_preserved` is therefore exactly what the code says it is, and nothing more:

```aiken
// validators/global_state_logic.ak
let value_preserved = without_lovelace(own_input.output.value) == without_lovelace(
  global_state_output.value,
)
```

Non-ADA value — the GlobalState NFT above all — is pinned. Lovelace is not, in either direction.

An earlier revision of this section also claimed that draining the UTxO to the min-ADA floor could
make it *permanently unspendable*, because a later datum growth would leave the continuing output
unsatisfiable. **That was overstated and is withdrawn.** Since the validator ignores lovelace
entirely, any spend may top the UTxO back up in the same transaction, so there is no floor to get
stuck at.

What remains true, and is an operational note rather than a defect: the control UTxO is spent by
every mint, burn and admin action, and a transaction carrying attestation proofs is not small. Keep
enough ADA on it to cover the min-UTxO of a datum that may grow (see
[the datum caps](#datum-size-the-three-caps-do-not-add-up-to-a-joint-bound) below).

The regression test that pinned the removed check (`global_state_spend_rejects_a_lovelace_withdrawal`)
was deleted with it.

---

## 8. Genesis did not sanity-check the two list policy ids

**Severity: low**, but unfixable after the fact.

Genesis required each list's root NFT to be minted in the same transaction, but never required
`power_user_linked_list_policy_id` and `denylist_linked_list_policy_id` to **differ**, nor bound
either to a real list validator. Set equal, a power-user node would double as a denylist covering
node and the sanctions list would be inert from day one.

Both fields are immutable afterwards — every spend branch reproduces the datum wholesale — so
genesis is the only chance to catch it.

### The fix

`sanitise_initial_datum` now requires the two ids to differ and both to be exactly 28 bytes. The
length check is the same defence one step earlier: a malformed id can never name a real minting
policy, so that list would be permanently un-initialisable.

What the on-chain code **cannot** do is bind an id to a compiled validator hash. Off-chain must
verify both ids against the compiled list-validator hashes before signing genesis.

**Pinned by** `sanitise_rejects_identical_list_policies` and `sanitise_rejects_short_list_policy_id`
in `validators/global_state.ak`. The second deliberately mints a root under the malformed id, so the
pre-existing "both roots minted here" check still passes and only the new length check can reject it
— otherwise the test would pass for the wrong reason.

---

## 9. Credential type was erased throughout

**Severity: low** as an exploit; a real identification defect for a `registerführende Stelle`.

Every identity path collapsed a `Credential` to its bare 28-byte hash:

```aiken
when stake_cred is { VerificationKey(hash) -> hash; Script(hash) -> hash }
```

Denylist entries, KYC attestation payloads and the receiver-KYC bypass all keyed on that hash with
no record of whether it was a key or a script.

That matters because **the base layer treats them as genuinely different owners**: a
`VerificationKey` owner consents by signature, a `Script` owner by withdraw-0. So a KYC attestation
issued for a key credential was equally valid for a script credential with the same hash, and the
holder register could not distinguish the two.

### The fix

Carry the `Credential`, and commit the constructor into the proof.

- **Attestation payload gained a `credential_type` byte** at offset 66 — `0x00` for
  `VerificationKey`, `0x01` for `Script`. It was **appended**, so every pre-existing offset is
  unchanged and only `payload_length` moved 66 → 67. It must be in the *signed* payload, not checked
  alongside it, or it could simply be swapped.
- **Membership leaf key** became `credential_type ‖ hash` (29 bytes).
- `lib/utils.ak` gained `credential_hash` and `credential_type_byte`.
- All four identity paths now carry `Credential` through their folds.

**Two places deliberately still use the bare hash**, and this is not an oversight:

The **denylist** keys on the hash, so sanctioning a hash sanctions **both** credential forms. That
is the conservative direction; inverting it would let a sanctioned party reappear as the other form.

The **power-user receiver-KYC exemption** in `minting_authority` compares hashes, because a
power-user node's key is a bare hash with no constructor recorded — there is nothing to compare the
other half against. It is an exemption from receiver KYC only; the denylist check still applies to
that destination.

### A consequence worth knowing about

Deduplication now runs over the full `Credential`, so `VerificationKey(H)` and `Script(H)` count as
**two parties**, each consuming its own slot in `actions_for_each_input` / `destination_actions`.
Constructing such a pair is computationally infeasible, so in practice nothing changes — but the
rule is stated because it decides which key an integrator deduplicates on.

**Pinned by** `attestation_fails_when_credential_type_mismatches` and
`attestation_fails_when_script_payload_used_for_a_key`, both using genuine signatures so the
credential-form mismatch is isolated (both directions — a one-directional check would still let one
form impersonate the other), `membership_leaf_key_separates_credential_forms`, and four tests
covering the two *separate* dedup implementations:
`transfer_treats_key_and_script_forms_of_one_hash_as_two_parties` /
`transfer_rejects_one_action_covering_both_credential_forms` for `list.unique`, and
`mint_treats_key_and_script_forms_of_one_hash_as_two_destinations` /
`mint_rejects_one_action_covering_both_credential_forms` for the hand-rolled recursion in
`verify_mint_destinations`.

---

## 10. The membership KYC variant bound neither policy nor network

**Severity: info.**

The two KYC proof variants are meant to be interchangeable. `verify_attestation_proof` bound the
security policy id and the network id explicitly. `verify_membership_proof` bound **neither** — it
checked the holder's key, the TTL, and tree membership, and nothing else.

Two deployments that ever shared a membership root would accept each other's proofs, and a proof was
not pinned to a network. Contrived today — the root is per-deployment GlobalState state, so sharing
one is an operational choice rather than something an attacker can force — but it was a latent
asymmetry between two mechanisms that are supposed to be equivalent.

### The fix

The MPF leaf value now commits the same three things the attestation payload does:

```
valid_until_ms(8) ‖ security_policy_id(28) ‖ network_id(1)
```

Both halves are derived from the **expected** credential and this deployment's own policy and
network — never from the proof — so a proof cannot select which deployment it belongs to.
`lib/kyc/verify.ak` exports `membership_leaf_key` and `membership_leaf_value` as the normative
encoders so off-chain cannot drift.

**Pinned by** `membership_leaf_value_binds_policy_and_network`.

**Still unhandled, and small:** `ttl_ok` on both proof paths ignores the validity bound's
`is_inclusive` flag. At most a 1 ms edge.

---

## 11. The power-user authority footgun was undocumented

**Severity: info** — a documentation gap, but one with a silent, fail-open failure mode.

`must_be_signed_by_credential` treats a bare signature and a script's withdraw-0 as equivalent
evidence. `lib/types/global_state.ak` explained at length why that is dangerous for
`minting_script_credential_hash`, and prescribed a deployment smoke test.

The **same helper gates all five power-user roles** — `is_admin`, `can_mint`, `can_burn`,
`can_pause`, `can_force_transfer` — and that case was undocumented. The worst instance: point
`can_force_transfer` at `transfer_logic_script`, whose withdraw-0 requires no signature at all, and
seizure powers become public.

### The fix

The warning was extended on `utils.must_be_signed_by_credential` and in `lib/types/global_state.ak`
to cover every role, with the prescribed smoke test extended to match: **after granting or rotating
any role, assert that an operation exercising it without that operator's signature is rejected.**

This is a deployment requirement, not an on-chain check. An on-chain reserved-hash list would not
stop a malicious admin — who would simply deploy their own permissive script — and it would go stale
the moment any named script is upgraded.

---

## 12. Dismantling either linked list was a one-way freeze of a live protocol

**Severity: medium.** Admin-only, but irreversible and — unlike `DeactivateContract` — invisible
afterwards: the token keeps reporting itself active.

### What was wrong

Both list mint validators carried a `Deinit` branch that burned the list's root NFT. Its only
preconditions were the admin's signature and an empty list (the library's `deinit` requires the
root's `link` to be `None`). Nothing checked whether the protocol was still running.

Burning a root is irreversible in both directions:

* `Init` is gated on a one-shot `OutputReference` consumed at genesis, so a root can never be
  re-created; and
* `denylist_linked_list_policy_id` / `power_user_linked_list_policy_id` are immutable in the
  GlobalState datum — no spend branch writes them — so GlobalState can never be pointed at a
  replacement list either.

For the **denylist**, that is a total freeze. Every movement of the security token resolves a
covering node of that list as a reference input — the transfer path, the seizure path, and every
mint destination all go through `lib/denylist/absence.ak`. With no element in existence, no covering
node can be produced, so nothing can ever move again. The token is not `deactivated`, so nothing on
chain says why.

For the **power-users list** it is at least as broad. `AddPowerUser` needs an existing element as
its insert anchor, so with the root gone no operator can ever be added again: mint, burn, pause,
unpause, seizure and sanctions administration all authenticate against a node of that list. If
transfers happened to be paused at that moment they stay paused forever, because unpausing needs a
`can_pause` node.

Neither consequence was documented, and an empty list is not an unusual state — it is the state at
genesis, and the state again after the last sanctioned wallet is released.

### The fix

`Deinit` is now **post-decommission cleanup**: it requires `deactivated` first.

```aiken
// validators/denylist.ak — and the same shape in validators/power_users.ak
let gs = gs_datum_from_ref_input(
  self.reference_inputs,
  global_state_ref_input_index,
  global_state_policy_id,
)
and {
  gs.deactivated?,
  must_be_signed_by_credential(self, gs.admin_credential_hash),
  ...
}
```

Two irreversible decisions now have to happen in the only honest order: retire the token, then
dismantle its lists. The branch keeps its purpose — reclaiming the root's min-ADA once the token is
finished — and loses its ability to end a live protocol.

Note the reader: `gs_datum_from_ref_input`, **not** `active_admin_from_ref_input`. The latter traps
on a deactivated protocol, which is exactly the state this branch now requires. The GlobalState UTxO
can no longer be *spent* after `DeactivateContract` (the spend validator's terminal guard), but it
is still *readable* as a reference input, so the admin credential remains available.

**Pinned by** `denylist_deinit_succeeds_for_the_admin_after_deactivation` /
`denylist_deinit_rejects_a_live_protocol` (`validators/regression.ak`) and
`power_users_deinit_succeeds_for_the_admin_after_deactivation` /
`power_users_deinit_rejects_a_live_protocol` (`validators/power_users.ak`), each paired with the
existing missing-signature test. The negative tests are `!` rather than `fail`: `gs.deactivated?` is
a conjunct of an `and { }`, so the validator returns False. Both traces were read and name that
assertion.

### The decommissioning runbook, in order

Deactivation is a tombstone: the terminal guard makes the GlobalState UTxO unspendable by any path,
and node removal on both lists is blocked once it is set (`RemoveFromDenylist` goes through
`power_user_from_refs`, which asserts `!deactivated`; `RemovePowerUser` uses
`active_admin_from_ref_input`, which traps). `deinit` in turn requires an empty list. So the order
below is load-bearing, not advisory — every step after the first is unavailable once the one before
it has been skipped:

1. **Sweep the GlobalState UTxO's surplus ADA** down to what it needs. After deactivation that UTxO
   can never be spent again, so every lovelace left on it — along with the GlobalState NFT itself —
   is locked forever. This is the one place the accepted ADA-withdrawal behaviour of
   [§7](#7-the-globalstate-utxos-ada-balance-was-unconstrained) is not merely harmless but useful.
2. **Pause** (skip if already paused — a pause that does not flip the flag is rejected) — needs a
   live `can_pause` power user, so it must happen while the operator list is still populated.
3. **Empty the denylist** (`RemoveFromDenylist` per entry, `is_admin` power user).
4. **Empty the power-users list** (`RemovePowerUser` per entry, admin) — last, because steps 2 and 3
   consume power-user nodes.
5. **Deactivate** — admin signature and `transfers_paused` only; it deliberately needs **no**
   power-user reference input, so it still works after step 4 has emptied the list.
6. **`Deinit` both lists** — admin, now permitted because `deactivated` is set, and possible because
   steps 3 and 4 left each list empty.

Skipping step 1 strands the GlobalState UTxO's whole balance. Skipping step 3 or 4 strands that
list's remaining nodes **and its root** — roughly 2 ADA each — because `deinit` can never run on a
non-empty list and the nodes can no longer be removed. None of this risks the register or any
holder's tokens; it is the operator's own deposits. But note the realistic case: a token retired for
compliance reasons will usually still have denylist entries, and un-sanctioning those parties purely
to reclaim deposits may not be an acceptable action — so expect the denylist's `Deinit` to go unused
in practice, and treat its deposits as sunk.

**The trade this fix makes, stated plainly.** Before it, `Deinit` was reachable at any time, so those
deposits were always recoverable — at the cost of a single admin transaction being able to freeze a
live protocol irreversibly and invisibly. After it, the freeze is impossible and the deposits are
recoverable only in the documented order. That is the right way round, but it is a trade, not a pure
win.

---

## 13. CIP-68 metadata tokens were governed by an exact name, not by their kind

**Severity: medium. Fixed.** Reported as a seizure defect; fixed as a general rule, because the
seizure hole was one symptom of the underlying shape.

### What was wrong

Every compliance scan in this module is scoped to `security_asset_name` — the destination folds
that feed `compliance.verify_parties`, `at_least_one_seized_input`, the mint destination walk. A
CIP-68 token lives under the **same issuance policy** but a different asset name, so it was invisible
to all of them, and the only thing that distinguished it was an exact-name compile-time parameter,
`reference_asset_name`.

That produced three gaps:

1. **The seizure path could take it.** A `can_force_transfer` operator could spend the CIP-68
   metadata UTxO alongside one unit of their own security-token dust — the dust satisfying "must
   actually seize something" — and re-output the token to any address with any datum. No admin
   signature, no denylist check, no KYC check, even with `requires_receiver_kyc` set. That defeats the
   property registration establishes: the CIP-68 metadata token has its own owner and cannot be moved
   through the seizure path.
2. **"Only one metadata token" was true by accident, not by design.** With an exact-name parameter at
   most one name could ever match the metadata arm of the mint allowlist, so a second metadata token
   was unconstructible — but nothing *stated* the rule, and it would have evaporated the moment the
   parameter became anything less specific.
3. **The UTxO's shape was a posture at genesis, not an invariant.** `reference_nft_output_is_pinned`
   checked the owner and that the first supply was not co-located, once, at registration. It did not
   inspect the datum at all, and nothing re-checked anything afterwards — so a later metadata update,
   which travels the ordinary transfer path, could co-locate the token with supply or write a datum
   no CIP-68 reader can parse.

There was also a trap in the exact-name design. Setting `reference_asset_name == security_asset_name`
was the documented way to disable CIP-68, which made "was a metadata token minted?" ambiguous: the
quantity test read the security token's own mint. Every check had to carry an aliasing escape hatch,
and getting one wrong would have refused every ordinary transfer.

### The fix

Identify metadata tokens by **kind**, not by name. `constants.cip68_protected_prefix` is the CIP-67
label that marks a token as metadata — `(100)`, and nothing else is or can be — and `lib/cip68.ak`
holds the predicates the validators share.

```aiken
// lib/constants.ak
pub const cip68_protected_prefix: ByteArray = #"000643b0"
pub const cip68_protected_prefix_length = 4
```

A single constant rather than a list, on review feedback: `(100)` is the only CIP-68 metadata label,
so `is_protected` is one comparison against one constant instead of a fold over a one-element list.
On a check that runs per token per output on the transfer path that is not cosmetic — the predicate
dropped from 5.91 K memory / 1.29 M CPU to **200 memory / 16.1 K CPU**.

**The security token may not be protected.** `verify_registration_structure` asserts
`!cip68.is_protected(security_asset_name)`. This is what removes the aliasing trap: the protected set
and the supply name are now disjoint by construction, so no check needs an escape hatch, and a
deployment that named its supply `(100)…` fails closed at registration instead of silently refusing
every transfer and seizure later.

**Rule 1 — at most one metadata token, minted once.** `only_permitted_assets_minted` now admits a
non-supply name only if a branch allows it (`RegisterMint` alone), it carries a protected prefix, and
its quantity is exactly one — and separately counts protected entries, requiring `<= 1`. With
prefixes, `(100)Foo` and `(100)Bar` both reach that arm, so the count has to be stated rather than
assumed.

**Rule 2 — the UTxO holds ADA plus that token, with a well-formed datum and inline owner.**
`cip68.output_is_well_formed` asserts the value structurally (`[Pair(ada, _), Pair(policy, names)]`,
then `[Pair(name, 1)]`) and decodes the datum as `Cip68Datum` — CIP-68's `Constr 0 [metadata,
version, extra]`. It runs at registration via `cip68_output_is_pinned`, which also requires an inline
stake credential for the metadata authority, **and on every later move** inside
`transfer_logic_script`'s existing output fold. That second half is what makes it an invariant: the
transfer path is how a metadata update happens.

**Rule 3 — seizure may not touch it.** `third_party_transfer_logic_script` refuses any transaction
whose **inputs** carry a protected token. Inputs, not outputs, because the token can only change
hands if its UTxO is spent, so refusing the whole transaction is simpler and stricter than vetting
where it lands. Metadata updates are unaffected — they take the transfer path, where the base layer
requires the owner's own consent.

### Cost

Rule 2's transfer-path half is on the hot path, so it was measured rather than assumed. The output
fold now does ONE `assets.tokens` lookup per output and answers both of its questions from it — "is
this a destination?" and "does this carry metadata?" — where it previously did one `quantity_of`.
`aiken bench -m "transfer_logic_script.{..}"`, same seed, before and after:

| | memory | CPU |
|---|---|---|
| 1 sender + 1 destination, before | 613.12 K | 182.77 M |
| 1 sender + 1 destination, after | 626.45 K | 186.34 M |
| | **+2.2 %** | **+1.9 %** |

Growing to roughly +4 % memory at 30 parties per side. That is the price of the invariant, paid by
every transfer; it was judged worth it because the alternative is a rule that is true only at genesis.

Two review-driven changes brought that figure down from an initial +2.9 % / +2.6 %: the single
constant above, and dropping the ADA entry from the value with `dict.expect_tail` instead of
comparing it — every UTxO carries lovelace and a `Value` sorts the empty policy id first, so the
comparison was provably redundant.

### Tests

`lib/cip68.ak` carries unit tests for both predicates — label `(100)` protected, `(333)` not, a
truncated name not (and not a trap); and the canonical shape accepted against five rejections
(co-located security token, foreign policy, quantity two, malformed datum, missing datum). The
validators carry the integration tests: a registration whose metadata output has a malformed datum or
holds supply; a registration whose `security_asset_name` is protected; a seizure that spends a
protected token, with the ordinary seizure beside it as control; and a metadata update through the
transfer path, well-formed as control and rejected when malformed or co-located. Every negative was
run individually and its trace read, to confirm it stops at the intended assertion rather than
incidentally — one of them did not at first, and was rewritten.

One existing test changed its ANNOTATION, not its meaning:
`register_mint_rejects_a_reference_nft_co_located_with_supply` was `!run_withdraw` and is now `fail`,
because the co-location rule moved from a `Bool` conjunct into the structural assertion in
`output_is_well_formed`. The transaction was rejected before and is rejected now.

### Deployment

`minting_authority_validator` loses the `reference_asset_name` parameter — **9 → 8** — so deploy
scripts must drop it. No redeemer or datum schema changes. Three hashes move, all upgradeable in
place: `minting_authority` (rotatable via `RotateMintingScript`), `transfer_logic_script` and
`third_party_transfer_logic_script` (registry fields 3 and 4, re-pointable via
`UpgradeRegistryNode`). Verified empirically: the two list mint validators' hashes do **not** move, so
adding the constant perturbs nothing that does not use it.

---

## 14. Registry fields 3 and 4 accepted any script (F08)

At registration and on `UpgradeRegistryNode` the minting authority only checked that registry fields
3 and 4 were *some* script credential. The base layer authorises a seizure by the field-4 script's
withdraw-0 alone, with no owner consent, so a swapped pair or a foreign script there would have let
anyone seize: with this deployment's transfer logic in field 4, every seizure passes on pause,
denylist and KYC alone.

**Changed (2026-10-15):** `minting_authority_validator` takes two more parameters,
`transfer_logic_script_hash` and `third_party_transfer_logic_script_hash`, and both registration
branches and `UpgradeRegistryNode` require fields 3 and 4 to equal exactly `Script` of them. The two
must differ. Re-pointing either field now means `RotateMintingScript` to an authority built with the
new hash first, then `UpgradeRegistryNode`. Only the minting authority's hash changes, so a
deployment that has not locked upgrades can adopt the fix by rotation; nothing permanent is
redeployed. Rotation does not re-check the node already registered: after rotating, read the live
node and confirm field 3 is `Script` of the transfer logic and field 4 `Script` of the seizure logic;
if not, run `UpgradeRegistryNode` before `LockUpgrades`.

**Pinned by** the `registration_*` and `upgrade_*` tests in the F08 section of
`validators/minting_authority.ak` (swapped scripts, a foreign transfer or seizure script, the
transfer script in both fields) and
`an_authority_built_with_one_hash_for_both_scripts_refuses_registration`; each pin was
mutation-checked.

## 15. Genesis never ran the field-0 logic, and rotation accepted any script that runs

Two halves of one gap, raised in review of PR #29. Genesis only checked field 0's length and that it
differed from the proxy, the admin and the minting authority: a field 0 that could not run (a typo,
an unregistered stake credential, a build for another GlobalState policy) produced a GlobalState that
no action could ever spend, rotation included, since rotation needs the current logic to run. And the rotation's check
that the new logic runs was satisfied by any script whose withdraw-0 passes in a GlobalState
transaction, such as this deployment's own transfer logic.

**Changed (2026-10-16):**
* The GlobalState mint requires the withdraw-0 of the logic field 0 names, and `global_state_logic`
  gained a one-shot genesis branch, gated on the GlobalState NFT being minted in the same
  transaction: the output carrying the NFT must name this logic in field 0 and fit this logic's own
  `max_global_state_datum_bytes`, so the two caps agree at birth. Outside genesis the logic's
  withdrawal still proves nothing without a spent GlobalState.
* The outgoing side of `RotateGlobalStateScript` requires the new logic to run with the very same
  rotation redeemer, so a script that cannot decode a GlobalState rotation cannot be installed.

Neither proves the script is a correct GlobalState logic — one that ignores its redeemer passes — so
the runbooks now require re-deriving the hash from source and every parameter before signing genesis
or a rotation. The mint change moves the GlobalState policy id and applies to new deployments only;
the logic change can be adopted by rotation.

**Pinned by** `global_state_mint_fails_without_the_global_state_logic_withdrawal`,
`global_state_mint_fails_when_only_another_script_withdraws`, `logic_accepts_the_genesis_that_names_it`,
the `logic_genesis_*` tests, `logic_built_for_another_global_state_policy_fails_genesis`, and
`rotate_gs_logic_fails_when_the_new_logic_runs_with_another_redeemer`,
`rotate_gs_logic_fails_when_the_new_logic_redeemer_names_another_logic` and
`rotate_gs_logic_fails_without_a_redeemer_for_the_new_logic`; each new check was mutation-checked.
The new checks also hid five older guards from the tests written for them — rotation's 28-byte,
self-rotation, minting-authority and admin guards, and genesis's proxy guard — so each now has a
test in which it is the only check that fails (`t_consistent_rotate_tx`,
`global_state_mint_fails_when_field_0_is_the_proxy_even_if_it_runs`).

## 16. The power-users list policy id was held twice on the mint path

Raised in review of PR #29. The minting authority took `power_users_linked_list_policy_id` as a
compile-time parameter and required it to equal GlobalState field 3, the same value. The seizure
logic (2026-08-20) and the denylist (a5d5883) had already dropped their copies. The GlobalState
datum's copy cannot go: the GlobalState mint checks the list root at genesis, and the list's policy
is built from the GlobalState policy, so it cannot be a parameter there.

**Changed (2026-10-21):** `minting_authority_validator` drops the parameter (**10 → 9**) and
authenticates power-user nodes under field 3 of the NFT-authenticated GlobalState input. This
supersedes the 2026-08-20 cross-check. Only the minting authority's hash moves, so a deployment that
has not locked upgrades adopts it by `RotateMintingScript`. Deploy scripts must drop the fourth
argument.

**What it costs.** Under this GlobalState logic, field 3 is set once at genesis and no action writes
it, so the authority accepts no new transaction. The cross-check differed only if genesis had named
a wrong policy (or if a future logic rewrote field 3). Then every mint trapped; now mints follow
that policy's nodes, as seizure, sanctions and `PauseTransfers` already did. Field 3's value is
therefore a replacement-logic invariant (`global_state_logic.ak`, invariant 11), and the genesis
check that both list policy ids match their compiled `mint` hashes is load-bearing for the mint path
too. `power_user_list_script_hash` pins only the node's address: anyone can pay a foreign-policy NFT
there.

**Pinned by** `mint_fails_when_global_state_power_user_policy_id_mismatches` and its positive
control, re-purposed: field 3 names a policy the node is not under, so `authenticated_power_user`
traps. Mutation-checked: authenticating under a fixed policy instead of field 3 makes the negative
test fail.

## 17. Partial freeze: a denylist entry can freeze an amount, not only the whole holding

A feature, not a defect, recorded here because it changes what a denylist entry means and adds a
mutation path to a permanent validator. Requested to match CMTAT `freezePartialTokens`: "this
address has that many tokens frozen; which ones does not matter".

**Changed (2026-10-23):**

* The node datum is `Denylist { frozen_amount: Option<Int>, metadata }`. `None` is a full freeze,
  exactly what every entry meant before. `Some(f)` with `f > 0` is a partial freeze. `Some(f)` with
  `f <= 0` is refused at every write (`AddToDenylist`, `UpdateDenylistEntry`).
* A party's denylist index may now name **its own node** as well as a covering node
  (`absence.party_permitted`). Own node with `None`: rejected on every side. Own node with
  `Some(f)`: every destination gate accepts (transfer, mint, seizure); the transfer path's sender
  gate accepts only if the outputs whose inline stake credential hash is the node key carry at
  least `f` of the security token. The on-chain redeemer encoding does not change, and an unlisted
  party's proof is byte-identical to before; the index fields are renamed in the blueprint, though
  (see [what this changes for off-chain](#the-2026-10-23-partial-freeze-one-datum-change-one-redeemer-variant-two-new-parameters)).
* `denylist_validator` (spend) gains `UpdateDenylistEntry`, which rewrites one node's data in place
  through the library's `spend_for_updating_elements_data`, gated like Add/Remove (an `is_admin`
  power user, signed, protocol not deactivated), nodes only, strict decode, metadata ≤ 512 B, and
  the node's ADA may not decrease. Remove-then-add cannot do this: the burn and re-mint of the same
  node NFT cancel out, so it would take two transactions with the holder unlisted in between. The
  validator gains two parameters, `global_state_policy_id` and `power_user_list_script_hash`
  (README row 5), so its hash moves, and with it every hash that pins it (rows 8–10).

**Invariants** (complexity-specialist review, 2026-10-23):

1. *Freeze floor.* In a `TransferAct` transaction that spends hash `h`'s security tokens, the
   outputs to stake hash `h` carry at least `f`, or at least what the transaction spends from `h`
   (amended 2026-10-29, PR #30 review). So `post ≥ min(pre, f)`: a holder at or above `f` keeps
   `f`, and one below `f` cannot lower its balance. The guarantee is net per transaction — tokens
   paid to `h` in the same transaction count — where CMTAT checks each gross transfer. The only
   ways below `min(pre, f)` are a seizure (`can_force_transfer`) or an `is_admin` Remove/Update,
   which change `f` and move nothing. The second arm reuses `paid_back_to_holder` over the inputs'
   outputs and runs only when the first fails. Reusing it rather than a dedicated early-exit walk
   keeps the script at +81 B instead of +190 B, which every transfer pays as reference-script fee.
   A send that pays back `f` costs a constant +2 201 mem / +428 049 cpu over the old rule, however
   many inputs it has; every other transfer pays a constant +200 mem / +32 000 cpu (≈ 14 lovelace,
   against ≈ 1 600 lovelace of reference-script fee saved by the smaller script). The complexity-specialist review (2026-10-29: sound, no counterexample)
   covered the rule with a dedicated walk; the shipped fold computes the same `spent` (bare hash,
   security token only), and its `expect` cannot trap where the sender fold has not already.
2. *Full freeze unchanged.* `None` rejects `h` as a sender and as every kind of destination.
3. *Exact membership.* A party's element is authenticated (list policy from GlobalState field 7,
   list spend address pinned) and is either the party's own node or covers it — never both, since
   keys are unique and strictly ascending and `covers_key` is strict.
4. *Writes are strict, reads fail closed.* Writers `expect` a well-formed `Denylist`; a reader that
   meets an own node it cannot decode rejects that party (a strict soft cast returning False)
   rather than trapping the whole transaction.
5. *The memo caches the element, never a verdict.* `compliance.vet_remembering` — since
   2026-10-27 one self-recursive function walking every party after the first — re-decides membership for
   each party's own hash, so one party's membership proof cannot pass another.
6. *Update and insert/remove never share a transaction.* One requires a list-policy mint, the
   other forbids it.

**A dependency worth stating plainly.** The sender rule reads only the *stake* credential of the
paid-back outputs. On Cardano the *payment* credential controls spending, so the rule is sound only
because the CIP-113 base layer keeps this token at programmable-base outputs on every path
(`no_escape` on mint, transfer conservation, seizure pairing, unfracking disabled by registry
field 5) — the same premise the destination fold has always relied on.

**Costs, accepted.** Every send that lowers a partially frozen holder's balance must pay `f`
back, so it normally includes at least `f` of the holder's own tokens; a balance in many small
UTxOs can be consolidated first, which the second arm of the rule always allows (16 KiB limit per
transaction). Neither `AddToDenylist` nor `UpdateDenylistEntry` can see the holder's balance, so
`f` is not bounded by it: an `f` above the balance blocks every send that would lower it until the
balance reaches `f` (receiving and consolidating still work). The pay-back output makes the
holder a destination of its own transaction, so with `requires_receiver_kyc` set it needs valid
receiver KYC to send even when `requires_sender_kyc` is off; a partially frozen holder with lapsed
KYC must renew it first (pinned by
`partially_frozen_sender_without_valid_kyc_is_blocked_by_receiver_kyc`). Exempting that change from
receiver KYC was considered and deferred to keep the gate simple. An update
changes the node's UTxO reference, so in-flight transactions that cite it — the holder's own, or a
neighbour's absence proof — must be rebuilt. A seizure can leave the holder below `f`; update `f`
afterwards if that is not intended. A partially frozen holder can now take a partial seizure's
residual, which a fully frozen one still cannot (see the operational constraints below).

**Where this differs from CMTAT v3.2.0.** The model is CMTAT's "an amount is frozen, which tokens
does not matter", but three behaviours of `ERC20EnforcementModuleInternal` are not reproduced:

* *Forced transfer does not reduce `f`.* CMTAT's `_forcedTransfer` (and its forced burn, the
  `to == address(0)` case) calls `_unfreezeTokens`, which lowers the frozen amount by however much
  the transfer exceeds the active balance. Here a seizure moves tokens without touching the denylist
  node, so `f` survives it: a holder seized below `f` cannot lower its balance until an `is_admin` power user
  lowers `f` with `UpdateDenylistEntry` or the holder's balance climbs back to `f`. An operator
  wanting CMTAT behaviour updates `f` in the same operating procedure as the seizure. Burning goes
  through the same forced-transfer path here, so the same applies.
* *Freezing is not bounded by the balance.* CMTAT's `_freezePartialTokens` reverts when the frozen
  amount would exceed the balance. No denylist write can see a holder's balance, so `f` is
  unbounded (see costs above).
* *Full and partial freeze are one field, not two.* CMTAT keeps the address freeze and the frozen
  amount independently, so lifting a full freeze restores the earlier partial one. Here
  `frozen_amount` is either `None` or `Some(f)`: escalating to a full freeze discards `f`, and
  relaxing back must write it again.

**Pinned by** the `partially_frozen_*` / `fully_frozen_*` / `memo_*` / `paid_back_*` / `both_*` /
`each_*` / `own_node_*` / `undecodable_*` / `below_floor_*` tests in `validators/transfer_logic_script.ak`, the partial-seizure tests in
`validators/third_party_transfer_logic_script.ak`, `mint_to_a_*_frozen_destination_*` in
`validators/minting_authority.ak`, and the `denylist_insert_*_freeze` / `denylist_update_*` tests in
`validators/denylist.ak`. Every new guard was mutation-checked: replacing it with `True` (or the
memo's per-party check with a cached verdict) makes at least one of these tests fail.

## 18. Two-step transfer approval: hazards closed before release

Not a defect in shipped code. The [two-step transfer approval](../../README.md#two-step-transfer-approval)
went through repeated spec reviews and an invariant review before it was written; each hazard below
was found there, is closed in the code, and is pinned by a test that was checked to go red when its
guard is replaced by a no-op (mutation-tested; no guard survived).

| Hazard | How it was closed | Pinned by |
|---|---|---|
| In a `MintSecurity` transaction the GlobalState logic's withdrawal is present, so a proxy that only required it would settle pending transfers without any approver | The proxy requires GlobalState as a reference input and refuses any transaction whose inputs hold the GlobalState NFT; `DelegateApproval` refuses a spent or minted GlobalState too | `proxy_rejects_a_spent_global_state`, `delegate_refuses_a_spent_global_state` |
| An approval-logic pointer equal to the proxy makes proxy and delegate satisfy each other — no approval rule ever runs | `DelegateApproval`, `RotateApprovalLogic` and genesis refuse it. A pointer to the transfer logic itself is a deployment rule (README), not checked | `delegate_refuses_a_pointer_to_a_free_credential_or_role` |
| The withdrawals of the approval logic, the proxy and the GlobalState logic are free (anyone can produce them) | The approval logic and the proxy stay distinct from fields 0, 2 and 4 at every writer that sees the pair; operators equal to them are refused by `PauseTransfers`, mint/burn and seizure (seizure checks the GlobalState logic only; the denylist cannot check — a deployment rule); mint refuses them as owners. **Accepted risk, owner decision 2026-10-27:** holder transfers and seizure do not check owners — sending tokens there loses only the sender's own tokens. A retired approval logic does not run (`retired_logic_never_runs`), but is still treated as free: a successor without that check, or a rotation back, would free it again | `rotate_minting_script_refuses_a_free_credential`, `pause_refuses_an_operator_that_is_a_free_credential`, `mint_to_a_free_credential_is_rejected`, `seizure_rejects_an_operator_that_is_the_global_state_logic` |
| A settlement that also spends the holder's own tokens skips the request rules | The approval logic rejects a holder token input next to any vault input (ADA-only included), whatever the switch | `mixing_rejected_with_the_switch_on`, `mixing_rejected_with_the_switch_off`, `mixing_rejected_with_an_ada_only_vault_input` |
| A request redeemer shaped like a settlement could skip the binding | The approval logic binds every new pending transfer and settles every vault input on every run, whatever the redeemer | `lock_binds_whatever_the_redeemer_says` |
| A datum that misstates its sender or amount | Binding: sender = the only holder, amount = held, nothing else beside it; settlement moves the exact tokens | `lock_rejects_a_datum_naming_another_sender`, `lock_rejects_an_understated_amount` |
| Double satisfaction, skipped vault inputs | One action per vault input, positional; strictly increasing output indices | `settle_rejects_one_output_for_two_inputs`, `settle_rejects_decreasing_output_indices`, `settle_rejects_a_missing_action` |
| An approval logic built with another programmable-base hash recognised the vault by its full address, saw no vault input, settled nothing and — with the switch off — let anyone take every pending transfer | The approval logic recognises the vault by its owner alone (stake credential `Script(approval_proxy)`), as the transfer logic does; the base layer keeps every token at the programmable base, so the PLB hash is no longer a parameter. The remaining parameters (proxy, policy, asset name) are a deployment checklist and two smoke tests (README) | `vault_is_recognised_by_its_owner_alone` |
| Exact lovelace pairing freezes every pending transfer if min-ADA rises | Tokens exact, lovelace `>=` | `settle_accepts_a_lovelace_top_up_and_refuses_a_shortfall` |
| A holder sanctioned after the request still completes it | **Accepted risk, owner decision 2026-10-27 (D6):** the vault is no party, so the original sender is not re-vetted on-chain at settlement; the signature of the GlobalState admin or a `can_approve` operator on Approve is the sanctions screen. Reject and Cancel to a sanctioned sender still fail (the sender is vetted as the payee) | `settlement_does_not_vet_the_original_sender`, `approval_settlement_revets_the_recipient` |
| Threshold bypass by a dust input, or by two recipients under a `max` | Net gain per credential, summed (in the approval logic) | `threshold_counts_a_recipient_that_adds_a_dust_input`, `threshold_sums_every_recipient` |
| A gated transfer that skips the approval logic, so the threshold never runs | With the switch on the transfer logic requires the approval logic GlobalState names in every transaction, the CIP-68 metadata update included | `approval_on_requires_the_approval_logic_in_every_transfer`, `approval_on_metadata_update_needs_the_approval_logic`, `metadata_update_runs_the_logic` |
| The admin is a free credential (the approval logic, the proxy or the GlobalState logic), so anyone approves | The approval logic refuses such an admin before reading its consent (Cancel never reads it) | `admin_never_a_free_credential`, `cancel_needs_no_admin_and_works_switched_off` |
| A `can_approve` operator's consent produced by a script anyone can run (the transfer logic, the CIP-113 global logic, the approval logic, the proxy and the GlobalState logic all run in a settlement) | The operator path accepts only the operator's KEY signature (`extra_signatories`), never a withdrawal; `can_approve` is deliberately not gated by `must_be_signed_by_credential` | `operator_withdrawal_is_not_a_signature`, `operator_must_sign_with_its_own_key` |
| A removed or forged operator entry still approving | The entry is authenticated by the shared `authenticated_power_user`: the list NFT of GlobalState field 3's policy, and still at the list's script address; removal consumes it | `revoked_operator_entry_off_the_list_address_is_refused`, `operator_entry_without_the_list_nft_is_refused`, `operator_without_can_approve_is_refused` |
| An operator sweeping stray vault UTxOs, or a bad operator index blocking Cancel or an admin approval | Close stays admin-only; the operator entry is read once per run and only when an Approve or Reject needs it and the admin did not sign | `operator_cannot_close`, `cancel_ignores_the_operator_index`, `admin_approval_ignores_the_operator_index` |
| A retired approval logic's free withdrawal used to settle | The approval logic runs only while GlobalState names it | `retired_logic_never_runs` |
| Unbound pending transfers created while approval is off | With the switch off, no security token can be sent to the vault; the switch is read from the pre-transaction GlobalState | `approval_request_is_refused_with_the_switch_off`, `approval_switch_read_from_the_spent_pre_state` (positive control `approval_request_with_global_state_spent_and_on_is_accepted`) |
| Partial seizure leaves a residual whose datum misstates what it holds | Seizure refuses token-holding vault outputs; pending transfers are seized whole | `partial_seizure_of_a_pending_transfer_is_rejected`, `full_seizure_of_a_pending_transfer_succeeds` |
| The CIP-68 metadata token stranded at the vault, or taken from a free credential | Registration refuses the vault. **Accepted risk, owner decision 2026-10-27:** a metadata update may send the token to the vault or a free credential; only its owner (the issuer) can, and only its own token is lost | `register_mint_rejects_a_reference_nft_owned_by_the_vault` |
| A recipient that is a free credential freezing the request | The recipient is checked only where it is paid (Approve); Reject and Cancel still return the tokens | `settle_a_bad_recipient_does_not_block_reject_or_cancel` |

Lessons kept from writing it: Aiken drops a discarded `let _ = f(...)` together with every `expect`
inside `f` — consume validating calls' results; and a `fail` test passes on any trap, so each
negative test here was mutation-checked to fail for its own guard.

**Accepted limit.** The threshold applies per transaction; splitting a transfer below it is not
prevented, because that needs per-holder state over time.

---

## Acknowledged, and deliberately not changed

Findings from the 2026-08-28 audit that were reviewed and judged not to warrant a code change. They
are recorded here so a future reader does not have to re-derive the reasoning — and so that a future
*change* in any of these areas is a conscious one. Entries marked "partly changed" were revisited
later; each says what changed and when.

### The transfer withdraw-0 is satisfiable with no parties

`transfer_logic_validator.withdraw` accepts a transaction that moves no security token at all: both
party folds produce `[]`, `compliance.verify_parties` returns True on the empty list, and only the
pause and deactivation flags remain. Any wallet can therefore include this script's withdraw-0 in a
transaction of its own.

On its own this moves nothing. The CIP-113 base layer only dispatches to this script when a
programmable-base UTxO of the policy is actually spent, and that spend independently requires the
holder's consent (`programmable_logic/owner.ak`). What it does mean is that the transfer script's
hash behaves as a credential *anyone* can satisfy — which matters only in combination with the
documented footgun in [§11](#11-the-power-user-authority-footgun-was-undocumented): a role
credential or `admin_credential_hash` mistakenly set to this script's hash would be publicly
satisfiable. The prescribed smoke test already catches exactly that misconfiguration.

Left as is. The seizure path carries an equivalent guard (`at_least_one_seized_input`) because it
authorises an *override* and must be bound to real seized value; the transfer path authorises
nothing on its own.

### `PauseTransfers` churn can race admin recovery (F11, issue #17) — partly changed

**Changed (2026-10-14):** the branch now requires `transfers_paused` to flip. Previously a
`can_pause` operator could re-pause an already-paused protocol (or re-unpause an unpaused one) as
often as they liked. Each such write changed nothing but the GlobalState UTxO reference, and every
admin transaction built against the previous reference became stale. That includes the power-users
update that revokes the operator's `can_pause`, because it reads GlobalState as a reference input.
Pinned by the `pause_flip_*` tests in `validators/global_state_logic_tests.ak`.

**Still accepted:** contention on the singleton UTxO is not removed. An operator can still
alternate paused → unpaused → paused, one write per flip, and lovelace stays unconstrained (§7).
Every such write now changes the protocol state visibly and is attributable to the signing
operator. Recovery is the ordinary one: the admin revokes `can_pause`, built against the freshest
GlobalState UTxO and resubmitted if it goes stale. Removing the race entirely needs a larger change
to emergency semantics, such as admin-only unpause or direct deactivation without a paused
pre-state, and was not chosen.

### Datum size: the three caps do not add up to a joint bound (F09, issue #15) — partly changed

**Changed (2026-10-14):** a joint bound now exists. `max_global_state_datum_bytes`, a parameter of
both the GlobalState mint and the GlobalState logic (recommended 8192), caps the serialised datum,
appended fields included, at genesis and on every GlobalState action: one check runs before the
action dispatch, so a future branch cannot forget it. A write passes if it fits the cap **or** does
not grow the datum, so a datum left over the cap (for example by a logic with a higher cap) can always be
shrunk. The exception is excess held in fields a later logic appended: this logic cannot remove them.
The mint and logic values are not tied together on chain; the deployment script must check them.
The per-field caps stay: they still bound a single entry. Pinned by the `datum_cap_*` tests in
`validators/global_state.ak` and `validators/global_state_logic_tests.ak`. The original assessment
follows.

`max_trusted_entities` (64), `max_trusted_entity_metadata_bytes` (512 B) and
`max_security_info_bytes` (4096 B) are enforced independently, and nothing checks their sum. At the
maxima the GlobalState datum would serialise to roughly 40 KB — well past the ~16 KiB transaction
limit the caps' own comment cites as their reason for existing.

Not a lockup, and this is the part worth stating precisely: the transaction that would push the
datum over the limit is itself rejected by the ledger, and since the validator ignores lovelace and
every branch may shrink a field again, there is no state you can get stuck in. What a determined
admin *can* do is inflate their own control UTxO to the point where a mint carrying attestation
proofs (≈ 370 B per attested destination) no longer fits alongside it — a self-inflicted, reversible
squeeze.

Operationally: keep `security_info` and the trusted-entity list small. If a joint bound is ever
wanted, one `serialise_data` of the continuing output datum per spend replaces all three caps and is
strictly stronger.

### KYC revocation is per issuer or per holding, never per holder-before-TTL

The two proof channels are independent by design. `verify_attestation_proof` never consults
`member_root_hash`, and `verify_membership_proof` never consults the trusted-entity list. So
removing a holder from the membership tree does **not** invalidate an attestation that holder already
holds: until it expires, they can still transfer.

The on-chain levers are therefore: revoke the *issuer* (remove its vkey from the TEL — immediate,
but it invalidates every attestation that issuer signed), or sanction the *holder* (add them to the
denylist — immediate and per holder, but it means "sanctioned", which is a different regulatory
statement from "KYC lapsed").

**This makes attestation TTL a compliance parameter, not a performance one.** The exposure window
for a withdrawn KYC status is exactly the TTL baked into the outstanding attestation
(`valid_until_ms`, payload bytes 29–36). Issue short-lived attestations — hours, not weeks — and
treat the TTL as the maximum time a de-KYC'd holder may still transact. A per-holder revocation
before expiry would need a second MPF (a revocation tree the attestation path also has to miss);
that is a design change, not a fix, and is not implemented.

### Sanctions are single-signer and have no exempt list

Any power user holding `is_admin` can add any 28-byte hash to the denylist, including the
GlobalState admin's own credential, the treasury, or a fellow operator. There is no threshold and no
exclusion list.

Left as is, deliberately. Sanctioning an address freezes that address's *holdings*; it does not
touch anyone's *role* — GlobalState actions never consult the denylist — so an operator cannot lock
the admin out of administration. It is recoverable in one transaction (`RemoveFromDenylist`), and
the admin can revoke the flag. Separation of duties, if wanted, means requiring two distinct
`is_admin` signatures; that is a policy change for the deployment to decide.

### Composition limits worth knowing when building transactions

Two shapes that are simply not buildable, neither of them a defect:

* **A list mutation cannot share a transaction with a GlobalState-spending admin action.** The list
  validators read GlobalState as a *reference* input; admin actions *spend* it; Conway rejects a
  transaction whose inputs and reference inputs overlap.
* **Everything funnels through one control UTxO.** Every mint, burn and admin action spends
  GlobalState, so they serialise against each other and a busy operator will hit contention. Batch
  admin work rather than issuing it concurrently.

### CI could not explain its own failures

`aiken check` emits JSON and suppresses all diagnostics when stdout is not a terminal, which a CI log
is not — so a failing test surfaced as a bare non-zero exit with no test name, assertion or trace.
The job always failed correctly; it just could not say why. `.github/workflows/tests.yml` now runs
the suite under a pseudo-terminal (`script -q -e -c "aiken check -D" /dev/null`).

### Dead code removed

`lib/types/issuance.ak` (unreferenced), and `is_paused` / `is_deactivated` in
`lib/types/global_state.ak` with their tests. The two readers had no callers left — every validator
decodes the full GlobalState datum — and an unused *weaker* authenticator (they check the NFT with
`> 0` where `gs_datum_from_output` requires `== 1`) is a trap for the next person who needs a quick
flag read. The field-order invariant comment that referred to them now states the real reason field
order is load-bearing: the positional `idx_*` constants and the tripwire test that guards them.

---

## What the CIP-113 base layer actually guarantees

The base layer is not vendored here, so several severity judgements originally rested on
assumptions. Those were checked by reading
`cardano-foundation/cip113-programmable-tokens` at `feat/upgradability-in-place` (commit `018415d`),
and **re-checked on 2026-08-28 against that repository's `main` at commit `9db7e06`.**

**Every guarantee in the table below still holds at `9db7e06`.** What moved in between — five
commits: #99 federated upgradability, #110 the dissolution of the programmable-logic *global*
coordinator, #114 a PLB performance pass, #115 output-shape rules, #116 the Aiken v1.1.23 bump — and
what a redeploy onto that base would have to account for:

* **Dispatch is now per input.** `programmable_logic_base` reads the live `transfer_cred` /
  `third_party_cred` / `unfracking_cred` from the protocol-params (coordination) datum and requires
  the witnessed one's withdraw-0, under a `SpendViaTransfer` / `SpendViaThirdParty` /
  `SpendViaUnfracking` redeemer. The *guarantee* — that this deployment's logic runs on every spend
  of its token — is unchanged; the transaction shape and the base-layer redeemer are not, so
  off-chain builders need updating before a redeploy.
* **Programmable-base outputs must stay seizable (#115).** No datum hash and no reference script on
  any output holding the policy, and every such output needs an inline stake credential. This is
  enforced on the issuance path and on both third-party output scans.
* **Inline datums are size-bounded (#115).** `max_inline_datum_bytes`, a protocol-params field,
  now caps the inline datum of programmable-base outputs. **This applies to the CIP-68 reference
  NFT's metadata datum**, which is the only datum this deployment puts on a token UTxO. Check the
  deployed value before publishing metadata.
* **A new trust dependency, and it is worth stating plainly.** `coordination_spend` lets whoever
  holds `upgrade_cred` rewrite those three delegate credentials in place, subject only to a 28-byte
  shape check. A rewrite pointing `transfer_cred` or `third_party_cred` at a permissive stub would
  bypass this module's transfer and seizure gates entirely, in one transaction, with nothing on
  this side able to detect or resist it. **Record who holds that authority for the target
  deployment** (script, signers, threshold) and treat any change to the coordination datum as a
  security event. See [what is still open](#what-is-still-open).

The deployment currently targeted on preview still bootstraps a pre-#110 base layer — the layout the
`018415d` verification describes — so the table applies as written to what is deployed today, and
the notes above apply to any redeploy onto current `main`.

| Claim | Verdict | Evidence | Relied upon by |
|---|---|---|---|
| Registry field 2 is cryptographically bound to the node's key | **True** | `registry_mint` calls `is_programmable_token_id_valid(key, …, minting_logic_script)` — the key is *derived* from the template parameterised with that credential | `MintBurn`'s registry-node read removal (2026-08-20) — no independent field-2 identity re-check on mint or burn |
| Registry keys are unique | **True** | `validate_directory_node_output` asserts `key < next` on **both** insert outputs, forcing `covering.key < new.key < covering.next`; in a sorted list a duplicate is unconstructible | Same as above — rules out a duplicate node at this policy's key |
| Registry fields 3 and 4 are free | **True — confirmed the defect** | `is_inserted_directory_node` only length-checks them | — |
| A stranger can register a node naming someone else's minting logic | **False** — a protection that was not assumed | `RegistryInsert` requires that credential's own withdraw-0 ("proof of instance") | — |
| Minted supply is confined to programmable-base addresses | **True** | `issuance_mint`'s `no_escape` forbids the policy at any non-base output and requires an inline stake credential on every base output | The mint-path programmable-base payment-credential pin removal (2026-08-20) |
| Transfers cannot move tokens out of the base, and conserve value | **True** | the transfer path requires base outputs ⊇ base inputs per policy, which with ledger value-conservation forbids escape | The ordinary-transfer-path programmable-base payment-credential pin removal (2026-08-20) |
| Seizure (forced-transfer) custody: tokens cannot escape the programmable base | **True** | `validate_io_constraints_and_balance` (`third_party.ak`) requires each spent programmable-base input to pair with an output at the identical address, datum and reference script, and requires the acted-on policy's tokens across **all** programmable-base outputs to be a superset of those across programmable-base inputs plus mint/burn | The seizure-path programmable-base payment-credential pin removal (2026-08-21) |
| This deployment's transfer logic runs on every spend of its token | **True** | `has_withdrawal(transfer_logic_script)` is required for every input policy proved to exist | `transfer_logic_validator`/`third_party_transfer_logic_validator`'s registry-node read removal (2026-08-20) — no independent registry lookup on transfer or seizure |
| A registry-node spend can never mint or burn that node's own token | **True** | `registry_spend` hoists `!mint_has_policy(self.mint, spent_node.key)` above its `when`, so it covers both the in-place update and the covering-node spend | `UpgradeRegistryNode`'s belt-and-braces no-mint re-check removal (2026-08-21) |
| The seizure path is the only one that skips owner consent | **True** | the third-party path never calls `authorised_stake_cred`; the transfer path always does | — |

Two things this settled:

**Defect 2 was exploitable end to end.** The independence of the two node indices is real.

**Defect 6's transfer-path extension was safe to add**, which is why it went in as defence in depth
rather than being left alone.

One severity fear was **not** borne out: a reachable third-party path does not make seizure available
to anyone. The base layer requires the named node's third-party logic to run, and this deployment's
third-party validator requires a `can_force_transfer` power user.

---

## What this changes for off-chain

### Compile-time parameters

Every validator's parameter list changed. The build order is in the README's *Building the scripts*
section. The trap worth repeating: **the list SPEND validator hashes are not the list POLICY ids.**
Passing a policy id where a script hash is expected makes the protocol inert *quietly* — every
element read rejects, and nothing tells you why.

### KYC proof formats — breaking, but fail-closed

An old-format proof simply stops verifying, so there is no window in which a stale attestor silently
weakens the gate. But nothing works until off-chain moves:

1. **Attestation payloads are 67 bytes, not 66.** Append `0x00` for a `VerificationKey` holder,
   `0x01` for a `Script` holder. Every other offset is unchanged. The attestor must know which
   credential form it is attesting — it can no longer sign a bare hash.
2. **The membership MPF tree must be rebuilt.** Leaf key `credential_type ‖ hash`; leaf value
   `valid_until_ms ‖ security_policy_id ‖ network_id`. Use the exported encoders. Rebuild the root
   **before** calling `UpdateMemberRootHash`.

### The 2026-10-23 partial freeze: one datum change, one redeemer variant, two new parameters

* **Datum, breaking for encoders.** `Denylist` is now `{ frozen_amount: Option<Int>, metadata }`,
  `frozen_amount` first. `AddToDenylist` and `UpdateDenylistEntry` builders must encode it; an entry
  written in the old one-field shape does not decode, so readers reject its holder and
  `RemoveFromDenylist`'s `expect` traps on it. No deployment exists, so there is nothing to migrate.
* **Spend redeemer.** `SpendRedeemer` gains `UpdateDenylistEntry { own_input_index,
  own_output_index, global_state_ref_input_index, power_user_node_ref_input_index }`;
  `StateTransition` keeps its encoding.
* **Parameters.** `denylist_validator` goes from 1 to 3, in the same positions as `denylist.mint`'s:
  `(global_state_policy_id, denylist_linked_list_policy_id, power_user_list_script_hash)` — the list
  policy id moves from first to second (README row 5). Its hash moves, and with it every script
  that pins it: transfer logic, third-party logic, minting authority (rows 8–10).
* **Proofs.** The per-party denylist index may name the party's own node (partially frozen) as
  well as a covering node. An unlisted party's proof is unchanged.
* **Blueprint field names, breaking for generated types.** The per-party index fields lose
  `covering`: `source_denylist_covering_ref_input_index` → `source_denylist_ref_input_index` in
  `TransferLogicScriptAction`, and `destination_denylist_covering_ref_input_index` →
  `destination_denylist_ref_input_index` in `TransferLogicScriptDestinationAction`,
  `MintingLogicDestinationAction` and `ThirdPartyDestinationAction`. Plutus data is positional, so
  the on-chain encoding is unchanged and hand-written encoders keep working; types generated from
  `plutus.json` change their field names and their call sites must follow.

### The 2026-08-28 fixes: no schema change, one dropped parameter, five moved hashes

**No redeemer or datum schema changed.** Every redeemer constructor, field order and datum shape in
`plutus.json` is byte-identical, so a transaction builder's *encoding* is untouched.

One compile-time **parameter list** changed: `minting_authority_validator` drops
`reference_asset_name` (9 → 8), because fix 13 identifies metadata tokens by prefix rather than by an
exact name. Deploy scripts must drop that argument; nothing else about them changes.

Five hashes move in total across the two fixes, and they fall into two very different groups —
see the tables below.

**Fix 12 — redeploy-only.** These two hashes *are* the list policy ids, written into the GlobalState
datum at genesis and immutable thereafter:

| Validator | Change | Consequence |
|---|---|---|
| `denylist.mint` | `Deinit` deactivation gate | **Redeploy-only** |
| `power_users.mint` | `Deinit` deactivation gate | **Redeploy-only** |

**Fix 13 — upgradeable in place.** None of these is baked into an immutable field:

| Validator | Change | How it is rolled out |
|---|---|---|
| `minting_authority` | prefix rules, dropped parameter | `RotateMintingScript` — the GlobalState datum names it, admin-signed |
| `transfer_logic_script` | the shape invariant on every move | `UpgradeRegistryNode` — registry field 3 |
| `third_party_transfer_logic_script` | refuses protected inputs | `UpgradeRegistryNode` — registry field 4 |

The two list mint hashes were verified **not** to move under fix 13, so adding
`constants.cip68_protected_prefix` perturbs nothing that does not read it.

Every other validator's *source* is byte-identical, so every other **unapplied** hash in
`plutus.json` is unchanged. But the two changed hashes are the two list **policy ids**, and those are
compile-time parameters of most of the protocol — so the *applied* hashes cascade:

| Applied artefact | Moves? | Because |
|---|---|---|
| `global_state_mint_validator` → **GlobalState policy id** | **no** | parameters are only the genesis UTxO |
| `minting_logic_script` → **issuance policy id**, registry `key`, registry field 2 | **no** | its only parameter is the GlobalState policy id |
| `power_users.mint` → power-users policy id | yes | source changed |
| `power_users_validator` → power-users list address, `power_user_list_script_hash` | yes | takes the power-users policy id |
| `denylist.mint` → denylist policy id | yes | source changed **and** takes `power_user_list_script_hash` |
| `denylist_validator` → denylist address, `denylist_script_hash` | yes | takes the denylist policy id |
| `global_state_spend_validator` → **the GlobalState UTxO's address** | yes | takes `power_user_list_script_hash` |
| `transfer_logic_validator` → its withdraw-0 credential, registry field 3 | yes | takes `denylist_script_hash` |
| `third_party_transfer_logic_validator` → its withdraw-0 credential, registry field 4 | yes | takes both list hashes |
| `minting_authority_validator` → `minting_script_credential_hash` | yes | takes both list hashes and the power-users policy id |

The token's own identity therefore survives — same issuance policy id, same registry key, same
permanent proxy — but the GlobalState UTxO's **address** moves, and a GlobalState UTxO cannot migrate
to a new address (every spend branch asserts `address_preserved`). **So this is a fresh genesis, not
an upgrade.** Nothing is on mainnet, so that is the clean path.

What does *not* change is the off-chain **code**: no redeemer, datum or parameter list is different,
so every builder, encoder and parser keeps working verbatim. What changes is **configuration** — the
addresses and policy ids above — plus one sequencing rule: a `Deinit` transaction is now valid only
after `DeactivateContract`, though its redeemer and transaction shape are unchanged.

### Deployment

This change set is **redeploy-only** — it moves the denylist policy id and the GlobalState UTxO's
address. Nothing is on mainnet, so that is the clean path.

Do **not** call `LockUpgrades` until these fixes are deployed. It permanently closes both upgrade
paths (and, since `SetMintableAmount` and `RotateGlobalStateScript` were added, admin changes to
the supply cap and replacement of the GlobalState logic).

---

## Operational constraints imposed by the base layer

These are not defects in either layer — each side is doing its job. They are consequences of
composing them, they are not visible from either file alone, and off-chain procedure has to plan
for them. Found by working through each operation's full transaction shape against the vendored
CIP-113 source.

### Seizure is all-or-nothing per UTxO, against a fully frozen holder

The base layer pairs each spent programmable-base input with an output at the **same address**, so a
partial seizure's residual necessarily returns to the holder. This deployment vets every
token-bearing output as a destination, and a sanctioned (fully frozen, `frozen_amount: None`) holder
cannot clear the denylist gate for their own address: it has no covering node, and its own node
rejects it. So a partial seizure that leaves a residual with a fully frozen holder is rejected.

A **partially frozen** holder (`Some(f)`, [§17](#17-partial-freeze-a-denylist-entry-can-freeze-an-amount-not-only-the-whole-holding))
is not bound by this: it clears the destination gate by citing its own node, so it can take a
partial seizure's residual, and the seizure ignores its floor `f`. Pinned by
`partial_seizure_leaving_a_residual_with_a_partially_frozen_holder_succeeds` and
`seizure_may_take_a_partially_frozen_holder_below_the_floor`. With `requires_receiver_kyc` set, the
residual still needs the holder's valid KYC, as for any destination.

**Full-draining a UTxO works**, because a paired output holding none of the security token is not a
destination at all. A position can therefore still be partially seized at the *account* level, by
draining some UTxOs and leaving others untouched — but no single UTxO can be left with a non-zero
residual for a sanctioned holder.

Relaxing this is not a one-line change: the validator cannot tell "returning change" from "paying
out" without per-credential amount accounting, and the naive relaxation — exempting any destination
that is also a source — would let an operator route seized tokens to a sanctioned party who happens
to also spend a token UTxO in the same transaction.

Pinned by `seizure_of_a_sanctioned_holder_succeeds_when_the_utxo_is_drained` and
`partial_seizure_of_a_sanctioned_holder_is_not_possible`.

### Burning needs more authority than `can_burn`

This one corrects the reasoning recorded under [defect 5](#5-pause-does-not-stop-issuance).

Destroying existing supply means **spending** a programmable-base UTxO, and the base layer gates
every such spend on the programmable-logic global's withdraw-0. For a burn that means `TransferAct`,
which requires a `TokenExists` proof for the policy, which requires this deployment's transfer logic
to run — pause gate, sender denylist proof and sender KYC included. Neither escape applies:
`TokenDoesNotExist` needs a registry node covering the policy and a registered policy has none, and
`UnfrackingAct` is unavailable because registration pins `unfracking_logic_script` to the empty vkey.

So the pause exemption is **half** what it was originally documented to be:

- **Minting really does stay available during a pause** — a fresh mint spends no programmable-base
  UTxO, so the transfer logic never runs.
- **Burning does not.** A burn during a pause, or from a sanctioned or uncooperative holder, has to
  be routed through the seizure path, which has no pause gate and no source-side checks — and which
  requires an operator holding `can_force_transfer`, not merely `can_burn`.

`can_burn` alone is therefore not sufficient authority to retire a sanctioned holder's position.
Grant the two roles together to whoever is expected to perform court- or regulator-ordered burns.

---

## What is still open

**Three deployment properties that no code here can check:**

- **The GlobalState NFT must actually land at `global_state_spend_validator`'s address at genesis.**
  The genesis mint validator cannot verify this — the circularity is real, and it says so. Verify
  the NFT's address on chain immediately after genesis. If it is wrong, the protocol's entire state
  is forgeable and destructible by whoever holds that UTxO, with no exploit needed.
- **Every role credential must name something that genuinely decides.** Run the smoke test described
  in defect 11, for all five roles, after every grant and rotation.
- **The CIP-113 coordination UTxO's upgrade authority is part of this token's trust boundary.**
  Whoever holds `upgrade_cred` can re-point the base layer's `transfer_cred`, `third_party_cred` and
  `unfracking_cred` at scripts of their choosing, which would bypass every gate in this module
  at once. Nothing on this side can detect or resist it. Record the authority (script, signers,
  threshold) for the target network alongside the deployment parameters, and monitor the
  coordination datum for changes. Identified in the 2026-08-28 re-audit.

**Not attacked, and worth picking up:**

- **Execution-budget exhaustion.** This is now measured rather than merely suspected. Two
  `aiken bench` scaling benchmarks — `transfer_cost_by_party_count` in
  `validators/transfer_logic_script.ak` and `seizure_cost_by_destination_count` in
  `validators/third_party_transfer_logic_script.ak` — profile cost as party/destination count grows.
  Cost is dominated by per-party denylist covering-node authentication, plus one Ed25519
  verification when KYC applies; memory binds before CPU; and the covering node is now authenticated
  once per run of adjacent parties citing the same node, rather than once per party. The README's
  *Execution budget and transaction sizing* section states the measured per-party costs and gives
  conservative per-transaction maxima at 25% of the shared CIP-113 budget. What remains open is the
  cost of the CIP-113 base layer's own scripts running in the same transaction — this deployment's
  scripts were measured in isolation.
- **Merkle-Patricia-Forestry proof forgery.** The membership variant was analysed only at the
  binding level. No attempt was made against the vendored library.
- **Attestation revocation windows — now examined, and the answer is a policy one.** An attestation
  stays valid until its TTL regardless of the membership tree, so per-holder KYC withdrawal before
  expiry is not achievable on chain; the levers are issuer revocation (TEL) and sanctioning (the
  denylist), and the denylist check is independent and live throughout. See
  [Acknowledged, and deliberately not changed](#acknowledged-and-deliberately-not-changed).
  What remains open is the *operational* choice: pick and document a maximum attestation TTL.
- **UTxO contention.** GlobalState is a single UTxO that every mint and burn must spend, so issuance
  is serialised at roughly one transaction per block. Inherent to the design, but worth sizing
  before launch.
- **Escalation beyond `aiken check`.** Every finding here is proven at the validator level against a
  hand-built `Transaction`. None is confirmed against a real ledger. The intended ladder is
  `aiken check` → Yaci devnet → preview, and skipping a rung tells you very little about *why*
  something failed.

### Re-audit — 2026-08-28

A full re-audit against `main @ ff5624e` — every non-test line re-read and composed against the
CIP-113 base layer at its then-current HEAD, plus a multi-agent find/refute/prove-by-test pass —
found **no Critical or High defect**. It produced defects [12](#12-dismantling-either-linked-list-was-a-one-way-freeze-of-a-live-protocol)
and [13](#13-cip-68-metadata-tokens-were-governed-by-an-exact-name-not-by-their-kind) (both Medium,
both fixed),
the correction to [§7](#7-the-globalstate-utxos-ada-balance-was-unconstrained) recorded above, the
[acknowledged items](#acknowledged-and-deliberately-not-changed), and the base-layer
re-verification. Around fifty attempted attacks were refuted against a specific line — including one
that a single-validator test appeared to confirm (a same-transaction mint+burn netting to zero,
claimed to skip destination vetting) and that composition refutes: the mint field is a net per asset
name, so those units come from spent programmable-base inputs, and the base layer dispatches every
such spend to this deployment's transfer or seizure logic.

### Later hardening — 2026-08-20

After the eleven defects above, a further round of defence-in-depth changes was made, none of them
answers to a newly found exploit: GlobalState datum size caps (on entity count and on the serialised
sizes of `security_info` and metadata) are now enforced both at genesis and on every mutation; admin
actions on GlobalState may no longer move the security token in the same transaction, closing the
possibility of bundling a pre-state change with a transfer or seizure; the list spend validators now
bind the spend to an input that carries the corresponding list token; list keys must be exactly 28
bytes; CIP-113 registry fields 3 and 4 must be script credentials both on registration and on
upgrade; the compile-time power-users policy id is now cross-checked against the GlobalState field on
the mint path, and the seizure validator no longer compiles it in at all — it reads the power-users
policy id from the NFT-authenticated GlobalState datum, so GlobalState is the single root of trust
for that lookup; and zero-amount mints now require `can_mint`. Alongside these, the
test suite gained a genesis validator test, power-users branch coverage, a membership-KYC end-to-end
test, and memo regression tests, and the toolchain was pinned with a CI reproducibility gate added to
catch drift between the committed blueprint and a fresh build.

A later same-day pass removed the registry-node read on the transfer, seizure and mint-burn paths and
the mint- and ordinary-transfer-path programmable-base payment-credential pins in favour of the
base-layer guarantees in [the table above](#what-the-cip-113-base-layer-actually-guarantees), and
collapsed the mint path's GlobalState decode to run once per transaction instead of at every call
site. The same three removals were independently requested, in review comments on upstream PR
[cardano-foundation/cpt-rwa-ch-de-cmta-reference#2](https://github.com/cardano-foundation/cpt-rwa-ch-de-cmta-reference/pull/2):
that the programmable-base pin parameter and destination pin are redundant with the CIP-113 core, and
that the programmable-token policy id should be passed as a validator parameter rather than
recomputed from the registry node.

### Later hardening — 2026-08-21

Two further removals, both following the same upstream PR #2 review comment (groups A and B): the
seizure path's programmable-base payment-credential pin was removed, on the same basis as the mint
and ordinary-transfer removals above, now that the seizure custody guarantee is independently
verified against the base layer (see the "Seizure (forced-transfer) custody" row in
[the base-layer table](#what-the-cip-113-base-layer-actually-guarantees)); and the upgrade path's
belt-and-braces re-check that a registry-node spend mints or burns no supply was removed, relying
instead on `registry_spend`'s own guarantee (see the "A registry-node spend can never mint or burn
that node's own token" row in the same table). The same review comment's other two recommendations —
the list-integrity checks (group C) and the GlobalState/denylist pins (group D) — were reviewed and
kept, by deliberate decision, as module-level invariants the base layer does not itself provide.
Separately, and by independent decision rather than the review comment: the CIP-68 reference NFT must
now be minted alone into its own UTxO, never co-located with the first supply.

The reference NFT is no longer pinned to the GlobalState admin credential at registration. The admin
still authorises registration, but the reference NFT's inline stake credential is the metadata
authority. Updating the metadata is that owner's consented re-output of the UTxO with a new inline
datum; `RotateAdmin` does not rotate metadata custody.

Following the upstream review of 2026-08-21, the "no security token in this transaction" guard was
made cheaper without changing what it accepts: it scans only the INPUTS, because every branch that
composes it also forbids any mint or burn of the security asset, and the ledger conserves value — so
no output can carry a unit that was neither spent nor minted. The continuing-output value check was
reworked in the same round and then simplified again when the ADA constraint was dropped; see
[§7](#7-the-globalstate-utxos-ada-balance-was-unconstrained) for what it does today.
