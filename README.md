# Programmable asset tokens on Cardano based on the CMTA framework

Aiken (Plutus V3) contracts providing on-chain primitives for programmable asset tokens   designed as reference profiles for use cases based on the CMTA framework and supporting the implementation of Swiss legal requirements. The primitives include KYC-gated transfers, denylisting with full or partial freezes, global pause, forced transfers and seizures, supply caps, role-based permissions, and an irreversible decommission mechanism.

The contracts build on CIP-113 (programmable tokens) by Michele Nuzzi, Matteo Coppola, Giovanni Gargiulo and Philip Di Sarro: [CIP-113](https://github.com/HarmonicLabs/CIPs/blob/master/CIP-0113/README.md) 

---

## Important note and disclaimer

The proposed profile draws on relevant Swiss requirements, translated technical standards and functional requirements developed by CMTA. 

The profile provides technical functionality only and is intended to support the implementation of certain features that may be relevant for legal or regulatory compliance under a certain jurisdiction. Its use does not imply, establish, or ensure compliance with any applicable legal or regulatory requirements. Each user is solely responsible for assessing the legal and regulatory implications of their specific implementation and/or use case and for ensuring it meets legal and regulatory requirements. It is strongly recommended to obtain appropriate professional advice where necessary.


---

### CMTA profile

Reflects technical requirements and functionalities defined by the CMTA Framework (Blockchain-agnostic functional specification of the CMTA token), providing a technical basis for implementations seeking to address relevant requirements under Swiss law. The framework defines 42 numbered functionalities `ABS-01…42`, of which **only `ABS-01…14` are mandatory**. CMTAT v3.2.0 (Solidity) serves as a semantic reference and technical reference for this profile, without implying full equivalence or conformity. The v3.2.0 release has not itself been fully audited; the latest fully audited release is v3.0.0.
The profile implements the relevant base and enforcement functionality of the CMTA Framework, covering supply and balance views (ledger-native on Cardano), transfer, mint, burn, pause/unpause and status, deactivate and status, full-address freeze/unfreeze and status, and partial freeze (a frozen amount per address). Optional modules (snapshots, distributions, debt terms, delegated approval) are not implemented; EVM-specific machinery (allowance mechanic, gasless relaying, cross-chain, interface conformance) is not applicable on eUTxO.
A third-party equivalency assessment of this codebase is maintained at [CMTA/CMTAT-Cardano](https://github.com/CMTA/CMTAT-Cardano).

---

## CMTA recognition

On 6 October 2026 the Expert Committee of the [Capital Markets and Technology Association](https://cmta.ch)
recognised this contract set as a **Recognized Smart Contract** for the purposes of the CMTA Standard for
the Tokenization of Equity Securities (the Equity Standard) and the CMTA Tokenized Shares Certification
Mark Regulations. The delegation determined unanimously that it includes the features required by
Appendix 2 of the Equity Standard and the mandatory functionalities of the CMTAT Framework, that it
contains no function contradicting the Equity Standard, and that it may accordingly be used **in lieu of
the CMTAT reference implementation** for the purposes of CMTA's certification schemes.

The signed decision is in
[`documents/certification/`](documents/certification/2026-10-06-cmta-expert-committee-recognition-decision.pdf).

**What was recognised.** Commit `36cc71b677ccc7c98fd8d83cf1f83072055baf63`, and release
[`1.0.0`](https://github.com/cardano-foundation/cpt-rwa-ch-de-cmta-reference/releases/tag/1.0.0)
(`af153094c1222ca2fa956676540d0e4b1a002806`), which changes only this README and therefore carries
identical scripts. Those scripts are the `plutus.json` with SHA-256
`3ecc70618ab360795425b42be98fdf394100b33154336a1bea0c337e69f8c48e`, built with Aiken v1.1.23
(`8949565a9969278846ffefe30bc3b892029dd318`) for Plutus V3, with dependency versions locked in
[`aiken.lock`](aiken.lock). The delegation reviewed that code, the third-party security audit and the
equivalency pre-assessment, all three linked from [Review and audit](#review-and-audit) below.

**Conditions on each deployment.** Recognition is granted subject to each deployment including:

1. a reference to, or a hash of, the tokenization terms, recorded on chain;
2. `decimals`, published as zero in the token's metadata;
3. a metadata token carrying the name and ticker symbol of the token; and
4. a record, alongside its deployment parameters, of the CIP-113 base-layer commit against which this
   contract set's reliance on the base layer was checked.

Condition 1 is a deployment duty rather than a contract feature: `security_info` is opaque to every
validator, as described under [Technical compliance status](#technical-compliance-status). Conditions 2
and 3 are carried by the CIP-68 metadata token, described under
[CIP-68 metadata tokens](#cip-68-metadata-tokens). A deployment has that token only if its
`security_asset_name` carries a CIP-68 user-token label (`(333)` or `(444)` for a fungible security,
`(222)` for an NFT): registration then mints it, and a plain name can never have one. For condition
4, the base-layer commit cited by the audit report is `9db7e0629a1509cc9d41d069f0ef0ed251601173`.

Provided those four elements are present at deployment, an issuer using this contract set for the
tokenization of equity securities may refer to it as a smart contract "recognized by the CMTA" when
applying for the right to use the CMTA Tokenized Shares certification mark, subject to the other
requirements and recommendations of the Equity Standard and the Certification Mark Regulations.

**What the recognition does not cover.**

* The **CIP-113 base layer**
  ([cardano-foundation/cip113-programmable-tokens](https://github.com/cardano-foundation/cip113-programmable-tokens)),
  which was excluded from the scope of the audit and was audited separately.
* The **CMTA Tokenized Debt** certification scheme. The recognition is for tokenized shares only.
* Any **regulatory approval**. Issuers remain solely responsible for ensuring that their tokenized
  shares and related processes comply with all applicable legal and regulatory requirements.

The Expert Committee also recorded that the base layer's core upgrade authority is a trusted role able
to redefine the validation logic of every programmable token, including tokens already issued, and that
it is currently held under a limited multi-signature arrangement. The recognition is given on the basis
of that arrangement and does not constitute an endorsement of it. Issuers should take it into account in
their own risk assessment and disclosures.

**Validity.** The recognition holds for so long as this contract set is not materially modified without
the Expert Committee's prior approval, the base layer used by a deployment is not materially modified in
a way that affects the functioning of this contract set, and no change in the applicable legal or
regulatory framework renders it incompatible with the Equity Standard or the Certification Mark
Regulations. The Expert Committee reserves the right to withdraw the recognition if any of those
conditions ceases to be met.


---

## What the modules do

This repository supplies the token-specific rules around a deployed CIP-113 programmable-token
base layer. The base layer holds the tokens and dispatches to the logic scripts; it is not included
in this repository.

| Module | Responsibility |
|---|---|
| [`validators/global_state.ak`](validators/global_state.ak) | Mints the one-shot GlobalState NFT at genesis, with a sanitised initial datum, into the permanent spend proxy. |
| [`validators/global_state_proxy.ak`](validators/global_state_proxy.ak) | Permanent, unparameterised home of the GlobalState NFT. Reads only datum field 0 and requires that script's withdraw-0 in the same transaction. |
| [`validators/global_state_logic.ak`](validators/global_state_logic.ak) | Replaceable GlobalState logic (the withdraw-0 script named by datum field 0) that controls the continuing state UTxO. It permits the per-mint write of the remaining supply, governs the cap's amendments, and controls pause, KYC settings, trusted issuers, admin rotation, upgrades, logic rotation, list migration and deactivation. Its tests are in `global_state_logic_tests.ak`. |
| [`validators/power_users.ak`](validators/power_users.ak) | Maintains the operator linked list. The GlobalState admin grants or changes the five independent role flags. |
| [`validators/denylist.ak`](validators/denylist.ak) | Maintains the sanctions linked list. An `is_admin` power user can add or remove an entry, or update one in place (`UpdateDenylistEntry`). An entry's `frozen_amount` is `None` (fully frozen) or `Some(f)` (partially frozen: may receive, and may send only what it holds above `f`). |
| [`validators/minting_logic_script.ak`](validators/minting_logic_script.ak) | Permanent CIP-113 minting proxy. It reads GlobalState, authenticated by its NFT and not deactivated, and requires the currently named minting authority, never itself, to run; it decides nothing else. Its hash, applied to the base layer's issuance template, yields this token's issuance policy ID. |
| [`validators/minting_authority.ak`](validators/minting_authority.ak) | Replaceable authority for registration, mint, burn and registry-node upgrades. It decides who may mint, to whom, which asset names and how much: its `MintBurn` debits every mint and burn of the security token from `mintable_amount` in the same transaction. It checks supply-changing transactions against roles, destinations, the denylist and KYC. |
| [`validators/transfer_logic_script.ak`](validators/transfer_logic_script.ak) | Checks ordinary transfers for pause, deactivation, the sender and receiver denylist gates (absence, or a partial freeze the sender's transaction respects), and enabled KYC gates. |
| [`validators/third_party_transfer_logic_script.ak`](validators/third_party_transfer_logic_script.ak) | Checks forced transfers: `can_force_transfer` authority and vetted destinations, while allowing a sanctioned or expired source and remaining available during a pause. |
| [`lib/types/`](lib/types/) | On-chain datum and redeemer schemas consumed by transaction builders, including GlobalState, operator roles and KYC proofs. |
| [`lib/kyc/verify.ak`](lib/kyc/verify.ak), [`lib/denylist/absence.ak`](lib/denylist/absence.ak), [`lib/compliance.ak`](lib/compliance.ak) | Verify attestations or membership proofs, prove denylist absence using a covering node or membership through the party's own (partially frozen) node, and apply those checks to each party. |
| [`lib/cip68.ak`](lib/cip68.ak), [`lib/constants.ak`](lib/constants.ak), [`lib/utils.ak`](lib/utils.ak) | Enforce metadata-token shape and provide shared protocol constants and transaction helpers. |

For transaction inputs, withdrawals and redeemer examples, see the
[practical integration guide](documents/integration-guide.md).

---

## Technical compliance status

The mandatory enforcement core is implemented and covered by the test suite: KYC-gated transfers
(sender and receiver, each independently toggleable), a sanctions denylist with full and partial
freezes, global pause, forced
transfer, a supply cap, mint and burn, role-split operators, and an irreversible decommission
switch.

Optional CMTA modules — snapshots, distributions, debt terms, delegated approval — are **not**
implemented. EVM-specific machinery (the allowance mechanic, gasless relaying, cross-chain
messaging, interface conformance) does not apply on eUTxO.

One item is a deliberate deployment responsibility rather than a contract feature: `security_info`
is carried in the GlobalState datum as opaque `Data` and is not parsed by any validator.
[`lib/types/security/bafin.ak`](lib/types/security/bafin.ak) defines the intended shape, but
populating it correctly — and keeping it consistent with the register — is an off-chain duty of the
issuer and registrar.

Keep it, and the trusted-entity list, **small**. Besides the per-field caps in
[`lib/constants.ak`](lib/constants.ak) (64 entities, 512 B of metadata each, 4096 B of
`security_info`), the whole datum (as Plutus serialises it, appended fields included) is bounded by the deployment
parameter `max_global_state_datum_bytes` (recommended: 8192). It is checked at genesis and on every
GlobalState action, mints and burns included. A write that does not grow the datum always passes, so
a datum over the cap can always be shrunk. Keep headroom: at the cap, even a burn that adds a byte to
`mintable_amount` is refused until the datum shrinks. The GlobalState UTxO is
spent by every mint, burn and admin action, and its datum takes room a mint needs for its KYC proofs
(≈ 230 B per attested destination with a wallet-made proof).

Denylist entry metadata is also free-form `Data`, but an entry's `metadata` field is capped at
512 B once CBOR-serialised (on insert and on update; `frozen_amount` is not part of that cap). Larger case files, legal records, or evidence should live off-chain and be
referenced by compact identifiers or hashes.

### Review and audit

* **Penetration testing** — two engagements have been carried out by FT Labs, on 23 and 26 June
  2026, against commits `dd2b754` and `1beeed6` respectively; the reports are in
  [`documents/pentesting/`](documents/pentesting/). The 2026-08-19/20 internal review and its
  fixes ([`documents/security/security-fixes.md`](documents/security/security-fixes.md)), the
  minting-proxy upgradability, and the `GlobalStateLocation` change all postdate both engagements,
  so neither report covers the current code.
* **Third-party security audit** — No Witness Labs, report version 0.1.0 dated 22 September 2026, in
  [`documents/audit/`](documents/audit/2026-09-22-cip-113-1st-module-audit-report.pdf). It audited commit
  `06a8059d` and verified the fixes at `f454505d`; its compiled scripts are identical to those recognised
  by the CMTA Expert Committee. The CIP-113 base layer was **out of scope** — it was audited separately
  ([reports of 10 August and 24 September 2026](https://github.com/cardano-foundation/cip113-programmable-tokens/tree/369e8c280609208b388c77937dc3a18e02561b0a/documentation/audit)).
* **Internal security review** — an adversarial self-review of the compliance layer found and fixed
  a set of defects, two of them critical. Each is written up with its cause, its fix and the
  reasoning in [`documents/security/security-fixes.md`](documents/security/security-fixes.md), and
  each is pinned by a test in [`validators/regression.ak`](validators/regression.ak). This is not a
  substitute for the third-party audit above.
* **Internal re-audit, 2026-08-28** — every non-test line re-read and composed against the CIP-113
  base layer at its then-current HEAD, with a multi-agent find/refute/prove-by-test pass alongside.
  **No Critical or High defect.** Two Mediums were found: §12 (dismantling a linked list could
  freeze a live protocol) was fixed; §13 (a seizure operator can move the CIP-68 reference NFT) was
  **accepted by decision**, with its rationale and an implemented-then-reverted fix recorded in the
  same document. The current code refuses it: the seizure path cannot move the reference NFT (see
  [§13](documents/security/security-fixes.md#13-cip-68-metadata-tokens-were-governed-by-an-exact-name-not-by-their-kind)
  and
  [§20](documents/security/security-fixes.md#20-a-cip-68-reference-token-was-never-paired-with-the-security-tokens-name)).
  Several further items were reviewed and deliberately left unchanged, with the
  reasoning under *Acknowledged, and deliberately not changed*. Still not a substitute for the
  third-party audit.
* **Third-party equivalency assessment** — an independent CMTAT mapping of this codebase is
  maintained at [CMTA/CMTAT-Cardano](https://github.com/CMTA/CMTAT-Cardano). Version 0.2.0 of that
  mapping is the pre-assessment the Expert Committee reviewed; it was filled against version 0.2.0 of
  CMTA's criteria, which have since been superseded.
* **GlobalState and list hardening, 2026-11** — the append-only GlobalState datum, lists that keep
  their own NFTs at their spend scripts, and `MigrateLists` are written up, with their tests and
  accepted residue, in [§22 of the security
  notes](documents/security/security-fixes.md#22-a-rotation-could-rewrite-the-datum-and-a-list-could-never-be-replaced).

---

## Actors

* **Admin** — the `admin_credential_hash` held in the GlobalState datum. Controls the power-user
  list itself (add, remove, modify), the security metadata, the remaining supply cap
  (`SetMintableAmount`, until `LockUpgrades`), the GlobalState logic itself
  (`RotateGlobalStateScript`, until `LockUpgrades`), which two lists GlobalState names
  (`MigrateLists`, until `LockUpgrades`), and the irreversible deactivation switch. Rotatable, so
  the master key can be replaced without redeploying. Never the minting authority: genesis and
  `RotateAdmin` refuse it, and `RotateMintingScript` refuses an authority equal to the admin. Use a
  key or a native multisig, never a script of this deployment.
* **Power user** — a node in the power-users linked list, carrying independently grantable flags
  (a credential equal to GlobalState datum field 0, the GlobalState logic hash, is refused
  wherever the role is used — that logic's withdrawal is in every GlobalState transaction and
  would otherwise sign for it; likewise, the minting authority refuses
  its own hash, the minting proxy and the transfer and seizure scripts it pins for every operator
  and admin it checks, and the seizure logic refuses its own hash and the current minting authority.
  Any other script — this deployment's transfer and seizure logic above all, and any superseded
  script — stays an operator rule: never grant a role to a script whose withdraw-0 someone else can
  run):
  * `is_admin` — add, remove and update denylist entries (including the frozen amount). Deliberately split from the master admin key, so a
    compliance function can be delegated without handing over control of the protocol.
  * `can_mint` — mint new tokens, up to the remaining supply cap
  * `can_burn` — burn tokens, restoring headroom under the cap
  * `can_pause` — pause and unpause all standard transfers (each write must flip the flag)
  * `can_force_transfer` — seize tokens, moving them to a vetted address
* **Trusted entity** — an off-chain KYC attestor whose Ed25519 verification key is listed in the
  GlobalState datum. It signs the KYC proofs that transfers present. Not an on-chain role: it never
  submits transactions, it only signs attestations.
* **Holder** — any wallet or script holding the token. Must be absent from the denylist (or only
  partially frozen, see below) and, when
  the corresponding flag is set, must present a valid KYC proof (or prove membership of the
  allowlist tree).

## How it works

* An issuer initialises the protocol, then grants power-user flags to the operators who need them.
* Power users and denylist entries are each stored on-chain as a linked list. A denylist entry
  freezes the holder's credential hash, fully or partially (CMTAT `freezePartialTokens`):
  * `frozen_amount: None` — **fully frozen** (sanctioned): the holder can neither send nor receive.
  * `frozen_amount: Some(f)` — **partially frozen**: the holder receives freely. It can send only in
    a transaction that pays back to outputs carrying its own stake credential hash either at least
    `f` of the token, or at least as much as the transaction spends from that hash. So the holder
    always ends with at least `min(balance before, f)`: at or above `f` it keeps `f`; below `f` it
    can consolidate its UTxOs but not lower its balance. This is CMTAT's "only the amount above
    `f` is transferable", measured net per transaction (tokens paid to the holder in the same
    transaction count). Either credential form of that hash counts, so a holder that pays back to
    the form it cannot authorise strands those tokens (recoverable only by seizure). A send that
    lowers the holder's balance must still pay `f` back, so it normally includes at least `f` of the
    holder's own tokens as inputs; a balance spread over many small UTxOs can be consolidated
    first, in as many transactions as needed (16 KiB transaction limit). `f` is not checked against
    the holder's balance: an admin may set it above what the holder holds, and the holder then
    cannot lower its balance until it
    reaches `f` (it can still receive and consolidate). The pay-back output also makes the holder a
    destination of its own transaction, so when `requires_receiver_kyc` is set the holder needs a
    valid KYC proof to send — even if `requires_sender_kyc` is off. A partially frozen holder whose
    KYC has lapsed must renew it before it can send.

  An unlisted party proves absence with a covering-node proof; a partially frozen party cites its
  own node instead. An `is_admin` power user changes `f` in place with `UpdateDenylistEntry`.
  Seizure ignores a partial freeze (it is an override) and can leave the holder below `f`.
  Unlike CMTAT v3.2.0, a seizure does not lower `f` to match, a freeze is not bounded by the
  holder's balance, and a full freeze replaces `f` rather than sitting beside it — see
  [§17 of the security notes](documents/security/security-fixes.md#17-partial-freeze-a-denylist-entry-can-freeze-an-amount-not-only-the-whole-holding).
* A transfer must clear the pause gate, then per sender and per receiver: the denylist gate (absence,
  or a partial freeze — which a sender's transaction must respect), plus a
  valid KYC proof whenever `requires_sender_kyc` / `requires_receiver_kyc` is set. The two are
  toggled independently.
* Forced transfers move tokens to a vetted destination. They intentionally remain available while
  transfers are paused, so enforcement is not blocked by a pause.
* **The pause gate covers transfers only.** Minting and burning stay available during a pause, for
  the same reason forced transfers do: the register must remain correctable, and a court- or
  regulator-ordered burn cannot wait for an unpause. This follows the CMTAT reference
  implementation, where mint and burn go through `_update` rather than the pause-checked transfer
  path. Two consequences to plan around: position sizes can change while the register is otherwise
  static (every such change is still signed, on-chain, power-user-gated and cap-enforced), and a
  holder minted to during a pause cannot move the tokens until it lifts — so do not mint to third
  parties mid-pause.
* Minting is capped; burning returns headroom to the cap. With this repository's minting authority
  installed, every mint or burn of the security token is debited from `mintable_amount` in the same
  transaction, whichever GlobalState logic is installed: the authority's `MintBurn` checks it. A
  replacement authority must keep the debit; nothing frozen re-checks it. Until `LockUpgrades` the
  admin chooses the authority (`RotateMintingScript`) and can set the cap directly
  (`SetMintableAmount`); after it, `RotateMintingScript` is closed, so the installed authority and
  its debit are permanent. The debit is the authority's and not the minting proxy's because the
  issuance policy ID is derived from the proxy's hash, so a defect there could never be fixed; the
  authority can be rotated. That is not a promise that no rotation can change the cap. A write of `mintable_amount`
  outside a mint or burn is a cap amendment, governed by the installed GlobalState logic: this
  repository's logic allows only `SetMintableAmount`, admin-signed, until `LockUpgrades`, and never
  beside a mint or burn. The cap is remaining headroom, not total supply: until `LockUpgrades`, the
  admin may also reset it to any non-negative absolute value
  with `SetMintableAmount` (setting it below what is already minted simply stops further minting).
  There is no upper bound: off-chain readers must decode it as an arbitrary-precision integer. That action cannot share a transaction with a mint. **Burning existing supply spends a
  programmable-base UTxO, so the CIP-113 base layer makes the transfer logic run over it** — which
  means a burn during a pause, or from a sanctioned holder, must instead be routed through the
  forced-transfer path and needs `can_force_transfer`, not just `can_burn`.
* **Seizure is all-or-nothing per UTxO whenever the holder cannot clear the destination gates.**
  The base layer returns a partial seizure's residual to the holder's own address, and this
  deployment vets every token-bearing output as a destination — so the residual must itself clear
  the denylist gate and, when `requires_receiver_kyc` is set, present a valid KYC proof. A fully
  frozen holder can do neither (a *partially* frozen one can receive the residual); **so can a holder whose attestation has simply expired**, which is the case
  that surprises operators. Drain whole UTxOs instead; a position can still be partially seized by
  choosing which UTxOs to spend. Both constraints are explained in
  [`documents/security/security-fixes.md`](documents/security/security-fixes.md).
* Deactivation is one-way and requires a paused protocol first — it is a decommissioning switch, not
  a stronger pause. **Dismantling the two linked lists (`Deinit`) is only possible afterwards**, and
  is equally irreversible: burning a list's root NFT can never be undone, because that list
  instance's root can never be re-created (its `Init` nonce is spent), and a new instance, which
  `Init` can create at any time, stays inert: the deactivated GlobalState can no longer be spent, so
  `MigrateLists` can no longer adopt it. **Decommissioning has a required order** — sweep the
  GlobalState UTxO's surplus ADA, pause, empty the denylist, empty the power-users list, deactivate,
  then `Deinit` both lists. Each step becomes unavailable once a later one has happened: the
  deactivated GlobalState UTxO can never be spent again (so any ADA left on it is locked with it),
  and node removal is blocked after deactivation while `Deinit` requires an empty list. The full
  runbook and what each skipped step costs are in
  [`documents/security/security-fixes.md`](documents/security/security-fixes.md) §12.
* **Sanctions are single-signer and have no exempt list.** Any power user holding `is_admin` can
  denylist any address, including the admin's or another operator's. That freezes the address's
  *holdings*; it never touches anyone's *role*, since GlobalState actions do not consult the
  denylist. It is reversible in one transaction. If you want separation of duties here, that is a
  policy decision to make before launch.

### Upgrading and locking the rules

The GlobalState admin has four distinct upgrade paths, plus control over the supply cap, while
`upgrades_locked` is false:

* `RotateMintingScript` changes `minting_script_credential_hash` in GlobalState. The permanent
  minting proxy then requires the replacement authority's withdraw-0. The proxy checks delegation
  only, not the authority's rules — the supply debit, who may mint, to whom, which names,
  registration; review and test the replacement before rotating. The replacement must keep the
  debit: one that drops it mints past the cap. Only `security_asset_name` is debited. Which names may be
  minted under the issuance policy is the minting authority's rule; a replacement authority that
  drops it can mint other names there, uncapped. Only this token's exact reference name is protected.
  A replacement authority that mints another `(100)`-labelled name under the issuance policy creates
  a token that neither the transfer nor the seizure logic polices. Nothing on chain checks that the
  new value names a working authority, so rebuild it from source with every parameter and compare
  its hash before signing. Register its stake credential before the first withdrawal. The new value
  must differ from the admin, from the current authority and from the GlobalState logic. The
  outgoing authority does not have to consent. A replacement authority must keep this build's newest
  invariant: **a `MintBurn` that changes no supply authorises nothing**. Without it, any `can_mint`
  operator could make the authority and the proxy run beside an unrelated action.
* `UpgradeRegistryNode` changes this token's CIP-113 transfer and/or third-party transfer logic
  credentials in its registry node. The admin signs and the minting authority verifies the
  continuing node, which must name exactly the transfer and seizure scripts that authority was built
  with (F08). Re-pointing either is therefore two admin steps: `RotateMintingScript` to an authority
  built with the new hash, then `UpgradeRegistryNode`. The minting proxy, GlobalState policy and disabled unfracking hook stay pinned;
  an upgrade cannot mint or burn this token in the same transaction. Register replacement logic
  stake credentials before use.
* `SetMintableAmount { new_mintable_amount }` sets `mintable_amount` to any non-negative absolute
  value (no upper bound). Admin-signed; it cannot mint, burn or move the security token in the
  same transaction.
* `RotateGlobalStateScript { new_global_state_script_hash }` replaces the GlobalState **logic**. The
  GlobalState NFT lives forever at `global_state_proxy`, a tiny spend validator that reads only
  datum field 0 (`global_state_script_credential_hash`) and requires that credential's withdraw-0;
  every GlobalState rule lives in the script field 0 names. Rotation rewrites field 0 and must run
  **both** logics in one transaction: the current one checks the admin signature, the lock, that the
  new hash is not the admin's or the minting authority's, and that the output datum keeps every
  input field unchanged apart from field 0 (append-only, below); the new one must run its own
  withdraw-0 with the same `RotateGlobalStateScript` redeemer — which proves its script is
  producible, its stake credential registered and that it decodes a GlobalState rotation, but
  **not** that it is a correct GlobalState logic — and checks the datum it is about to govern (this
  version accepts exactly the input with field 0 rewritten). **The new logic governs every later
  GlobalState action, the cap's amendments included**: a permissive logic can rewrite
  `mintable_amount` outside a mint or burn or hand GlobalState to anyone, which is stronger than a
  permissive minting authority; it cannot let a mint or burn skip the minting authority's debit.
  Rotate only to a reviewed build of this repository: before signing, rebuild the new logic from
  source at a pinned commit with every parameter and check that its hash equals
  `new_global_state_script_hash` (do the same for field 0 before genesis). A rotation cannot change
  any other field: the outgoing logic refuses it. Fields appended after the input's are the incoming
  logic's to accept, so reviewing a successor includes reviewing what its incoming side accepts. One
  admin signature authorises a rotation. As with `RotateAdmin`, the old side authorises and the new
  side proves it is live — the new admin by signing, the new logic by running — but the logic is
  code the admin chose, so its run is not a second approval. For two-party control, make the admin a
  native-script multisig with a registered stake credential: a script admin signs through its own
  zero-value withdrawal. The NFT never moves, and readers find GlobalState by its NFT, never its
  address.

  **The datum is append-only.** Its **core**, fields 0–4 (logic hash, `deactivated`, admin,
  power-users list id, minting authority), is exactly what the scripts that can never be
  redeployed read after genesis — the GlobalState proxy, the minting proxy and the two lists — so
  its position and type are fixed forever. `transfers_paused` is field 5 and `mintable_amount`
  field 6: no permanent script reads them. Every field, in the core or after it, keeps its
  position, its type and, across a rotation, its value; a new logic may only append fields
  (within `max_global_state_datum_bytes`). A field that falls out of use is set to its type's empty
  value by a later logic, never dropped or retyped; a real redesign of the datum is a new
  deployment. **The limit:** the outgoing logic enforces this in the rotation transaction only, by
  requiring the output's first N fields (N = the input's field count) to equal the input's except
  field 0. After that the installed logic governs, so each version must carry the check forward
  into its own rotation; the rule is absolute only after `LockUpgrades`. The replaceable readers
  (minting authority, transfer and third-party logic) decode the v1 fields and ignore anything
  appended, so before installing a logic whose appended fields they must honour, first rotate them
  to versions that read them: the authority through `RotateMintingScript`, then the transfer
  scripts through the new authority's `UpgradeRegistryNode`, then the GlobalState logic — all
  before `LockUpgrades`. The invariants every replacement logic must keep are listed in
  `validators/global_state_logic.ak`.
* `MigrateLists { new_power_user_linked_list_policy_id, new_denylist_linked_list_policy_id }` points
  the token at new lists: its redeemer carries only the two new policy ids, and it rewrites fields 3
  and 7 together, and nothing else. Readers authenticate list elements by these two policy ids
  alone, so this is the only way to replace a list with a bug. Beyond the guards every GlobalState
  action shares, it checks only five things: the admin's signature, upgrades not locked, both ids 28
  bytes, at least one id different from its current value, and the output datum equal to the input
  with fields 3 and 7 replaced. It does not check the new lists' roots, addresses, contents or code,
  nor any relation between the ids: a swap of the two lists, or two equal ids, passes. The admin is
  trusted with this choice, because no on-chain check can prove that a policy id runs this
  repository's list code. So verify the new ids off-chain before signing: recompute each policy id
  from this repository's list mint applied with its GlobalState policy, the chosen nonce and its
  `list_script_hash`, and confirm each list's contents. A list built from this repository is created
  with its mint's `Init`, at genesis or at any later time; `InitAfterGenesis` no longer exists.
  Copying the operators and the sanctions over is the operator's job (see the [list-migration
  runbook](documents/integration-guide.md#migrating-the-lists)).

`LockUpgrades` is an admin-signed, one-way GlobalState action that closes **all five** for later
transactions — with this repository's GlobalState logic installed, after it `mintable_amount` moves
only through mint and burn, the GlobalState logic can no longer be replaced, and the two list policy
ids (fields 3 and 7) are final, so finish any `MigrateLists` before locking. `LockUpgrades` is
enforced by the installed GlobalState logic itself, which also closes `RotateMintingScript` and
`MigrateLists`; the lock's closure of `UpgradeRegistryNode` is enforced by the installed minting
authority, which refuses the upgrade once `upgrades_locked` is set. So after the lock both the
installed GlobalState logic (datum field 0) and the installed minting authority (field 4) are
permanent, and "closes all five" holds only if both are reviewed builds of this repository: before
locking, check datum fields 0 and 4 against rebuilds (see [Deployment
checklist](#deployment-checklist)). It does not deactivate transfers, minting or burning. If a
registry upgrade is bundled with the lock in one transaction, the upgrade reads the pre-lock
GlobalState input and can still succeed; audit the whole transaction when deciding which rules were
locked. The same pre-state rule applies to a registry upgrade bundled with admin rotation or
deactivation.

#### Upgrading a running deployment in place

A redeployment (burn and re-mint) needs none of this. To upgrade a running deployment in place:

1. Register the stake credentials of the new GlobalState logic, minting authority and seizure
   logic.
2. `RotateGlobalStateScript` to the new GlobalState logic **first**. Until then `RotateMintingScript`
   runs under the old logic, which does not keep the admin and the authority apart.
3. `RotateMintingScript` to the new authority.
4. In a **separate** transaction, with GlobalState referenced, `UpgradeRegistryNode` re-points the
   registry node's third-party (seizure) logic to the new seizure script. The proxy now delegates to
   the new authority, whose F08 pins name that script. Steps 3 and 4 cannot share a transaction:
   the proxy reads the spent GlobalState, so during step 3 it still delegates to the old authority,
   whose pins name the old seizure script. The old seizure logic keeps working until step 4.

The active authority and role credentials are part of the deployment's trust boundary. At genesis,
after each authority rotation, and after granting or rotating an operator role, test that an action
without that role's authorised signature is rejected. A permissive script credential used as a role
or minting authority can silently weaken the checks. See the
[integration guide](documents/integration-guide.md#upgrades-and-operator-checks) for an operator
checklist.

## Building the scripts

Requires Aiken **v1.1.24** (`bacbeb35fbc9f1db93cd2e1e93fb1d93053acb4a`) with stdlib **v4.0.0**, pinned in [`aiken.toml`](aiken.toml) and matched
by CI. Both linked lists are built on `anastasia-labs/aiken-design-patterns` **v1.9.0** (v1.8.0's
logic; only the stdlib `Value` → `Assets` rename). The scripts use Plutus batch-6 builtins
(`dropList`, `unValueData`, `lookupCoin`), enabled for Plutus V3 at protocol version 11 (van Rossem,
on mainnet since 2026-07-18): they cannot run on a network below protocol version 11.

```sh
aiken fmt --check   # formatting
aiken check -D      # type-check and run the test suite
aiken build         # compile; regenerates plutus.json
```

`aiken build` writes the blueprint to `plutus.json`. Every validator except `global_state_proxy` takes compile-time parameters,
so the blueprint contains **unapplied** scripts — apply parameters with `aiken blueprint apply` (or
the equivalent in your off-chain library) before deriving any hash or address.

### Prerequisites

Two values come from the deployed CIP-113 base layer of the target network, not from this repo —
obtain them before applying any parameters:

* **`registry_policy_id`** — the CIP-113 registry mint policy id, a compile-time parameter of row
  10 only.
* **The issuance template** — `prefix_cbor_hex` and `postfix_cbor_hex` from the base layer's
  `IssuanceCborHex` datum (the reference UTxO carrying its `IssuanceCborHex` NFT). Applied to the
  minting proxy's hash (row 6) it yields this token's issuance policy ID; see
  [What the derived parameters must equal](#what-the-derived-parameters-must-equal).

**`plb_script_hash`** — the CIP-113 programmable-logic-base (PLB) script hash — is **off-chain
only**: the address of every programmable-token UTxO. No validator in this repo takes it as a
compile-time parameter any more; the base layer's own custody guarantees cover mint, ordinary
transfer and seizure alike (see
[What is delegated to the CIP-113 base layer](#what-is-delegated-to-the-cip-113-base-layer)).

### Parameter order

Parameters have to be applied in dependency order — GlobalState proxy → GlobalState policy → each
list's spend validator, then its mint → the minting-logic proxy → the rest — because each layer's
policy ID or script hash feeds later validators. For the lists the order is: list spend validator
(takes the GlobalState policy) → list mint (takes the GlobalState policy, its one-shot input and the
spend validator's hash) → list policy ID → the GlobalState genesis datum (fields 3 and 7). There is
no cycle: a list spend validator takes no list policy ID, it reads the policy off the element it
spends. The table below is exhaustive and lists, for every validator, its parameters in the
exact order the blueprint (`plutus.json`) declares them; apply top to bottom. `security_asset_name`
must be fixed before genesis: datum field 0 names a GlobalState logic built with it (row 7). It does
not feed the issuance policy ID, because the minting proxy (row 6) does not take it.

> `aiken blueprint apply` takes parameters **positionally, one at a time**, and shared parameters
> are **not** in a shared order across validators — e.g. row 7 (`global_state_logic`)
> lists the issuance policy id before `global_state_policy_id`, while rows 8–10 list
> `global_state_policy_id` first. Always follow this validator's own row below; never assume a
> "usual" order.

| # | Validator | Parameters (blueprint order) | Source |
|---|---|---|---|
| 0 | `global_state_proxy.global_state_proxy` (spend) | — | No parameters: its hash is the same for every deployment. |
| 1 | `global_state.global_state_mint_validator` (mint) | `tx0`, `index0`, `global_state_proxy_hash`, `max_global_state_datum_bytes` | The genesis UTxO you choose to spend; the hash of `global_state_proxy` (row 0). The NFT must be minted to that script address; the datum-size cap (recommended 8192, **same value as row 7** — nothing on chain ties the two). |
| 2 | `power_users.power_users_validator` (spend) | `global_state_policy_id` | Row 1. Its hash is where every power-users list UTxO lives. |
| 3 | `power_users.mint` | `global_state_policy_id`, `init_input_out_ref`, `list_script_hash` | Row 1; a genesis UTxO reserved for this list; the hash of `power_users_validator` (row 2, **spend**). Its hash is the **power-users policy ID** (datum field 3). |
| 4 | `denylist.denylist_validator` (spend) | `global_state_policy_id` | Row 1. Its hash is where every denylist UTxO lives. |
| 5 | `denylist.mint` | `global_state_policy_id`, `init_input_out_ref`, `list_script_hash` | Row 1; a genesis UTxO reserved for this list; the hash of `denylist_validator` (row 4, **spend**). Its hash is the **denylist policy ID** (datum field 7). Same positions as row 3's parameters. |
| 6 | `minting_logic_script.minting_logic_validator` | `global_state_policy_id` | Row 1. Nothing else, so the issuance policy ID derived from this hash depends on the GlobalState policy ID alone (see below). |
| 7 | `global_state_logic.global_state_logic` (withdraw) | `security_asset_name`, `issuance_policy_id`, `global_state_policy_id`, `max_global_state_datum_bytes` | Operator choice; the **issuance policy ID**, i.e. the security token's policy ID, derived from row 6's hash (see below; **not** row 6's hash itself); row 1; the datum-size cap (same value as row 1; a rotated-in logic may choose another). Its hash goes into GlobalState datum **field 0** at genesis. |
| 8 | `transfer_logic_script.transfer_logic_validator` | `security_asset_name`, `global_state_policy_id`, `security_policy_id` | Operator choice; row 1; the issuance policy ID (as row 7). The denylist policy ID is read from the GlobalState datum at run time, not compiled in. |
| 9 | `third_party_transfer_logic_script.third_party_transfer_logic_validator` | `security_asset_name`, `global_state_policy_id`, `security_policy_id` | Operator choice; row 1; the issuance policy ID (as row 7). Both list policy IDs are read from the GlobalState datum at run time, not compiled in. |
| 10 | `minting_authority.minting_authority_validator` | `security_asset_name`, `global_state_policy_id`, `registry_policy_id`, `minting_logic_script_credential_hash`, `security_policy_id`, `transfer_logic_script_hash`, `third_party_transfer_logic_script_hash` | Operator choice; row 1; Prerequisites; row 6's hash; the issuance policy ID (as row 7 — it **differs** from row 6's hash, see below); row 8's hash; row 9's hash (the scripts registry fields 3 and 4 must name). Both list policy IDs are read from the GlobalState datum at run time, not compiled in. |

### What the derived parameters must equal

* `list_script_hash` (rows 3 and 5) — the hash of that list's own **spend** validator (row 2 for the
  power-users list, row 4 for the denylist), **never** a policy ID. The mint pins its list there: a
  list mint applied with the wrong spend hash roots its list at that script (see the warning under
  [Deployment: reference scripts](#deployment-reference-scripts)).
* The power-users and denylist policy IDs (GlobalState datum fields 3 and 7) — the hashes of the
  applied list mints (rows 3 and 5).
* `minting_logic_script_credential_hash` — the hash of `minting_logic_script.minting_logic_validator`
  (row 6), the permanent minting proxy.
* `issuance_policy_id` (row 7) and `security_policy_id` (rows 8–10) — the security token's policy
  ID, which is the base layer's issuance template applied to the proxy: `blake2b_224(0x03 ‖
  prefix_cbor_hex ‖ proxy hash ‖ postfix_cbor_hex)`, with the template from Prerequisites. It is the
  key of this token's CIP-113 registry node, and it is **never** the proxy hash itself. No script
  refuses a wrong value — not the GlobalState logic, not the transfer scripts, and not the minting
  authority, whose `Register` derives the policy from the registry node rather than comparing it
  with this parameter — so the deploy script must derive the ID this way and assert it, including
  that it differs from `minting_logic_script_credential_hash`. A transfer logic built with the wrong
  policy ID finds no parties and skips the denylist and KYC checks for every transfer. A minting
  authority built with the wrong `security_policy_id` still passes `Register`, but every `MintBurn`
  is refused until `RotateMintingScript` installs a corrected one (fails closed). After
  `LockUpgrades` the refusal is permanent, because that rotation is closed then.
* `transfer_logic_script_hash` and `third_party_transfer_logic_script_hash` (row 10) — the hashes of
  rows 8 and 9, in that order. Registration and every `UpgradeRegistryNode` require registry fields 3
  and 4 to name exactly these (F08), and the two must differ. The pin is only as good as row 10's
  build: assert the order in the deploy script, and include "a seizure without a
  `can_force_transfer` operator is rejected" in the post-deploy smoke test.
* `security_asset_name` — an operator choice, and its first four bytes, compared byte for byte,
  decide its class: `(222)`, `(333)` and `(444)` make it a CIP-68 name (see
  [CIP-68 metadata tokens](#cip-68-metadata-tokens)); `(100)` is refused at registration, because the
  supply would be its own metadata token; anything else makes it a plain name. A CIP-68 name needs at
  least one byte after the label; a plain name must not be empty. Registration fails closed on a name
  that breaks these rules. The name is built into rows 7–10 and must be byte-identical in all four.
* There is still **no** parameter for the reference name. A CIP-68 token's reference name is `(100)`
  followed by the same body, derived from `security_asset_name` by `cip68.reference_name` alone, so
  nothing is configured: scripts built with byte-identical `security_asset_name` bytes cannot disagree on it.
* `tx0` / `index0` / `init_input_out_ref` — one-shot genesis UTxOs, each spent once during
  initialisation (see [Initialising a token](#initialising-a-token)).

### Deployment: reference scripts

Five validators are withdraw-0 scripts, i.e. they run as zero-value withdrawals rather than as the
spending or minting script of any UTxO: `global_state_logic` (every GlobalState action — the proxy
holding the NFT requires it), `transfer_logic_validator` (~7.2 KB, every transfer),
`third_party_transfer_logic_validator` (~7.3 KB, every seizure), `minting_authority_validator` (~9.2
KB, every mint and burn) and the minting proxy `minting_logic_validator` (~0.8 KB, also every mint
and burn — the proxy's withdraw-0 is what the CIP-113 registry node invokes, and it in turn requires
the authority's). The four large ones (`global_state_logic` is ~5.9 KB and runs in every mint and
burn too) must be published once as reference-script UTxOs and supplied via reference inputs — not
inlined (a transaction is capped at 16 KiB); the proxy is small enough to inline but is simplest to
publish alongside them. The two list `mint` validators (~4.1–4.7 KB) must be treated the same way:
the genesis transaction runs both, the GlobalState mint and `global_state_logic` — ≈ 17.1 KB of
scripts against the 16 KiB limit — so publish them and `global_state_logic` before genesis (step 0
of [Initialising a token](#initialising-a-token)). Sizes are of the unapplied scripts in
`plutus.json` (`compiledCode` hex length ÷ 2); applying the parameters adds their encoded bytes.

All five withdraw-0 scripts need their **stake credential registered** on chain before the first
transaction that names them in `withdrawals` — see steps 0 and 2 of [Initialising a token](#initialising-a-token).
A withdrawal from an unregistered credential is rejected by the ledger at phase 1, before any script
runs, so forgetting the proxy's registration makes every mint and burn fail from genesis on.

> **The list SCRIPT hashes are not the list POLICY IDs.** Each list file declares a `mint` validator
> and a separate spend validator, so their hashes differ. Each list mint takes its own spend
> validator's hash (`list_script_hash`) and keeps every NFT of its policy there, starting with the
> root at `Init`. A list mint applied with the wrong spend hash roots its list at that script, whose
> rules, not the list's, then govern every element — and readers do not re-check an element's
> address. Nothing on chain can tell a wrong hash from the right one, but the policy ID commits to
> it: re-deriving each list's policy ID from its right spend hash, and comparing it with datum
> fields 3 and 7, is the check.

> **Verify before genesis, off-chain:** that the two linked-list policy IDs differ and each equals
> the hash of its list's `mint` applied with that list's own spend-validator hash (rows 2–5), and
> that datum field 0 is the hash of `global_state_logic` rebuilt from source with this deployment's
> parameters. The on-chain code checks what it can (the IDs must differ and be 28 bytes; the NFT
> must land at `global_state_proxy`; field 0 must be 28 bytes, differ from the admin, the minting
> authority and the proxy, and run in the genesis transaction, where this logic accepts only a datum
> that names it and fits its own cap; the GlobalState mint requires both list policies the datum
> names to mint alongside it; each list's `Init` pins the root to `Script(list_script_hash)`) but
> cannot bind field 0 to a hash: field 0 depends on the GlobalState policy, which depends on the
> mint's own parameters. A field 0 that cannot run now fails genesis; one that runs and accepts it —
> another validator, or this logic applied with a wrong parameter — still gets through and then
> governs GlobalState. Smoke-test one GlobalState action right after genesis. The power-users policy
> ID (field 3) is the only anchor for which list's nodes are operators: the minting authority, the
> denylist, seizure and `PauseTransfers` authenticate them under it, with no compile-time copy, so a
> wrong field 3 hands those roles to whoever controls that policy. Field 3, like the denylist's
> field 7, changes only through `MigrateLists`, admin-signed and before `LockUpgrades`.

### Deployment checklist

1. **One name, byte-identical, in rows 7–10.** Each script polices only the `security_asset_name` it
   was built with. Transfer or seizure scripts built with a name other than the authority's find no
   parties, so the minted token goes unpoliced. A GlobalState logic built with another name refuses
   every `MintSecurity`, but its name-scoped security-token guard then misses the real token, so
   before `LockUpgrades` an admin-signed `SetMintableAmount` (in − n) can carry a mint of n that is
   still debited from the cap, with role, KYC and denylist still applying. Check by rebuilding each
   script from source and comparing hashes. After deployment, smoke-test that a mint whose
   GlobalState output is not debited is rejected, and that a transfer of the minted token without a
   denylist proof is rejected.
2. **The name passes the registration rules** (see `security_asset_name` under
   [What the derived parameters must equal](#what-the-derived-parameters-must-equal)). Check it
   before genesis, because a refused name is found only at registration: by then datum field 0
   already names a GlobalState logic built with the name.
3. **A CIP-68 name.** Choose the metadata authority (see
   [CIP-68 metadata tokens](#cip-68-metadata-tokens)), and keep the reference NFT's datum within the
   base layer's `max_inline_datum_bytes`.
4. **Before `LockUpgrades`.** Rebuild `global_state_logic` and `minting_authority` from source at
   the commit being deployed (or its tagged release) with every parameter, and check their hashes
   against datum fields 0 and 4 respectively. The lock is enforced by the installed GlobalState
   logic itself, so after it the cap is final only if that logic is a reviewed build of this
   repository (see [Upgrading and locking the rules](#upgrading-and-locking-the-rules)). The lock
   makes the installed authority permanent too: it cannot be rotated afterwards, and it enforces the
   registry-upgrade lock itself. It also makes the two list policy IDs (fields 3 and 7) final, so
   finish any `MigrateLists` first.
5. **The base-layer commit.** Record the CIP-113 base-layer commit the reliance was checked against
   alongside the deployment parameters; this is recognition condition 4 (see
   [CMTA recognition](#cmta-recognition)). On any CIP-113 version change, re-verify
   [What is delegated to the CIP-113 base layer](#what-is-delegated-to-the-cip-113-base-layer) first.
6. **Each list mint built with its own spend hash.** Before genesis, re-derive datum fields 3 and 7
   from rows 2–5: each list mint applied with the hash of that list's spend validator. A wrong
   `list_script_hash` roots the list at another script (see [Deployment: reference
   scripts](#deployment-reference-scripts)). On any change of the linked-list library version,
   re-verify [What is relied on from the linked-list
   library](#what-is-relied-on-from-the-linked-list-library).

### What is delegated to the CIP-113 base layer

This deployment's own scripts do not re-check everything the CIP-113 base layer already enforces
independently. In plain terms, the base layer guarantees:

* **Custody on mint.** `issuance_mint`'s `no_escape` rule keeps every newly minted token inside the
  programmable base and forces an inline stake credential onto every programmable-base output.
* **Every mint or burn runs the token's minting logic.** `issuance_mint` requires the withdraw-0 of
  the minting-logic credential it is parameterised by, on every mint and burn of its policy. This is
  why a mint or burn of this token always runs the permanent minting proxy, which requires the
  installed minting authority to run, so that authority's same-transaction debit applies.
* **Custody on ordinary transfer.** The transfer path requires programmable-base outputs to hold, per
  policy, at least as much as programmable-base inputs (`tokens.contains(PLB outputs, PLB inputs)`),
  which — combined with ledger value conservation — keeps the token inside the base.
* **Custody on seizure (forced transfer).** `validate_io_constraints_and_balance` (`third_party.ak`)
  requires every spent programmable-base input to be paired with an output at the identical address,
  datum and reference script, and requires the acted-on policy's tokens across **all**
  programmable-base outputs to be a superset of those across programmable-base inputs plus mint/burn
  — the same custody guarantee as mint and ordinary transfer, independently verified for the seizure
  path.
* **Registry integrity.** A registry node's key is cryptographically bound to its
  `minting_logic_script` field, and on an in-place upgrade the base layer itself keeps `key`, `next`
  and `minting_logic_script` frozen. Registry keys are unique: the base layer forbids a duplicate
  key.
* **No supply change on an upgrade.** `registry_spend` hoists
  `!mint_has_policy(self.mint, spent_node.key)` above its `when`, so it covers both the in-place
  update and the covering-node spend: a transaction that spends a registry node can never mint or
  burn that node's own token. An upgrade can change transfer-logic rules; it can never touch supply.
* **Which registry node gets to invoke a logic script.** The base layer authenticates the registry
  node it uses to dispatch to a logic script's withdraw-0.

The minting authority's `Register` and `UpgradeRegistryNode` derive the issuance policy ID from the
registry node that names the proxy, and neither compares the ID with the authority's compile-time
`security_policy_id`. That is sound only because the base layer derives a node's key from its field
2 and keeps keys unique. The minting authority's supply debit applies only because every mint or burn
runs the token's minting logic (above). These are relied on, not re-checked; re-verify them on any
change of the CIP-113 version.

Because of the registry-dispatch point, this deployment's transfer and seizure logic and the minting
authority's `MintBurn` read no registry node on those paths — the issuance policy each one polices
is pinned at compile time instead, in their `security_policy_id` parameter. The minting proxy reads
none either; only `Register` and `UpgradeRegistryNode` read one, as described above. Because of
the three custody points, none of the mint,
ordinary-transfer or seizure paths re-check programmable-base custody themselves any more; all three
rely on the base layer's own guarantees. And because of the no-supply-change point, the upgrade path
no longer re-checks that a spend-and-update transaction mints or burns nothing; it relies on
`registry_spend` alone.

These guarantees were verified against CIP-113 base-layer commit `018415d`, re-verified on 2026-08-28
at `9db7e06`, and **re-verified on 2026-10-15 at `95e99ac`**, whose validator code is identical to
that repository's `main` at `369e8c2` — all of them still hold. Upgrading the
deployed base layer invalidates that verification and requires re-checking it before relying on this
section again; record the commit you checked against alongside the deployment parameters.

Three things a redeploy onto a base layer at `9db7e06` or later must account for, none of which
changes the guarantees above:

* **Dispatch is per input.** The base spend validator reads the live transfer / third-party /
  unfracking credentials from the coordination datum and requires the witnessed one's withdraw-0
  (`SpendViaTransfer` / `SpendViaThirdParty` / `SpendViaUnfracking`). Transaction shape and base-layer
  redeemers change; this repo's validators do not.
* **Programmable-base outputs must stay seizable**, and their inline datums are size-bounded by a
  protocol parameter (`max_inline_datum_bytes`). At `95e99ac` this holds on the ordinary transfer
  path too, not only on issuance and seizure: every programmable-base output of a transfer needs an
  inline stake credential and the seizable shape (`collect_output_assets`). The only datum this deployment puts on a token UTxO
  is the CIP-68 reference NFT's metadata — check the deployed bound before publishing it.
* **The coordination UTxO's upgrade authority is part of this token's trust boundary.** Whoever holds
  it can re-point the base layer's transfer and third-party validators in place (at `95e99ac` also
  its issuance logic and programmable-logic-global validator), which would bypass every gate here at
  once. Record who holds it, and monitor the coordination datum.

### What is relied on from the linked-list library

Both lists keep every NFT of their policy at their own spend script, and the readers rely on it. The
guarantee has two parts. First, this repository's `Init` pin, which requires the root's payment
credential to be `Script(list_script_hash)`. Second, the linked-list library
(`anastasia-labs/aiken-design-patterns` v1.9.0):

* its placement checks: an insert keeps the continued anchor at the anchor's exact address and the
  new node at the anchor's payment credential, its stake part being free; a remove keeps the
  continued anchor at its address; an in-place update keeps the element at its address;
* its one-token rule (`is_only_mint_under_policy`: each mint or burn changes exactly one token of
  the policy), which is also why a list spend reads its policy off its own input without checking
  the names or quantities under it;
* its input scan, singular on an insert and on `Deinit` (`validate_singular_authentic_input`) and
  dual on a remove (`validate_dual_authentic_inputs`), which refuses any extra canonical element
  input at the list's credential (every element is there, by the `Init` pin and the placement
  checks).

The scan sees only canonical elements (exactly ADA plus one list NFT), and every token of the policy
is in one: each output that receives a token is authenticated by the library as canonical, so an
input carrying the policy in another shape cannot exist. The list mints therefore count no inputs of
their own. So the readers — the minting authority, the transfer and seizure logic, the denylist and
the GlobalState pause branch — authenticate a list element by its policy ID alone, read from datum
field 3 or 7, and do not re-check its address. This is relied on, not re-checked: re-verify the
library's placement checks, one-token rule and input scan on any change of the library version.
Tests on every list path refuse moving a list NFT off its list script; see [§22 of the security
notes](documents/security/security-fixes.md#22-a-rotation-could-rewrite-the-datum-and-a-list-could-never-be-replaced).

### Two shapes that cannot be built

Neither is a defect; both bite when composing transactions:

* **A list mutation cannot share a transaction with a GlobalState-spending admin action.** The
  denylist and power-users validators read GlobalState as a *reference* input, admin actions *spend*
  it, and Conway rejects a transaction whose inputs and reference inputs overlap. Issue them
  separately.
* **Everything funnels through one control UTxO.** Every mint, burn and admin action spends
  GlobalState, so they serialise against each other — roughly one such transaction per block. Batch
  administrative work instead of submitting it concurrently, and expect to rebuild on contention.

### CIP-68 metadata tokens

A CIP-68 token is **metadata, not value**: it is exempt from the supply cap and from the denylist and
KYC gates, because none of those questions mean anything about a metadata record. That exemption is
only safe if such a token can never be moved *like* value — which is what the rules below enforce.

**Which tokens are CIP-68.** `security_asset_name` alone decides. Its first four bytes are compared
byte for byte with the three CIP-68 user-token labels — `(222)` `#"000de140"`, `(333)` `#"0014df10"`
and `(444)` `#"001bc280"`; a name that starts with one of them is a CIP-68 name, and anything else is
a plain name (a `(100)` name is refused at registration). A CIP-68 token's metadata token is its
reference NFT, named `(100)` `#"000643b0"` followed by the same body. `cip68.reference_name` is the
only place that name is built, so every script derives the same one.

**Registration.** For a CIP-68 name, `Register` must mint exactly its reference NFT, quantity 1,
under the issuance policy; for a plain name it must mint nothing there. It never mints supply. A
CIP-68 name cannot opt out of its metadata token, and the token is CIP-68 for life: the name is built
into the scripts.

Three rules follow, and together they are an invariant rather than a posture at genesis:

1. **Minted once, at registration.** The reference NFT is minted only by `Register` and is never
   re-minted or burned by this repository's minting authority: `MintBurn` mints and burns only `security_asset_name`, so a metadata token
   cannot be re-minted after the token is live.
2. **Its UTxO holds ADA plus that token, and nothing else.** The carrier holds ADA plus that one
   token, has an inline owner stake credential, and carries a CIP-68
   `Constr 0 [metadata, version, extra]` datum; the contents are not interpreted. The value and
   datum shape is checked when the NFT is minted and on **every later move** through the transfer
   logic — because the transfer path is how a metadata update happens; the inline stake credential
   is checked when it is minted, and the base layer requires one on every programmable-base output.
   The owner may be a separate metadata authority from the GlobalState admin. Only the exact
   reference name is checked.
3. **The seizure path may not touch it.** A forced transfer is refused outright if any input carries
   the exact reference name. Seizure moves value; metadata is out of its reach, so a
   `can_force_transfer` operator cannot carry the token's metadata authority away under cover of an
   ordinary seizure.

A metadata update is therefore the metadata authority spending that UTxO — an ordinary CIP-113
owner-consent transfer — and re-outputting the token with a new inline datum, in the same shape.
Updates pass through the transfer logic's gates, so they are blocked while transfers are paused and
after deactivation.

Only this token's exact reference name is protected. A replacement authority that mints another
`(100)`-labelled name under the issuance policy creates a token that neither the transfer nor the
seizure logic polices.

Operational rules:

* Follow the CIP-68 label convention: `(333)` or `(444)` for a fungible security token, `(222)` for
  an NFT; the metadata token's `(100)` name is derived, never chosen. A `(222)` issuer sets
  `mintable_amount = 1` at genesis; nothing on chain requires it.
* A deployment that wants no metadata token uses a plain name.
* `RotateAdmin` does not rotate metadata custody. If the metadata authority should change, the current
  owner transfers the metadata token to the new authority with an ordinary owner transfer.
* The metadata token cannot be burned. It is minted once and no branch burns it, so decommissioning
  leaves it in the metadata authority's custody.
* On a base layer at `9db7e06` or later, its inline datum must fit `max_inline_datum_bytes` (see
  [What is delegated to the CIP-113 base layer](#what-is-delegated-to-the-cip-113-base-layer)).

**Choosing the metadata authority.** The carrier's inline stake credential is the only key to the
token's metadata. The transfer gates vet only holders of the security token, so the authority is not
checked against the denylist or KYC, and denylisting it does not stop updates; a pause or
deactivation does. This repository's seizure logic cannot recover the token, and it can never be
burned: a lost credential freezes the metadata forever, and a compromised one lets its holder rewrite
the metadata, though the shape rule still holds. Use a dedicated key or a native multisig under the
issuer's control, recorded with the deployment parameters. A native-multisig owner is authorised by
a withdrawal of its stake credential, so that stake credential must be registered before the first
metadata update. Never use a script of this deployment: the transfer logic,
above all, runs in every metadata update.

### Execution budget and transaction sizing

Figures below are measured with `aiken bench` (`aiken bench -m "transfer_logic_script.{..}"
--max-size 40`; the per-test execution units `aiken check -D` prints are the other source) against
the current, cost-optimised implementation, and were all re-measured on 2026-11-12 under Aiken
v1.1.24 (the GlobalState proxy and logic figures again on 2026-11-13). In the bullets, a single
transaction's figure is a named test's execution units; a per-party increment is the slope of the
named bench from `n = 1` to `n = 4`, halved where each step adds a sender and a destination. They
are for this deployment's scripts alone — the CIP-113 base layer shares the same per-transaction
budget, 10 000 M CPU / 14 M memory, and **memory is the binding axis**.

* **Ordinary transfer**, denylist-only, one sender and one destination: ≈ 0.59 M mem / 0.18 G CPU
  (`transfer_succeeds_when_clean`). Each further party on a side that cites the same denylist
  covering node as the party before it adds ≈ 0.10 M mem / 33 M CPU
  (`transfer_cost_by_party_count_shared_node`) — the node is authenticated once per run of adjacent
  parties citing it; a party citing a different node pays the full authentication, ≈ 0.16 M mem / 52
  M CPU (`transfer_cost_by_party_count_alternating_nodes`). The dedupe check adds a small quadratic
  term that matters only beyond ~20 parties per side.
* **Attestation KYC** (a trusted issuer signs the claim through CIP-30 `signData`, including
  Ledger's CIP-8 hashed mode) adds ≈ 76 K mem / 80.4 M CPU per vetted party (measured on the
  transfer fixture with and without the proof checked): the transaction builder extracts the COSE
  parts off chain, and the validator only rebuilds the COSE `Sig_structure` and verifies one Ed25519
  signature (plus one BLAKE2b-224 when hashed). Membership (MPF) proofs are cheaper. A raw Ed25519
  signature over the bare claim was supported until 2026-10-15 and is no longer accepted; it cost ≈
  20 K mem / 7.5 M CPU and ≈ 47 bytes less per proof. An earlier revision parsed the full COSE
  objects on chain at +3.5 KB per script and ≈ 300 K mem / 92 M CPU per proof; the lean form checks
  everything that matters for authorisation and nothing else (see the integration guide). (Those two
  are historical figures, not re-measured.)
* **Forced transfer** ≈ 0.63 M mem / 0.19 G CPU with one destination
  (`force_transfer_succeeds_when_clean`), ≈ 0.08 M mem / 28 M CPU per further destination sharing a
  node (`seizure_cost_by_destination_count`).
* **Redeemer size** ≈ 20 B per party without KYC and ≈ 230 B with an attestation proof made by a
  wallet (its ≈ 42-byte protected header names the signing address); a backend issuer's minimal
  3-byte header brings it to ≈ 190 B. Measured with `serialise_data` on a transfer action.

`aiken bench -m "transfer_logic_script.{..}" --max-size 40` scales linearly in `n` on both benches
(`transfer_cost_by_party_count`: `n` senders + `n` destinations, denylist-only, root-only covering
node; `seizure_cost_by_destination_count`: one seized input, `n` destinations, denylist-only):

| n | transfer mem | transfer CPU | seizure mem | seizure CPU |
|---:|---:|---:|---:|---:|
| 1 | 638,140 | 194,503,128 | 608,725 | 189,066,762 |
| 4 | 1,213,540 | 386,099,118 | 853,831 | 273,816,978 |
| 8 | 2,052,996 | 696,920,846 | 1,216,767 | 414,497,470 |
| 16 | 4,010,116 | 1,515,110,094 | 2,081,743 | 794,131,350 |

What moved since the previous measurement: readers no longer re-check a list element's address (see
[What is relied on from the linked-list library](#what-is-relied-on-from-the-linked-list-library)),
so every row is 9,816 mem / 3,392,805 CPU cheaper for a transfer and 8,884 mem / 3,167,142 CPU for a
seizure — once per transaction here, because these benches authenticate one element — and a party
that authenticates a different node saves about 4.6 K mem more. The bullets above had predated the
Aiken v1.1.24 bump; the redeemer sizes and the KYC increment did not move.

> **Conservative maxima, at 25% of the budget:** ordinary transfer ≤ 14 unique parties per side
> denylist-only, ≤ 8 per side with attestation KYC on both sides; seizure ≤ 26 destinations
> denylist-only, ≤ 17 with receiver KYC. Each is the largest `n` whose bench memory above, plus
> ≈ 76 K per attestation proof, stays within 3.5 M (CPU stays within 25% at those sizes). Split
> larger distributions; keep parties that share a
> covering node adjacent in the action lists — they follow input/output order.

#### Mint and burn

A mint or burn runs four of this deployment's scripts: the GlobalState proxy and logic
(`MintSecurity`), the minting proxy and the minting authority. Only the authority's cost grows with
the number of destinations. Measured with `aiken bench -m "minting_authority.{..}"` and
`aiken bench -m "global_state_logic_tests.{..}"` (`--seed 42 --max-size 16`). These benches build
their transaction in the sampler, so fixture construction is excluded. They call the handlers with
already-decoded arguments, so the on-chain entry point's redeemer decoding is not included (it grows
with the number of destination actions), and the GlobalState figure assumes GlobalState is the first
transaction input (each input before it adds about 11.5 K mem); the transfer and seizure
benches above build theirs in the bench body, which adds the fixture's cost to their figures.

Per mint or burn, whatever the destination count: the minting proxy 81,539 mem / 30,040,763 CPU, the
GlobalState proxy and logic 275,023 mem / 118,390,209 CPU.

| n | authority mem | authority CPU | whole mint mem | whole mint CPU |
|---:|---:|---:|---:|---:|
| 1 | 447,744 | 153,878,746 | 804,306 | 302,309,718 |
| 4 | 714,339 | 254,656,270 | 1,070,901 | 403,087,242 |
| 8 | 1,110,371 | 417,689,230 | 1,466,933 | 566,120,202 |
| 16 | 2,041,539 | 842,028,046 | 2,398,101 | 990,459,018 |

`mint_cost_by_destination_count` is one `MintBurn` to `n` distinct destinations, denylist-only,
every destination citing the empty denylist root; "whole mint" adds the two constant figures above.
A burn (`burn_cost`, no destinations): authority 250,303 mem / 87,284,101 CPU, whole burn 606,865
mem / 235,715,073 CPU. Sixteen destinations use about 17% of the memory budget before redeemer
decoding, somewhat more with it; the CIP-113 base layer's own scripts in the same transaction are
not included.

What moved since the previous measurement: the minting proxy is 5,128 mem / 1,560,820 CPU cheaper,
because `mintable_amount` left the core it decodes; the GlobalState proxy and logic, last given here
as 275,823 mem / 118,518,209 CPU, now cost 800 mem / 128,000 CPU less; the authority is 5,684 mem /
2,202,420 CPU cheaper at one destination and 71,564 mem / 25,835,985 CPU at sixteen, because a
destination's denylist element is no longer address-checked; the authority's burn is 1,292 mem /
626,849 CPU cheaper.

## KYC proof formats

Both proof types (attestation and membership) bind the same five things: **who** (credential hash), **which credential form**
(key or script), **how long** (TTL), **which token** (issuance policy ID) and **which network**.

**Attestation** (`Cip30Attestation`) — a 67-byte claim, signed through CIP-30 `signData` (an
Ed25519 signature over the COSE `Sig_structure` wrapping the claim, or its BLAKE2b-224 hash) by a
key in `trusted_entity_vkeys`. A raw Ed25519 signature over the bare claim is not accepted:

| Bytes | Field | Width |
|---|---|---|
| 0–27 | `user_pkh` | 28 |
| 28 | `user_kyc_tier` | 1 |
| 29–36 | `valid_until_ms` (big-endian) | 8 |
| 37–64 | `security_policy_id` | 28 |
| 65 | `network_id` | 1 |
| 66 | `credential_type` — `0x00` VerificationKey, `0x01` Script | 1 |

**Membership** — a Merkle-Patricia-Forestry leaf under `member_root_hash`:

* key — `credential_type(1) ‖ credential_hash(28)`
* value — `valid_until_ms(8) ‖ security_policy_id(28) ‖ network_id(1)`

#### Attestation TTL is a compliance parameter

The two proof channels are independent by design: an attestation is checked against the trusted-entity
list and never against the membership tree, and a membership proof is checked against the tree and
never against the TEL. A holder removed from the membership tree therefore **keeps transacting until
their outstanding attestation expires**.

The on-chain levers for withdrawing KYC are consequently:

| Lever | Scope | Effect |
|---|---|---|
| Remove the issuer's vkey from the TEL | every holder that issuer attested | immediate |
| Add the holder to the denylist | that holder | immediate — but it means *sanctioned*, not *KYC lapsed* |
| Update the membership root | that holder, membership proofs only | immediate for the tree; does **not** revoke an attestation |

So `valid_until_ms` is the maximum time a de-KYC'd holder may still transact. **Issue short-lived
attestations — hours, not weeks** — and size the TTL against your own re-verification cycle. A
per-holder revocation before expiry would require a second (revocation) tree that the attestation
path must also miss; that is a design change and is not implemented.

`lib/kyc/verify.ak` exports `membership_leaf_key` and `membership_leaf_value` as the normative
encoders; the off-chain tree builder must produce byte-identical leaves.

> **The credential form is part of the identity.** A verification key and a script sharing a 28-byte
> hash are different holders — the CIP-113 base layer authorises the first by signature and the
> second by withdraw-0 — so an attestation names which one it was issued for. An attestation issued
> for one form is rejected for the other.
>
> The **denylist** deliberately works the other way: it keys on the bare hash, so sanctioning a hash
> sanctions both forms. That is the conservative direction and is intentional.

**Redeemer indexing.** The transfer redeemer's `actions_for_each_input` and `destination_actions`
are matched positionally against the list of unique parties, and "unique" now means unique
*credential*, not unique hash. So a verification key and a script sharing a 28-byte hash count as
two parties needing two actions. Constructing such a pair is computationally infeasible, so in
practice nothing changes — but the rule is stated so an integrator building the action list knows
which key to deduplicate on.

## Initialising a token

Genesis is a short sequence of transactions. Apply the parameters first, then submit each
dependent transaction after the preceding output is available.

0. **Prepare.** Register the stake credential of `global_state_logic`, applied with this
   deployment's parameters (its `publish` handler accepts `RegisterCredential`), and publish it and
   both list `mint` validators as reference-script UTxOs: the genesis transaction runs those three
   and the GlobalState mint, ≈ 17.1 KB of scripts (unapplied), which cannot all be inlined under the
   16 KiB transaction limit. No transaction before genesis may spend one of the three reserved
   one-shot inputs, so exclude them from coin selection: they are baked into the mint parameters,
   and spending one means choosing a new input and re-applying every parameter that depends on it.
1. **Create GlobalState and both linked-list roots in one transaction.** Spend the three reserved
   one-shot inputs and mint the GlobalState NFT, power-users root NFT and denylist root NFT
   together. The GlobalState mint validator rejects genesis unless both root policies mint in this
   same transaction. Put the GlobalState NFT at `global_state_proxy` (the mint validator enforces
   this) with an inline `GlobalStateDatum` in exactly this field order: the core — 0 the hash of
   `global_state_logic`, 1 `deactivated = False`, 2 the admin credential, 3 the power-users list
   policy ID, 4 the initial minting-authority hash — then 5 `transfers_paused = False`, 6
   `mintable_amount` (the supply cap), 7 the denylist policy ID, 8 `security_info`, 9 the trusted
   entity keys, 10 `member_root_hash`, 11/12 the sender/receiver KYC flags, 13 the network ID and 14
   `upgrades_locked = False`. Put each root at its own list spend validator. Each list's `Init`
   rejects a root whose payment credential is not `Script(list_script_hash)`, the spend hash that
   list's mint was applied with. `Init` is gated only by the list's one-shot nonce,
   `init_input_out_ref`: it reads no GlobalState and needs no admin signature, so what forces the
   genesis wiring is the GlobalState mint's requirement above. That is safe because whoever creates
   a list's root gains no control over the list: every change to a list's contents is gated through
   GlobalState, by the GlobalState admin for the power-users list and by an `is_admin` power user
   under the current field 3 for the denylist. A new instance of either list, for `MigrateLists` to
   switch to, is created later with the same `Init`, from that list's mint applied with a fresh
   nonce, which gives it a new policy ID (see the [list-migration
   runbook](documents/integration-guide.md#migrating-the-lists)). The GlobalState mint also requires
   the withdraw-0 of the logic field 0 names: add it with a `GlobalStateSpendRedeemer` whose
   `global_state_output_index` points at the GlobalState output (its action is ignored at genesis);
   the logic accepts only a datum that names it and fits its own `max_global_state_datum_bytes`.
   Before signing, rebuild `global_state_logic` from source with every parameter to check field 0,
   which nothing on chain can bind to a hash, and re-derive both list policy IDs (fields 3 and 7)
   from their spend hashes: the mints pin each root on chain, but only to the hash they were applied
   with.
2. **Register the other logic scripts' stake credentials.** Register the minting proxy
   `minting_logic_validator` and current `minting_authority_validator` **before** the CIP-113
   registration, which invokes both as zero-value withdrawals. Register
   `transfer_logic_validator` and `third_party_transfer_logic_validator` before their first use.
   An unregistered withdrawal fails at ledger phase 1. Each script's `publish` handler accepts
   `RegisterCredential` and rejects deregistration.
3. **Assign power users** by inserting one node per operator, with the role flags needed for later
   actions. A `can_mint` operator must exist before the first issuance (step 5).
4. **Register in the CIP-113 registry.** Insert the node keyed by the issuance policy ID, naming
   the proxy, exactly the transfer and third-party transfer logic scripts the minting authority was
   built with (rows 8 and 9), and the GlobalState policy. The authority's `Register` needs the
   admin's signature; GlobalState is a reference input, never spent, and must not be deactivated.
   The insert runs the minting proxy and the authority. Under the issuance policy it mints nothing
   for a plain name and exactly the reference NFT for a CIP-68 name (see
   [CIP-68 metadata tokens](#cip-68-metadata-tokens)), and never supply.
5. **Mint the initial supply.** First issuance is a separate `MintBurn` once the node exists;
   this repository's `Register` refuses any supply, so a registry insert cannot carry one (the base
   layer alone would allow a first mint there). It spends GlobalState, and the minting authority's
   `MintBurn` debits the cap. This token's registry node is a reference input, because the base
   layer's issuance logic needs a registry proof; the minting proxy does not read it. Destinations
   must pass the denylist and the enabled KYC gates.

For the exact transaction shapes and index fields, follow the
[practical integration guide](documents/integration-guide.md#bootstrap-a-token).

From there the protocol is live: mint and burn, pause and unpause, force transfers, verify or
denylist holders, and add or modify power users.

## Token uniqueness

Uniqueness derives from the genesis UTxO. `tx0`/`index0` are applied to `global_state_mint_validator`,
which makes the GlobalState policy ID unique to that deployment; every other validator except the
unparameterised `global_state_proxy` takes that policy ID (directly or transitively) as a parameter.
The proxy's address is therefore shared by every deployment — locate GlobalState by its NFT. This means
each deployment compiles to different validator hashes — and therefore to a different security token
policy ID — even for identical source code. The policy ID follows from the genesis UTxO, through the
GlobalState policy ID the minting proxy takes, not from `security_asset_name`.

## How to retrieve information

For wallets and dApps reading protocol state:

1. Go to the CIP-113 registry and find the linked-list node with `key ==` this token's policy ID
2. Read its GlobalState field to identify the NFT holding the GlobalState datum
3. Find that UTxO and read the GlobalState datum for: pause and deactivation flags, remaining
   mintable amount, security info, the KYC requirement flags, the trusted entity keys, and the
   power-users and denylist linked-list policy IDs
4. To check whether a holder is frozen, look for a UTxO holding an NFT with `policy_id ==` the
   denylist policy ID and asset name `"Node"` ‖ the holder's 28-byte credential hash (the node
   datum carries no key — the key IS the asset name after the 4-byte `"Node"` prefix). **Presence
   means listed** —
   then read the entry's `frozen_amount`: `None` = fully frozen, `Some(f)` = partially frozen (the
   holder may send only what it holds above `f`). On chain, an unlisted holder proves absence with a covering-node
   proof, and a partially frozen one cites its own node
5. For operator roles, read the power-users list the same way; each node's datum carries that
   operator's role flags

---

## Authors

- **Matteo Coppola**, as part of the Finest team.
- **Giovanni Gargiulo**, Cardano Foundation
- **Thomas Kammerlocher**, Cardano Foundation
