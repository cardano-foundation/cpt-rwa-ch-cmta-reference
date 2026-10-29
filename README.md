# Programmable asset tokens on Cardano based on the CMTA framework

Aiken (Plutus V3) contracts providing on-chain primitives for programmable asset tokens   designed as reference profiles for use cases based on the CMTA framework and supporting the implementation of Swiss legal requirements. The primitives include KYC-gated transfers, denylisting, global pause, forced transfers and seizures, supply caps, role-based permissions, and an irreversible decommission mechanism.

The contracts build on CIP-113 (programmable tokens) by Michele Nuzzi, Matteo Coppola, Giovanni Gargiulo and Philip Di Sarro: [CIP-113](https://github.com/HarmonicLabs/CIPs/blob/master/CIP-0113/README.md) 

---

## Important note and disclaimer

The proposed profile draws on relevant Swiss requirements, translated technical standards and functional requirements developed by CMTA. 

The profile provides technical functionality only and is intended to support the implementation of certain features that may be relevant for legal or regulatory compliance under a certain jurisdiction. Its use does not imply, establish, or ensure compliance with any applicable legal or regulatory requirements. Each user is solely responsible for assessing the legal and regulatory implications of their specific implementation and/or use case and for ensuring it meets legal and regulatory requirements. It is strongly recommended to obtain appropriate professional advice where necessary.


---

### CMTA profile

Reflects technical requirements and functionalities defined by the CMTA Framework (Blockchain-agnostic functional specification of the CMTA token), providing a technical basis for implementations seeking to address relevant requirements under Swiss law. The framework defines 42 numbered functionalities `ABS-01…42`, of which **only `ABS-01…14` are mandatory**. CMTAT v3.2.0 (Solidity) serves as a semantic reference and technical reference for this profile, without implying full equivalence or conformity. The v3.2.0 release has not itself been fully audited; the latest fully audited release is v3.0.0.
The profile implements the relevant base and enforcement functionality of the CMTA Framework, covering supply and balance views (ledger-native on Cardano), transfer, mint, burn, pause/unpause and status, deactivate and status, and full-address freeze/unfreeze and status. Optional modules (snapshots, distributions, debt terms, delegated approval) are not implemented; EVM-specific machinery (allowance mechanic, gasless relaying, cross-chain, interface conformance) is not applicable on eUTxO.
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
[CIP-68 metadata tokens](#cip-68-metadata-tokens). For condition 4, the base-layer commit cited by the
audit report is `9db7e0629a1509cc9d41d069f0ef0ed251601173`.

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
| [`validators/global_state_logic.ak`](validators/global_state_logic.ak) | Replaceable GlobalState logic (the withdraw-0 script named by datum field 0) that controls the continuing state UTxO: remaining mintable supply, pause, KYC settings, trusted issuers, admin rotation, upgrades, logic rotation and deactivation. Its tests are in `global_state_logic_tests.ak`. |
| [`validators/power_users.ak`](validators/power_users.ak) | Maintains the operator linked list. The GlobalState admin grants or changes the six independent role flags. |
| [`validators/denylist.ak`](validators/denylist.ak) | Maintains the sanctions linked list. An `is_admin` power user can add or remove an entry; presence means sanctioned. |
| [`validators/minting_logic_script.ak`](validators/minting_logic_script.ak) | Permanent CIP-113 minting proxy. It reads GlobalState and requires the currently named minting authority to run. Its hash, applied to the base layer's issuance template, yields this token's issuance policy ID. |
| [`validators/minting_authority.ak`](validators/minting_authority.ak) | Replaceable authority for registration, mint, burn and registry-node upgrades. It checks supply-changing transactions against roles, destinations, the denylist and KYC. |
| [`validators/transfer_logic_script.ak`](validators/transfer_logic_script.ak) | Checks ordinary transfers for pause, deactivation, sender and receiver denylist absence, and enabled KYC gates. |
| [`validators/third_party_transfer_logic_script.ak`](validators/third_party_transfer_logic_script.ak) | Checks forced transfers: `can_force_transfer` authority and vetted destinations, while allowing a sanctioned or expired source and remaining available during a pause. |
| [`validators/approval_proxy.ak`](validators/approval_proxy.ak) | Permanent owner of every pending transfer of the [two-step transfer approval](#two-step-transfer-approval). Reads GlobalState field 0 from a reference input and requires that logic's withdraw-0 (`DelegateApproval`). |
| [`validators/approval_logic.ak`](validators/approval_logic.ak) | Replaceable approval rules named by GlobalState's `approval_logic_hash`: enforces the threshold, binds every new pending transfer and decides every settlement (the GlobalState admin or a `can_approve` operator approves, sender Cancels). |
| [`lib/types/`](lib/types/) | On-chain datum and redeemer schemas consumed by transaction builders, including GlobalState, operator roles and KYC proofs. |
| [`lib/kyc/verify.ak`](lib/kyc/verify.ak), [`lib/denylist/absence.ak`](lib/denylist/absence.ak), [`lib/compliance.ak`](lib/compliance.ak) | Verify attestations or membership proofs, prove denylist absence using a covering node, and apply those checks to each party. |
| [`lib/cip68.ak`](lib/cip68.ak), [`lib/constants.ak`](lib/constants.ak), [`lib/utils.ak`](lib/utils.ak) | Enforce metadata-token shape and provide shared protocol constants and transaction helpers. |

For transaction inputs, withdrawals and redeemer examples, see the
[practical integration guide](documents/integration-guide.md).

---

## Technical compliance status

The mandatory enforcement core is implemented and covered by the test suite: KYC-gated transfers
(sender and receiver, each independently toggleable), a sanctions denylist, global pause, forced
transfer, a supply cap, mint and burn, role-split operators, and an irreversible decommission
switch.

Optional CMTA modules — snapshots, distributions, debt terms, delegated approval — are **not**
implemented. An issuer-side **two-step transfer approval** above a configurable threshold is
implemented; see [Two-step transfer approval](#two-step-transfer-approval). EVM-specific machinery (the allowance mechanic, gasless relaying, cross-chain
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

Denylist entry metadata is also free-form `Data`, but each new entry is capped at 512 B once
CBOR-serialised. Larger case files, legal records, or evidence should live off-chain and be
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
  same document. Several further items were reviewed and deliberately left unchanged, with the
  reasoning under *Acknowledged, and deliberately not changed*. Still not a substitute for the
  third-party audit.
* **Third-party equivalency assessment** — an independent CMTAT mapping of this codebase is
  maintained at [CMTA/CMTAT-Cardano](https://github.com/CMTA/CMTAT-Cardano). Version 0.2.0 of that
  mapping is the pre-assessment the Expert Committee reviewed; it was filled against version 0.2.0 of
  CMTA's criteria, which have since been superseded.

---

## Actors

* **Admin** — the `admin_credential_hash` held in the GlobalState datum. Controls the power-user
  list itself (add, remove, modify), the security metadata, the remaining supply cap
  (`SetMintableAmount`, until `LockUpgrades`), the GlobalState logic itself
  (`RotateGlobalStateScript`, until `LockUpgrades`), and the irreversible deactivation switch. Rotatable, so the master key can be replaced without redeploying.
* **Power user** — a node in the power-users linked list, carrying independently grantable flags
  (a credential equal to GlobalState datum field 0, the GlobalState logic hash, is refused
  wherever the role is used — that logic's withdrawal is in every GlobalState transaction and
  would otherwise sign for it; `can_approve` needs no such check, since only a key signature
  counts for it):
  * `is_admin` — add and remove denylist entries. Deliberately split from the master admin key, so a
    compliance function can be delegated without handing over control of the protocol.
  * `can_mint` — mint new tokens, up to the remaining supply cap
  * `can_burn` — burn tokens, restoring headroom under the cap
  * `can_pause` — pause and unpause all standard transfers (each write must flip the flag)
  * `can_force_transfer` — seize tokens, moving them to a vetted address
  * `can_approve` — approve or reject pending transfers. **Key signature only**: unlike every other
    role, a script's withdrawal never counts, so granting it to a script hash grants nothing
* **Approver** — the GlobalState **admin**, or an operator holding `can_approve`. With [two-step
  transfer approval](#two-step-transfer-approval) on, either approves or rejects pending transfers;
  only the admin sweeps stray vault UTxOs. The approver's signature is the sanctions screen for a
  release, so protect `can_approve` keys like the admin key (hardware wallet).
* **Trusted entity** — an off-chain KYC attestor whose Ed25519 verification key is listed in the
  GlobalState datum. It signs the KYC proofs that transfers present. Not an on-chain role: it never
  submits transactions, it only signs attestations.
* **Holder** — any wallet or script holding the token. Must be absent from the denylist and, when
  the corresponding flag is set, must present a valid KYC proof (or prove membership of the
  allowlist tree).

## How it works

* An issuer initialises the protocol, then grants power-user flags to the operators who need them.
* Power users and denylist entries are each stored on-chain as a linked list; **presence in the
  denylist is the sanction** — there is no flag to toggle, and absence is proven with a covering-node
  proof.
* A transfer must clear the pause gate, then per sender and per receiver: denylist absence, plus a
  valid KYC proof whenever `requires_sender_kyc` / `requires_receiver_kyc` is set. The two are
  toggled independently.
* With [two-step transfer approval](#two-step-transfer-approval) switched on, a transfer above the
  configured threshold must first be parked at the vault and is delivered only by a second
  transaction signed by the admin or a `can_approve` operator.
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
* Minting is capped; burning returns headroom to the cap. The cap is remaining headroom, not total
  supply: until `LockUpgrades`, the admin may also reset it to any non-negative absolute value
  with `SetMintableAmount` (setting it below what is already minted simply stops further minting).
  There is no upper bound: off-chain readers must decode it as an arbitrary-precision integer. That action cannot share a transaction with a mint. **Burning existing supply spends a
  programmable-base UTxO, so the CIP-113 base layer makes the transfer logic run over it** — which
  means a burn during a pause, or from a sanctioned holder, must instead be routed through the
  forced-transfer path and needs `can_force_transfer`, not just `can_burn`.
* **Seizure is all-or-nothing per UTxO whenever the holder cannot clear the destination gates.**
  The base layer returns a partial seizure's residual to the holder's own address, and this
  deployment vets every token-bearing output as a destination — so the residual must itself prove
  denylist absence and, when `requires_receiver_kyc` is set, present a valid KYC proof. A sanctioned
  holder can do neither; **so can a holder whose attestation has simply expired**, which is the case
  that surprises operators. Drain whole UTxOs instead; a position can still be partially seized by
  choosing which UTxOs to spend. Both constraints are explained in
  [`documents/security/security-fixes.md`](documents/security/security-fixes.md).
* Deactivation is one-way and requires a paused protocol first — it is a decommissioning switch, not
  a stronger pause. **Dismantling the two linked lists (`Deinit`) is only possible afterwards**, and
  is equally irreversible: burning a list's root NFT can never be undone, because `Init` is gated on
  a genesis UTxO that has been spent and the list's policy id is immutable in the GlobalState datum.
  **Decommissioning has a required order** — sweep the GlobalState UTxO's surplus ADA, pause, empty
  the denylist, empty the power-users list, deactivate, then `Deinit` both lists. Each step becomes
  unavailable once a later one has happened: the deactivated GlobalState UTxO can never be spent
  again (so any ADA left on it is locked with it), and node removal is blocked after deactivation
  while `Deinit` requires an empty list. The full runbook and what each skipped step costs are in
  [`documents/security/security-fixes.md`](documents/security/security-fixes.md) §12.
* **Sanctions are single-signer and have no exempt list.** Any power user holding `is_admin` can
  denylist any address, including the admin's or another operator's. That freezes the address's
  *holdings*; it never touches anyone's *role*, since GlobalState actions do not consult the
  denylist. It is reversible in one transaction. If you want separation of duties here, that is a
  policy decision to make before launch.

### Upgrading and locking the rules

The GlobalState admin has three distinct upgrade paths, plus control over the supply cap, while
`upgrades_locked` is false:

* `RotateMintingScript` changes `minting_script_credential_hash` in GlobalState. The permanent
  minting proxy then requires the replacement authority's withdraw-0. The proxy checks delegation,
  not the new authority's mint, burn or registration rules; review and test the replacement before
  rotating. Register its stake credential before the first withdrawal. The outgoing authority does
  not have to consent.
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
* `RotateGlobalStateScript { new_global_state_script_hash }` replaces the GlobalState **logic**.
  The GlobalState NFT lives forever at `global_state_proxy`, a tiny spend validator that reads only
  datum field 0 (`global_state_script_credential_hash`) and requires that credential's withdraw-0;
  every GlobalState rule lives in the script field 0 names. Rotation rewrites field 0 and must run
  **both** logics in one transaction: the current one checks the admin signature, the lock, that the
  new hash is not the admin's or the minting authority's, and that the datum's frozen core (below)
  still decodes and is unchanged apart from field 0; the new one must run its own withdraw-0 with
  the same `RotateGlobalStateScript` redeemer — which proves its script is producible, its stake
  credential registered and that it decodes a GlobalState rotation, but **not** that it is a correct
  GlobalState logic — and checks the datum it is about to govern (this version accepts exactly the
  input with field 0 rewritten). **The new logic governs every
  later GlobalState action, the supply cap included** — rotating to a permissive script hands
  GlobalState to anyone, which is stronger than a permissive minting authority. Rotate only to a
  reviewed build of this repository: before signing, rebuild the new logic from source at a pinned
  commit with every parameter and check that its hash equals `new_global_state_script_hash` (do the
  same for field 0 before genesis). Everything after the frozen core is the incoming logic's to
  accept: this version accepts only field 0 rewritten, but a successor may also change tail values
  in the rotation transaction itself — the denylist policy ID, `network_id`, `transfers_paused` or
  `upgrades_locked` — so reviewing a successor includes reviewing what its incoming side accepts.
  One admin signature authorises a rotation. As with `RotateAdmin`, the old side authorises and the
  new side proves it is live — the new admin by signing, the new logic by running — but the logic
  is code the admin chose, so its run is not a second approval. For two-party control, make the
  admin a native-script multisig with a registered stake credential: a script admin signs through
  its own zero-value withdrawal. The NFT never moves, and
  readers find GlobalState by its NFT, never its address. The datum has a **frozen core and a free
  tail**. Fields 0–4 (logic hash, `deactivated`, admin, power-users list id, minting authority) are
  the only fields the scripts that can never be redeployed read after genesis; they keep their
  position and type forever. Fields 5+ belong to the installed logic: a new logic may drop, reorder,
  retype or append them (within `max_global_state_datum_bytes`). The replaceable readers (minting
  authority, transfer and third-party logic) decode the v1 tail, and would trap on or silently misread
  a different one, so before installing a logic that changes the tail, first rotate them to versions
  that accept **both** the current and the new layout: the authority through `RotateMintingScript`,
  then the transfer scripts through the new authority's `UpgradeRegistryNode`, then the GlobalState
  logic — all before `LockUpgrades`. The invariants every replacement logic must keep are listed in
  `validators/global_state_logic.ak`.

`RotateApprovalLogic { new_approval_logic_hash }` replaces the approval rules of the
[two-step transfer approval](#two-step-transfer-approval); it is closed by `LockUpgrades` like the
paths above. `SetApprovalRequired` and `SetApprovalThreshold` stay open after the lock.

`LockUpgrades` is an admin-signed, one-way GlobalState action that closes **all five** for later
transactions — after it, `mintable_amount` moves only through mint and burn and the GlobalState
logic can no longer be replaced. It does not deactivate transfers, minting or burning. If a registry upgrade is bundled
with the lock in one transaction, the upgrade reads the pre-lock GlobalState input and can still
succeed; audit the whole transaction when deciding which rules were locked. The same pre-state rule
applies to a registry upgrade bundled with admin rotation or deactivation.

The active authority and role credentials are part of the deployment's trust boundary. At genesis,
after each authority rotation, and after granting or rotating an operator role, test that an action
without that role's authorised signature is rejected. A permissive script credential used as a role
or minting authority can silently weaken the checks. See the
[integration guide](documents/integration-guide.md#upgrades-and-operator-checks) for an operator
checklist.

## Two-step transfer approval

An issuer can require that a holder's transfer is **approved on-chain before it reaches the
recipient**. Everything about it is configured in GlobalState, and its rules are replaceable without
moving a single pending transfer.

**The two steps.**

1. **Request** — the holder sends the tokens to the **vault**: the programmable-base address owned
   by the permanent [`approval_proxy`](validators/approval_proxy.ak)
   (`PLB + Inline(Script(approval_proxy))`), with an inline [`PendingTransfer`](lib/types/approval.ak)
   datum `{ sender, recipient, amount }`. The tokens never leave the programmable base: the proxy is
   simply another owner, which the CIP-113 base layer authorises by its withdraw-0.
2. **Decision** — per pending transfer:
   * **Approve** (GlobalState admin or a `can_approve` operator) — every token, and at least the
     lovelace, go to `recipient`;
   * **Reject** (GlobalState admin or a `can_approve` operator) — back to `sender`;
   * **Cancel** (sender, at any time, without the admin and whatever the switch says) — back to
     `sender`. A Cancel that returns tokens runs the transfer logic, so it waits out a pause, needs
     the sender to pass the denylist (and receiver KYC, if required) as the payee, and stops at
     deactivation.

The paid-out output carries no datum and sits at the programmable base. Several decisions can share
one transaction; each pending transfer names its own output, at strictly increasing indices. "At
least the lovelace" lets the settler top up if the minimum-ADA requirement has risen since the
request.

**What it is configured by** — three GlobalState tail fields, each changed by an admin-signed
action:

| Field | Action | After `LockUpgrades` |
|---|---|---|
| `approval_required` — the switch | `SetApprovalRequired` (must flip) | open — switching off is the way out if the installed approval logic cannot run; it releases nothing pending |
| `approval_threshold` — largest net movement without approval, base units; `0` = all | `SetApprovalThreshold` (`>= 0`) | open |
| `approval_logic_hash` — the replaceable rules | `RotateApprovalLogic` | **closed** |

**What needs approval.** With the switch on, a transaction that spends a holder's tokens may move at
most `approval_threshold` of them, **net**, to other credentials. Per credential, the gain is what
outputs give it minus what its own inputs held; the movement is the sum of the positive gains.
Change back to the sender nets to zero, and a recipient that adds an input of its own gains just as
much. Sending to the vault is the approval route and is not counted. **With the switch off,
transfers behave as before and no security token can be sent to the vault** (pending transfers created while
it was on still settle).

**Who decides.** [`approval_logic`](validators/approval_logic.ak) holds **every** approval rule; the
transfer logic only skips the vault as a party, refuses vault outputs while the switch is off, and
— while it is on — requires the withdraw-0 of the approval logic GlobalState names in **every**
transfer. The approval logic also runs in every settlement, through this chain:

```
vault UTxO spent → approval_proxy (permanent) → GlobalState logic, action DelegateApproval
                 → approval_logic named by approval_logic_hash
```

On every run it reads GlobalState (admin, switch, threshold), enforces the **threshold**, refuses
**mixing** (a holder's token input never shares a transaction with a vault input), **binds** every new
pending transfer (sender = the transaction's only holder, `amount` = the security quantity held,
nothing else beside it but ADA) and **settles** every pending transfer spent — Approve and Reject
need the GlobalState admin's signature or a `can_approve` operator's KEY signature (its power-user
entry, still in the list, named by the redeemer), Close the admin's, Cancel only the sender's. It
runs only while it is the installed logic. To change the rules, compile a new instance and
`RotateApprovalLogic`; to change the approvers, `RotateAdmin` or grant/revoke `can_approve` in the
power-user list (a revoked operator's next approval fails at once). Pending transfers follow,
because the proxy that owns them delegates to whatever GlobalState names. The transfer logic and
the approval logic both recognise a pending transfer by its owner alone (stake credential
`Script(approval_proxy)`); the CIP-113 base layer keeps every token at the programmable base.

**Compliance.** The vault is no party: the transfer logic never KYC- or denylist-checks it. At the
request it vets the holder as the sender; the recipient is vetted only when it is paid, at
settlement. **The original sender is not re-vetted at settlement** — the signature of the admin or
of a `can_approve` operator is the sanctions screen for a release (owner decision, 2026-10-27; the
operator role 2026-10-28): screen the sender before signing an Approve. Pause and deactivation
apply to both steps.

**Why GlobalState is never spent in a settlement.** The proxy requires GlobalState as a reference
input and refuses any transaction in which an input holds the GlobalState NFT. In a transaction that
spends GlobalState — `MintSecurity` above all — the GlobalState logic's withdrawal is present under a
spend redeemer, and the approval would be skipped. The consequence: a settlement can never share a
transaction with any action that spends GlobalState — a mint, a burn or a GlobalState admin action.
(Power-user and denylist changes read GlobalState only and are unaffected.)

**Free credentials.** Anyone can make the withdrawals of `approval_logic`, `approval_proxy` and the
GlobalState logic appear in a transaction (an ADA-only vault UTxO and its Cancel is enough). So none
of them may ever be the admin, the minting authority, an operator or the approval logic, and nothing
of this policy should be owned by one:

* every writer of fields 0, 2 and 4 and of `approval_logic_hash` keeps the approval logic and the
  proxy distinct from the GlobalState logic, the admin and the minting authority wherever it can see
  the pair (the admin and the minting authority are not checked against each other);
* `PauseTransfers` and mint/burn refuse an operator equal to any of them; seizure refuses only the
  GlobalState logic. **The denylist and seizure do not check the approval logic or the proxy**, so
  never grant `is_admin`, `can_force_transfer` (or any role) to the approval logic's or the proxy's
  hash;
* the mint path refuses them as owners of the security token (and of the CIP-68 token at
  registration). Seizure and mint also refuse
  the vault itself as a destination: neither runs the approval logic, so their vault outputs would
  be unbound;
* **holder transfers and seizure do not check owners** (owner decision 2026-10-27): tokens a holder
  or an operator sends to the GlobalState logic or the approval logic can be taken by anyone who
  passes the recipient checks, and a CIP-68 metadata token sent to the vault (whatever the switch
  says) can never leave it. Both only lose the sender's own tokens; wallets and the operator tooling must
  refuse these destinations. With receiver KYC on, no attestation exists for them, so such a
  transfer fails anyway;
* the transfer logic does not check that `approval_logic_hash` differs from its own hash or the
  proxy's. The proxy case is refused by every GlobalState writer and by `DelegateApproval`; the
  transfer-logic case is the deployment requirement below. Seizure checks neither an operator
  equal to the current or a retired approval logic, nor one equal to the proxy: such an operator
  could be impersonated by anyone on the seizure path.

**Treat every approval logic ever installed as a free credential.** A retired one does not run (it
checks that GlobalState names it), but its stake credential can never be deregistered, the checks
compare against the current one only, and a successor without that check — or a rotation back —
frees it again. Never send tokens to, or grant a role to, a retired approval-logic hash.

> **Deployment requirement, not enforceable on-chain:** `approval_logic_hash` must name an
> `approval_logic` compiled with **every** parameter of this deployment (row 11 of the parameter
> table): the `approval_proxy` hash, the GlobalState policy ID, the power-user list script hash,
> the issuance policy ID, the security asset name and a `close_payout` you control. Only
> `close_payout` is checked on-chain; a wrong proxy hash, policy ID or asset name passes every run
> and switches the gate off. It is the **only** place the threshold is enforced: a logic that skips
> it switches the threshold off. Never the transfer logic, the third-party logic, the minting proxy
> or authority, a base-layer delegate, or any script whose withdraw-0 passes without the admin.
> After every rotation, and before `LockUpgrades`, smoke-test: a settlement **without** the admin
> is rejected; spending a pending transfer with **no** action is rejected; Approve, Reject and Close
> **with** the admin and Cancel **with** the sender are accepted; a holder transfer **above** the
> threshold is rejected and one **within** it accepted; a `can_approve` operator's Approve is
> accepted with its key signature and rejected with only a withdrawal of its hash. Rotate only to a
> fresh hash, and record every retired one (see *Free credentials*). On a live deployment, rotate
> the approval logic **before** the transfer logic: the new transfer logic no longer enforces the
> threshold itself.

**Limits to plan around:**

* **Splitting.** The threshold applies per transaction. Splitting a large transfer into several
  below it is not prevented; that needs per-holder state over time and is not implemented.
* **The register.** While a transfer is pending, the on-chain owner is the proxy; the legal holder is
  the datum's `sender`. Attribute vault UTxOs that hold the token to their `sender`, and ignore vault
  UTxOs that hold none (anyone can pay ADA to the vault address).
* **Seizure of a pending transfer is whole-UTxO only.** Drain it, sending the court-ordered part to
  its destination and the remainder to the `sender`, in one transaction; the token-free residual is
  closed by the sender's Cancel. If the sender is sanctioned, the remainder cannot go back to them,
  so the UTxO is seized whole or not at all — as with any sanctioned holding.
* **Liveness.** If the sender is denylisted while a request is pending, Reject and Cancel fail (the
  sender is vetted as the payee); the admin or a `can_approve` operator may still Approve — screen
  before signing — or an operator may seize. If the recipient's KYC lapses, Approve fails and the
  admin or a `can_approve` operator Rejects. Deactivation freezes pending
  transfers like every other holding.
* **GlobalState-logic successors** must keep `DelegateApproval` (invariant 12 in
  [`global_state_logic.ak`](validators/global_state_logic.ak)); one without it freezes every pending
  transfer until rotated back (seizure is the only other exit). Switch approval off and let pending
  transfers drain before rotating the GlobalState logic.
* **Clean-up.** A vault UTxO that holds only lovelace and whose datum is not a `PendingTransfer` can
  be swept by the admin (`Close`) to the approval logic's `close_payout` address.
* **`PendingTransfer` is frozen in practice**: every approval logic must settle what earlier ones
  bound. Changing it means draining every pending transfer first. The transfer logic never reads it.
* **GlobalState tail layout.** The approval logic reads `approval_required`, `approval_threshold` and
  `approval_logic_hash`; a GlobalState logic that reshapes those fields must rotate it in lockstep.
* **Cost.** With the switch on, every transfer runs the approval logic as well.

## Building the scripts

Requires Aiken **v1.1.23**, pinned in [`aiken.toml`](aiken.toml) and matched by CI.
Both linked lists are built on `anastasia-labs/aiken-design-patterns` **v1.8.0**.

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

* **`registry_policy_id`** — the CIP-113 registry mint policy id.
* **The issuance template** — `prefix_cbor_hex` and `postfix_cbor_hex` from the base layer's
  `IssuanceCborHex` datum (the reference UTxO carrying its `IssuanceCborHex` NFT). Applied to the
  minting proxy's hash (row 6) it yields this token's issuance policy ID; see
  [What the derived parameters must equal](#what-the-derived-parameters-must-equal).

**`plb_script_hash`** — the CIP-113 programmable-logic-base (PLB) script hash — is the address of
every programmable-token UTxO. Only `approval_logic` takes it as a compile-time parameter, to
recognise pending transfers by their exact address; the other validators rely on the base layer's
own custody guarantees for mint, ordinary transfer and seizure (see
[What is delegated to the CIP-113 base layer](#what-is-delegated-to-the-cip-113-base-layer)).

### Parameter order

Parameters have to be applied in dependency order — GlobalState proxy → GlobalState policy → the two lists →
the minting-logic proxy → the rest — because each layer's policy ID or script hash feeds later
validators. The table below is exhaustive and lists, for every validator, its parameters in the
exact order the blueprint (`plutus.json`) declares them; apply top to bottom.

> `aiken blueprint apply` takes parameters **positionally, one at a time**, and shared parameters
> are **not** in a shared order across validators — e.g. row 7 (`global_state_logic`)
> lists the issuance policy id before `global_state_policy_id`, while rows 8–10 list
> `global_state_policy_id` first. Always follow this validator's own row below; never assume a
> "usual" order.

| # | Validator | Parameters (blueprint order) | Source |
|---|---|---|---|
| 0 | `global_state_proxy.global_state_proxy` (spend) | — | No parameters: its hash is the same for every deployment. |
| 1 | `global_state.global_state_mint_validator` (mint) | `tx0`, `index0`, `global_state_proxy_hash`, `max_global_state_datum_bytes` | The genesis UTxO you choose to spend; the hash of `global_state_proxy` (row 0). The NFT must be minted to that script address; the datum-size cap (recommended 8192, **same value as row 7** — nothing on chain ties the two). |
| 2 | `power_users.mint` | `global_state_policy_id`, `init_input_out_ref` | Row 1; a genesis UTxO reserved for this list. |
| 3 | `power_users.power_users_validator` (spend) | `global_state_policy_id`, `power_users_linked_list_policy_id` | Row 1; the hash of `power_users.mint` (row 2) — this is the **power-users policy ID**. |
| 4 | `denylist.mint` | `global_state_policy_id`, `init_input_out_ref`, `power_user_list_script_hash` | Row 1; a genesis UTxO reserved for this list; the hash of `power_users_validator` (row 3, **spend** — not row 2's policy id). |
| 5 | `denylist.denylist_validator` (spend) | `denylist_linked_list_policy_id` | The hash of `denylist.mint` (row 4) — this is the **denylist policy ID**. |
| 6 | `minting_logic_script.minting_logic_validator` | `global_state_policy_id` | Row 1. Its only parameter. |
| 6a | `approval_proxy.approval_proxy` (withdraw) | `global_state_policy_id` | Row 1. Its hash is the **approval proxy hash**; the vault address is `PLB + Inline(Script(<this hash>))`. |
| 7 | `global_state_logic.global_state_logic` (withdraw) | `security_asset_name`, `issuance_policy_id`, `global_state_policy_id`, `power_user_list_script_hash`, `max_global_state_datum_bytes`, `approval_proxy_hash` | Operator choice; the **issuance policy ID**, i.e. the security token's policy ID, derived from row 6's hash (see below; **not** row 6's hash itself); row 1; the hash of `power_users_validator` (row 3); the datum-size cap (same value as row 1; a rotated-in logic may choose another); row 6a's hash. Its hash goes into GlobalState datum **field 0** at genesis. |
| 8 | `transfer_logic_script.transfer_logic_validator` | `security_asset_name`, `global_state_policy_id`, `expected_issuance_policy_id`, `denylist_script_hash`, `approval_proxy_hash` | Operator choice; row 1; the issuance policy ID (as row 7); the hash of `denylist_validator` (row 5); row 6a's hash. |
| 9 | `third_party_transfer_logic_script.third_party_transfer_logic_validator` | `security_asset_name`, `global_state_policy_id`, `expected_issuance_policy_id`, `denylist_script_hash`, `power_user_list_script_hash`, `approval_proxy_hash` | Operator choice; row 1; the issuance policy ID (as row 7); row 5's hash; row 3's hash; row 6a's hash. (The power-users policy id is read from the GlobalState datum at run time, not compiled in.) |
| 10 | `minting_authority.minting_authority_validator` | `security_asset_name`, `global_state_policy_id`, `registry_policy_id`, `minting_logic_script_credential_hash`, `expected_issuance_policy_id`, `denylist_script_hash`, `power_user_list_script_hash`, `transfer_logic_script_hash`, `third_party_transfer_logic_script_hash`, `approval_proxy_hash` | Operator choice; row 1; Prerequisites; row 6's hash; the issuance policy ID (as row 7 — it **differs** from row 6's hash, see below); row 5's hash; row 3's hash; row 8's hash; row 9's hash (the scripts registry fields 3 and 4 must name); row 6a's hash. The power-users policy id is read from the GlobalState datum at run time, not compiled in. |
| 11 | `approval_logic.approval_logic` (withdraw) | `approval_proxy_hash`, `global_state_policy_id`, `power_user_list_script_hash`, `issuance_policy_id`, `security_asset_name`, `close_payout` | Row 6a's hash; the GlobalState NFT policy ID; the power-user list's spend script hash (as seizure's — a wrong value only shuts the operator path off); the issuance policy ID (as row 7); as row 7; the address `Close` pays stray lovelace to. Its hash goes into GlobalState's `approval_logic_hash` at genesis and on every `RotateApprovalLogic`. |

### What the derived parameters must equal

* `power_user_list_script_hash` — the hash of `power_users.power_users_validator` (the **spend**
  validator), **not** `power_users.mint`'s policy id.
* `denylist_script_hash` — the hash of `denylist.denylist_validator` (**spend**), **not**
  `denylist.mint`'s policy id.
* `power_users_linked_list_policy_id` / `denylist_linked_list_policy_id` — the respective `mint`
  validator hashes (their policy ids).
* `minting_logic_script_credential_hash` — the hash of `minting_logic_script.minting_logic_validator`
  (row 6), the permanent minting proxy.
* `issuance_policy_id` (row 7) and `expected_issuance_policy_id` (rows 8–10) — the security token's
  policy ID, which is the base layer's issuance template applied to the proxy:
  `blake2b_224(0x03 ‖ prefix_cbor_hex ‖ proxy hash ‖ postfix_cbor_hex)`, with the template from
  Prerequisites. It is the key of this token's CIP-113 registry node, and it is **never** the proxy
  hash itself. A deploy script should derive it this way and assert it differs from
  `minting_logic_script_credential_hash`: the authority's registration fails closed on a wrong value,
  but the GlobalState and transfer scripts cannot detect one — a transfer logic built with the wrong
  policy ID finds no parties and skips the denylist and KYC checks for every transfer.
* `transfer_logic_script_hash` and `third_party_transfer_logic_script_hash` (row 10) — the hashes of
  rows 8 and 9, in that order. Registration and every `UpgradeRegistryNode` require registry fields 3
  and 4 to name exactly these (F08), and the two must differ. The pin is only as good as row 10's
  build: assert the order in the deploy script, and include "a seizure without a
  `can_force_transfer` operator is rejected" in the post-deploy smoke test.
* `approval_proxy_hash` — the hash of row 6a, **identical** in rows 7–11. A mismatch fails closed
  for transfers that create or settle a pending transfer in rows 7, 8 and 11, but would silently
  leave the vault unprotected on the seizure (row 9) or mint (row 10) path; assert all five
  off-chain.
* `approval_logic_hash` (GlobalState tail) — the hash of row 11, never equal to field 0, the admin,
  the minting authority or the approval proxy (genesis, the GlobalState logic and every writer check
  the pairs they can see). See the deployment requirement under
  [Two-step transfer approval](#two-step-transfer-approval).
* `security_asset_name` — an operator choice, with one constraint: it must **not** carry a protected
  CIP-67 prefix (see [CIP-68 metadata tokens](#cip-68-metadata-tokens)). Registration asserts this
  and fails closed if it is violated, because a protected supply name would make every rule meant
  for metadata fire on the supply itself. Follow the CIP-68 label convention and the constraint is
  automatic: `(333)` or `(444)` for the security token, never `(100)`.
* There is **no** `reference_asset_name` parameter. The CIP-68 token is identified by its label
  prefix, not by an exact name, so nothing has to be configured per deployment and no two validators
  can drift apart on it.
* `tx0` / `index0` / `init_input_out_ref` — one-shot genesis UTxOs, each spent once during
  initialisation (see [Initialising a token](#initialising-a-token)).

### Deployment: reference scripts

Seven validators are withdraw-0 scripts, i.e. they run as zero-value withdrawals rather than as the
spending or minting script of any UTxO: `global_state_logic` (every GlobalState action — the proxy
holding the NFT requires it), `transfer_logic_validator` (~6.8 KB, every transfer),
`third_party_transfer_logic_validator` (~7.1 KB, every seizure), `minting_authority_validator`
(~9.3 KB, every mint and burn) and the minting proxy `minting_logic_validator` (~1.0 KB, also every
mint and burn — the proxy's withdraw-0 is what the CIP-113 registry node invokes, and it in turn
requires the authority's), the approval proxy `approval_proxy` (~1.0 KB, every settlement of a
pending transfer) and `approval_logic` (~3.1 KB, every request and settlement). The four large ones (`global_state_logic` is ~5.9 KB and runs in every
mint and burn too) must be published once as reference-script UTxOs and
supplied via reference inputs — not inlined (a transaction is capped at 16 KiB); the proxy is small
enough to inline but is simplest to publish alongside them. The two list `mint` validators
(~5.2–5.8 KB) must be treated the same way: the genesis transaction runs both, the GlobalState
mint and `global_state_logic` — ≈ 19.3 KB of scripts against the 16 KiB limit — so publish them
and `global_state_logic` before genesis (step 0 of [Initialising a token](#initialising-a-token)).

All seven withdraw-0 scripts need their **stake credential registered** on chain before the first
transaction that names them in `withdrawals` — see steps 0 and 2 of [Initialising a token](#initialising-a-token).
A withdrawal from an unregistered credential is rejected by the ledger at phase 1, before any script
runs, so forgetting the proxy's registration makes every mint and burn fail from genesis on.

> **The list SCRIPT hashes are not the list POLICY IDs.** Each list file declares a `mint` validator
> and a separate spend validator, so their hashes differ. Passing a policy ID where a script hash is
> expected disables the check silently — every element read would reject, and the protocol would be
> inert rather than insecure, but it would be inert *quietly*.

> **Verify before genesis, off-chain:** that the two linked-list policy IDs differ and each matches
> the corresponding compiled `mint` validator hash, and that datum field 0 is the hash of
> `global_state_logic` rebuilt from source with this deployment's parameters. The on-chain code
> checks what it can (the IDs must differ and be 28 bytes; the NFT must land at
> `global_state_proxy`; field 0 must be 28 bytes, differ from the admin, the minting authority and
> the proxy, and run in the genesis transaction, where this logic accepts only a datum that names
> it and fits its own cap; each list's `Init` requires the GlobalState minted alongside to name
> that list's policy id) but cannot bind field 0 to a hash: field 0 depends on the GlobalState
> policy, which depends on the mint's own parameters. A field 0 that cannot run now fails genesis;
> one that runs and accepts it — another validator, or this logic applied with a wrong parameter —
> still gets through and then governs GlobalState. Smoke-test one GlobalState action right after
> genesis. The power-users policy ID (field 3) is the only anchor for which list's nodes are
> operators: the minting authority, the denylist, seizure and `PauseTransfers` authenticate
> them under it, with no compile-time copy, so a wrong field 3 hands those roles to whoever
> controls that policy.

### What is delegated to the CIP-113 base layer

This deployment's own scripts do not re-check everything the CIP-113 base layer already enforces
independently. In plain terms, the base layer guarantees:

* **Custody on mint.** `issuance_mint`'s `no_escape` rule keeps every newly minted token inside the
  programmable base and forces an inline stake credential onto every programmable-base output.
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
  and `minting_logic_script` frozen.
* **No supply change on an upgrade.** `registry_spend` hoists
  `!mint_has_policy(self.mint, spent_node.key)` above its `when`, so it covers both the in-place
  update and the covering-node spend: a transaction that spends a registry node can never mint or
  burn that node's own token. An upgrade can change transfer-logic rules; it can never touch supply.
* **Which registry node gets to invoke a logic script.** The base layer authenticates the registry
  node it uses to dispatch to a logic script's withdraw-0.

Because of the registry-dispatch point, this deployment's transfer, seizure and mint/burn logic no
longer read or re-derive a registry node at all on those paths — the issuance policy each one polices
is pinned at compile time instead. Because of the three custody points, none of the mint,
ordinary-transfer or seizure paths re-check programmable-base custody themselves any more; all three
rely on the base layer's own guarantees. And because of the no-supply-change point, the upgrade path
no longer re-checks that a spend-and-update transaction mints or burns nothing; it relies on
`registry_spend` alone.

These guarantees were verified against CIP-113 base-layer commit `018415d`, and **re-verified on
2026-08-28 against that repository's `main` at `9db7e06`** — all of them still hold. Upgrading the
deployed base layer invalidates that verification and requires re-checking it before relying on this
section again; record the commit you checked against alongside the deployment parameters.

Three things a redeploy onto a base layer at `9db7e06` or later must account for, none of which
changes the guarantees above:

* **Dispatch is per input.** The base spend validator reads the live transfer / third-party /
  unfracking credentials from the coordination datum and requires the witnessed one's withdraw-0
  (`SpendViaTransfer` / `SpendViaThirdParty` / `SpendViaUnfracking`). Transaction shape and base-layer
  redeemers change; this repo's validators do not.
* **Programmable-base outputs must stay seizable**, and their inline datums are size-bounded by a
  protocol parameter (`max_inline_datum_bytes`). The only datum this deployment puts on a token UTxO
  is the CIP-68 reference NFT's metadata — check the deployed bound before publishing it.
* **The coordination UTxO's upgrade authority is part of this token's trust boundary.** Whoever holds
  it can re-point the base layer's transfer and third-party validators in place, which would bypass
  every gate here at once. Record who holds it, and monitor the coordination datum.

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
only safe if such a token can never be moved *like* value — which is what the protected-prefix rules
enforce.

**The protected prefix.** `constants.cip68_protected_prefix` is the CIP-67 asset-name label that marks
a token as metadata: `(100)` = `#"000643b0"`. A name under the issuance policy carrying it is
*protected*. One prefix, not a list — `(100)` is the only CIP-68 label that denotes a metadata token,
so the set is closed at one and the check is a single comparison rather than a fold.

The user-token labels — `(222)` `#"000de140"`, `(333)` `#"0014df10"`, `(444)` `#"001bc280"` — must
never be protected. The security token carries one of them, and protecting it would refuse every
seizure and every ordinary transfer. Registration asserts that `security_asset_name` does not carry
the protected prefix, so that misconfiguration fails closed at the one moment it is still cheap to
catch.

Three rules follow, and together they are an invariant rather than a posture at genesis:

1. **At most one metadata token, minted once.** Only `RegisterMint` may mint a protected name, at
   quantity exactly one, and at most one protected name per transaction. Steady-state mint and burn
   refuse protected names outright, so a metadata token cannot be re-minted after the token is live.
2. **Its UTxO holds ADA plus that token, and nothing else.** Checked when it is minted, and re-checked
   on **every later move** by the transfer logic — because the transfer path is how a metadata update
   happens. The datum must decode as CIP-68's `Constr 0 [metadata, version, extra]`; the contents are
   not interpreted. The owner is the output's inline stake credential and may be a separate metadata
   authority from the GlobalState admin.
3. **The seizure path may not touch it.** A forced transfer is refused outright if any input carries a
   protected token. Seizure moves value; metadata is out of its reach, so a `can_force_transfer`
   operator cannot carry the token's metadata authority away under cover of an ordinary seizure.

A metadata update is therefore the metadata authority spending that UTxO — an ordinary CIP-113
owner-consent transfer — and re-outputting the token with a new inline datum, in the same shape.
Updates pass through the transfer logic's gates, so they are blocked while transfers are paused and
after deactivation.

Operational rules:

* Follow the CIP-68 label convention: `(100)` for the metadata token, `(333)` or `(444)` for the
  fungible security token. Rule 1 and the registration assertion both depend on it.
* A deployment that wants no metadata token simply never mints one — there is nothing to configure.
* `RotateAdmin` does not rotate metadata custody. If the metadata authority should change, the current
  owner transfers the metadata token to the new authority with an ordinary owner transfer.
* The metadata token cannot be burned. It is minted once and no branch burns it, so decommissioning
  leaves it in the metadata authority's custody.
* On a base layer at `9db7e06` or later, its inline datum must fit `max_inline_datum_bytes` (see
  [What is delegated to the CIP-113 base layer](#what-is-delegated-to-the-cip-113-base-layer)).

### Execution budget and transaction sizing

Figures below are measured with `aiken bench` (`aiken bench -m "transfer_logic_script.{..}"
--max-size 40`; the per-test execution units `aiken check` prints are the other source) against the
current, cost-optimised implementation. They are for this deployment's scripts alone — the CIP-113
base layer shares the same per-transaction budget, 10 000 M CPU / 14 M memory, and **memory is the
binding axis**.

* **Ordinary transfer**, denylist-only, one sender and one destination: ≈ 0.61 M mem / 0.18 G CPU.
  Each further party on a side that cites the same denylist covering node as the party before it
  adds ≈ 0.10 M mem / 33 M CPU — the node is authenticated once per run of adjacent parties citing
  it; a party citing a different node pays the full authentication, ≈ 0.15 M mem / 45 M CPU. The
  dedupe check adds a small quadratic term that matters only beyond ~20 parties per side.
* **Attestation KYC** (a trusted issuer signs the claim through CIP-30 `signData`, including
  Ledger's CIP-8 hashed mode) adds ≈ 76 K mem / 80.5 M CPU per vetted party (measured on the transfer
  fixture with and without the proof checked): the transaction builder
  extracts the COSE parts off chain, and the validator only rebuilds the COSE `Sig_structure` and
  verifies one Ed25519 signature (plus one BLAKE2b-224 when hashed). Membership (MPF) proofs are
  cheaper. A raw Ed25519 signature over the bare claim was supported until 2026-10-15 and is no
  longer accepted; it cost ≈ 20 K mem / 7.5 M CPU and ≈ 47 bytes less per proof. An earlier
  revision parsed the full COSE objects on chain at +3.5 KB per script and ≈ 300 K mem / 92 M CPU
  per proof; the lean form checks everything that matters for authorisation and nothing else (see
  the integration guide).
* **Forced transfer** ≈ 0.60 M mem / 0.18 G CPU with one destination, ≈ 0.10 M mem / 32 M CPU per
  further destination sharing a node.
* **Two-step approval** (per-test figures from `aiken check`; the base layer's own cost comes on
  top): a request with the switch on ≈ 1.20 M mem / 0.37 G CPU in the transfer logic plus
  ≈ 0.33 M mem / 0.12 G CPU in `approval_logic`; a settlement adds `approval_proxy`
  (≈ 0.16 M mem / 51 M CPU), the GlobalState logic's `DelegateApproval` and `approval_logic`
  (≈ 0.39 M mem / 0.14 G CPU for one decision, ≈ 0.67 M / 0.24 G for two) to the transfer logic's
  run. An ordinary transfer on this branch measures ≈ 0.75 M mem / 0.23 G CPU.
* **Redeemer size** ≈ 20 B per party without KYC and ≈ 230 B with an attestation proof made by a
  wallet (its ≈ 45-byte protected header names the signing address); a backend issuer's minimal
  3-byte header brings it to ≈ 190 B. Measured with `serialise_data` on a transfer action.

`aiken bench -m "transfer_logic_script.{..}" --max-size 40` scales linearly in `n` on both benches
(`transfer_cost_by_party_count`: `n` senders + `n` destinations, denylist-only, root-only covering
node; `seizure_cost_by_destination_count`: one seized input, `n` destinations, denylist-only):

| n | transfer mem | transfer CPU | seizure mem | seizure CPU |
|---:|---:|---:|---:|---:|
| 1 | 694,134 | 207,875,081 | 692,317 | 209,306,067 |
| 4 | 1,347,964 | 414,369,677 | 992,220 | 304,515,714 |
| 8 | 2,278,308 | 742,662,445 | 1,421,376 | 457,945,230 |
| 16 | 4,417,204 | 1,595,793,773 | 2,418,792 | 863,077,158 |

> **Conservative maxima, at 25% of the budget:** ordinary transfer ≤ 12 unique parties per side
> denylist-only, ≤ 8 per side with attestation KYC on both sides; seizure ≤ 23 destinations
> denylist-only, ≤ 15 with receiver KYC. The KYC figures add ≈ 76 K memory per attestation proof to
> the benches above. Split larger distributions; keep parties that share a
> covering node adjacent in the action lists — they follow input/output order.

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
   deployment's parameters (its `publish` handler accepts `RegisterCredential`), and publish it
   and both list `mint` validators as reference-script UTxOs: the genesis transaction runs those
   three and the GlobalState mint, ≈ 19.3 KB of scripts, which cannot all be inlined under the
   16 KiB transaction limit. No transaction before genesis may spend one of the three reserved
   one-shot inputs, so exclude them from coin selection: they are baked into the mint parameters,
   and spending one means choosing a new input and re-applying every parameter that depends on it.
1. **Create GlobalState and both linked-list roots in one transaction.** Spend the three reserved
   one-shot inputs and mint the GlobalState NFT, power-users root NFT and denylist root NFT
   together. The GlobalState mint validator rejects genesis unless both root policies mint in this
   same transaction. Put the GlobalState NFT at `global_state_proxy` (the mint validator enforces
   this) with an inline `GlobalStateDatum` in exactly this field order: the frozen core — 0 the hash of
   `global_state_logic`, 1 `deactivated = False`, 2 the admin credential, 3 the power-users list
   policy ID, 4 the initial minting-authority hash — then the v1 tail: 5 `transfers_paused = False`,
   6 the supply cap, 7 the denylist policy ID, 8 `security_info`, 9 the trusted entity keys,
   10 `member_root_hash`, 11/12 the sender/receiver KYC flags, 13 the network ID,
   14 `upgrades_locked = False`, then the approval fields: 15 `approval_required`, 16
   `approval_threshold` (`>= 0`) and 17 `approval_logic_hash` (the hash of row 11; never field 0,
   the admin, the minting authority or the approval proxy). Put each root at its own list
   spend validator. Each list's `Init` rejects a GlobalState datum that does not name it. The
   GlobalState mint also requires the withdraw-0 of the logic field 0 names: add it with a
   `GlobalStateSpendRedeemer` whose `global_state_output_index` points at the GlobalState output
   (its action is ignored at genesis); the logic accepts only a datum that names it and fits its
   own `max_global_state_datum_bytes`. Verify the two list addresses off-chain, and rebuild
   `global_state_logic` from source with every parameter to check field 0, before signing; the
   mint validators cannot pin them at genesis.
2. **Register the other logic scripts' stake credentials.** Register the minting proxy
   `minting_logic_validator` and current `minting_authority_validator` **before** the CIP-113
   registration, which invokes both as zero-value withdrawals. Register
   `transfer_logic_validator` and `third_party_transfer_logic_validator` before their first use,
   and `approval_proxy` and `approval_logic` before the first pending transfer (requests need the
   logic, settlements the proxy).
   An unregistered withdrawal fails at ledger phase 1. Each script's `publish` handler accepts
   `RegisterCredential` and rejects deregistration.
3. **Assign power users** by inserting one node per operator, with the role flags needed for later
   actions. A `can_mint` operator must exist before a registration that mints initial supply.
4. **Register in the CIP-113 registry.** Insert the node keyed by the issuance policy ID, naming
   the proxy, exactly the transfer and third-party transfer logic scripts the minting authority was
   built with (rows 8 and 9), and the GlobalState policy. Use
   `RegisterStructural` with no issuance-policy mint, or use `RegisterMint` if minting the initial
   supply in this transaction.
5. **Mint the initial supply**, unless it was minted with `RegisterMint` in step 4. `MintBurn`
   spends GlobalState to decrement the cap and mints to destinations that pass the denylist and
   enabled KYC gates.

For the exact transaction shapes and index fields, follow the
[practical integration guide](documents/integration-guide.md#bootstrap-a-token).

From there the protocol is live: mint and burn, pause and unpause, force transfers, verify or
denylist holders, and add or modify power users.

## Token uniqueness

Uniqueness derives from the genesis UTxO. `tx0`/`index0` are applied to `global_state_mint_validator`,
which makes the GlobalState policy ID unique to that deployment; every other validator except the
unparameterised `global_state_proxy` takes that policy ID (directly or transitively) as a parameter.
The proxy's address is therefore shared by every deployment — locate GlobalState by its NFT. Together with `security_asset_name`, this means
each deployment compiles to different validator hashes — and therefore to a different security token
policy ID — even for identical source code.

## How to retrieve information

For wallets and dApps reading protocol state:

1. Go to the CIP-113 registry and find the linked-list node with `key ==` this token's policy ID
2. Read its GlobalState field to identify the NFT holding the GlobalState datum
3. Find that UTxO and read the GlobalState datum for: pause and deactivation flags, remaining
   mintable amount, security info, the KYC requirement flags, the trusted entity keys, and the
   power-users and denylist linked-list policy IDs
4. To check whether a holder is sanctioned, look for a UTxO holding an NFT with `policy_id ==` the
   denylist policy ID and `datum.key ==` the holder's credential hash. **Presence means denylisted**
   — there is no flag to read, and absence is proven on-chain with a covering-node proof
5. For operator roles, read the power-users list the same way; each node's datum carries that
   operator's role flags
6. For transfer approval, read `approval_required`, `approval_threshold` and `approval_logic_hash`
   from the GlobalState datum. **Pending transfers** are the programmable-base UTxOs whose stake
   credential is `Script(<approval proxy hash>)` and that hold the token; attribute each to its
   datum's `sender` in a holder register, and ignore vault UTxOs that hold no token

---

## Authors

- **Matteo Coppola**, as part of the Finest team.
- **Giovanni Gargiulo**, Cardano Foundation
- **Thomas Kammerlocher**, Cardano Foundation
