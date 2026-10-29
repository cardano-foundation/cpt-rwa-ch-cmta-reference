use aiken/builtin
use aiken/collection/dict
use aiken/collection/list
use aiken/fuzz
use aiken/interval.{
  Finite, Interval, IntervalBound, NegativeInfinity, PositiveInfinity,
}
use aiken/merkle_patricia_forestry as mpf
use aiken/primitive/bytearray
use aiken_design_patterns/linked_list.{Element, Node, Root}
use cardano/address.{Address, Credential, Inline, Script, VerificationKey}
use cardano/assets.{from_asset, from_lovelace, merge, quantity_of}
use cardano/certificate.{Certificate, RegisterCredential}
use cardano/transaction.{
  InlineDatum, Input, NoDatum, Output, OutputReference, Transaction,
}
use cip68
use compliance
use constants
use kyc/verify.{membership_leaf_key, membership_leaf_value}
use types/approval.{PendingTransfer}
use types/cip68.{Cip68Datum} as types_cip68
use types/denylist.{Denylist}
use types/global_state.{
  GlobalStateDatum, GlobalStateLocation, GlobalStateReferenced, GlobalStateSpent,
  gs_datum_from_location,
}
use types/kyc_proof.{
  Cip30Attestation, Cip30AttestationProof, KycProof, Membership, MembershipProof,
}
use types/transfer_logic_script.{
  TransferLogicScriptAction, TransferLogicScriptDestinationAction,
  TransferLogicScriptWithdrawRedeemer,
}
use utils.{must_run_script_withdrawal}

/// Transfer logic for a BAFIN security token (Track 4, TEL+denylist model).
///
/// Per-input check (for each unique sender stake credential):
///   1. The redeemer's matching KYC proof validates against GS.trusted_entity_vkeys or the pkh of the sender is in the GS's merkle tree.
///   2. The sender is NOT in the denylist (covering-node absence proof), or is only
///      PARTIALLY frozen (own node, `Some(f)`) and this transaction pays back to its
///      stake credential hash at least `f`, or at least what it spends from that hash.
///
/// Per-output check (for each unique destination stake credential):
///   3. The destination is NOT in the denylist, or is only partially frozen.
///   4. If GS.requires_receiver_kyc, the redeemer's matching KYC proof validates against GS.trusted_entity_vkeys as well (same checks as for senders)
///      or if the pkh of the receiver is in the GS's merkle tree. 
///
/// Plus the pause gate (GS must not be paused).
///
/// TWO-STEP TRANSFER APPROVAL (validators/approval_logic.ak). A security-token
/// UTxO owned by `Script(approval_proxy_hash)` — the VAULT — is a pending
/// transfer. Every approval rule lives in the approval logic; this handler only:
///   5. skips the vault as a party: a vault input or output needs no source or
///      destination action and is not KYC- or denylist-checked (owner decision
///      D6: the approver's signature — admin or `can_approve` operator — is
///      the screen for a release, and the recipient is vetted when it is
///      paid);
///   6. with `approval_required` off, refuses any security-token output at the
///      vault — nothing is parked unbound;
///   7. with `approval_required` on, requires the withdraw-0 of the approval
///      logic GlobalState names in EVERY transaction — it enforces the
///      threshold, binds every new vault output and refuses mixing.
validator transfer_logic_validator(
  security_asset_name: ByteArray,
  global_state_policy_id: ByteArray,
  /// The issuance policy this deployment's transfer logic exists to
  /// police, pinned at compile time.
  ///
  /// NOT circular: a CIP-113 registry node's `key` is derived from the MINTING
  /// logic hash, never from this script's hash, so the issuance policy id is
  /// known before this validator is ever compiled. Dependency order is
  /// `gs_policy → proxy hash → issuance_policy_id → this script`.
  ///
  /// This is the ONLY authentication of which policy this script polices —
  /// the withdraw handler no longer reads a CIP-113 registry node at all. The
  /// base layer already authenticates whichever registry node invoked this
  /// withdraw-0 (that authentication is what makes this script run in the
  /// first place), so re-deriving the policy from that same node here would
  /// only re-prove what already held. And the old "this node names me"
  /// identity assertion was never the real defence anyway: registry field 3
  /// is a FREE CIP-113 field, so any wallet may permissionlessly register a
  /// throwaway node naming this script — under the old design that decoy's
  /// foreign policy made every scan below vacuous. The compile-time pin is
  /// what closes that; nothing about "did some node name me" was ever
  /// load-bearing.
  expected_issuance_policy_id: ByteArray,
  /// The DENYLIST SPEND VALIDATOR's script hash, which every denylist element
  /// a party cites must sit at. See `absence.with_denylist_element`.
  denylist_script_hash: ByteArray,
  /// The permanent approval proxy's script hash
  /// (validators/approval_proxy.ak): the owner of every pending transfer.
  approval_proxy_hash: ByteArray,
) {
  withdraw(
    redeemer: TransferLogicScriptWithdrawRedeemer,
    credential: Credential,
    self: Transaction,
  ) {
    // A withdrawal credential may be a verification key, so this is a real
    // assertion, not a formality.
    expect Script(_) = credential
    let issuance_policy_id = expected_issuance_policy_id

    // 1. Resolve and AUTHENTICATE GlobalState, then read every flag from the
    //    one parsed datum.
    //
    //    One resolve, one NFT check, one decode. An earlier revision reached
    //    for single-field readers to test the pause and deactivation flags
    //    before decoding, which cost a second NFT scan and a second decode of
    //    the same UTxO on the hot path — this handler needs the full datum
    //    anyway, for the TEL, the denylist policy id and the two KYC flags.
    //
    //    It is also the safer shape. A bare `expect gs: GlobalStateDatum`
    //    authenticates NOTHING — it only checks that the bytes parse — so a
    //    read split from its authentication depends on some earlier line having
    //    proved the NFT was there. `gs_datum_from_location` does the NFT check
    //    (`== 1`) and the parse together, so a later edit cannot separate them.
    let gs_datum: GlobalStateDatum = gs_datum_from_location(
      self.inputs,
      self.reference_inputs,
      redeemer.global_state_location,
      global_state_policy_id,
    )

    // 2. Aggregate unique sender stake-cred hashes from inputs carrying the
    //    security token.
    // The full `Credential` is carried, not a bare 28-byte hash. The
    // constructor is part of the holder's identity: the CIP-113 base layer
    // authorises a `VerificationKey` owner by signature and a `Script` owner by
    // withdraw-0, so they are genuinely different parties. Deduplicating on
    // `Credential` therefore treats them as two, which is what lets the KYC
    // check below bind to the right one. The denylist deliberately keeps
    // keying on the bare hash — see its call site.
    //
    // Deduplicated DURING the fold: `list.has` walks the accumulator without
    // rebuilding it, whereas `list.unique` afterwards filters and re-allocates
    // the remaining list once per element — the same comparisons twice over,
    // plus an allocation per party. Left fold + final reverse keeps the
    // first-occurrence order of the old `foldr`+`unique`, and the order is
    // part of the redeemer contract (actions are matched positionally).
    let vault = Script(approval_proxy_hash)

    // The vault is no party (5.): its inputs are skipped.
    let inputs_user_credentials = list.reverse(
      list.foldl(
        self.inputs,
        [],
        fn(input, result) {
          if quantity_of(
            input.output.value,
            issuance_policy_id,
            security_asset_name,
          ) > 0 {
            // Senders must also sit INSIDE the programmable-logic base.
            // Guaranteed by the base layer's transfer conservation
            // (`tokens.contains(PLB outputs, PLB inputs)` per policy) — an
            // input carrying this token cannot sit anywhere else, so nothing
            // further to assert here.
            expect Some(Inline(stake_cred)) = input.output.address.stake_credential
            if stake_cred == vault || list.has(result, stake_cred) {
              result
            } else {
              [stake_cred, ..result]
            }
          } else {
            result
          }
        },
      ),
    )

    // 3. Aggregate unique destination stake-cred hashes from outputs carrying
    //    the security token.
    let outputs_user_credentials = list.reverse(
      list.foldl(
        self.outputs,
        [],
        fn(output, result) {
          // ONE lookup of this policy's tokens per output, answering both
          // questions this fold has: is the output a destination, and does it
          // carry a CIP-68 metadata token whose shape must hold?
          let policy_tokens = assets.tokens(output.value, issuance_policy_id)

          // The metadata token's shape is an INVARIANT, not a posture at
          // genesis. `minting_authority` pins it when it is minted; this is
          // what keeps it true afterwards, because the ordinary transfer path
          // is how a metadata update happens — the owner spends the UTxO and
          // re-outputs the token with a new datum. Without this, an update
          // could co-locate it with supply or write an unparseable datum.
          expect
            cip68.enforce_if_protected(
              policy_tokens,
              output,
              issuance_policy_id,
            )

          let security_quantity = when
            dict.get(policy_tokens, security_asset_name)
          is {
            Some(quantity) -> quantity
            None -> 0
          }
          if security_quantity > 0 {
            // Destinations must sit INSIDE the programmable-logic base.
            // Guaranteed by the base layer: `issuance_mint`'s `no_escape`
            // bars this policy from any non-PLB output on a mint, and
            // transfer conservation (`tokens.contains(PLB outputs, PLB
            // inputs)` per policy) forbids it on a transfer too — verified
            // 2026-08-19 against the deployed base layer.
            expect Some(Inline(stake_cred)) = output.address.stake_credential
            if stake_cred == vault {
              // A new pending transfer: only with approval switched on (6.),
              // where the approval logic runs and binds it (7.). No party (5.).
              expect gs_datum.approval_required
              result
            } else if list.has(result, stake_cred) {
              result
            } else {
              [stake_cred, ..result]
            }
          } else {
            result
          }
        },
      ),
    )

    // 4. Per-sender and per-destination: the denylist gate, plus KYC when the
    //    corresponding flag is set. Swiss CO Art. 973e / eWpG §14 / ERC-3643
    //    all require the RECIPIENT to be KYC'd at transfer time (a named
    //    creditor / registered holder), which is why both sides are vetted.
    //
    //    A PARTIALLY frozen sender (own denylist node, `frozen_amount:
    //    Some(f)`) may send only if this transaction pays back to outputs
    //    whose inline stake credential hash is the sender's either at least
    //    `f` of the security token, or at least what it spends from that hash
    //    (the same count over the inputs). Those outputs are part of what the sender holds
    //    once the transaction lands, so the first arm leaves it at least `f`,
    //    the second leaves its balance no lower: `post ≥ min(pre, f)`, the
    //    freeze floor. Conservative — UTxOs the sender does not spend are not
    //    seen and not counted, which is why a send that lowers the balance must
    //    include `f` again; the second arm is what lets a holder consolidate
    //    without `f` (below `f`, or with `f` spread over too many UTxOs).
    //
    //    Reading only the STAKE credential is sound because of the base
    //    layer, not because of anything here: the security token can only sit
    //    at a programmable-logic-base output (mint `no_escape`, transfer
    //    conservation of PLB outputs over PLB inputs), so no output can carry
    //    it under someone else's payment key while naming the sender's stake
    //    credential. Same premise as the destination fold above.
    //
    //    Destinations — the sender's own change included — accept a partially
    //    frozen party unconditionally: a partial freeze limits sending, never
    //    receiving.
    let all_senders_ok = compliance.verify_parties(
      inputs_user_credentials,
      redeemer.actions_for_each_input,
      fn(action) { action.source_proof },
      fn(action) { action.source_denylist_ref_input_index },
      fn(holder_hash, frozen_amount) {
        let paid_back = paid_back_to_holder(
          self.outputs,
          issuance_policy_id,
          security_asset_name,
          holder_hash,
        )
        // `||` is lazy: a send that keeps the floor never looks at the inputs.
        // Below the floor, what the holder spends is counted by the same
        // function over the inputs' outputs — by bare hash, both credential
        // forms adding up. Reusing it rather than a dedicated early-exit walk
        // keeps the script ~110 bytes smaller, which every transfer pays for
        // as reference-script fee; only below-floor sends pay the full fold.
        // Its `expect` cannot trap here: the sender fold above has already
        // trapped on any input holding the token without an inline stake
        // credential.
        paid_back >= frozen_amount || paid_back >= paid_back_to_holder(
          list.map(self.inputs, fn(input) { input.output }),
          issuance_policy_id,
          security_asset_name,
          holder_hash,
        )
      },
      gs_datum.requires_sender_kyc,
      gs_datum,
      issuance_policy_id,
      denylist_script_hash,
      self,
    )

    let all_destinations_ok = compliance.verify_parties(
      outputs_user_credentials,
      redeemer.destination_actions,
      fn(action) { action.destination_proof },
      fn(action) { action.destination_denylist_ref_input_index },
      fn(_, _) { True },
      gs_datum.requires_receiver_kyc,
      gs_datum,
      issuance_policy_id,
      denylist_script_hash,
      self,
    )

    // 7. With approval on, the approval logic GlobalState names decides the
    //    rest: threshold, binding, mixing.
    let approval_ok = if gs_datum.approval_required {
      must_run_script_withdrawal(self, gs_datum.approval_logic_hash)
    } else {
      True
    }

    and {
      //General transfers of this token must NOT be paused
      gs_datum.transfers_paused == False,
      gs_datum.deactivated == False,
      approval_ok?,
      all_senders_ok,
      all_destinations_ok,
    }
  }

  // Whitelist RegisterCredential only — see minting_logic_script for rationale.
  // A rubber-stamp publish would let anyone de-register this script's stake
  // credential via UnregisterCredential, bricking every transfer until
  // re-registered (and paying the attacker the 2 ADA deposit refund).
  publish(_r: Data, c: Certificate, _s: Transaction) {
    when c is {
      RegisterCredential { .. } -> True
      _ -> False
    }
  }

  else(_) {
    fail
  }
}

/// How much of the security token this transaction pays to outputs whose
/// inline stake credential hash is `holder_hash` — the holder's holdings that
/// this transaction creates, and therefore a lower bound on what the holder
/// holds once it lands.
///
/// Counted by BARE HASH, as the denylist keys: a node freezes the hash, so an
/// output to either credential form of it counts towards the floor.
///
/// Only outputs carrying the security token are inspected, and only those must
/// have an inline stake credential — the same shape the destination fold
/// already demands of them, so an ADA-only output with no stake credential is
/// skipped, never trapped on. Other asset names and other policies count for
/// nothing.
fn paid_back_to_holder(
  outputs: List<Output>,
  issuance_policy_id: ByteArray,
  security_asset_name: ByteArray,
  holder_hash: ByteArray,
) -> Int {
  list.foldl(
    outputs,
    0,
    fn(output, paid_back) {
      let quantity = quantity_of(
        output.value,
        issuance_policy_id,
        security_asset_name,
      )
      if quantity > 0 {
        expect Some(Inline(stake_cred)) = output.address.stake_credential
        if utils.credential_hash(stake_cred) == holder_hash {
          paid_back + quantity
        } else {
          paid_back
        }
      } else {
        paid_back
      }
    },
  )
}

// ============================================================================
// Tests — transfer_logic_validator.withdraw (handler-level)
// ============================================================================
// Fixtures model the real programmable-token address shape (PLB script payment
// credential + inline owner stake credential) and the CIP-113 registry node
// (this validator's credential at field index 3). GS is a REFERENCE input.
// Reference-input order: 0 = registry node, 1 = GlobalState, 2 = denylist root.

// The permanent approval proxy's hash: owner of every pending transfer.
const t_approval_proxy_hash: ByteArray =
  #"b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0"

const t_sec_name: ByteArray = "SEC"

const t_gs_policy: ByteArray =
  #"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

const t_issuance_policy: ByteArray =
  #"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"

const t_registry_policy: ByteArray =
  #"cccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

const t_denylist_policy: ByteArray =
  #"dddddddddddddddddddddddddddddddddddddddddddddddddddddddd"

const t_minting_hash: ByteArray =
  #"f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1"

// This validator's OWN credential — must equal registry field index 3.
const t_transfer_hash: ByteArray =
  #"f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2"

const t_third_party_hash: ByteArray =
  #"f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3"

// The denylist SPEND validator's hash — distinct from the denylist
// POLICY id (mint and spend are separate validators). Node fixtures live here.
const t_denylist_script_hash: ByteArray =
  #"d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0"

const t_plb_hash: ByteArray =
  #"05050505050505050505050505050505050505050505050505050505"

const t_sender_stake: ByteArray =
  #"0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a"

const t_dest_stake: ByteArray =
  #"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"

// ── Genuine KYC-attestation fixtures ──────────────────────────────────────────
// The end-to-end positive controls below need an ACTUAL Ed25519 signature — a
// proof that always fails (`dummy_proof`) cannot exercise the accept path.

// Public half of the fixed-seed test issuer key (same key pair as
// `lib/kyc/verify.ak`'s `test_issuer_vkey`). Add it to a TEL to make the
// vectors below verify.
const t_kyc_issuer_vkey: ByteArray =
  #"03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8"

// t_transfer_tx's own validity_range upper bound is PositiveInfinity, which
// verify_payload always rejects (Finite required); the positive
// controls below use `t_transfer_tx_with_tel` instead, which sets a Finite
// upper bound of t_kyc_tx_upper — strictly below the 100_000_000 ms
// valid_until_ms baked into the claims below.
const t_kyc_tx_upper: Int = 50_000_000

// Genuine CIP-30 parts, generated off-repository with a public TEST seed. Each signs a
// 67-byte claim for t_sender_stake / t_dest_stake as a VerificationKey
// credential (matching how `t_token_utxo` builds the stake credential), tier
// User, valid_until_ms = 100_000_000, for t_issuance_policy on network 1. The
// hashed (Ledger-style) receiver proof was cross-checked against Emurgo's
// cardano-message-signing when generated: byte-identical.
fn t_sender_cip30() -> Cip30AttestationProof {
  Cip30AttestationProof {
    protected_header: #"a201276761646472657373581d6027e38d0e19e3434e33fbd001d3fe04b5b76763f88acd625e0d770b43",
    payload: #"0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a010000000005f5e100eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee0100",
    hashed: False,
    signature: #"f3be430bf286c18ea284134558c3caab3f01d121041063c286b245ccf3c4adcef5da4d4c6ec7e8f6543978dd90cdc57b84668fdb4345a6e26ac42839d61a1700",
    issuer_vkey: t_kyc_issuer_vkey,
  }
}

fn t_dest_cip30() -> Cip30AttestationProof {
  Cip30AttestationProof {
    protected_header: #"a201276761646472657373581d6027e38d0e19e3434e33fbd001d3fe04b5b76763f88acd625e0d770b43",
    payload: #"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b010000000005f5e100eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee0100",
    hashed: False,
    signature: #"088eb18a610edf95c77503162ae1b0c182f13aa53fd4fe228eef83d80cb356a37e6f0e87e159b8e54f9ba5f514311ab1a6f4e762316d748ede075fec4ed69503",
    issuer_vkey: t_kyc_issuer_vkey,
  }
}

fn t_dest_cip30_hashed() -> Cip30AttestationProof {
  Cip30AttestationProof {
    protected_header: #"a201276761646472657373581d6027e38d0e19e3434e33fbd001d3fe04b5b76763f88acd625e0d770b43",
    payload: #"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b010000000005f5e100eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee0100",
    hashed: True,
    signature: #"5d58da53a2e9124361f505582c475514a4ea1f83b2378137dda2280869a1eb356cfcc35019a6546894758ed1448b746760c678da75e179e36315f5a1ef6d8a03",
    issuer_vkey: t_kyc_issuer_vkey,
  }
}

type TRegNode {
  key: ByteArray,
  next: ByteArray,
  minting_logic_script: Credential,
  transfer_logic_script: Credential,
  third_party_transfer_logic_script: Credential,
  /// CIP-113 v0.4.0 field 5. `VerificationKey(#"")` means unfracking is
  /// FORBIDDEN for this policy — core's least-permission default.
  unfracking_logic_script: Credential,
  global_state_cs: ByteArray,
}

fn t_out_ref(ix: Int) -> OutputReference {
  OutputReference {
    transaction_id: #"0000000000000000000000000000000000000000000000000000000000000000",
    output_index: ix,
  }
}

fn t_gs_datum(
  paused: Bool,
  deactivated: Bool,
  req_sender: Bool,
  req_receiver: Bool,
) -> GlobalStateDatum {
  GlobalStateDatum {
    global_state_script_credential_hash: #"9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a",
    transfers_paused: paused,
    deactivated,
    mintable_amount: 1_000_000,
    admin_credential_hash: #"",
    power_user_linked_list_policy_id: #"",
    denylist_linked_list_policy_id: t_denylist_policy,
    security_info: builtin.constr_data(0, []),
    trusted_entity_vkeys: [],
    member_root_hash: #"",
    requires_sender_kyc: req_sender,
    requires_receiver_kyc: req_receiver,
    network_id: 1,
    minting_script_credential_hash: #"",
    upgrades_locked: False,
    approval_required: False,
    approval_threshold: 0,
    approval_logic_hash: #"a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7",
  }
}

fn t_gs_ref_input(
  paused: Bool,
  deactivated: Bool,
  req_sender: Bool,
  req_receiver: Bool,
) -> Input {
  Input {
    output_reference: t_out_ref(1),
    output: Output {
      address: Address {
        payment_credential: Script(t_gs_policy),
        stake_credential: None,
      },
      value: merge(
        from_lovelace(2_000_000),
        from_asset(t_gs_policy, constants.global_state_asset_name, 1),
      ),
      datum: InlineDatum(
        t_gs_datum(paused, deactivated, req_sender, req_receiver),
      ),
      reference_script: None,
    },
  }
}

fn t_registry_ref_input() -> Input {
  let node = TRegNode {
    key: t_issuance_policy,
    next: #"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    minting_logic_script: Script(t_minting_hash),
    transfer_logic_script: Script(t_transfer_hash),
    third_party_transfer_logic_script: Script(t_third_party_hash),
    unfracking_logic_script: VerificationKey(#""),
    global_state_cs: t_gs_policy,
  }
  Input {
    output_reference: t_out_ref(0),
    output: Output {
      address: Address {
        payment_credential: Script(t_registry_policy),
        stake_credential: None,
      },
      value: merge(
        from_lovelace(2_000_000),
        from_asset(t_registry_policy, "Node", 1),
      ),
      datum: InlineDatum(node),
      reference_script: None,
    },
  }
}

fn t_denylist_root_ref_input() -> Input {
  let element: Element<Data, Data> = Element {
    data: Root { data: builtin.constr_data(0, []) },
    link: None,
  }
  Input {
    output_reference: t_out_ref(2),
    output: Output {
      address: Address {
        payment_credential: Script(t_denylist_script_hash),
        stake_credential: None,
      },
      value: merge(
        from_lovelace(2_000_000),
        from_asset(t_denylist_policy, constants.linked_list_root_key, 1),
      ),
      datum: InlineDatum(element),
      reference_script: None,
    },
  }
}

fn t_token_utxo(stake_hash: ByteArray, amount: Int) -> Output {
  Output {
    address: Address {
      payment_credential: Script(t_plb_hash),
      stake_credential: Some(Inline(VerificationKey(stake_hash))),
    },
    value: merge(
      from_lovelace(2_000_000),
      from_asset(t_issuance_policy, t_sec_name, amount),
    ),
    datum: NoDatum,
    reference_script: None,
  }
}

fn t_sender_input(stake_hash: ByteArray, amount: Int) -> Input {
  Input {
    output_reference: t_out_ref(10),
    output: t_token_utxo(stake_hash, amount),
  }
}

fn dummy_proof() -> KycProof {
  Cip30Attestation {
    cip30_proof: Cip30AttestationProof {
      protected_header: #"",
      payload: #"",
      hashed: False,
      signature: #"",
      issuer_vkey: #"",
    },
  }
}

// Covering-node index 2 = the empty denylist root (covers every key).
fn t_source_action() -> TransferLogicScriptAction {
  TransferLogicScriptAction {
    source_proof: dummy_proof(),
    source_denylist_ref_input_index: 2,
  }
}

fn t_dest_action() -> TransferLogicScriptDestinationAction {
  TransferLogicScriptDestinationAction {
    destination_proof: dummy_proof(),
    destination_denylist_ref_input_index: 2,
  }
}

fn t_transfer_tx(
  paused: Bool,
  deactivated: Bool,
  req_sender: Bool,
  req_receiver: Bool,
) -> Transaction {
  Transaction {
    inputs: [t_sender_input(t_sender_stake, 1_000)],
    reference_inputs: [
      t_registry_ref_input(),
      t_gs_ref_input(paused, deactivated, req_sender, req_receiver),
      t_denylist_root_ref_input(),
    ],
    outputs: [t_token_utxo(t_dest_stake, 1_000)],
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

fn run_transfer(
  redeemer: TransferLogicScriptWithdrawRedeemer,
  tx: Transaction,
) -> Bool {
  transfer_logic_validator.withdraw(
    t_sec_name,
    t_gs_policy,
    t_issuance_policy,
    t_denylist_script_hash,
    t_approval_proxy_hash,
    redeemer,
    Script(t_transfer_hash),
    tx,
  )
}

fn t_redeemer() -> TransferLogicScriptWithdrawRedeemer {
  TransferLogicScriptWithdrawRedeemer {
    global_state_location: GlobalStateReferenced {
      global_state_ref_input_index: 1,
    },
    actions_for_each_input: [t_source_action()],
    destination_actions: [t_dest_action()],
  }
}

// ── KYC positive-control fixtures ─────────────────────────────────────────────
// Siblings of the fixtures above, extended with a Trusted Entity List — needed
// to exercise a genuine `Attestation` proof end to end. The originals
// (`t_gs_datum`, `t_gs_ref_input`, `t_transfer_tx`, `t_redeemer`) are left
// completely untouched, so every existing test keeps its original behaviour.

/// A Trusted Entity List containing exactly one issuer vkey.
fn t_tel_with(vkey: ByteArray) -> Pairs<ByteArray, Data> {
  [Pair(vkey, builtin.constr_data(0, []))]
}

/// Sibling of `t_gs_datum` that also carries a TEL.
fn t_gs_datum_with_tel(
  req_sender: Bool,
  req_receiver: Bool,
  trusted_keys: Pairs<ByteArray, Data>,
) -> GlobalStateDatum {
  GlobalStateDatum {
    global_state_script_credential_hash: #"9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a",
    transfers_paused: False,
    deactivated: False,
    mintable_amount: 1_000_000,
    admin_credential_hash: #"",
    power_user_linked_list_policy_id: #"",
    denylist_linked_list_policy_id: t_denylist_policy,
    security_info: builtin.constr_data(0, []),
    trusted_entity_vkeys: trusted_keys,
    member_root_hash: #"",
    requires_sender_kyc: req_sender,
    requires_receiver_kyc: req_receiver,
    network_id: 1,
    minting_script_credential_hash: #"",
    upgrades_locked: False,
    approval_required: False,
    approval_threshold: 0,
    approval_logic_hash: #"a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7",
  }
}

/// Sibling of `t_gs_ref_input` carrying the TEL-aware datum above.
fn t_gs_ref_input_with_tel(
  req_sender: Bool,
  req_receiver: Bool,
  trusted_keys: Pairs<ByteArray, Data>,
) -> Input {
  Input {
    output_reference: t_out_ref(1),
    output: Output {
      address: Address {
        payment_credential: Script(t_gs_policy),
        stake_credential: None,
      },
      value: merge(
        from_lovelace(2_000_000),
        from_asset(t_gs_policy, constants.global_state_asset_name, 1),
      ),
      datum: InlineDatum(
        t_gs_datum_with_tel(req_sender, req_receiver, trusted_keys),
      ),
      reference_script: None,
    },
  }
}

fn t_cip30_proof(proof: Cip30AttestationProof) -> KycProof {
  Cip30Attestation { cip30_proof: proof }
}

fn t_source_action_with_proof(proof: KycProof) -> TransferLogicScriptAction {
  TransferLogicScriptAction {
    source_proof: proof,
    source_denylist_ref_input_index: 2,
  }
}

fn t_dest_action_with_proof(
  proof: KycProof,
) -> TransferLogicScriptDestinationAction {
  TransferLogicScriptDestinationAction {
    destination_proof: proof,
    destination_denylist_ref_input_index: 2,
  }
}

/// Sibling of `t_transfer_tx` that (a) accepts a TEL for the GlobalState
/// reference input, so a genuine attestation can find its issuer, and (b)
/// gives the transaction a FINITE validity upper bound (`t_kyc_tx_upper`) —
/// `t_transfer_tx`'s own upper bound is PositiveInfinity, which
/// `verify_payload` always rejects (it requires a Finite bound
/// no later than the attestation's `valid_until_ms`).
fn t_transfer_tx_with_tel(
  req_sender: Bool,
  req_receiver: Bool,
  trusted_keys: Pairs<ByteArray, Data>,
) -> Transaction {
  Transaction {
    inputs: [t_sender_input(t_sender_stake, 1_000)],
    reference_inputs: [
      t_registry_ref_input(),
      t_gs_ref_input_with_tel(req_sender, req_receiver, trusted_keys),
      t_denylist_root_ref_input(),
    ],
    outputs: [t_token_utxo(t_dest_stake, 1_000)],
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
        bound_type: Finite(t_kyc_tx_upper),
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

fn t_redeemer_with(
  source_action: TransferLogicScriptAction,
  dest_action: TransferLogicScriptDestinationAction,
) -> TransferLogicScriptWithdrawRedeemer {
  TransferLogicScriptWithdrawRedeemer {
    global_state_location: GlobalStateReferenced {
      global_state_ref_input_index: 1,
    },
    actions_for_each_input: [source_action],
    destination_actions: [dest_action],
  }
}

test transfer_succeeds_when_clean() {
  // Not paused, not deactivated, no KYC required, sender & receiver absent from
  // the (empty) denylist.
  run_transfer(t_redeemer(), t_transfer_tx(False, False, False, False))
}

// This validator no longer reads a CIP-113 registry node at all — the policy
// it polices is pinned at compile time. Every fixture above still carries
// `t_registry_ref_input()` at reference index 0 (unused, kept to minimise
// their diff); this one omits it entirely to prove the removal is real.
// GlobalState moves to index 0 and the denylist root to index 1.
test transfer_succeeds_without_any_registry_reference_input() {
  let tx = Transaction {
    ..t_transfer_tx(False, False, False, False),
    reference_inputs: [
      t_gs_ref_input(False, False, False, False),
      t_denylist_root_ref_input(),
    ],
  }
  run_transfer(
    TransferLogicScriptWithdrawRedeemer {
      global_state_location: GlobalStateReferenced {
        global_state_ref_input_index: 0,
      },
      actions_for_each_input: [
        TransferLogicScriptAction {
          source_proof: dummy_proof(),
          source_denylist_ref_input_index: 1,
        },
      ],
      destination_actions: [
        TransferLogicScriptDestinationAction {
          destination_proof: dummy_proof(),
          destination_denylist_ref_input_index: 1,
        },
      ],
    },
    tx,
  )
}

// ── GlobalState may be spent instead of referenced ──────────────────────────
//
// `global_state_location` widened this validator to accept a SPENT GlobalState,
// so the spent branch is exercised here rather than left as an unverified
// branch of shared, security-relevant code. Nothing in the platform builds this
// combination today — a plain transfer references GlobalState — but the point of
// the widening is that a transfer chained with a mint, a burn or an admin action
// stays buildable, and those all SPEND it.
//
// GlobalState is absent from `reference_inputs` here, exactly as it would be in
// such a transaction, which shifts the denylist root from index 2 to 1.

fn t_spent_gs_tx() -> Transaction {
  Transaction {
    ..t_transfer_tx(False, False, False, False),
    inputs: [
      t_sender_input(t_sender_stake, 1_000),
      t_gs_ref_input(False, False, False, False),
    ],
    reference_inputs: [t_registry_ref_input(), t_denylist_root_ref_input()],
  }
}

fn t_spent_gs_redeemer(
  location: GlobalStateLocation,
) -> TransferLogicScriptWithdrawRedeemer {
  TransferLogicScriptWithdrawRedeemer {
    global_state_location: location,
    actions_for_each_input: [
      TransferLogicScriptAction {
        source_proof: dummy_proof(),
        source_denylist_ref_input_index: 1,
      },
    ],
    destination_actions: [
      TransferLogicScriptDestinationAction {
        destination_proof: dummy_proof(),
        destination_denylist_ref_input_index: 1,
      },
    ],
  }
}

test transfer_succeeds_when_global_state_is_spent() {
  run_transfer(
    t_spent_gs_redeemer(GlobalStateSpent { global_state_input_index: 1 }),
    t_spent_gs_tx(),
  )
}

test transfer_rejected_when_location_names_the_wrong_list() fail {
  // What gives the test above its meaning: same transaction, same index, read
  // from the reference list instead. Reference input 1 is the denylist root and
  // carries no GlobalState NFT, so authentication traps — the constructor really
  // does select which list is read.
  run_transfer(
    t_spent_gs_redeemer(
      GlobalStateReferenced { global_state_ref_input_index: 1 },
    ),
    t_spent_gs_tx(),
  )
}

test transfer_rejected_when_spent_index_is_not_global_state() fail {
  // Input 0 is the sender's token UTxO. `GlobalStateSpent` may be pointed
  // anywhere; the NFT is still what decides whether the datum is believed.
  run_transfer(
    t_spent_gs_redeemer(GlobalStateSpent { global_state_input_index: 0 }),
    t_spent_gs_tx(),
  )
}

test transfer_rejected_when_paused() {
  !run_transfer(t_redeemer(), t_transfer_tx(True, False, False, False))
}

test transfer_rejected_when_deactivated() {
  // Deactivation implies paused; the explicit `transfers_deactivated == False`
  // gate rejects independently.
  !run_transfer(t_redeemer(), t_transfer_tx(True, True, False, False))
}

test transfer_rejected_when_sender_kyc_required_and_proof_invalid() {
  // F-20 regression: sender gate must read `requires_sender_kyc`. With sender
  // KYC required (receiver OFF) and an invalid sender proof, the transfer is
  // rejected. Under the OLD bug (sender gate read `requires_receiver_kyc`),
  // sender KYC would be SKIPPED here and this would wrongly pass.
  !run_transfer(t_redeemer(), t_transfer_tx(False, False, True, False))
}

test transfer_allowed_when_sender_kyc_not_required() {
  // Same invalid sender proof, but sender KYC not required → skipped → allowed.
  // Confirms the sender flag actually gates the sender check.
  run_transfer(t_redeemer(), t_transfer_tx(False, False, False, False))
}

test transfer_rejected_when_receiver_kyc_required_and_proof_invalid() {
  // Receiver gate reads `requires_receiver_kyc`; invalid receiver proof → reject.
  !run_transfer(t_redeemer(), t_transfer_tx(False, False, False, True))
}

// ── KYC positive controls (end-to-end) ────────────────────────────────────────
// Every KYC-related test above proves a rejection. None of them proves the
// sender/receiver KYC gate can ever be satisfied by a real proof — a
// `verify_kyc_proof` that always returns False would pass every test above
// too. These run the FULL validator with a genuine Ed25519 attestation.

test transfer_succeeds_with_cip30_sender_proof() {
  let source_action = t_source_action_with_proof(
    t_cip30_proof(t_sender_cip30()),
  )
  run_transfer(
    t_redeemer_with(source_action, t_dest_action()),
    t_transfer_tx_with_tel(True, False, t_tel_with(t_kyc_issuer_vkey)),
  )
}

test transfer_succeeds_with_cip30_receiver_proof() {
  let dest_action = t_dest_action_with_proof(t_cip30_proof(t_dest_cip30()))
  run_transfer(
    t_redeemer_with(t_source_action(), dest_action),
    t_transfer_tx_with_tel(False, True, t_tel_with(t_kyc_issuer_vkey)),
  )
}

test transfer_succeeds_with_hashed_cip30_receiver_proof() {
  let dest_action = t_dest_action_with_proof(
    t_cip30_proof(t_dest_cip30_hashed()),
  )
  run_transfer(
    t_redeemer_with(t_source_action(), dest_action),
    t_transfer_tx_with_tel(False, True, t_tel_with(t_kyc_issuer_vkey)),
  )
}

test transfer_rejects_cip30_proof_from_untrusted_issuer() {
  let source_action = t_source_action_with_proof(
    t_cip30_proof(t_sender_cip30()),
  )
  !run_transfer(
    t_redeemer_with(source_action, t_dest_action()),
    t_transfer_tx_with_tel(True, False, []),
  )
}

test transfer_rejects_swapped_cip30_holder_claims() {
  let source_action = t_source_action_with_proof(t_cip30_proof(t_dest_cip30()))
  !run_transfer(
    t_redeemer_with(source_action, t_dest_action()),
    t_transfer_tx_with_tel(True, False, t_tel_with(t_kyc_issuer_vkey)),
  )
}

// ============================================================================
// Membership KYC end-to-end
// ============================================================================
// Every KYC test above exercises the `Attestation` proof variant. These drive
// the OTHER variant — `Membership`, checked against an on-chain Merkle
// Patricia Forestry root — through the real withdraw handler, using a root
// built with the vendored MPF library itself (never hand-pasted), the same way
// `lib/kyc/verify.ak`'s `membership_succeeds_with_a_genuine_single_leaf_root`
// does.

/// Sibling of `t_gs_datum` that carries a membership root instead of a TEL.
fn t_gs_datum_with_member_root(
  req_sender: Bool,
  req_receiver: Bool,
  member_root_hash: ByteArray,
) -> GlobalStateDatum {
  GlobalStateDatum {
    global_state_script_credential_hash: #"9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a",
    transfers_paused: False,
    deactivated: False,
    mintable_amount: 1_000_000,
    admin_credential_hash: #"",
    power_user_linked_list_policy_id: #"",
    denylist_linked_list_policy_id: t_denylist_policy,
    security_info: builtin.constr_data(0, []),
    trusted_entity_vkeys: [],
    member_root_hash,
    requires_sender_kyc: req_sender,
    requires_receiver_kyc: req_receiver,
    network_id: 1,
    minting_script_credential_hash: #"",
    upgrades_locked: False,
    approval_required: False,
    approval_threshold: 0,
    approval_logic_hash: #"a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7",
  }
}

/// Sibling of `t_gs_ref_input` carrying the member-root-aware datum above.
fn t_gs_ref_input_with_member_root(
  req_sender: Bool,
  req_receiver: Bool,
  member_root_hash: ByteArray,
) -> Input {
  Input {
    output_reference: t_out_ref(1),
    output: Output {
      address: Address {
        payment_credential: Script(t_gs_policy),
        stake_credential: None,
      },
      value: merge(
        from_lovelace(2_000_000),
        from_asset(t_gs_policy, constants.global_state_asset_name, 1),
      ),
      datum: InlineDatum(
        t_gs_datum_with_member_root(req_sender, req_receiver, member_root_hash),
      ),
      reference_script: None,
    },
  }
}

/// Sibling of `t_transfer_tx_with_tel`: same Finite validity upper bound (a
/// membership proof also needs one — `verify_membership_proof` requires the
/// tx's validity upper bound to be Finite and <= the proof's `valid_until_ms`)
/// but GlobalState carries a membership root instead of a TEL.
fn t_transfer_tx_with_member_root(
  req_sender: Bool,
  req_receiver: Bool,
  member_root_hash: ByteArray,
) -> Transaction {
  Transaction {
    inputs: [t_sender_input(t_sender_stake, 1_000)],
    reference_inputs: [
      t_registry_ref_input(),
      t_gs_ref_input_with_member_root(
        req_sender,
        req_receiver,
        member_root_hash,
      ),
      t_denylist_root_ref_input(),
    ],
    outputs: [t_token_utxo(t_dest_stake, 1_000)],
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
        bound_type: Finite(t_kyc_tx_upper),
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

/// POSIX millisecond TTL used by the membership fixtures below — comfortably
/// beyond `t_kyc_tx_upper`, exactly like the attestation fixtures' TTL.
const t_membership_valid_until_ms: Int = 100_000_000

/// A genuine single-leaf MPF root committing to `credential`'s membership,
/// built the same way `lib/kyc/verify.ak`'s positive-control tests do:
/// `mpf.empty |> mpf.insert(membership_leaf_key(cred), membership_leaf_value(...), [])
/// |> mpf.root`. An empty proof list is correct for a one-leaf trie.
fn t_membership_root_for(
  credential: Credential,
  valid_until_ms: Int,
) -> ByteArray {
  mpf.empty
    |> mpf.insert(
        membership_leaf_key(credential),
        membership_leaf_value(valid_until_ms, t_issuance_policy, 1),
        [],
      )
    |> mpf.root()
}

fn t_membership_proof(pkh: ByteArray, valid_until_ms: Int) -> KycProof {
  Membership {
    membership_proof: MembershipProof { pkh, valid_until_ms, mpf_proof: [] },
  }
}

/// POSITIVE. A genuine single-leaf root for `t_sender_stake` as a
/// VerificationKey credential (matches how `t_sender_input` constructs the
/// stake credential), set as GlobalState's `member_root_hash` with
/// `requires_sender_kyc = True`, driven through a `Membership` proof with an
/// empty inclusion proof. Must succeed.
test transfer_succeeds_when_sender_membership_proof_is_genuine() {
  let root = t_membership_root_for(
    VerificationKey(t_sender_stake),
    t_membership_valid_until_ms,
  )
  let source_action = t_source_action_with_proof(
    t_membership_proof(t_sender_stake, t_membership_valid_until_ms),
  )
  run_transfer(
    t_redeemer_with(source_action, t_dest_action()),
    t_transfer_tx_with_member_root(True, False, root),
  )
}

/// NEGATIVE TWIN. Identical transaction and proof, but the on-chain root
/// commits to a DIFFERENT credential (`t_dest_stake`, not the sender's
/// `t_sender_stake`) — the same leaf-mismatch shape
/// `membership_genuine_root_rejects_other_credential` pins in
/// `lib/kyc/verify.ak`. The sender's leaf is not in this tree, so `mpf.has`
/// returns False and the transfer is rejected. Rejection is a clean `False`,
/// not a trap, hence `!` rather than `fail`.
test transfer_rejected_when_sender_membership_root_is_for_another_credential() {
  let root = t_membership_root_for(
    VerificationKey(t_dest_stake),
    t_membership_valid_until_ms,
  )
  let source_action = t_source_action_with_proof(
    t_membership_proof(t_sender_stake, t_membership_valid_until_ms),
  )
  !run_transfer(
    t_redeemer_with(source_action, t_dest_action()),
    t_transfer_tx_with_member_root(True, False, root),
  )
}

// ============================================================================
// Benchmarks — cost scaling vs. party count
// ============================================================================
// `aiken bench -m "transfer_logic_script"` runs this. It builds a transfer
// with `n` distinct senders and `n` distinct destinations (unique
// VerificationKey stake credentials on both sides), denylist-only
// (`requires_sender_kyc = requires_receiver_kyc = False` — the additive cost
// of KYC is read off the existing `transfer_succeeds_when_clean` vs.
// `..._kyc_required_and_proof_is_genuine` tests' ex-units instead, since a
// bench can't easily vary per-party proof bytes and Ed25519-verify cost
// independently of party count), every action citing reference input 2 —
// the same root-only denylist covering node the fixtures above already use,
// which covers every key.
//
// The sampler is `fuzz.constant(size)`: `n` is exactly the current growth
// step of `--max-size`, with NO randomness. Cost must be a pure function of
// `n` for the linear fit in the bench report to mean anything — a randomised
// size-to-n mapping would reintroduce noise the report would then have to
// explain away.
//
// `n = 1` reproduces `transfer_succeeds_when_clean`'s SHAPE (one sender, one
// PLB-address VerificationKey stake credential, one matching destination, GS
// referenced, no KYC) as a sanity anchor between the two suites — not its
// exact bytes, since the party hashes below are derived rather than the
// fixed `t_sender_stake` / `t_dest_stake` constants.

/// Deterministic i-th 28-byte stake-credential hash: a 4-byte big-endian
/// index followed by a fixed 24-byte tail. Distinct tails for senders vs.
/// destinations so index `i` never collides across the two roles — not
/// required for correctness (the two credential lists are aggregated and
/// checked independently) but keeps "n distinct parties per side" honest.
fn t_bench_hash(i: Int, tail: ByteArray) -> ByteArray {
  bytearray.concat(bytearray.from_int_big_endian(i, 4), tail)
}

const t_bench_sender_tail: ByteArray =
  #"1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a"

const t_bench_dest_tail: ByteArray =
  #"2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b"

fn t_bench_sender_input(i: Int) -> Input {
  Input {
    output_reference: t_out_ref(100 + i),
    output: t_token_utxo(t_bench_hash(i, t_bench_sender_tail), 1_000),
  }
}

fn t_bench_dest_output(i: Int) -> Output {
  t_token_utxo(t_bench_hash(i, t_bench_dest_tail), 1_000)
}

/// Sampler: the bench size IS the party count `n`, via `fuzz.constant` — see
/// the section note above for why this must not be randomised.
fn n_parties(size: Int) -> Fuzzer<Int> {
  fuzz.constant(size)
}

bench transfer_cost_by_party_count(n via n_parties) {
  let redeemer = TransferLogicScriptWithdrawRedeemer {
    global_state_location: GlobalStateReferenced {
      global_state_ref_input_index: 1,
    },
    actions_for_each_input: list.repeat(t_source_action(), n),
    destination_actions: list.repeat(t_dest_action(), n),
  }
  let tx = Transaction {
    ..t_transfer_tx(False, False, False, False),
    inputs: list.map(list.range(0, n - 1), t_bench_sender_input),
    outputs: list.map(list.range(0, n - 1), t_bench_dest_output),
  }
  // Assert rather than `fail`-annotate: a bench body that silently accepted
  // a False here would keep reporting plausible-looking mem/cpu numbers for
  // a validator run that actually rejected the transaction, which would make
  // every downstream cost-scaling conclusion meaningless.
  expect run_transfer(redeemer, tx)
}

// ── CIP-68 shape is an invariant, not a posture at genesis ───────────────────
//
// `minting_authority` pins the metadata token's UTxO when it is minted. That
// alone would make the shape true only at birth: the ordinary transfer path is
// how a metadata update happens (the owner spends the UTxO and re-outputs the
// token with a new datum), so without a check here an update could co-locate
// the token with supply, or write a datum no CIP-68 reader can parse, and
// nothing would object.
//
// The check therefore lives in the output fold this handler already runs, and
// costs one prefix comparison per token of the policed policy.

/// CIP-67 label `(100)` — a protected, metadata name under the policed policy.
const t_cip68_name: ByteArray = #"000643b04d657461"

fn t_cip68_datum() -> Data {
  let d = Cip68Datum {
    metadata: [],
    version: 1,
    extra: builtin.constr_data(0, []),
  }
  let raw: Data = d
  raw
}

/// The metadata UTxO: ADA + exactly the one protected token, owned by `stake`.
fn t_cip68_output(stake_hash: ByteArray, datum: Data) -> Output {
  Output {
    address: Address {
      payment_credential: Script(t_plb_hash),
      stake_credential: Some(Inline(VerificationKey(stake_hash))),
    },
    value: merge(
      from_lovelace(2_000_000),
      from_asset(t_issuance_policy, t_cip68_name, 1),
    ),
    datum: InlineDatum(datum),
    reference_script: None,
  }
}

/// A metadata update: the owner spends the metadata UTxO and re-outputs it.
/// No security token moves, so there are no parties to vet.
fn t_metadata_update_tx(output: Output) -> Transaction {
  Transaction {
    ..t_transfer_tx(False, False, False, False),
    inputs: [
      Input {
        output_reference: t_out_ref(20),
        output: t_cip68_output(t_sender_stake, t_cip68_datum()),
      },
    ],
    outputs: [output],
  }
}

fn t_metadata_redeemer() -> TransferLogicScriptWithdrawRedeemer {
  TransferLogicScriptWithdrawRedeemer {
    global_state_location: GlobalStateReferenced {
      global_state_ref_input_index: 1,
    },
    actions_for_each_input: [],
    destination_actions: [],
  }
}

/// POSITIVE CONTROL: a well-formed metadata update is accepted.
test transfer_accepts_a_well_formed_cip68_output() {
  run_transfer(
    t_metadata_redeemer(),
    t_metadata_update_tx(t_cip68_output(t_dest_stake, t_cip68_datum())),
  )
}

/// THE ATTACK: the update writes a datum that is not the CIP-68 constructor.
test transfer_rejects_a_malformed_cip68_datum() fail {
  run_transfer(
    t_metadata_redeemer(),
    t_metadata_update_tx(
      t_cip68_output(t_dest_stake, builtin.constr_data(0, [])),
    ),
  )
}

/// THE ATTACK: the update co-locates the metadata token with security tokens,
/// which would carry value through a path that never inspects it.
///
/// The output DOES carry the security token, so it is a destination and must be
/// vetted — the redeemer therefore supplies a destination action, and the
/// denylist root at reference index 2 covers every key. Without that this test
/// would trap on the missing action instead of on the shape, and would pass
/// while proving nothing.
test transfer_rejects_a_cip68_output_holding_security_tokens() fail {
  let out = t_cip68_output(t_dest_stake, t_cip68_datum())
  run_transfer(
    TransferLogicScriptWithdrawRedeemer {
      ..t_metadata_redeemer(),
      destination_actions: [t_dest_action()],
    },
    t_metadata_update_tx(
      Output {
        ..out,
        value: merge(out.value, from_asset(t_issuance_policy, t_sec_name, 5)),
      },
    ),
  )
}

// ============================================================================
// Tests — two-step transfer approval (validators/approval_logic.ak)
// ============================================================================
// A VAULT UTxO is a PLB UTxO owned by `Script(t_approval_proxy_hash)`. The
// switch and threshold are GlobalState tail fields, set here on whatever
// GlobalState reference input a fixture carries; the approval logic the datum
// names (`t_approval_logic`) is added as a withdrawal where approval is on.
// The threshold, binding and mixing rules are the approval logic's and are
// tested there (validators/approval_logic.ak). KYC is off unless stated;
// covering index 2 is the empty denylist root, which covers every key.

const t_approval_logic: ByteArray =
  #"a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7"

const t_other_stake: ByteArray =
  #"0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c"

/// The same transaction with GlobalState's approval switch and threshold set.
fn with_approval(tx: Transaction, required: Bool, threshold: Int) -> Transaction {
  Transaction {
    ..tx,
    reference_inputs: list.map(
      tx.reference_inputs,
      fn(input) {
        if quantity_of(
          input.output.value,
          t_gs_policy,
          constants.global_state_asset_name,
        ) == 1 {
          expect InlineDatum(raw) = input.output.datum
          expect datum: GlobalStateDatum = raw
          Input {
            ..input,
            output: Output {
              ..input.output,
              datum: InlineDatum(
                GlobalStateDatum {
                  ..datum,
                  approval_required: required,
                  approval_threshold: threshold,
                },
              ),
            },
          }
        } else {
          input
        }
      },
    ),
  }
}

/// The approval logic GlobalState names runs in the transaction.
fn with_approval_logic(tx: Transaction) -> Transaction {
  Transaction {
    ..tx,
    withdrawals: [Pair(Script(t_approval_logic), 0), ..tx.withdrawals],
  }
}

fn t_holder_input(ix: Int, stake_hash: ByteArray, amount: Int) -> Input {
  Input {
    output_reference: t_out_ref(ix),
    output: t_token_utxo(stake_hash, amount),
  }
}

fn t_pending(
  sender: ByteArray,
  recipient: ByteArray,
  amount: Int,
) -> PendingTransfer {
  PendingTransfer {
    sender: VerificationKey(sender),
    recipient: VerificationKey(recipient),
    amount,
  }
}

fn t_vault_utxo(amount: Int, datum: Data) -> Output {
  Output {
    ..t_token_utxo(t_sender_stake, amount),
    address: Address {
      payment_credential: Script(t_plb_hash),
      stake_credential: Some(Inline(Script(t_approval_proxy_hash))),
    },
    datum: InlineDatum(datum),
  }
}

fn t_vault_input(ix: Int, pending: PendingTransfer) -> Input {
  Input {
    output_reference: t_out_ref(ix),
    output: t_vault_utxo(pending.amount, pending),
  }
}

fn t_tx(inputs: List<Input>, outputs: List<Output>) -> Transaction {
  Transaction { ..t_transfer_tx(False, False, False, False), inputs, outputs }
}

/// `n` clean actions per side: one per party is consumed positionally and
/// surplus actions are ignored, so this fits any party count up to `n`.
fn t_redeemer_n(n: Int) -> TransferLogicScriptWithdrawRedeemer {
  TransferLogicScriptWithdrawRedeemer {
    global_state_location: GlobalStateReferenced {
      global_state_ref_input_index: 1,
    },
    actions_for_each_input: list.repeat(t_source_action(), n),
    destination_actions: list.repeat(t_dest_action(), n),
  }
}

/// Switch on, at `threshold`, approval logic running.
fn on(threshold: Int, tx: Transaction) -> Bool {
  run_transfer(
    t_redeemer_n(4),
    with_approval_logic(with_approval(tx, True, threshold)),
  )
}

/// Switch off (the fixtures' default), approval logic running.
fn off(tx: Transaction) -> Bool {
  run_transfer(t_redeemer_n(4), with_approval_logic(tx))
}

/// Alice parks 1000 for Bob: the canonical request.
fn t_request_tx() -> Transaction {
  t_tx(
    [t_holder_input(10, t_sender_stake, 1_000)],
    [t_vault_utxo(1_000, t_pending(t_sender_stake, t_dest_stake, 1_000))],
  )
}

/// The approver releases it to Bob: the canonical settlement.
fn t_settlement_tx() -> Transaction {
  t_tx(
    [t_vault_input(11, t_pending(t_sender_stake, t_dest_stake, 1_000))],
    [t_token_utxo(t_dest_stake, 1_000)],
  )
}

// ── Requests (Tx 1) ──────────────────────────────────────────────────────────

test approval_request_to_the_vault_is_accepted_above_threshold() {
  on(0, t_request_tx())
}

test approval_request_requires_the_approval_logic() {
  // The approval logic binds the datum; without it no vault output passes.
  !run_transfer(t_redeemer_n(4), with_approval(t_request_tx(), True, 0))
}

test approval_request_is_refused_with_the_switch_off() fail {
  // Nothing can be parked while approval is off — so nothing can be parked
  // unbound.
  off(t_request_tx())
}

// ── Settlements (Tx 2) ───────────────────────────────────────────────────────

test approval_settlement_is_not_subject_to_the_threshold() {
  and {
    on(0, t_settlement_tx()),
    off(t_settlement_tx()),
    // The transfer logic does not demand the approval logic here: the vault's
    // owner (the proxy) does, through the base layer.
    run_transfer(t_redeemer_n(4), t_settlement_tx()),
  }
}

test approval_settlement_revets_the_recipient() {
  // Receiver KYC on; the genuine attestation is for t_dest_stake only.
  let redeemer = t_redeemer_with(
    t_source_action(),
    t_dest_action_with_proof(t_cip30_proof(t_dest_cip30())),
  )
  let base = t_transfer_tx_with_tel(False, True, t_tel_with(t_kyc_issuer_vkey))
  let settle = fn(recipient) {
    Transaction {
      ..base,
      inputs: [t_vault_input(11, t_pending(t_sender_stake, recipient, 1_000))],
      outputs: [t_token_utxo(recipient, 1_000)],
    }
  }
  and {
    run_transfer(redeemer, settle(t_dest_stake)),
    !run_transfer(redeemer, settle(t_other_stake)),
  }
}

test approval_settlement_is_blocked_by_pause() {
  !on(
    0,
    Transaction {
      ..t_transfer_tx(True, False, False, False),
      inputs: t_settlement_tx().inputs,
      outputs: t_settlement_tx().outputs,
    },
  )
}

// ── Switch ON: the approval logic runs in every transfer ─────────────────────

test approval_on_requires_the_approval_logic_in_every_transfer() {
  // Within any threshold, so only the missing approval logic can refuse.
  let plain = with_approval(
    t_transfer_tx(False, False, False, False),
    True,
    1_000_000,
  )
  let settlement = with_approval(t_settlement_tx(), True, 1_000_000)
  let wrong = fn(tx: Transaction) {
    Transaction {
      ..tx,
      withdrawals: [
        Pair(
          Script(#"51515151515151515151515151515151515151515151515151515151"),
          0,
        ),
      ],
    }
  }
  and {
    // Positive controls.
    run_transfer(t_redeemer_n(4), with_approval_logic(plain)),
    run_transfer(t_redeemer_n(4), with_approval_logic(settlement)),
    !run_transfer(t_redeemer_n(4), plain),
    !run_transfer(t_redeemer_n(4), settlement),
    // Another script's withdrawal (e.g. a retired approval logic) is not it.
    !run_transfer(t_redeemer_n(4), wrong(plain)),
  }
}

test approval_on_metadata_update_needs_the_approval_logic() {
  let update = with_approval(
    t_metadata_update_tx(t_cip68_output(t_sender_stake, t_cip68_datum())),
    True,
    0,
  )
  and {
    run_transfer(t_metadata_redeemer(), with_approval_logic(update)),
    !run_transfer(t_metadata_redeemer(), update),
  }
}

/// A request in a transaction that also spends GlobalState: the spent datum
/// has the switch `input_on`; the continuing GlobalState output switches it ON.
fn t_spent_gs_request(input_on: Bool) -> Transaction {
  let gs = t_gs_ref_input(False, False, False, False)
  let with_switch = fn(on) {
    Output {
      ..gs.output,
      datum: InlineDatum(
        GlobalStateDatum {
          ..t_gs_datum(False, False, False, False),
          approval_required: on,
        },
      ),
    }
  }
  with_approval_logic(
    Transaction {
      ..t_spent_gs_tx(),
      inputs: [
        t_sender_input(t_sender_stake, 1_000),
        Input { ..gs, output: with_switch(input_on) },
      ],
      outputs: [
        t_vault_utxo(1_000, t_pending(t_sender_stake, t_dest_stake, 1_000)),
        with_switch(True),
      ],
    },
  )
}

test approval_request_with_global_state_spent_and_on_is_accepted() {
  // Positive control for the test below: the spent datum has the switch on.
  run_transfer(
    t_spent_gs_redeemer(GlobalStateSpent { global_state_input_index: 1 }),
    t_spent_gs_request(True),
  )
}

test approval_switch_read_from_the_spent_pre_state() fail {
  // OFF -> ON in the same transaction: the spent (pre-transaction) datum has
  // approval off, so the vault output is refused although the continuing
  // GlobalState output switches it on.
  run_transfer(
    t_spent_gs_redeemer(GlobalStateSpent { global_state_input_index: 1 }),
    t_spent_gs_request(False),
  )
}

// ── The vault is no party ────────────────────────────────────────────────────

fn t_kyc_redeemer(
  sources: List<TransferLogicScriptAction>,
  destinations: List<TransferLogicScriptDestinationAction>,
) -> TransferLogicScriptWithdrawRedeemer {
  TransferLogicScriptWithdrawRedeemer {
    global_state_location: GlobalStateReferenced {
      global_state_ref_input_index: 1,
    },
    actions_for_each_input: sources,
    destination_actions: destinations,
  }
}

test vault_is_never_vetted_as_a_party() {
  // Sender AND receiver KYC on. A request carries only the sender's proof: the
  // vault output needs no destination action.
  let base = t_transfer_tx_with_tel(True, True, t_tel_with(t_kyc_issuer_vkey))
  let request = with_approval_logic(
    with_approval(
      Transaction {
        ..base,
        outputs: [
          t_vault_utxo(1_000, t_pending(t_sender_stake, t_dest_stake, 1_000)),
        ],
      },
      True,
      0,
    ),
  )
  run_transfer(
    t_kyc_redeemer(
      [t_source_action_with_proof(t_cip30_proof(t_sender_cip30()))],
      [],
    ),
    request,
  )
}

test request_does_not_vet_the_recipient() {
  // Receiver KYC on, recipient without any attestation: accepted at the
  // request (it is vetted when paid). Also the positive control for "switch
  // on + vault output + approval logic present".
  let base = t_transfer_tx_with_tel(False, True, t_tel_with(t_kyc_issuer_vkey))
  run_transfer(
    t_kyc_redeemer([t_source_action()], []),
    with_approval_logic(
      with_approval(
        Transaction {
          ..base,
          outputs: [
            t_vault_utxo(1_000, t_pending(t_sender_stake, t_other_stake, 1_000)),
          ],
        },
        True,
        0,
      ),
    ),
  )
}

test settlement_does_not_vet_the_original_sender() {
  // Owner decision D6 (2026-10-27): sender KYC on, the request's sender holds
  // no attestation — the settlement needs no source action; the admin's
  // signature (approval logic) is the screen.
  let base = t_transfer_tx_with_tel(True, False, t_tel_with(t_kyc_issuer_vkey))
  run_transfer(
    t_kyc_redeemer([], [t_dest_action()]),
    Transaction {
      ..base,
      inputs: [t_vault_input(11, t_pending(t_other_stake, t_dest_stake, 1_000))],
      outputs: [t_token_utxo(t_dest_stake, 1_000)],
    },
  )
}

// ── Partial freeze (denylist `frozen_amount`) ─────────────────────────────────
//
// A listed holder cites its OWN node; `None` is a full freeze, `Some(f)` lets
// it receive freely and send only while paying at least `f` back to itself
// (or, below the floor, everything it spends — see the section at the end).
//
// Keys, in list order: A = 0a… (t_sender_stake), C = 0b… (t_dest_stake),
// B = 0c…, D = 0d…. Reference inputs: 0 registry, 1 GlobalState, 2 denylist
// root, 3+ denylist nodes — built per test, because each test needs its own
// list. KYC is off throughout: these tests are about the denylist gate only.

const pf_b: ByteArray =
  #"0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c"

const pf_d: ByteArray =
  #"0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d"

fn pf_root(link: Option<ByteArray>) -> Input {
  let element: Element<Data, Data> = Element {
    data: Root { data: builtin.constr_data(0, []) },
    link,
  }
  Input {
    ..t_denylist_root_ref_input(),
    output: Output {
      ..t_denylist_root_ref_input().output,
      datum: InlineDatum(element),
    },
  }
}

/// A denylist node at the list's own address, holding `data` as its entry.
fn pf_node_with_data(
  ix: Int,
  key: ByteArray,
  link: Option<ByteArray>,
  data: Data,
) -> Input {
  let element: Element<Data, Data> = Element { data: Node { data }, link }
  Input {
    output_reference: t_out_ref(20 + ix),
    output: Output {
      address: Address {
        payment_credential: Script(t_denylist_script_hash),
        stake_credential: None,
      },
      value: merge(
        from_lovelace(2_000_000),
        from_asset(
          t_denylist_policy,
          bytearray.concat(constants.linked_list_node_key_prefix, key),
          1,
        ),
      ),
      datum: InlineDatum(element),
      reference_script: None,
    },
  }
}

fn pf_node(
  ix: Int,
  key: ByteArray,
  link: Option<ByteArray>,
  frozen_amount: Option<Int>,
) -> Input {
  pf_node_with_data(
    ix,
    key,
    link,
    Denylist { frozen_amount, metadata: builtin.constr_data(0, []) },
  )
}

fn pf_input(ix: Int, stake: Credential, amount: Int) -> Input {
  Input {
    output_reference: t_out_ref(10 + ix),
    output: Output {
      ..t_token_utxo(#"", amount),
      address: Address {
        payment_credential: Script(t_plb_hash),
        stake_credential: Some(Inline(stake)),
      },
    },
  }
}

fn pf_output(stake: Credential, amount: Int) -> Output {
  Output {
    ..t_token_utxo(#"", amount),
    address: Address {
      payment_credential: Script(t_plb_hash),
      stake_credential: Some(Inline(stake)),
    },
  }
}

fn pf_src(index: Int) -> TransferLogicScriptAction {
  TransferLogicScriptAction {
    source_proof: dummy_proof(),
    source_denylist_ref_input_index: index,
  }
}

fn pf_dst(index: Int) -> TransferLogicScriptDestinationAction {
  TransferLogicScriptDestinationAction {
    destination_proof: dummy_proof(),
    destination_denylist_ref_input_index: index,
  }
}

fn pf_run(
  nodes: List<Input>,
  inputs: List<Input>,
  outputs: List<Output>,
  sources: List<TransferLogicScriptAction>,
  destinations: List<TransferLogicScriptDestinationAction>,
) -> Bool {
  let tx = Transaction {
    ..t_transfer_tx(False, False, False, False),
    inputs,
    outputs,
    reference_inputs: [
      t_registry_ref_input(),
      t_gs_ref_input(False, False, False, False),
      ..nodes
    ],
  }
  run_transfer(
    TransferLogicScriptWithdrawRedeemer {
      ..t_redeemer(),
      actions_for_each_input: sources,
      destination_actions: destinations,
    },
    tx,
  )
}

/// Root → A(frozen_amount) → end. Index 2 root, 3 A's node.
fn pf_list_a(frozen_amount: Option<Int>) -> List<Input> {
  [
    pf_root(Some(t_sender_stake)),
    pf_node(0, t_sender_stake, None, frozen_amount),
  ]
}

fn pf_a() -> Credential {
  VerificationKey(t_sender_stake)
}

fn pf_c() -> Credential {
  VerificationKey(t_dest_stake)
}

// A (frozen 400) sends 600 of 1000 to C and keeps exactly 400: the floor holds.
test partially_frozen_sender_may_send_above_the_floor() {
  pf_run(
    pf_list_a(Some(400)),
    [pf_input(0, pf_a(), 1_000)],
    [pf_output(pf_c(), 600), pf_output(pf_a(), 400)],
    [pf_src(3)],
    // C is covered by A's node (0a < 0b, A is the tail); A by its own node.
    [pf_dst(3), pf_dst(3)],
  )
}

// One token too far: A keeps 399 < 400.
test partially_frozen_sender_may_not_breach_the_floor() {
  !pf_run(
    pf_list_a(Some(400)),
    [pf_input(0, pf_a(), 1_000)],
    [pf_output(pf_c(), 601), pf_output(pf_a(), 399)],
    [pf_src(3)],
    [pf_dst(3), pf_dst(3)],
  )
}

// A full freeze is unchanged: paying everything back does not help.
test fully_frozen_sender_is_rejected_even_when_paying_everything_back() {
  !pf_run(
    pf_list_a(None),
    [pf_input(0, pf_a(), 1_000)],
    [pf_output(pf_a(), 1_000)],
    [pf_src(3)],
    [pf_dst(3)],
  )
}

// Sender side in isolation: A appears only as a sender (all 1_000 go to C),
// so nothing but A's own `None` node can reject the transaction.
test fully_frozen_sender_alone_is_rejected() {
  !pf_run(
    pf_list_a(None),
    [pf_input(0, pf_a(), 1_000)],
    [pf_output(pf_c(), 1_000)],
    [pf_src(3)],
    [pf_dst(3)],
  )
}

// Positive control for the isolated sender tests: the same shape, with A
// partially frozen at 1 and keeping 1.
test partially_frozen_sender_alone_keeping_its_floor_passes() {
  pf_run(
    pf_list_a(Some(1)),
    [pf_input(0, pf_a(), 1_000)],
    [pf_output(pf_c(), 999), pf_output(pf_a(), 1)],
    [pf_src(3)],
    [pf_dst(3), pf_dst(3)],
  )
}

// A partially frozen holder receives freely.
test partially_frozen_receiver_is_accepted() {
  pf_run(
    pf_list_a(Some(400)),
    [pf_input(0, pf_c(), 1_000)],
    [pf_output(pf_a(), 1_000)],
    [pf_src(3)],
    [pf_dst(3)],
  )
}

// …a fully frozen one does not.
test fully_frozen_receiver_is_rejected() {
  !pf_run(
    pf_list_a(None),
    [pf_input(0, pf_c(), 1_000)],
    [pf_output(pf_a(), 1_000)],
    [pf_src(3)],
    [pf_dst(3)],
  )
}

// A copy of A's node held anywhere but the denylist's own address
// authenticates nothing — here under a foreign SCRIPT, so it is the hash
// equality, not the credential kind, that must reject it.
test partially_frozen_proof_from_a_node_outside_the_list_is_rejected() fail {
  let wallet_node = Input {
    ..pf_node(0, t_sender_stake, None, Some(1)),
    output: Output {
      ..pf_node(0, t_sender_stake, None, Some(1)).output,
      address: Address {
        payment_credential: Script(t_third_party_hash),
        stake_credential: None,
      },
    },
  }
  pf_run(
    [pf_root(Some(t_sender_stake)), wallet_node],
    [pf_input(0, pf_a(), 1_000)],
    [pf_output(pf_c(), 999), pf_output(pf_a(), 1)],
    [pf_src(3)],
    // Every proof leans on the wallet copy, so the address pin is the only
    // thing that can reject this transaction.
    [pf_dst(3), pf_dst(3)],
  )
}

// Only the security asset of the pinned policy counts as paid back: 400 of
// another asset name to A does not keep the floor.
test paid_back_counts_only_the_security_asset() {
  let other_name_to_a = Output {
    ..pf_output(pf_a(), 1),
    value: merge(
      from_lovelace(2_000_000),
      from_asset(t_issuance_policy, "OTHER", 400),
    ),
  }
  !pf_run(
    pf_list_a(Some(400)),
    [pf_input(0, pf_a(), 1_000)],
    [pf_output(pf_c(), 1_000), other_name_to_a],
    [pf_src(3)],
    [pf_dst(3)],
  )
}

// …and neither does another policy's token under the same name.
test paid_back_ignores_another_policy() {
  let other_policy_to_a = Output {
    ..pf_output(pf_a(), 1),
    value: merge(
      from_lovelace(2_000_000),
      from_asset(t_gs_policy, t_sec_name, 400),
    ),
  }
  !pf_run(
    pf_list_a(Some(400)),
    [pf_input(0, pf_a(), 1_000)],
    [pf_output(pf_c(), 1_000), other_policy_to_a],
    [pf_src(3)],
    [pf_dst(3)],
  )
}

// An ADA-only output without any stake credential is skipped, not trapped on.
test paid_back_skips_outputs_without_the_security_token() {
  let ada_change = Output {
    address: Address {
      payment_credential: VerificationKey(t_dest_stake),
      stake_credential: None,
    },
    value: from_lovelace(5_000_000),
    datum: NoDatum,
    reference_script: None,
  }
  pf_run(
    pf_list_a(Some(400)),
    [pf_input(0, pf_a(), 1_000)],
    [ada_change, pf_output(pf_c(), 600), pf_output(pf_a(), 400)],
    [pf_src(3)],
    [pf_dst(3), pf_dst(3)],
  )
}

// The freeze is on the HASH: paying back to the script form of A's hash keeps
// the floor (and that form receives through the same node).
test paid_back_counts_the_other_credential_form_of_the_same_hash() {
  pf_run(
    pf_list_a(Some(400)),
    [pf_input(0, pf_a(), 1_000)],
    [pf_output(pf_c(), 600), pf_output(Script(t_sender_stake), 400)],
    [pf_src(3)],
    [pf_dst(3), pf_dst(3)],
  )
}

// …but paying "back" to anyone else's hash does not.
test paid_back_to_a_different_hash_does_not_count() {
  !pf_run(
    pf_list_a(Some(400)),
    [pf_input(0, pf_a(), 1_000)],
    [pf_output(pf_c(), 600), pf_output(VerificationKey(pf_d), 400)],
    [pf_src(3)],
    [pf_dst(3), pf_dst(3)],
  )
}

// Both credential forms of A as senders share A's node through the memo and
// the one paid-back sum: kept floor → pass.
test both_credential_forms_of_a_partially_frozen_hash_pass_together() {
  pf_run(
    pf_list_a(Some(400)),
    [pf_input(0, pf_a(), 500), pf_input(1, Script(t_sender_stake), 500)],
    [pf_output(pf_c(), 600), pf_output(pf_a(), 400)],
    [pf_src(3), pf_src(3)],
    [pf_dst(3), pf_dst(3)],
  )
}

// …breached floor → both fail, so the transaction does.
test both_credential_forms_of_a_partially_frozen_hash_fail_together() {
  !pf_run(
    pf_list_a(Some(400)),
    [pf_input(0, pf_a(), 500), pf_input(1, Script(t_sender_stake), 500)],
    [pf_output(pf_c(), 601), pf_output(pf_a(), 399)],
    [pf_src(3), pf_src(3)],
    [pf_dst(3), pf_dst(3)],
  )
}

// A node whose entry does not decode as `Denylist` rejects its holder cleanly
// — as a sender…
test undecodable_own_node_rejects_the_sender() {
  !pf_run(
    [
      pf_root(Some(t_sender_stake)),
      pf_node_with_data(0, t_sender_stake, None, builtin.constr_data(0, [])),
    ],
    [pf_input(0, pf_a(), 1_000)],
    [pf_output(pf_c(), 600), pf_output(pf_a(), 400)],
    [pf_src(3)],
    [pf_dst(3), pf_dst(3)],
  )
}

// Sender side in isolation: A only sends, so only its undecodable node can
// reject.
test undecodable_own_node_rejects_a_sender_alone() {
  !pf_run(
    [
      pf_root(Some(t_sender_stake)),
      pf_node_with_data(0, t_sender_stake, None, builtin.constr_data(0, [])),
    ],
    [pf_input(0, pf_a(), 1_000)],
    [pf_output(pf_c(), 1_000)],
    [pf_src(3)],
    [pf_dst(3)],
  )
}

// …and as a receiver.
test undecodable_own_node_rejects_the_receiver() {
  !pf_run(
    [
      pf_root(Some(t_sender_stake)),
      pf_node_with_data(0, t_sender_stake, None, builtin.constr_data(0, [])),
    ],
    [pf_input(0, pf_c(), 1_000)],
    [pf_output(pf_a(), 1_000)],
    [pf_src(3)],
    [pf_dst(3)],
  )
}

// ── Partial freeze through the covering-node memo ─────────────────────────────
//
// List: root → A(Some 400) → B(None) → end. Index 2 root, 3 A, 4 B. C sits
// between A and B, so A's node legitimately covers C — and only C.

fn pf_list_ab() -> List<Input> {
  [
    pf_root(Some(t_sender_stake)),
    pf_node(0, t_sender_stake, Some(pf_b), Some(400)),
    pf_node(1, pf_b, None, None),
  ]
}

// (a) A first proves membership with node 3; B then cites node 3 too. The memo
// hands B the same element, which neither is B's node nor covers B: rejected.
// A cached "permitted" verdict would wave B through.
test memo_never_lends_a_membership_proof_to_the_next_party() {
  !pf_run(
    pf_list_ab(),
    [pf_input(0, pf_a(), 1_000), pf_input(1, VerificationKey(pf_b), 1)],
    [pf_output(pf_a(), 1_001)],
    [pf_src(3), pf_src(3)],
    [pf_dst(3)],
  )
}

// (b1) C first (covered by node 3, fresh), A second on the REMEMBERED element:
// A's membership is still recognised and its floor (kept) honoured.
test memo_recognises_membership_on_the_remembered_element() {
  pf_run(
    pf_list_ab(),
    [pf_input(0, pf_c(), 100), pf_input(1, pf_a(), 1_000)],
    [pf_output(VerificationKey(pf_d), 700), pf_output(pf_a(), 400)],
    [pf_src(3), pf_src(3)],
    // D is past B, so B's node covers D.
    [pf_dst(4), pf_dst(3)],
  )
}

// (b2) Same shape, floor breached: the remembered path enforces it too.
test memo_enforces_the_floor_on_the_remembered_element() {
  !pf_run(
    pf_list_ab(),
    [pf_input(0, pf_c(), 100), pf_input(1, pf_a(), 1_000)],
    [pf_output(VerificationKey(pf_d), 701), pf_output(pf_a(), 399)],
    [pf_src(3), pf_src(3)],
    [pf_dst(4), pf_dst(3)],
  )
}

// (d) A first on its own node; C second, covered by that same remembered
// element: an absence proof still works through the memo.
test memo_lets_a_membership_node_cover_the_next_party() {
  pf_run(
    pf_list_ab(),
    [pf_input(0, pf_a(), 1_000), pf_input(1, pf_c(), 100)],
    [pf_output(VerificationKey(pf_d), 700), pf_output(pf_a(), 400)],
    [pf_src(3), pf_src(3)],
    [pf_dst(4), pf_dst(3)],
  )
}

// (c) Two partially frozen senders on different nodes; the outputs keep A's
// floor but not D's.
test each_partially_frozen_sender_keeps_its_own_floor() {
  let list = [
    pf_root(Some(t_sender_stake)),
    pf_node(0, t_sender_stake, Some(pf_d), Some(400)),
    pf_node(1, pf_d, None, Some(300)),
  ]
  !pf_run(
    list,
    [pf_input(0, pf_a(), 1_000), pf_input(1, VerificationKey(pf_d), 1_000)],
    [
      pf_output(pf_c(), 1_301),
      pf_output(pf_a(), 400),
      pf_output(VerificationKey(pf_d), 299),
    ],
    [pf_src(3), pf_src(4)],
    [pf_dst(3), pf_dst(3), pf_dst(4)],
  )
}

// (c, control) Both floors kept: pass.
test both_partially_frozen_senders_keeping_their_floors_pass() {
  let list = [
    pf_root(Some(t_sender_stake)),
    pf_node(0, t_sender_stake, Some(pf_d), Some(400)),
    pf_node(1, pf_d, None, Some(300)),
  ]
  pf_run(
    list,
    [pf_input(0, pf_a(), 1_000), pf_input(1, VerificationKey(pf_d), 1_000)],
    [
      pf_output(pf_c(), 1_300),
      pf_output(pf_a(), 400),
      pf_output(VerificationKey(pf_d), 300),
    ],
    [pf_src(3), pf_src(4)],
    [pf_dst(3), pf_dst(3), pf_dst(4)],
  )
}

// ── `party_permitted`'s covering arms ─────────────────────────────────────────
//
// A listed party must not get past the gate by citing some OTHER element.
// Before partial freezes these were pinned through `covers_key` by the
// sanctioned-holder tests; those now take the own-node branch, so the covering
// arms are pinned here.

// A fully frozen A cites a node that sorts ABOVE it (D): D's key is not below
// A, so D cannot cover A.
test fully_frozen_sender_cannot_cite_a_later_node() {
  let list = [
    pf_root(Some(t_sender_stake)),
    pf_node(0, t_sender_stake, Some(pf_d), None),
    pf_node(1, pf_d, None, Some(300)),
  ]
  !pf_run(
    list,
    [pf_input(0, pf_a(), 1_000)],
    [pf_output(pf_c(), 1_000)],
    [pf_src(4)],
    [pf_dst(3)],
  )
}

// A fully frozen A, the first listed key, cites the ROOT: the root's link IS
// A, so the root cannot cover A.
test fully_frozen_first_listed_sender_cannot_cite_the_root() {
  !pf_run(
    pf_list_a(None),
    [pf_input(0, pf_a(), 1_000)],
    [pf_output(pf_c(), 1_000)],
    [pf_src(2)],
    [pf_dst(3)],
  )
}

// Positive control for the shape: an unlisted A below the whole list is
// covered by the root.
test unlisted_sender_below_the_list_is_covered_by_the_root() {
  pf_run(
    [pf_root(Some(pf_d)), pf_node(0, pf_d, None, None)],
    [pf_input(0, pf_a(), 1_000)],
    [pf_output(pf_c(), 1_000)],
    [pf_src(2)],
    [pf_dst(2)],
  )
}

// ── Receiving is never limited by a partial freeze ───────────────────────────

// C (unlisted, covered by A's node) sends 100 to A, frozen at 400: A receives
// far less than its floor and is still accepted. A floor applied to the
// receiving side would reject this.
test partially_frozen_receiver_may_receive_less_than_its_floor() {
  pf_run(
    pf_list_a(Some(400)),
    [pf_input(0, pf_c(), 1_000)],
    [pf_output(pf_a(), 100), pf_output(pf_c(), 900)],
    [pf_src(3)],
    [pf_dst(3), pf_dst(3)],
  )
}

// ── Malformed own nodes fail closed ──────────────────────────────────────────
//
// The receiving side is the strict probe: its callback accepts any `Some`, so
// a looser decoder that read a malformed entry as `Some(_)` would let the
// receiver through. C (unlisted, covered by A's node) sends 1000 to A.

fn pf_receive_with_own_node_data(data: Data) -> Bool {
  pf_run(
    [
      pf_root(Some(t_sender_stake)),
      pf_node_with_data(0, t_sender_stake, None, data),
    ],
    [pf_input(0, pf_c(), 1_000)],
    [pf_output(pf_a(), 1_000)],
    [pf_src(3)],
    [pf_dst(3)],
  )
}

test own_node_in_the_old_one_field_shape_rejects_the_receiver() {
  !pf_receive_with_own_node_data(
    builtin.constr_data(0, [builtin.constr_data(0, [])]),
  )
}

test own_node_with_a_trailing_field_rejects_the_receiver() {
  !pf_receive_with_own_node_data(
    builtin.constr_data(
      0,
      [
        builtin.constr_data(0, [builtin.i_data(400)]),
        builtin.constr_data(0, []),
        builtin.i_data(1),
      ],
    ),
  )
}

test own_node_with_a_foreign_option_constructor_rejects_the_receiver() {
  !pf_receive_with_own_node_data(
    builtin.constr_data(
      0,
      [builtin.constr_data(2, []), builtin.constr_data(0, [])],
    ),
  )
}

test own_node_with_bytes_inside_some_rejects_the_receiver() {
  !pf_receive_with_own_node_data(
    builtin.constr_data(
      0,
      [
        builtin.constr_data(0, [builtin.b_data(#"01")]),
        builtin.constr_data(0, []),
      ],
    ),
  )
}

test own_node_with_an_int_for_the_option_rejects_the_receiver() {
  !pf_receive_with_own_node_data(
    builtin.constr_data(0, [builtin.i_data(400), builtin.constr_data(0, [])]),
  )
}

// Positive control: the same shape with a well-formed partial freeze passes.
test own_node_well_formed_partial_freeze_admits_the_receiver() {
  let entry: Data = Denylist {
    frozen_amount: Some(400),
    metadata: builtin.constr_data(0, []),
  }
  pf_receive_with_own_node_data(entry)
}

// ── Partial freeze × receiver KYC (documented limitation) ────────────────────
//
// The floor makes a partially frozen sender pay tokens back to itself (`f`,
// or all it spends), which makes it a DESTINATION of its own transaction. With
// `requires_receiver_kyc` set, it therefore needs a valid KYC proof as a
// receiver too: a partially frozen holder whose KYC has lapsed cannot send at
// all until it renews its KYC. Deliberate, kept simple (owner decision
// 2026-10-23). A self-send makes A the only destination, so A's own (invalid)
// proof is the only thing that can reject.

fn pf_self_send(requires_receiver_kyc: Bool) -> Bool {
  let tx = Transaction {
    ..t_transfer_tx(False, False, False, requires_receiver_kyc),
    inputs: [pf_input(0, pf_a(), 1_000)],
    outputs: [pf_output(pf_a(), 1_000)],
    reference_inputs: [
      t_registry_ref_input(),
      t_gs_ref_input(False, False, False, requires_receiver_kyc),
      ..pf_list_a(Some(400))
    ],
  }
  run_transfer(
    TransferLogicScriptWithdrawRedeemer {
      ..t_redeemer(),
      actions_for_each_input: [pf_src(3)],
      destination_actions: [pf_dst(3)],
    },
    tx,
  )
}

test partially_frozen_sender_without_valid_kyc_is_blocked_by_receiver_kyc() {
  !pf_self_send(True)
}

// Control: the same transaction with receiver KYC off passes.
test partially_frozen_sender_self_send_passes_without_receiver_kyc() {
  pf_self_send(False)
}

// ── The multi-party walk: one element per index, judged per party ─────────────
//
// `compliance.vet_remembering` carries the last authenticated element through
// the walk. These pin what that element may and may not be used for, in the
// index patterns the earlier tests did not reach: a rejected FIRST party among
// several, [i, j, i] and [i, j, j]. List N2: root → A (link B) → B → end;
// index 2 root, 3 A's node (covers 0a < x < 0c: C, C2), 4 B's node (covers
// x > 0c: D, E). In every N2 test the single destination (D, citing 4)
// passes, so each rejects only for the sender named; the first test uses its
// own one-node list, where the destination C cites A's node and passes.

const pf_c2: ByteArray =
  #"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b00"

const pf_e: ByteArray =
  #"0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e"

fn pf_list_n2() -> List<Input> {
  [
    pf_root(Some(t_sender_stake)),
    pf_node(0, t_sender_stake, Some(pf_b), None),
    pf_node(1, pf_b, None, None),
  ]
}

fn pf_walk(senders: List<ByteArray>, indices: List<Int>) -> Bool {
  pf_run(
    pf_list_n2(),
    list.indexed_map(
      senders,
      fn(i, key) { pf_input(i, VerificationKey(key), 1) },
    ),
    [pf_output(VerificationKey(pf_d), list.length(senders))],
    list.map(indices, pf_src),
    [pf_dst(4)],
  )
}

// The first of two senders is fully frozen and cites its own node; the second
// is clean and covered by that same element. The first party's own decision
// must reject — the second passing must not carry the transaction.
test memo_rejects_a_fully_frozen_first_party_among_several() {
  !pf_run(
    pf_list_a(None),
    [pf_input(0, pf_a(), 1_000), pf_input(1, pf_c(), 1_000)],
    [pf_output(pf_c(), 2_000)],
    [pf_src(3), pf_src(3)],
    [pf_dst(3)],
  )
}

// [i, j, i]: C (3), D (4), E (3). E is not covered by A's node. A walk that
// remembered index 3 alongside B's element would judge E against B, which
// covers it.
test memo_never_judges_a_party_against_another_index_element() {
  !pf_walk([t_dest_stake, pf_d, pf_e], [3, 4, 3])
}

// [i, j, j]: C2 (3), D (4), C (4). C is not covered by B's node. A walk that
// remembered index 4 alongside A's (stale) element would judge C against A,
// which covers it.
test memo_never_judges_a_party_against_a_stale_element() {
  !pf_walk([pf_c2, pf_d, t_dest_stake], [3, 4, 4])
}

// Control for [i, j, i]: the third party is one A's node does cover.
test memo_accepts_an_i_j_i_walk_of_covered_parties() {
  pf_walk([t_dest_stake, pf_d, pf_c2], [3, 4, 3])
}

// Control for [i, j, j]: the third party is one B's node does cover.
test memo_accepts_an_i_j_j_walk_of_covered_parties() {
  pf_walk([pf_c2, pf_d, pf_e], [3, 4, 4])
}

// Three senders, two actions: the third party, reached on the remembered path,
// has no action and the walk traps. (`fail` also accepts a clean rejection;
// what this guards against is the third party being silently ACCEPTED.)
test memo_path_traps_on_a_short_action_list() fail {
  pf_walk([t_dest_stake, pf_c2, pf_d], [3, 3])
}

// The second party cites index 1, the GlobalState UTxO — not a list element —
// so authenticating it afresh inside the walk traps. The second party is C2,
// which the FIRST party's element (A's node) covers: a walk that reused that
// element instead of authenticating index 1 would accept. (`fail` also
// accepts a clean rejection; what this guards against is the second party
// being silently ACCEPTED.)
test fresh_element_that_fails_authentication_traps_on_a_later_party() fail {
  pf_walk([t_dest_stake, pf_c2], [3, 1])
}

// ── Benches: parties covered by ordinary (non-root) nodes ─────────────────────
//
// `transfer_cost_by_party_count` cites the root, whose key is `None`; these
// cite nodes with a key, the arm every unlisted holder of a non-empty list
// takes. K0 and K1 sort below every `t_bench_hash` (its fifth byte is 1a or
// 2b) and have no successor, so each covers every party.

const t_bench_k0: ByteArray =
  #"00000000000000000000000000000000000000000000000000000000"

const t_bench_k1: ByteArray =
  #"00000000000000000000000000000000000000000000000000000001"

fn t_bench_node_tx(n: Int) -> Transaction {
  let base = t_transfer_tx(False, False, False, False)
  Transaction {
    ..base,
    inputs: list.map(list.range(0, n - 1), t_bench_sender_input),
    outputs: list.map(list.range(0, n - 1), t_bench_dest_output),
    reference_inputs: list.concat(
      base.reference_inputs,
      [pf_node(0, t_bench_k0, None, None), pf_node(1, t_bench_k1, None, None)],
    ),
  }
}

fn t_bench_node_redeemer(
  index_of: fn(Int) -> Int,
  n: Int,
) -> TransferLogicScriptWithdrawRedeemer {
  let indices = list.map(list.range(0, n - 1), index_of)
  TransferLogicScriptWithdrawRedeemer {
    global_state_location: GlobalStateReferenced {
      global_state_ref_input_index: 1,
    },
    actions_for_each_input: list.map(indices, pf_src),
    destination_actions: list.map(indices, pf_dst),
  }
}

// Every party cites K0: the remembered element serves all but the first.
bench transfer_cost_by_party_count_shared_node(n via n_parties) {
  expect run_transfer(t_bench_node_redeemer(fn(_) { 3 }, n), t_bench_node_tx(n))
}

// Parties alternate between K0 and K1: every party re-authenticates.
bench transfer_cost_by_party_count_alternating_nodes(n via n_parties) {
  expect
    run_transfer(
      t_bench_node_redeemer(fn(i) { 3 + i % 2 }, n),
      t_bench_node_tx(n),
    )
}

// ── Partial freeze below the floor: sends that do not lower the balance ──────
//
// A partially frozen sender passes if the transaction pays back at least `f`,
// OR at least what it spends from the holder's hash: then
// its balance cannot fall, so `post ≥ min(pre, f)`. List: root → A(f) → end,
// index 3 is A's node and also covers C (0b) and D (0d).

fn pf_a_script() -> Credential {
  Script(t_sender_stake)
}

/// An ADA-only wallet input with NO stake credential (a fee input).
fn pf_ada_input(ix: Int) -> Input {
  Input {
    output_reference: t_out_ref(40 + ix),
    output: Output {
      address: Address {
        payment_credential: VerificationKey(pf_e),
        stake_credential: None,
      },
      value: from_lovelace(5_000_000),
      datum: NoDatum,
      reference_script: None,
    },
  }
}

// A (frozen 400) holds 150 + 150 and merges them into one UTxO: nothing leaves.
test partially_frozen_sender_below_the_floor_may_consolidate() {
  pf_run(
    pf_list_a(Some(400)),
    [pf_input(0, pf_a(), 150), pf_input(1, pf_a(), 150)],
    [pf_output(pf_a(), 300)],
    [pf_src(3)],
    [pf_dst(3)],
  )
}

// …but exporting even one token is rejected.
test partially_frozen_sender_below_the_floor_may_not_export_one_token() {
  !pf_run(
    pf_list_a(Some(400)),
    [pf_input(0, pf_a(), 150), pf_input(1, pf_a(), 150)],
    [pf_output(pf_a(), 299), pf_output(pf_c(), 1)],
    [pf_src(3)],
    [pf_dst(3), pf_dst(3)],
  )
}

// An `f` above the holder's whole balance no longer blocks consolidation.
test partially_frozen_sender_below_the_floor_with_f_above_its_balance_may_consolidate() {
  pf_run(
    pf_list_a(Some(10_000)),
    [pf_input(0, pf_a(), 600), pf_input(1, pf_a(), 400)],
    [pf_output(pf_a(), 1_000)],
    [pf_src(3)],
    [pf_dst(3)],
  )
}

// Hot-path cost pin: above the floor with A's balance over eight inputs. Its
// cost delta against the one-input `..._may_send_above_the_floor` shows the
// inputs are not counted when `paid_back ≥ f`.
test partially_frozen_sender_above_the_floor_with_eight_inputs() {
  pf_run(
    pf_list_a(Some(400)),
    list.map(list.range(0, 7), fn(i) { pf_input(i, pf_a(), 125) }),
    [pf_output(pf_c(), 600), pf_output(pf_a(), 400)],
    [pf_src(3)],
    [pf_dst(3), pf_dst(3)],
  )
}

// What is spent is counted by bare hash: spending under both credential forms
// and paying back only one form's worth is an export.
test below_floor_spent_counts_both_credential_forms() {
  !pf_run(
    pf_list_a(Some(400)),
    [pf_input(0, pf_a(), 150), pf_input(1, pf_a_script(), 150)],
    [pf_output(pf_a(), 150), pf_output(pf_c(), 150)],
    [pf_src(3), pf_src(3)],
    [pf_dst(3), pf_dst(3)],
  )
}

// Control: the same inputs, everything paid back across both forms.
test below_floor_both_credential_forms_paying_back_everything_pass() {
  pf_run(
    pf_list_a(Some(400)),
    [pf_input(0, pf_a(), 150), pf_input(1, pf_a_script(), 150)],
    [pf_output(pf_a(), 200), pf_output(pf_a_script(), 100)],
    [pf_src(3), pf_src(3)],
    [pf_dst(3), pf_dst(3)],
  )
}

// Paid back to the other credential form of the hash still counts (and, as
// on the `≥ f` path, strands those tokens if A cannot authorise that form).
test below_floor_pay_back_to_the_other_credential_form_counts() {
  pf_run(
    pf_list_a(Some(400)),
    [pf_input(0, pf_a(), 300)],
    [pf_output(pf_a_script(), 300)],
    [pf_src(3)],
    [pf_dst(3)],
  )
}

// An unlisted sender's input comes before A's in an accept test: C's tokens
// are not counted as A's spending, and A, paying back all it spends, passes.
test below_floor_unlisted_senders_input_first_still_passes() {
  pf_run(
    pf_list_a(Some(400)),
    [pf_input(0, pf_c(), 100), pf_input(1, pf_a(), 300)],
    [pf_output(pf_c(), 100), pf_output(pf_a(), 300)],
    [pf_src(3), pf_src(3)],
    [pf_dst(3), pf_dst(3)],
  )
}

// Strict inflow: A spends 150 and ends with 250 (C pays it 100), still < f.
test below_floor_paid_back_above_spent_is_accepted() {
  pf_run(
    pf_list_a(Some(400)),
    [pf_input(0, pf_c(), 100), pf_input(1, pf_a(), 150)],
    [pf_output(pf_a(), 250)],
    [pf_src(3), pf_src(3)],
    [pf_dst(3)],
  )
}

// Another holder's large input is not counted as A's spending.
test below_floor_spent_ignores_other_holders_inputs() {
  pf_run(
    pf_list_a(Some(400)),
    [pf_input(0, pf_a(), 300), pf_input(1, pf_c(), 1_000)],
    [pf_output(pf_a(), 300), pf_output(pf_c(), 1_000)],
    [pf_src(3), pf_src(3)],
    [pf_dst(3), pf_dst(3)],
  )
}

// Another holder's input before A's does not hide A's export of one token.
test below_floor_another_holders_input_does_not_hide_an_export() {
  !pf_run(
    pf_list_a(Some(400)),
    [
      pf_input(0, pf_c(), 500),
      pf_input(1, pf_a(), 150),
      pf_input(2, pf_a(), 150),
    ],
    [pf_output(pf_c(), 500), pf_output(pf_a(), 299), pf_output(pf_c(), 1)],
    [pf_src(3), pf_src(3)],
    [pf_dst(3), pf_dst(3)],
  )
}

// An input without a stake credential is skipped, not trapped on…
test below_floor_input_without_a_stake_credential_is_skipped() {
  pf_run(
    pf_list_a(Some(400)),
    [pf_ada_input(0), pf_input(0, pf_a(), 150), pf_input(1, pf_a(), 150)],
    [pf_output(pf_a(), 300)],
    [pf_src(3)],
    [pf_dst(3)],
  )
}

// …and does not hide an export of one token after it.
test below_floor_input_without_a_stake_credential_does_not_hide_an_export() {
  !pf_run(
    pf_list_a(Some(400)),
    [pf_ada_input(0), pf_input(0, pf_a(), 150), pf_input(1, pf_a(), 150)],
    [pf_output(pf_a(), 299), pf_output(pf_c(), 1)],
    [pf_src(3)],
    [pf_dst(3), pf_dst(3)],
  )
}

// An input at A's address holding only another asset name spends nothing of
// the security token, so it counts as nothing spent.
test below_floor_holder_input_without_the_security_asset_counts_as_nothing_spent() {
  let other_name_value = merge(
    from_lovelace(2_000_000),
    from_asset(t_issuance_policy, "OTHER", 1_000),
  )
  let other_name_input = Input {
    ..pf_input(1, pf_a(), 1),
    output: Output { ..pf_output(pf_a(), 1), value: other_name_value },
  }
  pf_run(
    pf_list_a(Some(400)),
    [other_name_input, pf_input(0, pf_a(), 150)],
    [
      pf_output(pf_a(), 150),
      Output { ..pf_output(pf_a(), 1), value: other_name_value },
    ],
    [pf_src(3)],
    [pf_dst(3)],
  )
}

// Two partially frozen senders, A and D, each judged on its own hash and
// spending. List: root → A(400) → D(400) → end; index 3 A (covers C), 4 D.
fn pf_list_ad() -> List<Input> {
  [
    pf_root(Some(t_sender_stake)),
    pf_node(0, t_sender_stake, Some(pf_d), Some(400)),
    pf_node(1, pf_d, None, Some(400)),
  ]
}

// A consolidates, D exports 1. Judged against A's inputs (100 ≤ 149), D would
// pass, so only D's own spending rejects.
test below_floor_two_senders_are_judged_on_their_own_spending() {
  !pf_run(
    pf_list_ad(),
    [pf_input(0, pf_a(), 100), pf_input(1, VerificationKey(pf_d), 150)],
    [
      pf_output(pf_a(), 100),
      pf_output(VerificationKey(pf_d), 149),
      pf_output(pf_c(), 1),
    ],
    [pf_src(3), pf_src(4)],
    [pf_dst(3), pf_dst(4), pf_dst(3)],
  )
}

// Control: both consolidate.
test below_floor_two_senders_both_consolidating_pass() {
  pf_run(
    pf_list_ad(),
    [pf_input(0, pf_a(), 100), pf_input(1, VerificationKey(pf_d), 150)],
    [pf_output(pf_a(), 100), pf_output(VerificationKey(pf_d), 150)],
    [pf_src(3), pf_src(4)],
    [pf_dst(3), pf_dst(4)],
  )
}
