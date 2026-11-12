use aiken/builtin
use aiken/collection/dict
use aiken/collection/list
use aiken/fuzz
use aiken/interval.{Interval, IntervalBound, NegativeInfinity, PositiveInfinity}
use aiken/primitive/bytearray
use aiken_design_patterns/linked_list.{Element, Node, Root}
use cardano/address.{Address, Credential, Inline, Script, VerificationKey}
use cardano/assets.{Assets, from_asset, from_lovelace, merge, zero}
use cardano/certificate.{Certificate, RegisterCredential, UnregisterCredential}
use cardano/transaction.{
  InlineDatum, Input, NoDatum, Output, OutputReference, Transaction,
}
use cardano/value
use cip68
use constants
use denylist/absence.{verify_denylist_permits}
use kyc/verify.{verify_kyc_proof}
use types/cip68.{Cip68Datum} as types_cip68
use types/denylist.{Denylist}
use types/global_state.{
  GlobalStateDatum, GlobalStateReferenced, GlobalStateSpent, decode_global_state,
  resolve_global_state,
}
use types/kyc_proof.{Cip30Attestation, Cip30AttestationProof}
use types/minting_authority.{
  MintBurn, MintingAuthorityWithdrawRedeemer, Register, UpgradeRegistryNode,
}
use types/party_action.{PartyAction}
use types/power_users.{PowerUser}
use utils.{must_be_signed_by_credential}

/// The swappable minting authority — see the redeemer type's doc comment for
/// the trust model. This validator's OWN logic (KYC, denylist, power-user
/// roles) is exactly what "upgrading the minting path" is meant to change:
/// GlobalState.minting_script_credential_hash can be admin-rotated to a
/// DIFFERENT deployment of this same shape (a different compliance
/// integration, a bugfix, a new rule set) without ever touching
/// minting_logic_script.ak or the CIP-113 registry.
///
/// ============================================================================
/// INVARIANTS ANY REPLACEMENT AUTHORITY MUST PRESERVE
/// ============================================================================
/// minting_logic_script.ak — the permanent proxy — checks NOTHING except that
/// whichever script GlobalState names is running. That is what makes this
/// validator fully replaceable, and it means everything listed below is
/// enforced here or nowhere at all. A replacement that drops one of these does
/// not merely lose a feature; in the first two cases it causes damage no later
/// upgrade can undo, because the harm lands in the CIP-113 registry and in
/// circulating supply rather than in this script.
///
///   1. NO REGISTRY NODE MAY BE SPENT during a mint or burn.
///      `registry_spend`'s in-place UPDATE path mints no registry NFT and
///      demands the proxy's withdraw-0 as its "proof of instance" — which
///      this validator's approval supplies. Without the guard, anyone who
///      can get a routine mint authorised can ride along on an update that
///      re-points `transfer_logic_script` /
///      `third_party_transfer_logic_script` at permissive scripts,
///      permanently destroying transfer-side compliance. IRREVERSIBLE.
///   2. EVERY SUPPLY CHANGE IS DEBITED HERE — the supply cap, a core
///      CMTAT/BaFin invariant. Of the three redeemers, only `MintBurn`
///      approves a mint or burn of `security_asset_name`, and it debits
///      every one: `MintBurn` spends GlobalState (its bare
///      `global_state_input_index`), and GlobalState's continuing output
///      (`global_state_output_index`) keeps its address and non-ADA value and
///      carries the input datum with field 6 (`mintable_amount`) alone
///      rewritten to `in − minted`, never below zero; a burn credits it
///      (`debits_mintable_amount`). The other two cannot change supply.
///      `Register` mints no supply: at most the CIP-68 reference NFT,
///      quantity 1 (`registration_mint_matches_name`). `UpgradeRegistryNode`
///      cannot mint or burn under the issuance policy: CIP-113's
///      `registry_spend` refuses any same-transaction mint of the spent
///      node's own policy, which is this token's issuance policy (see 3).
///      That base-layer rule is relied on, not re-checked here. Neither the
///      proxy nor the GlobalState logic counts anything: `MintSecurity` only
///      permits the write. A replacement that drops the debit mints past the
///      cap. IRREVERSIBLE (tokens already exist).
///
///      Why here and not in the proxy: the proxy's hash is the token's
///      issuance policy id, so a defect in a rule written there could never
///      be fixed, while this authority can be rotated. Until `LockUpgrades`
///      the admin can already set the cap with `SetMintableAmount`; after it,
///      `RotateMintingScript` is closed, so the installed authority and its
///      debit are permanent.
///   3. ONLY THE NAMES EACH VARIANT ALLOWS may be minted under the issuance
///      policy. `MintBurn` mints or burns only `security_asset_name`
///      (`only_permitted_assets_minted`). `Register` mints nothing for a
///      plain name, and exactly `cip68.reference_name(security_asset_name)`,
///      quantity 1, for a CIP-68 name — and never supply
///      (`registration_mint_matches_name`). `issuance_mint` constrains no
///      asset names, and the destination checks only ever inspect the
///      security asset, so any other name would be minted with no KYC or
///      denylist scrutiny at all.
///
///      `UpgradeRegistryNode` does not inspect `self.mint`. It relies on
///      CIP-113's `registry_spend` forbidding a same-transaction mint of the
///      spent node's own policy (`expect !mint_has_policy(self.mint,
///      spent_node.key)`). That rule is hoisted above both of its branches, so
///      it covers the in-place update AND the case where this token's node is
///      the covering node spent by another token's insert.
///
///      DELIBERATE RESIDUE: protection is keyed on the EXACT reference name
///      and exists only for CIP-68 names. A replacement authority that mints
///      any other `(100)`-labelled name under the issuance policy creates a
///      token that neither the transfer nor the seizure logic polices.
///
///      DELIBERATE RESIDUE: this "only these names" rule, like the supply
///      debit, lives in this replaceable authority, not in the frozen minting
///      proxy. A replacement that drops it can mint other names under the
///      issuance policy, uncapped. That is the admin's choice, the same trust
///      as choosing the authority, and such an authority could already mint
///      the real token to unvetted destinations.
///   4. THE PROTOCOL MUST NOT BE `deactivated`. Deactivation is the terminal
///      decommissioning switch and is meant to be absolute.
///   5. REGISTRATION STRUCTURE, on the single `Register` variant: the node
///      must name this deployment's proxy, name exactly the transfer and
///      seizure scripts this authority was built with (F08 — also on every
///      `UpgradeRegistryNode`), forbid unfracking, and pin this deployment's
///      GlobalState — AND the node's own registry NFT must be minted in the
///      same transaction. Plus the NAME RULES, decided by
///      `security_asset_name` alone: a `(100)`-labelled name is refused (the
///      supply would be its own metadata token), a CIP-68 name needs a body
///      of at least one byte, and a plain name must not be empty.
///
///      That last clause is what makes registration a once-only event, and
///      it is load-bearing, not cosmetic. Requiring merely that SOME registry
///      NFT is minted is not enough: an admin-signed transaction can bundle a
///      throwaway insert for an unrelated token to satisfy it while this
///      token's already-registered node is spent and re-emitted through
///      `registry_spend`'s UPDATE path with `transfer_logic_script`
///      re-pointed at a permissive script. Every other structural check still
///      passes in that shape, because the base layer freezes
///      `minting_logic_script` across an update. Scoping the mint to THIS
///      node closes it — on an insert the NFT is created now, on an update it
///      is carried forward from the spent node — and, because CIP-113 keys
///      nodes by a policy id derived from the proxy hash and the linked list
///      forbids duplicate keys, no second node naming this proxy can ever be
///      inserted. Weaken this and registration becomes a stealthy, repeatable
///      vehicle for hijacking transfer compliance. IRREVERSIBLE.
///   6. POWER USERS ARE AUTHENTICATED UNDER GLOBALSTATE FIELD 3
///      (`power_user_linked_list_policy_id`), read from the NFT-authenticated
///      GlobalState input — there is no compile-time copy to check it
///      against, and the node's address is not re-checked (the list keeps
///      every NFT of its policy at its spend script), so field 3 is the sole
///      anchor for which list grants `can_mint` / `can_burn`. It is set
///      at genesis and changes only through the GlobalState logic's
///      `MigrateLists`, admin-signed and before `LockUpgrades` (see the
///      replacement-logic invariants in global_state_logic.ak).
///   7. A MintBurn THAT CHANGES NO SUPPLY AUTHORISES NOTHING.
///      A zero-delta MintBurn would let any `can_mint`
///      operator run this authority, and with it the minting proxy, beside
///      any GlobalState action, where their withdrawals count as signatures.
///      With supply forced to change, the GlobalState action can only be
///      MintSecurity, which carries no admin decision.
///   8. ROLE SIGNATURES REFUSE THE SCRIPTS THAT RUN HERE.
///      `must_be_signed_by_credential` accepts a withdraw-0 as a
///      signature, so an operator or admin keyed at this authority, the
///      minting proxy, or the transfer or seizure script it pins would be
///      "signed" by a script anyone (or any operator) can make run. Every
///      operator and admin signature check goes through `role_signed`.
/// ============================================================================
validator minting_authority_validator(
  security_asset_name: ByteArray,
  global_state_policy_id: ByteArray,
  registry_policy_id: ByteArray,
  // The permanent proxy's hash (validators/minting_logic_script.ak) — used
  // to independently re-verify the registry node this transaction concerns
  // (see the redeemer type's doc comment). Not circular: the proxy never
  // takes this validator's hash as one of its own compile-time parameters,
  // so this validator is free to be compiled after the proxy, at any time,
  // including long after initial deployment — that is the whole point of
  // making this validator swappable.
  minting_logic_script_credential_hash: ByteArray,
  /// The policy this deployment's `MintBurn` mints and burns, pinned at
  /// compile time. It pairs with `security_asset_name`, and `MintBurn` reads
  /// it from no registry node.
  ///
  /// `Register` and `UpgradeRegistryNode` do not compare against it: each
  /// derives the policy from the registry node that names this deployment's
  /// proxy at field 2, and relies on CIP-113 for that node being keyed to
  /// this deployment's policy — the registry binds a node's key to its
  /// minting logic (`is_programmable_token_id_valid`) and forbids duplicate
  /// keys. Building the authority with the right value is the deployer's
  /// duty: one built with a wrong value is not refused at `Register`.
  ///
  /// Not circular: `gs_policy → proxy hash → issuance_policy_id → this
  /// validator`, and this validator is compiled last (it is the swappable one).
  security_policy_id: ByteArray,
  /// F08: the hash of `transfer_logic_script.transfer_logic_validator` that
  /// registry field 3 must name, at registration and on every upgrade.
  ///
  /// CIP-113 leaves fields 3 and 4 free, and the base layer authorises a
  /// seizure by the field-4 script's withdraw-0 alone — no owner consent, no
  /// signature. Accepting any script there would let a swapped pair, or a
  /// foreign script, turn seizure into something anyone can do. These two
  /// parameters make the authority's own build the single source of truth.
  /// Re-pointing either field therefore means rotating to an authority built
  /// with the new hash first (`RotateMintingScript`), then
  /// `UpgradeRegistryNode`. Not circular: neither transfer script depends on
  /// this validator, which is compiled last.
  transfer_logic_script_hash: ByteArray,
  /// F08: the hash of
  /// `third_party_transfer_logic_script.third_party_transfer_logic_validator`
  /// that registry field 4 must name. Must differ from
  /// `transfer_logic_script_hash`. See that parameter.
  third_party_transfer_logic_script_hash: ByteArray,
) {
  withdraw(
    redeemer: MintingAuthorityWithdrawRedeemer,
    credential: Credential,
    self: Transaction,
  ) {
    // A withdrawal credential may be a verification key, so this is a real
    // assertion, not a formality.
    expect Script(own_hash) = credential

    // INVARIANT 8 — see the header. A role signature (operator or admin)
    // counts only from a credential whose withdraw-0 nobody else can put into
    // this transaction. This authority and the minting proxy run in every mint
    // and burn; the transfer and seizure scripts it pins can be run by others
    // (the transfer logic by anyone, whenever no token moves). Through
    // `must_be_signed_by_credential` each would otherwise sign for a role keyed
    // at its own hash. The GlobalState logic (field 0) is refused for the
    // operator separately, as before.
    let role_signed = fn(credential_hash: ByteArray) -> Bool {
      and {
        (credential_hash != own_hash)?,
        (credential_hash != minting_logic_script_credential_hash)?,
        (credential_hash != transfer_logic_script_hash)?,
        (credential_hash != third_party_transfer_logic_script_hash)?,
        must_be_signed_by_credential(self, credential_hash)?,
      }
    }

    // The variants differ in where this token's registry node is found — a
    // reference input in steady state, an output of this very transaction
    // during a CIP-113 insert — and in whether supply changes. In every case
    // the node is re-resolved and re-verified HERE against the proxy's known
    // hash; nothing is trusted from the proxy, which checks only the
    // delegation.
    when redeemer is {
      MintBurn {
        global_state_input_index,
        global_state_output_index,
        power_user_node_ref_input_index,
        minted_amount,
        destination_actions,
      } -> {
        // INVARIANT 1 — see the header. A steady-state mint or burn only
        // ever REFERENCES the registry node; spending one means a
        // `registry_spend` update is riding along on this authorisation.
        expect
          !list.any(
            self.inputs,
            fn(input) {
              utils.quantity_of_policy_id(
                input.output.value,
                registry_policy_id,
              ) > 0
            },
          )
        // Decode GlobalState ONCE. The NFT check authenticates the UTxO
        // BEFORE any field of its datum is read; `!deactivated` traps
        // immediately (INVARIANT 4). The power-users list policy id is read
        // from that same authenticated datum (INVARIANT 6), here, at the one
        // call site of `verify_mint_or_burn`, so it is read once.
        let gs_input = utils.safe_list_at(self.inputs, global_state_input_index)
        expect
          value.quantity_of(
            assets.to_value(gs_input.output.value),
            global_state_policy_id,
            constants.global_state_asset_name,
          ) == 1
        expect InlineDatum(gs_raw) = gs_input.output.datum
        let fields = builtin.unconstr_fields(gs_raw)
        expect !global_state.get_deactivated(fields)
        let power_user_linked_list_policy_id = global_state.get_power_user_linked_list_policy_id(
          fields,
        )
        and {
          // Steady state mints or burns supply and nothing else (INVARIANT
          // 3). A CIP-68 reference NFT is a registration-time artefact;
          // allowing one here would let it be re-minted after the token is
          // live.
          only_permitted_assets_minted(
            self,
            security_policy_id,
            security_asset_name,
          )?,
          verify_mint_or_burn(
            security_policy_id,
            minted_amount,
            gs_raw,
            power_user_node_ref_input_index,
            destination_actions,
            security_asset_name,
            power_user_linked_list_policy_id,
            role_signed,
            self,
          ),
          // INVARIANT 2 — see the header. Last, so every other refusal fires
          // first.
          debits_mintable_amount(
            gs_input.output,
            fields,
            global_state_output_index,
            security_policy_id,
            security_asset_name,
            self,
          ),
        }
      }
      Register { registry_node_output_index, global_state_ref_input_index } -> {
        // The registration's structural invariants are NOT a base-layer
        // duplicate: CIP-113 binds only key <-> minting logic and leaves
        // fields 3-6 free, and it never tells this authority whether an
        // insert of THIS token's node is actually happening. This call is
        // what ties `Register` to that (once-only) insert — the reason it
        // alone may mint the CIP-68 reference NFT — and what pins the free
        // fields at genesis (INVARIANT 5).
        let issuance_policy_id = verify_registration_structure(
          registry_node_output_index,
          registry_policy_id,
          global_state_policy_id,
          minting_logic_script_credential_hash,
          transfer_logic_script_hash,
          third_party_transfer_logic_script_hash,
          self,
        )
        // Read for the deactivation flag and the admin only, and always as a
        // reference input: GlobalState exists before any registration, and no
        // supply changes here, so nothing needs the GlobalState spend
        // validator to run.
        let gs_datum = resolve_global_state(
          self.inputs,
          self.reference_inputs,
          GlobalStateReferenced { global_state_ref_input_index },
          global_state_policy_id,
        )
        and {
          // INVARIANT 4.
          !gs_datum.deactivated,
          // The admin authorises the registration itself — CIP-113 binds the
          // node's key to the proxy but leaves its transfer-logic fields
          // free, so this signature is what stops a stranger registering the
          // token, and the F08 pin holds even the admin to this deployment's
          // transfer and seizure scripts. INVARIANT 8: the registry insert
          // runs the minting proxy, so an admin keyed at it must not count.
          role_signed(gs_datum.admin_credential_hash)?,
          // INVARIANTS 3 and 5: the name rules and the two-way mint rule.
          registration_mint_matches_name(
            self,
            issuance_policy_id,
            security_asset_name,
          ),
        }
      }
      UpgradeRegistryNode {
        registry_node_input_index,
        registry_node_output_index,
        global_state_location,
      } -> {
        // Purpose-binding: the node being spent must be THIS token's — i.e.
        // it must currently name this deployment's proxy. That is also what
        // makes the derived policy id ours.
        let spent_node = utils.safe_list_at(
          self.inputs,
          registry_node_input_index,
        ).output
        let issuance_policy_id = utils.derive_issuance_policy_id_from_registry_node(
          spent_node,
          registry_policy_id,
          minting_logic_script_credential_hash,
          constants.minting_logic_script_registry_node_index,
        )

        // The continuing node — AUTHENTICATED, not merely indexed. Deriving
        // its policy id the same way as the spent node's asserts three things
        // at once: it carries a genuine registry NFT, it names this
        // deployment's proxy, and (by comparing the two ids below) it is the
        // SAME node rather than some other token's.
        //
        // Without this, `registry_node_output_index` could be aimed at a
        // decoy plain output holding a copy of the original clean datum,
        // while the real continuing node — the only registry-NFT output, per
        // registry_spend's `expect [cont]` — re-pointed `global_state_cs` at
        // an attacker-authored GlobalState or switched unfracking on. The two
        // field checks below would then be inspecting the decoy.
        let continuing_node = utils.safe_list_at(
          self.outputs,
          registry_node_output_index,
        )
        let continuing_policy_id = utils.derive_issuance_policy_id_from_registry_node(
          continuing_node,
          registry_policy_id,
          minting_logic_script_credential_hash,
          constants.minting_logic_script_registry_node_index,
        )
        expect continuing_policy_id == issuance_policy_id

        let out_fields: List<Data> = builtin.unconstr_fields(
          utils.expect_inline_datum(continuing_node),
        )

        // `next` backstop REMOVED: CIP-113's `registry_spend` already
        // threads `next` unchanged through an in-place field update — this
        // deployment relies on that verified base-layer guarantee rather
        // than re-checking it.
        // F08: the continuing node must name exactly the transfer and
        // seizure scripts this authority was built with — CIP-113 lets both
        // fields change on update, so this is the only place an upgrade is
        // held to them. Re-pointing either field means rotating to an
        // authority built with the new hash first.
        expect
          names_pinned_transfer_scripts(
            out_fields,
            transfer_logic_script_hash,
            third_party_transfer_logic_script_hash,
          )

        // Re-assert the two fields the base layer leaves mutable but this
        // deployment treats as permanent.
        //
        // `global_state_cs`: pinning is unambiguously right — re-pointing it
        // would aim every later compliance read at a GlobalState the caller
        // authored.
        //
        // `unfracking_logic_script`: pinning it HERE, on the upgrade path, is
        // the consequential choice — it means the hook can never be enabled
        // for this token at all, not even later by a governed upgrade. That
        // permanently forecloses the co-mingled-freeze escape hatch described
        // in `verify_registration_structure`. Relaxing just this one line
        // (while leaving registration default-deny) would make the decision
        // reversible without weakening the genesis posture. Flagged in the
        // audit report as the single highest-value change to reconsider.
        let out_unfracking_data = utils.safe_list_at(
          out_fields,
          constants.unfracking_logic_script_registry_node_index,
        )
        expect out_unfracking: Credential = out_unfracking_data
        expect out_unfracking == VerificationKey(#"")

        let out_gs_cs_data = utils.safe_list_at(
          out_fields,
          constants.global_state_cs_registry_node_index,
        )
        expect out_gs_cs: ByteArray = out_gs_cs_data
        expect out_gs_cs == global_state_policy_id

        let gs_datum = resolve_global_state(
          self.inputs,
          self.reference_inputs,
          global_state_location,
          global_state_policy_id,
        )
        and {
          // INVARIANT 4.
          !gs_datum.deactivated,
          // The one-way lock closes this path permanently.
          (!gs_datum.upgrades_locked)?,
          // INVARIANT 8: the registry update itself runs the minting proxy,
          // so an admin keyed at it must not count as signed.
          role_signed(gs_datum.admin_credential_hash)?,
        }
      }
    }
  }

  // Same whitelist rationale as minting_logic_script.ak's publish handler:
  // rejecting UnregisterCredential prevents a rubber-stamp publish from
  // letting anyone de-register this script's stake credential, which would
  // brick every mint/burn the proxy tries to delegate here until
  // re-registered.
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

/// INVARIANT 3 — see the header. `MintBurn` mints or burns only
/// `security_asset_name` under the issuance policy: holds iff every name minted
/// under it equals `security_asset_name`.
///
/// Checked as a SHAPE, not a sum: `quantity_of_policy_id(...) == 0` would also
/// accept +N of the security asset netted against -N of another name under the
/// same policy. `issuance_mint` constrains no asset names — it delegates
/// entirely to this module — so a second name is possible, and it would be
/// invisible to the destination checks below, which only ever inspect outputs
/// carrying `security_asset_name`.
///
/// Vacuous on an empty mint: refusing a mint that changes nothing is
/// `(minted_amount != 0)?`'s job (INVARIANT 7), not this function's.
fn only_permitted_assets_minted(
  self: Transaction,
  issuance_policy_id: ByteArray,
  security_asset_name: ByteArray,
) -> Bool {
  list.all(
    dict.to_pairs(assets.tokens(self.mint, issuance_policy_id)),
    fn(entry) { entry.1st == security_asset_name },
  )
}

/// INVARIANT 2 — see the header. Every mint or burn of `security_asset_name`
/// under `security_policy_id` is debited from GlobalState's `mintable_amount`
/// in this same transaction: the continuing output at
/// `global_state_output_index` keeps the spent GlobalState input's address and
/// non-ADA value, and its inline datum is the input datum with field 6 alone
/// set to `in − minted`, never below zero. A burn credits.
///
/// The amount is ledger truth, derived from `self.mint`, never the redeemer's.
/// The datum is compared as Data, so every other field — core, tail and
/// appended — is pinned too. It is the last conjunct of `MintBurn`, so every
/// other refusal fires first.
fn debits_mintable_amount(
  gs_input: Output,
  gs_fields: List<Data>,
  global_state_output_index: Int,
  security_policy_id: ByteArray,
  security_asset_name: ByteArray,
  self: Transaction,
) -> Bool {
  let minted = value.quantity_of(
    assets.to_value(self.mint),
    security_policy_id,
    security_asset_name,
  )
  let gs_continuing = utils.safe_list_at(
    self.outputs,
    global_state_output_index,
  )
  expect InlineDatum(out_raw) = gs_continuing.datum
  let remaining = global_state.get_mintable_amount(gs_fields) - minted
  let same_address = gs_continuing.address == gs_input.address
  let same_tokens = assets.without_lovelace(gs_continuing.value) == assets.without_lovelace(
    gs_input.value,
  )
  let only_the_counter_moved = builtin.equals_data(
    global_state.set_mintable_amount(gs_fields, remaining),
    out_raw,
  )
  and {
    (remaining >= 0)?,
    same_address?,
    same_tokens?,
    only_the_counter_moved?,
  }
}

/// INVARIANTS 3 and 5 — see the header. `Register`'s name rules and its mint
/// rule, both decided by `security_asset_name` alone, and the mint rule
/// enforced in BOTH directions under the issuance policy: what must be minted
/// is minted, and nothing else is. Mints under other policies are not this
/// function's concern.
///
///   * A `(100)`-labelled security name is always refused: the supply would be
///     its own metadata token, and every rule meant for metadata would fire on
///     it.
///   * A CIP-68 name (`cip68.reference_name` is `Some`) needs a body of at
///     least one byte, mints EXACTLY its reference NFT once — never supply,
///     never another name — and pins it in one well-formed carrier
///     (`cip68_output_is_pinned`).
///   * A plain name must not be empty, and mints NOTHING.
///
/// Checked as a SHAPE (`minted == ..`), not a sum, for the same reason as
/// `only_permitted_assets_minted`. Returns False rather than trapping, with a
/// label on each rule, so a refusal names the rule that fired.
fn registration_mint_matches_name(
  self: Transaction,
  issuance_policy_id: ByteArray,
  security_asset_name: ByteArray,
) -> Bool {
  let minted = dict.to_pairs(assets.tokens(self.mint, issuance_policy_id))
  and {
    (bytearray.take(security_asset_name, constants.cip67_label_length) != constants.cip68_reference_label)?,
    when cip68.reference_name(security_asset_name) is {
      Some(ref_name) -> and {
          (bytearray.length(security_asset_name) > constants.cip67_label_length)?,
          (minted == [Pair(ref_name, 1)])?,
          cip68_output_is_pinned(self, issuance_policy_id, ref_name)?,
        }
      None -> and {
          (security_asset_name != "")?,
          (minted == [])?,
        }
    },
  }
}

/// THE CIP-68 REFERENCE NFT CUSTODY DECISION.
///
/// A CIP-68 token's reference NFT is metadata, not value — it is exempt from
/// the supply cap and from the denylist and KYC gates. It is minted exactly
/// once, here, at registration (only `Register` may mint it, and registration
/// is structurally a once-only event), and this function pins three things
/// about the UTxO it lands in:
///
///   * there is exactly ONE output carrying `reference_name` in the whole
///     transaction — with `registration_mint_matches_name` capping the mint at
///     one, that makes the reference NFT unique and locatable;
///   * that output is WELL FORMED — ADA plus exactly that one token, nothing
///     else co-located, and a correctly shaped CIP-68 datum
///     (`cip68.output_is_well_formed`); and
///   * it has an inline owner stake credential. Updating the metadata is that
///     owner spending this UTxO (base-layer owner consent) and re-outputting the
///     token with a new datum. The metadata authority may be separate from the
///     GlobalState admin; the admin still authorises registration itself.
///
/// The base layer's `no_escape` already confines every token of this policy —
/// the reference NFT included — to the programmable base, so no
/// payment-credential pin is needed here.
///
/// The SHAPE is re-checked on every later move by `transfer_logic_script`, and
/// the seizure path refuses to spend the reference NFT at all — both keyed on
/// the same exact name. So these are invariants, not a one-time posture at
/// genesis.
fn cip68_output_is_pinned(
  self: Transaction,
  issuance_policy_id: ByteArray,
  reference_name: ByteArray,
) -> Bool {
  let carriers = list.filter(
    self.outputs,
    fn(output) {
      cip68.value_has_reference(
        output.value,
        issuance_policy_id,
        reference_name,
      )
    },
  )
  when carriers is {
    [output] -> {
      expect Some(Inline(_owner)) = output.address.stake_credential
      cip68.output_is_well_formed(output, issuance_policy_id, reference_name)?
    }
    _ -> False
  }
}

/// INVARIANT 5 — see the header. The CIP-113 registration's structural
/// invariants, moved here from the proxy so that they too are upgradeable.
/// Returns this token's issuance policy id, derived from the node itself.
///
/// What CIP-113 guarantees and what it does not: `registry_mint` binds `key`
/// to `minting_logic_script` cryptographically
/// (`is_programmable_token_id_valid`), so the policy id cannot lie about which
/// minting logic governs it. It binds NOTHING about `transfer_logic_script`,
/// `third_party_transfer_logic_script`, `unfracking_logic_script` or
/// `global_state_cs` — those are free fields, and this module's consent
/// is the only thing standing between an attacker and a registration naming
/// permissive logic scripts, which would bypass every compliance gate from
/// genesis.
fn verify_registration_structure(
  registry_node_output_index: Int,
  registry_policy_id: ByteArray,
  global_state_policy_id: ByteArray,
  minting_logic_script_credential_hash: ByteArray,
  transfer_logic_script_hash: ByteArray,
  third_party_transfer_logic_script_hash: ByteArray,
  self: Transaction,
) -> ByteArray {
  let node_output = utils.safe_list_at(self.outputs, registry_node_output_index)
  let node_fields: List<Data> = builtin.unconstr_fields(
    utils.expect_inline_datum(node_output),
  )

  // Identity + policy id in one step: asserts the registry NFT and that the
  // node names THIS deployment's proxy. An insert emits TWO registry-node
  // outputs — the new node and the re-emitted covering node — so the index
  // alone does not identify ours.
  let issuance_policy_id = utils.derive_issuance_policy_id_from_registry_node(
    node_output,
    registry_policy_id,
    minting_logic_script_credential_hash,
    constants.minting_logic_script_registry_node_index,
  )

  // INSERT only — and specifically, an insert OF THIS NODE.
  expect [Pair(node_asset_name, _)] = dict.to_pairs(
    assets.tokens(node_output.value, registry_policy_id),
  )
  expect
    value.quantity_of(
      assets.to_value(self.mint),
      registry_policy_id,
      node_asset_name,
    ) == 1

  // F08: registry fields 3 and 4 must name exactly this deployment's
  // transfer and seizure scripts. See `names_pinned_transfer_scripts`.
  expect
    names_pinned_transfer_scripts(
      node_fields,
      transfer_logic_script_hash,
      third_party_transfer_logic_script_hash,
    )

  // Unfracking is left FORBIDDEN (`empty_vkey` is CIP-113's
  // least-permission value; no ledger transaction can carry a withdrawal
  // keyed by an empty hash, so an unset hook is default-deny).
  let unfracking_data = utils.safe_list_at(
    node_fields,
    constants.unfracking_logic_script_registry_node_index,
  )
  expect node_unfracking: Credential = unfracking_data
  expect node_unfracking == VerificationKey(#"")

  // The node must declare THIS deployment's GlobalState.
  let global_state_cs_data = utils.safe_list_at(
    node_fields,
    constants.global_state_cs_registry_node_index,
  )
  expect node_global_state_cs: ByteArray = global_state_cs_data
  expect node_global_state_cs == global_state_policy_id

  issuance_policy_id
}

/// F08: registry fields 3 and 4 name exactly the transfer and seizure scripts
/// this authority was built with.
///
/// Checking only that each field is SOME script let a swapped pair, or any
/// foreign script, through. Under the base layer a seizure is authorised by
/// the field-4 script's withdraw-0 alone, so with this deployment's transfer
/// logic in field 4 anyone could seize. A `VerificationKey` in either field is
/// refused too, as before. Traps on any mismatch.
fn names_pinned_transfer_scripts(
  node_fields: List<Data>,
  transfer_logic_script_hash: ByteArray,
  third_party_transfer_logic_script_hash: ByteArray,
) -> Bool {
  // An authority built with one hash in both slots would pin the very swap
  // this check exists to prevent.
  expect transfer_logic_script_hash != third_party_transfer_logic_script_hash
  let transfer_logic_data = utils.safe_list_at(
    node_fields,
    constants.transfer_logic_script_registry_node_index,
  )
  expect transfer_logic: Credential = transfer_logic_data
  let third_party_logic_data = utils.safe_list_at(
    node_fields,
    constants.third_party_transfer_logic_script_registry_node_index,
  )
  expect third_party_logic: Credential = third_party_logic_data
  and {
    transfer_logic == Script(transfer_logic_script_hash),
    third_party_logic == Script(third_party_transfer_logic_script_hash),
  }
}

/// The mint/burn authority — ported from minting_logic_script.ak's original,
/// pre-delegation logic. `issuance_policy_id` arrives already independently
/// derived and verified by the caller (see `withdraw` above); this function
/// is otherwise a pure decision over (amounts, GlobalState, power user,
/// destinations).
///
/// GlobalState arrives ALREADY AUTHENTICATED as `gs_raw` — the raw datum
/// `Data` of a UTxO the caller has already NFT-checked. This function must
/// not re-resolve or re-authenticate it: the deactivation trap already ran at
/// the call site, which also read `power_user_linked_list_policy_id` from the
/// same decoded field list. The only thing left genuinely
/// conditional on the caller's shape is the full TYPED decode, which only a
/// mint (`minted_amount > 0`) needs, for destination vetting — a burn pays
/// no decode at all.
fn verify_mint_or_burn(
  issuance_policy_id: ByteArray,
  expected_minted_amount: Int,
  gs_raw: Data,
  power_user_node_ref_input_index: Int,
  destination_actions: List<PartyAction>,
  security_asset_name: ByteArray,
  power_user_linked_list_policy_id: ByteArray,
  // The withdraw handler's signature check: refuses the scripts that run in
  // this transaction (INVARIANT 8) before it accepts a signature.
  role_signed: fn(ByteArray) -> Bool,
  self: Transaction,
) -> Bool {
  // Ledger truth, derived here rather than accepted from a caller so the
  // "actual vs claimed" comparison below cannot be defeated by passing a
  // matched-but-wrong pair.
  let minted_amount = value.quantity_of(
    assets.to_value(self.mint),
    issuance_policy_id,
    security_asset_name,
  )

  let power_user_ref_input = utils.safe_list_at(
    self.reference_inputs,
    power_user_node_ref_input_index,
  )

  let (power_user_node_key, power_user_data) = utils.authenticated_power_user(
    power_user_ref_input.output,
    power_user_linked_list_policy_id,
  )

  // Destination verification (mirrors transfer_logic_script's per-output
  // gate): CMTAT v3.2.0 refuses to mint to a frozen address (core) and to
  // a non-allowlisted receiver (Allowlist variant). When minting, every
  // unique destination stake credential among outputs carrying the
  // security token needs a denylist proof (a covering node, or the holder's
  // own node when only partially frozen), plus — when
  // GS.requires_receiver_kyc — a KYC check that passes if EITHER a valid
  // KYC proof is presented OR the receiver is the power user authorising
  // this mint (`power_user_node_key`, already resolved above; it holds
  // `can_mint` and signed the tx).
  //
  // DELIBERATE DEVIATION (on record): CMTAT's Allowlist variant requires the
  // mint receiver — the minter/treasury included — to be allowlisted. Here a
  // `can_mint` power user may mint to their OWN list-authenticated credential
  // without a separate KYC attestation. Rationale: under the CIP-113 address
  // model the destination's stake credential IS the owner identity, and this
  // is a signed, list-authenticated operator minting to itself; requiring the
  // operator to also hold an off-chain KYC attestation adds no compliance
  // value. The denylist gate still applies to the operator, so a
  // sanctioned operator cannot mint to itself. (If you prefer exact CMTAT
  // Allowlist behaviour, drop this branch and issue the treasury a KYC
  // attestation at setup.)
  //
  // Burns have no destinations — the holder side is vetted by the CIP-113
  // spend path.
  //
  // The checks themselves live in `verify_mint_destinations` below.
  let destinations_ok = if minted_amount > 0 {
    // Lenient like every GlobalState reader — see `decode_global_state`.
    let gs_datum = decode_global_state(gs_raw)
    verify_mint_destinations(
      self.outputs,
      destination_actions,
      [],
      issuance_policy_id,
      security_asset_name,
      gs_datum,
      power_user_node_key,
      self,
    )
  } else {
    True
  }

  and {
    // INVARIANT 7 — see the header. A MintBurn must change supply. One that
    // mints nothing would run this authority, and with it the minting proxy,
    // beside ANY GlobalState action (this repository's logic lets only
    // MintSecurity carry a mint or burn, provided it was built with this
    // token's name: that is an assumption about the installed logic, not
    // something checked here), where their withdrawals count as signatures. No legitimate flow
    // needs it: `MintBurn` mints or burns only `security_asset_name`, so a
    // zero delta means nothing is minted at all. Applied to the ledger-derived
    // `minted_amount`, which the next conjunct binds to the redeemer's.
    (minted_amount != 0)?,
    //Redeemer contains the amount just for easy reference for eventual other contracts
    (minted_amount == expected_minted_amount)?,
    // Never the GlobalState logic named in field 0: a supply change spends
    // GlobalState, so that logic's withdrawal is in this transaction and
    // would sign for the operator. Checked here, at use, rather than when the
    // role is granted, so a later logic rotation cannot reopen it.
    (power_user_node_key != global_state.get_global_state_script_credential_hash(
      builtin.unconstr_fields(gs_raw),
    ))?,
    //A power user must have signed the transaction — and not through a
    //script that runs here anyway (INVARIANT 8)
    role_signed(power_user_node_key)?,
    // A zero-amount mint removes nothing from circulation, so it is a MINT,
    // not a burn: gating it on `can_burn` would let a burn-only operator
    // perform what is structurally a mint action merely because its supply
    // delta happens to be zero. The first conjunct above already refuses a
    // zero delta (INVARIANT 7); this gate does not rely on that.
    //If minted_amount >= 0, power user must be minter
    //If minted_amount < 0, power user must be burner
    if minted_amount >= 0 {
      power_user_data.can_mint
    } else {
      power_user_data.can_burn
    }?,
    //Mint destinations must be vetted (denylist gate + optional KYC)
    destinations_ok?,
  }
}

/// The CMTAT rationale for the two gates below — and the DELIBERATE DEVIATION
/// permitting a `can_mint` power user to mint to itself without a KYC
/// attestation — is documented at the call site in `verify_mint_or_burn`.
fn verify_mint_destinations(
  outputs: List<Output>,
  actions: List<PartyAction>,
  seen: List<Credential>,
  issuance_policy_id: ByteArray,
  security_asset_name: ByteArray,
  gs_datum: GlobalStateDatum,
  power_user_node_key: ByteArray,
  self: Transaction,
) -> Bool {
  when outputs is {
    [] -> True
    [output, ..rest_outputs] ->
      if value.quantity_of(
        assets.to_value(output.value),
        issuance_policy_id,
        security_asset_name,
      ) > 0 {
        // The base layer's `no_escape` already forbids any token of this
        // policy at a non-programmable-base output, so only the inline
        // STAKE credential — the owner identity — needs reading here. An
        // enterprise address (no stake credential at all) still traps.
        // Carry the full `Credential` — a key and a script sharing a hash
        // are different holders, and `seen` must dedupe on both halves or the
        // second of the pair would inherit the first's vetting.
        expect Some(Inline(dest_credential)) = output.address.stake_credential
        let dest_pkh = utils.credential_hash(dest_credential)
        if list.has(seen, dest_credential) {
          // Already vetted by an earlier output — consume no action, so the
          // redeemer stays indexed by unique destination rather than by output.
          verify_mint_destinations(
            rest_outputs,
            actions,
            seen,
            issuance_policy_id,
            security_asset_name,
            gs_datum,
            power_user_node_key,
            self,
          )
        } else {
          // Mirrors the old `safe_list_at`: a destination with no matching
          // action traps rather than being waved through.
          expect [action, ..rest_actions] = actions
          and {
            if gs_datum.requires_receiver_kyc {
              or {
                // The receiver is the power user authorising this mint.
                //
                // Compared on the BARE HASH deliberately: a power-user
                // node's key is a bare 28-byte hash with no constructor
                // recorded, so there is nothing to compare the other half
                // against. The exemption is only from RECEIVER KYC — the
                // denylist check below still applies to this destination — so
                // the conservative reading (either credential form of the
                // operator's own hash is exempt) is acceptable. Recording the
                // constructor in the power-user node datum would tighten it.
                dest_pkh == power_user_node_key,
                // …or a valid KYC proof is presented for the receiver.
                verify_kyc_proof(
                  action.proof,
                  dest_credential,
                  gs_datum,
                  issuance_policy_id,
                  gs_datum.network_id,
                  self,
                ),
              }
            } else {
              True
            },
            // Not listed, or only PARTIALLY frozen: a partial freeze limits
            // sending, never receiving, so newly issued tokens may land with
            // such a holder. A fully frozen (`None`) holder is still refused.
            verify_denylist_permits(
              dest_pkh,
              action.denylist_ref_input_index,
              self.reference_inputs,
              gs_datum.denylist_linked_list_policy_id,
              fn(_, _) { True },
            ),
            verify_mint_destinations(
              rest_outputs,
              rest_actions,
              [dest_credential, ..seen],
              issuance_policy_id,
              security_asset_name,
              gs_datum,
              power_user_node_key,
              self,
            ),
          }
        }
      } else {
        verify_mint_destinations(
          rest_outputs,
          actions,
          seen,
          issuance_policy_id,
          security_asset_name,
          gs_datum,
          power_user_node_key,
          self,
        )
      }
  }
}

// ============================================================================
// Tests
// ============================================================================
//
// Fixtures follow the aiken-design-patterns linked-list conventions verified
// against the vendored library: an element UTxO carries exactly ADA + one
// list NFT, an inline `Element` datum, and no reference script.

const test_security_asset_name: ByteArray = "SEC"

/// CIP-67 label `(100)` followed by "REF", under the SAME issuance policy —
/// the reference NFT name of the CIP-68 security names below
/// (`cip68.reference_name`). For the plain "SEC" deployment it is just another
/// name.
const test_reference_asset_name: ByteArray = #"000643b0524546"

const test_gs_policy_id: ByteArray =
  #"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

const test_pu_policy_id: ByteArray =
  #"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

const test_registry_policy_id: ByteArray =
  #"cccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

const test_denylist_policy_id: ByteArray =
  #"dddddddddddddddddddddddddddddddddddddddddddddddddddddddd"

// Registry node `key` == the issuance policy id the mint must use.
const test_issuance_policy_id: ByteArray =
  #"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"

// The permanent proxy's hash (validators/minting_logic_script.ak) — this
// deployment's minting_logic_script_credential_hash compile-time parameter.
// The registry node names THIS, never this authority's own credential.
const test_proxy_hash: ByteArray =
  #"f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1"

// This authority's own credential — irrelevant to its checks (it never
// compares anything against its own hash), but supplied to `withdraw` the
// same way the ledger would.
const test_authority_hash: ByteArray =
  #"f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4"

const test_transfer_logic_hash: ByteArray =
  #"f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2"

const test_third_party_logic_hash: ByteArray =
  #"f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3"

const test_pu_credential_hash: ByteArray =
  #"01010101010101010101010101010101010101010101010101010101"

const test_dest_stake_hash: ByteArray =
  #"02020202020202020202020202020202020202020202020202020202"

// The list SPEND validators' hashes — deliberately distinct from the
// list POLICY ids above, because `denylist_validator`/`power_users_validator`
// (spend) and their `mint` counterparts are separate validators with separate
// hashes. The fixtures below place list nodes at THESE addresses, where the
// list mints keep them.
const test_denylist_spend_hash: ByteArray =
  #"d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0"

const test_pu_script_hash: ByteArray =
  #"d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1"

// The real programmable-token custody address: payment credential is the
// shared CIP-113 programmable-logic-base (PLB) SCRIPT, and the per-owner
// identity is the inline STAKE credential. Fixtures model this shape so a
// test can't silently pass under a broken PLB invariant.
const test_plb_hash: ByteArray =
  #"05050505050505050505050505050505050505050505050505050505"

// Faithful mirror of the CIP-113 registry node layout (field order is
// load-bearing: minting=2, transfer=3, third-party=4).
type TestRegistryNode {
  key: ByteArray,
  next: ByteArray,
  minting_logic_script: Credential,
  transfer_logic_script: Credential,
  third_party_transfer_logic_script: Credential,
  unfracking_logic_script: Credential,
  global_state_cs: ByteArray,
}

fn test_out_ref(ix: Int) -> OutputReference {
  OutputReference {
    transaction_id: #"0000000000000000000000000000000000000000000000000000000000000000",
    output_index: ix,
  }
}

fn make_gs_input(requires_receiver_kyc: Bool) -> Input {
  let gs_datum = GlobalStateDatum {
    global_state_script_credential_hash: #"9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a",
    transfers_paused: False,
    deactivated: False,
    mintable_amount: 1_000_000,
    admin_credential_hash: #"",
    power_user_linked_list_policy_id: test_pu_policy_id,
    denylist_linked_list_policy_id: test_denylist_policy_id,
    security_info: builtin.constr_data(0, []),
    trusted_entity_vkeys: [],
    member_root_hash: #"",
    requires_sender_kyc: False,
    requires_receiver_kyc,
    network_id: 1,
    // Irrelevant here — this field only matters to the PROXY's own
    // self-authorisation guard, which this validator never checks.
    minting_script_credential_hash: test_authority_hash,
    upgrades_locked: False,
  }
  Input {
    output_reference: test_out_ref(0),
    output: Output {
      address: Address {
        payment_credential: Script(test_gs_policy_id),
        stake_credential: None,
      },
      value: merge(
        from_lovelace(2_000_000),
        from_asset(test_gs_policy_id, constants.global_state_asset_name, 1),
      ),
      datum: InlineDatum(gs_datum),
      reference_script: None,
    },
  }
}

const test_admin_hash: ByteArray =
  #"0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a"

// GlobalState carrying a real admin credential, as a REFERENCE input — the
// shape a registration uses (no supply changes, so there is no cap to enforce
// and no reason to spend it).
fn make_gs_ref_input_with(deactivated: Bool) -> Input {
  let base = make_gs_input(False)
  expect InlineDatum(raw) = base.output.datum
  expect gs_datum: GlobalStateDatum = raw
  Input {
    output_reference: test_out_ref(5),
    output: Output {
      ..base.output,
      datum: InlineDatum(
        GlobalStateDatum {
          ..gs_datum,
          admin_credential_hash: test_admin_hash,
          deactivated,
        },
      ),
    },
  }
}

fn make_gs_ref_input() -> Input {
  make_gs_ref_input_with(False)
}

fn make_gs_ref_input_deactivated() -> Input {
  make_gs_ref_input_with(True)
}

fn make_gs_ref_input_locked() -> Input {
  let base = make_gs_ref_input()
  expect InlineDatum(raw) = base.output.datum
  expect gs_datum: GlobalStateDatum = raw
  Input {
    ..base,
    output: Output {
      ..base.output,
      datum: InlineDatum(GlobalStateDatum { ..gs_datum, upgrades_locked: True }),
    },
  }
}

// The mint-path GlobalState input (SPENT — `make_gs_input`'s shape), but
// with its `power_user_linked_list_policy_id` field overridden. Models a
// GlobalState whose field 3 names a different list policy than the one the
// power-user node's NFT is under.
fn make_gs_input_with_pu_policy(pu_policy_id: ByteArray) -> Input {
  let base = make_gs_input(False)
  expect InlineDatum(raw) = base.output.datum
  expect gs_datum: GlobalStateDatum = raw
  Input {
    ..base,
    output: Output {
      ..base.output,
      datum: InlineDatum(
        GlobalStateDatum {
          ..gs_datum,
          power_user_linked_list_policy_id: pu_policy_id,
        },
      ),
    },
  }
}

// A registry node output that ENABLES unfracking — must be rejected.
fn make_registry_node_output_with_unfracking() -> Output {
  let node = TestRegistryNode {
    key: test_issuance_policy_id,
    next: #"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    minting_logic_script: Script(test_proxy_hash),
    transfer_logic_script: Script(test_transfer_logic_hash),
    third_party_transfer_logic_script: Script(test_third_party_logic_hash),
    unfracking_logic_script: Script(test_pu_credential_hash),
    global_state_cs: test_gs_policy_id,
  }
  Output { ..make_registry_ref_input().output, datum: InlineDatum(node) }
}

// A registry node whose TRANSFER-LOGIC field (3) names a VerificationKey
// instead of a script. CIP-113 leaves the field free-form; this deployment
// requires it to be script-gated so the transfer path can actually run.
fn make_registry_node_output_with_vkey_transfer_logic() -> Output {
  let node = TestRegistryNode {
    key: test_issuance_policy_id,
    next: #"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    minting_logic_script: Script(test_proxy_hash),
    transfer_logic_script: VerificationKey(test_transfer_logic_hash),
    third_party_transfer_logic_script: Script(test_third_party_logic_hash),
    unfracking_logic_script: VerificationKey(#""),
    global_state_cs: test_gs_policy_id,
  }
  Output { ..make_registry_ref_input().output, datum: InlineDatum(node) }
}

// Same, but the THIRD-PARTY transfer-logic field (4) is the one that names a
// VerificationKey instead of a script.
fn make_registry_node_output_with_vkey_third_party_logic() -> Output {
  let node = TestRegistryNode {
    key: test_issuance_policy_id,
    next: #"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    minting_logic_script: Script(test_proxy_hash),
    transfer_logic_script: Script(test_transfer_logic_hash),
    third_party_transfer_logic_script: VerificationKey(
      test_third_party_logic_hash,
    ),
    unfracking_logic_script: VerificationKey(#""),
    global_state_cs: test_gs_policy_id,
  }
  Output { ..make_registry_ref_input().output, datum: InlineDatum(node) }
}

fn make_pu_node_ref_input(can_mint: Bool, can_burn: Bool) -> Input {
  let pu = PowerUser {
    credential_hash: test_pu_credential_hash,
    is_admin: False,
    can_mint,
    can_burn,
    can_pause: False,
    can_force_transfer: False,
  }
  let element: Element<Data, PowerUser> = Element {
    data: Node { data: pu },
    link: None,
  }
  let node_asset_name = bytearray.concat(
    constants.linked_list_node_key_prefix,
    test_pu_credential_hash,
  )
  Input {
    output_reference: test_out_ref(1),
    output: Output {
      address: Address {
        payment_credential: Script(test_pu_script_hash),
        stake_credential: None,
      },
      value: merge(
        from_lovelace(2_000_000),
        from_asset(test_pu_policy_id, node_asset_name, 1),
      ),
      datum: InlineDatum(element),
      reference_script: None,
    },
  }
}

// CIP-113 registry node ref input: exactly one registry NFT so
// `has_any_nft_strict` locates it; field 2 must equal the PROXY's known
// hash — never this authority's own credential.
fn make_registry_ref_input() -> Input {
  let node = TestRegistryNode {
    key: test_issuance_policy_id,
    next: #"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    minting_logic_script: Script(test_proxy_hash),
    transfer_logic_script: Script(test_transfer_logic_hash),
    third_party_transfer_logic_script: Script(test_third_party_logic_hash),
    unfracking_logic_script: VerificationKey(#""),
    global_state_cs: test_gs_policy_id,
  }
  Input {
    output_reference: test_out_ref(2),
    output: Output {
      address: Address {
        payment_credential: Script(test_registry_policy_id),
        stake_credential: None,
      },
      value: merge(
        from_lovelace(2_000_000),
        from_asset(test_registry_policy_id, "Node", 1),
      ),
      datum: InlineDatum(node),
      reference_script: None,
    },
  }
}

// A registry node belonging to a DIFFERENT programmable token — same
// registry policy, well-formed single NFT, but its `minting_logic_script`
// names neither this deployment's proxy nor anything related. Models the
// reference input a transaction picks up when it moves a second
// programmable token alongside this one.
fn make_decoy_registry_ref_input() -> Input {
  let node = TestRegistryNode {
    key: #"9999999999999999999999999999999999999999999999999999999999",
    next: #"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    minting_logic_script: Script(
      #"aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11",
    ),
    transfer_logic_script: Script(
      #"bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22",
    ),
    third_party_transfer_logic_script: Script(
      #"cc33cc33cc33cc33cc33cc33cc33cc33cc33cc33cc33cc33cc33cc33",
    ),
    unfracking_logic_script: VerificationKey(#""),
    global_state_cs: #"dd44dd44dd44dd44dd44dd44dd44dd44dd44dd44dd44dd44dd44dd44",
  }
  Input {
    output_reference: test_out_ref(9),
    output: Output {
      address: Address {
        payment_credential: Script(test_registry_policy_id),
        stake_credential: None,
      },
      value: merge(
        from_lovelace(2_000_000),
        from_asset(test_registry_policy_id, "Node", 1),
      ),
      datum: InlineDatum(node),
      reference_script: None,
    },
  }
}

// Denylist ROOT element with an empty list (`link: None`) — the root covers
// every possible key, so it is a valid absence proof for any target.
fn make_denylist_root_ref_input() -> Input {
  let root_info: Data = builtin.constr_data(0, [])
  let element: Element<Data, Data> = Element {
    data: Root { data: root_info },
    link: None,
  }
  Input {
    output_reference: test_out_ref(3),
    output: Output {
      address: Address {
        payment_credential: Script(test_denylist_spend_hash),
        stake_credential: None,
      },
      value: merge(
        from_lovelace(2_000_000),
        from_asset(test_denylist_policy_id, constants.linked_list_root_key, 1),
      ),
      datum: InlineDatum(element),
      reference_script: None,
    },
  }
}

// Denylist NODE keyed exactly at `pkh` — the target IS denylisted, so this
// node cannot witness its absence.
fn make_denylist_node_ref_input(pkh: ByteArray) -> Input {
  // A well-formed FULL freeze of `pkh`.
  let node_info: Data = Denylist {
    frozen_amount: None,
    metadata: builtin.constr_data(0, []),
  }
  let element: Element<Data, Data> = Element {
    data: Node { data: node_info },
    link: None,
  }
  let node_asset_name = bytearray.concat(
    constants.linked_list_node_key_prefix,
    pkh,
  )
  Input {
    output_reference: test_out_ref(3),
    output: Output {
      address: Address {
        payment_credential: Script(test_denylist_spend_hash),
        stake_credential: None,
      },
      value: merge(
        from_lovelace(2_000_000),
        from_asset(test_denylist_policy_id, node_asset_name, 1),
      ),
      datum: InlineDatum(element),
      reference_script: None,
    },
  }
}

fn make_dest_output(amount: Int) -> Output {
  make_dest_output_for(amount, test_dest_stake_hash)
}

fn make_dest_output_for(amount: Int, stake_hash: ByteArray) -> Output {
  Output {
    address: Address {
      payment_credential: Script(test_plb_hash),
      stake_credential: Some(Inline(VerificationKey(stake_hash))),
    },
    value: merge(
      from_lovelace(2_000_000),
      from_asset(test_issuance_policy_id, test_security_asset_name, amount),
    ),
    datum: NoDatum,
    reference_script: None,
  }
}

// A token-bearing output with NO stake credential (an enterprise address).
fn make_enterprise_dest_output(amount: Int) -> Output {
  Output {
    address: Address {
      payment_credential: Script(test_plb_hash),
      stake_credential: None,
    },
    value: merge(
      from_lovelace(2_000_000),
      from_asset(test_issuance_policy_id, test_security_asset_name, amount),
    ),
    datum: NoDatum,
    reference_script: None,
  }
}

/// GlobalState's continuing output for a `MintBurn` of `minted_amount`:
/// `input`'s output with its datum's `mintable_amount` lowered by
/// `minted_amount` (raised for a burn), everything else unchanged.
fn debited_gs_output(input: Input, minted_amount: Int) -> Output {
  expect InlineDatum(raw) = input.output.datum
  expect gs_datum: GlobalStateDatum = raw
  Output {
    ..input.output,
    datum: InlineDatum(
      GlobalStateDatum {
        ..gs_datum,
        mintable_amount: gs_datum.mintable_amount - minted_amount,
      },
    ),
  }
}

// Reference-input order: 0 = power-user node, 1 = registry node,
// 2 = denylist covering node (the index the destination actions cite).
// Output 0 is GlobalState's continuing output, debited by `minted_amount`
// (INVARIANT 2); `outputs` follow it.
fn make_withdraw_tx(
  minted_amount: Int,
  can_mint: Bool,
  can_burn: Bool,
  requires_receiver_kyc: Bool,
  denylist_ref: Input,
  outputs: List<Output>,
  signatories: List<ByteArray>,
) -> Transaction {
  Transaction {
    inputs: [make_gs_input(requires_receiver_kyc)],
    reference_inputs: [
      make_pu_node_ref_input(can_mint, can_burn),
      make_registry_ref_input(),
      denylist_ref,
    ],
    outputs: [
      debited_gs_output(make_gs_input(requires_receiver_kyc), minted_amount),
      ..outputs
    ],
    fee: 0,
    mint: from_asset(
      test_issuance_policy_id,
      test_security_asset_name,
      minted_amount,
    ),
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
    extra_signatories: signatories,
    redeemers: [],
    datums: dict.empty,
    id: #"0000000000000000000000000000000000000000000000000000000000000000",
    votes: [],
    proposal_procedures: [],
    current_treasury_amount: None,
    treasury_donation: None,
  }
}

// Structurally invalid KYC proof — only reachable when receiver KYC is
// required, where it must make the destination check fail.
fn dummy_proof() {
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

fn clean_dest_action() -> PartyAction {
  PartyAction { proof: dummy_proof(), denylist_ref_input_index: 2 }
}

fn run_withdraw(redeemer: MintingAuthorityWithdrawRedeemer, tx: Transaction) {
  run_withdraw_named(test_security_asset_name, redeemer, tx)
}

/// `run_withdraw` for a deployment whose security token is `security_name`.
fn run_withdraw_named(
  security_name: ByteArray,
  redeemer: MintingAuthorityWithdrawRedeemer,
  tx: Transaction,
) {
  // F08: the authority pins the transfer and seizure scripts it accepts in the
  // registry. The upgrade tests model the documented procedure: the authority
  // was first rotated to a build pinned to the NEW transfer script, and
  // `UpgradeRegistryNode` then re-points the node to it.
  let pinned_transfer_logic_hash = when redeemer is {
    UpgradeRegistryNode { .. } -> test_new_transfer_logic_hash
    _ -> test_transfer_logic_hash
  }
  minting_authority_validator.withdraw(
    security_name,
    test_gs_policy_id,
    test_registry_policy_id,
    test_proxy_hash,
    test_issuance_policy_id,
    pinned_transfer_logic_hash,
    test_third_party_logic_hash,
    redeemer,
    Script(test_authority_hash),
    tx,
  )
}

// ── destination verification ─────────────────────────────────────────────────

test mint_succeeds_with_clean_destination_no_receiver_kyc() {
  let amount = 1_000
  let redeemer = MintBurn {
    global_state_input_index: 0,
    global_state_output_index: 0,
    power_user_node_ref_input_index: 0,
    minted_amount: amount,
    destination_actions: [clean_dest_action()],
  }
  run_withdraw(
    redeemer,
    make_withdraw_tx(
      amount,
      True,
      False,
      False,
      make_denylist_root_ref_input(),
      [make_dest_output(amount)],
      [test_pu_credential_hash],
    ),
  )
}

test mint_fails_when_destination_denylisted() {
  let amount = 1_000
  let redeemer = MintBurn {
    global_state_input_index: 0,
    global_state_output_index: 0,
    power_user_node_ref_input_index: 0,
    minted_amount: amount,
    destination_actions: [clean_dest_action()],
  }
  !run_withdraw(
    redeemer,
    make_withdraw_tx(
      amount,
      True,
      False,
      False,
      make_denylist_node_ref_input(test_dest_stake_hash),
      [make_dest_output(amount)],
      [test_pu_credential_hash],
    ),
  )
}

test mint_fails_when_receiver_kyc_required_but_proof_invalid() {
  let amount = 1_000
  let redeemer = MintBurn {
    global_state_input_index: 0,
    global_state_output_index: 0,
    power_user_node_ref_input_index: 0,
    minted_amount: amount,
    destination_actions: [clean_dest_action()],
  }
  !run_withdraw(
    redeemer,
    make_withdraw_tx(
      amount,
      True,
      False,
      True,
      make_denylist_root_ref_input(),
      [make_dest_output(amount)],
      [test_pu_credential_hash],
    ),
  )
}

test mint_to_authorizing_power_user_bypasses_receiver_kyc() {
  let amount = 1_000
  let redeemer = MintBurn {
    global_state_input_index: 0,
    global_state_output_index: 0,
    power_user_node_ref_input_index: 0,
    minted_amount: amount,
    destination_actions: [clean_dest_action()],
  }
  run_withdraw(
    redeemer,
    make_withdraw_tx(
      amount,
      True,
      False,
      True,
      make_denylist_root_ref_input(),
      [make_dest_output_for(amount, test_pu_credential_hash)],
      [test_pu_credential_hash],
    ),
  )
}

test mint_fails_when_destination_action_missing() fail {
  let amount = 1_000
  let redeemer = MintBurn {
    global_state_input_index: 0,
    global_state_output_index: 0,
    power_user_node_ref_input_index: 0,
    minted_amount: amount,
    destination_actions: [],
  }
  run_withdraw(
    redeemer,
    make_withdraw_tx(
      amount,
      True,
      False,
      False,
      make_denylist_root_ref_input(),
      [make_dest_output(amount)],
      [test_pu_credential_hash],
    ),
  )
}

test burn_succeeds_without_destination_checks() {
  let amount = -1_000
  let redeemer = MintBurn {
    global_state_input_index: 0,
    global_state_output_index: 0,
    power_user_node_ref_input_index: 0,
    minted_amount: amount,
    destination_actions: [],
  }
  run_withdraw(
    redeemer,
    make_withdraw_tx(
      amount,
      False,
      True,
      False,
      make_denylist_root_ref_input(),
      [],
      [test_pu_credential_hash],
    ),
  )
}

test mint_to_enterprise_address_is_rejected() fail {
  let amount = 1_000
  let redeemer = MintBurn {
    global_state_input_index: 0,
    global_state_output_index: 0,
    power_user_node_ref_input_index: 0,
    minted_amount: amount,
    destination_actions: [clean_dest_action()],
  }
  run_withdraw(
    redeemer,
    make_withdraw_tx(
      amount,
      True,
      False,
      False,
      make_denylist_root_ref_input(),
      [make_enterprise_dest_output(amount)],
      [test_pu_credential_hash],
    ),
  )
}

// ── power-user authorisation ─────────────────────────────────────────────────

test mint_authority_withdraw_fails_when_not_signed_by_power_user() {
  let amount = 1_000
  let redeemer = MintBurn {
    global_state_input_index: 0,
    global_state_output_index: 0,
    power_user_node_ref_input_index: 0,
    minted_amount: amount,
    destination_actions: [clean_dest_action()],
  }
  !run_withdraw(
    redeemer,
    make_withdraw_tx(
      amount,
      True,
      False,
      False,
      make_denylist_root_ref_input(),
      [make_dest_output(amount)],
      [],
    ),
  )
}

test mint_authority_withdraw_fails_when_minting_without_mint_permission() {
  let amount = 1_000
  let redeemer = MintBurn {
    global_state_input_index: 0,
    global_state_output_index: 0,
    power_user_node_ref_input_index: 0,
    minted_amount: amount,
    destination_actions: [clean_dest_action()],
  }
  !run_withdraw(
    redeemer,
    make_withdraw_tx(
      amount,
      False,
      True,
      False,
      make_denylist_root_ref_input(),
      [make_dest_output(amount)],
      [test_pu_credential_hash],
    ),
  )
}

// ── power-user list policy id comes from GlobalState field 3 (INVARIANT 6) ───

test mint_succeeds_when_global_state_power_user_policy_id_matches() {
  // POSITIVE CONTROL. Same shape as `mint_succeeds_with_clean_destination_no_receiver_kyc`,
  // spelled out explicitly here so it differs from the negative test below in
  // exactly the GlobalState input's `power_user_linked_list_policy_id`.
  let amount = 1_000
  let redeemer = MintBurn {
    global_state_input_index: 0,
    global_state_output_index: 0,
    power_user_node_ref_input_index: 0,
    minted_amount: amount,
    destination_actions: [clean_dest_action()],
  }
  run_withdraw(
    redeemer,
    Transaction {
      ..make_withdraw_tx(
        amount,
        True,
        False,
        False,
        make_denylist_root_ref_input(),
        [make_dest_output(amount)],
        [test_pu_credential_hash],
      ),
      inputs: [make_gs_input_with_pu_policy(test_pu_policy_id)],
    },
  )
}

test mint_fails_when_global_state_power_user_policy_id_mismatches() fail {
  // Power users are authenticated under the GlobalState datum's own
  // `power_user_linked_list_policy_id`, never a fixed policy. Here it names a
  // policy the power-user node's NFT (under `test_pu_policy_id`) is not under,
  // so `utils.authenticated_power_user` in `verify_mint_or_burn` traps.
  let amount = 1_000
  let redeemer = MintBurn {
    global_state_input_index: 0,
    global_state_output_index: 0,
    power_user_node_ref_input_index: 0,
    minted_amount: amount,
    destination_actions: [clean_dest_action()],
  }
  run_withdraw(
    redeemer,
    Transaction {
      ..make_withdraw_tx(
        amount,
        True,
        False,
        False,
        make_denylist_root_ref_input(),
        [make_dest_output(amount)],
        [test_pu_credential_hash],
      ),
      inputs: [
        make_gs_input_with_pu_policy(
          #"9999999999999999999999999999999999999999999999999999999999",
        ),
      ],
    },
  )
}

// ── registry read removed from MintBurn ──────────────────────────────────────
//
// The three tests formerly here (resolving among decoy registry nodes,
// rejecting a wrong index, rejecting a node that names neither the proxy nor
// itself) pinned MintBurn's independent re-derivation of the issuance policy
// from a redeemer-cited registry node. That re-derivation is gone: the
// policy is pinned at compile time, and the base layer already authenticates
// whichever node invoked this withdraw-0. This positive test replaces them —
// proving the removal is real by omitting the registry node entirely.

test mint_succeeds_without_any_registry_reference_input() {
  // No registry node anywhere in this transaction — reference inputs are
  // power-user node (0) and denylist root (1); the registry node every
  // other fixture above keeps, unused, at index 1 is simply absent here.
  let amount = 1_000
  let redeemer = MintBurn {
    global_state_input_index: 0,
    global_state_output_index: 0,
    power_user_node_ref_input_index: 0,
    minted_amount: amount,
    destination_actions: [
      PartyAction { proof: dummy_proof(), denylist_ref_input_index: 1 },
    ],
  }
  run_withdraw(
    redeemer,
    Transaction {
      ..make_withdraw_tx(
        amount,
        True,
        False,
        False,
        make_denylist_root_ref_input(),
        [make_dest_output(amount)],
        [test_pu_credential_hash],
      ),
      reference_inputs: [
        make_pu_node_ref_input(True, False),
        make_denylist_root_ref_input(),
      ],
    },
  )
}

// ── Register: the CIP-113 registration, node reached via self.outputs ───────
//
// `Register` creates this token's registry node and nothing else under the
// issuance policy — except, for a CIP-68-named token, its reference NFT. The
// node is an OUTPUT here because at insert time it does not exist as a UTxO
// yet. GlobalState is referenced (no supply changes, so no cap to enforce) and
// the admin alone authorises. Every negative below differs from a positive
// control in exactly the condition its name gives.

/// CIP-68 user-token security names — `(222)`, `(333)` and `(444)` + "REF".
/// All three map to `test_reference_asset_name`, `(100)` + "REF".
const test_cip68_222_name: ByteArray = #"000de140524546"

const test_cip68_333_name: ByteArray = #"0014df10524546"

const test_cip68_444_name: ByteArray = #"001bc280524546"

/// `(100)` + "Y" — reference-labelled, but another body: not the reference
/// name of any security name these fixtures use.
const test_wrong_body_reference_name: ByteArray = #"000643b059"

/// A registration of a plain-named token: GlobalState referenced, the new
/// node at output 0, its registry NFT minted, `issuance_mint` added under the
/// issuance policy and `extra_outputs` appended after the node.
fn make_register_tx(
  issuance_mint: Assets,
  extra_outputs: List<Output>,
  signatories: List<ByteArray>,
) -> Transaction {
  Transaction {
    ..make_withdraw_tx(
      0,
      True,
      False,
      False,
      make_denylist_root_ref_input(),
      [],
      signatories,
    ),
    reference_inputs: [make_gs_ref_input()],
    outputs: [make_registry_ref_input().output, ..extra_outputs],
    mint: merge(from_asset(test_registry_policy_id, "Node", 1), issuance_mint),
  }
}

fn register_redeemer() -> MintingAuthorityWithdrawRedeemer {
  Register { registry_node_output_index: 0, global_state_ref_input_index: 0 }
}

/// A registration of a CIP-68-named token: its reference NFT minted once and
/// pinned in `carrier`.
fn make_cip68_register_tx(carrier: Output) -> Transaction {
  make_register_tx(
    from_asset(test_issuance_policy_id, test_reference_asset_name, 1),
    [carrier],
    [test_admin_hash],
  )
}

/// `Register` for a deployment whose security token is `name`.
fn register_named(name: ByteArray, tx: Transaction) -> Bool {
  run_withdraw_named(name, register_redeemer(), tx)
}

/// `Register` for the `(333)` CIP-68 deployment.
fn register_cip68(tx: Transaction) -> Bool {
  register_named(test_cip68_333_name, tx)
}

/// A carrier output holding exactly `name` ×1 under the issuance policy, at
/// the programmable base, owned by the admin, with a CIP-68 datum.
fn make_carrier_for(name: ByteArray) -> Output {
  Output {
    ..make_reference_nft_output(),
    value: merge(
      from_lovelace(2_000_000),
      from_asset(test_issuance_policy_id, name, 1),
    ),
  }
}

/// A reference-NFT output: at the programmable base, with an owner.
fn make_reference_nft_output_for_owner(owner_hash: ByteArray) -> Output {
  Output {
    address: Address {
      payment_credential: Script(test_plb_hash),
      stake_credential: Some(Inline(VerificationKey(owner_hash))),
    },
    value: merge(
      from_lovelace(2_000_000),
      from_asset(test_issuance_policy_id, test_reference_asset_name, 1),
    ),
    datum: InlineDatum(test_cip68_datum()),
    reference_script: None,
  }
}

fn make_reference_nft_output() -> Output {
  make_reference_nft_output_for_owner(test_admin_hash)
}

/// A correctly shaped CIP-68 datum: `Constr 0 [metadata, version, extra]`.
fn test_cip68_datum() -> Data {
  let d = Cip68Datum {
    metadata: [],
    version: 1,
    extra: builtin.constr_data(0, []),
  }
  let raw: Data = d
  raw
}

// ── Register: accepted shapes ────────────────────────────────────────────────

/// POSITIVE CONTROL for every plain-name negative: the node is created,
/// nothing is minted under the issuance policy, the admin signs.
test register_plain_name_succeeds_minting_nothing() {
  run_withdraw(
    register_redeemer(),
    make_register_tx(zero, [], [test_admin_hash]),
  )
}

test register_cip68_222_name_succeeds_minting_its_reference_nft() {
  register_named(
    test_cip68_222_name,
    make_cip68_register_tx(make_reference_nft_output()),
  )
}

/// POSITIVE CONTROL for every CIP-68-name negative.
test register_cip68_333_name_succeeds_minting_its_reference_nft() {
  register_cip68(make_cip68_register_tx(make_reference_nft_output()))
}

test register_cip68_444_name_succeeds_minting_its_reference_nft() {
  register_named(
    test_cip68_444_name,
    make_cip68_register_tx(make_reference_nft_output()),
  )
}

/// The metadata authority may be separate from the GlobalState admin. The admin
/// still signs the registration, but the reference NFT may start at a
/// different inline owner credential.
test register_allows_a_reference_nft_owned_by_a_metadata_authority() {
  register_cip68(
    make_cip68_register_tx(
      make_reference_nft_output_for_owner(test_dest_stake_hash),
    ),
  )
}

/// The mint rule is scoped to the issuance policy: a registration that also
/// mints an unrelated policy's token (a bundled insert, say) is not refused
/// for it.
test register_scopes_its_mint_rule_to_the_issuance_policy() {
  let tx = make_register_tx(zero, [], [test_admin_hash])
  run_withdraw(
    register_redeemer(),
    Transaction {
      ..tx,
      mint: merge(
        tx.mint,
        from_asset(
          #"abababababababababababababababababababababababababababab",
          "OTHER",
          1,
        ),
      ),
    },
  )
}

// ── Register: name rules ─────────────────────────────────────────────────────

/// A `(100)`-labelled security name is refused, even minting nothing: the
/// supply would be its own metadata token. Not a CIP-68 name, so the plain
/// rules all pass; only the label rule refuses. POSITIVE CONTROL:
/// `register_plain_name_succeeds_minting_nothing`.
test register_rejects_a_reference_labelled_security_name() {
  !register_named(
    #"000643b0534543",
    make_register_tx(zero, [], [test_admin_hash]),
  )
}

/// A plain name must not be empty. POSITIVE CONTROL:
/// `register_plain_name_succeeds_minting_nothing`.
test register_rejects_an_empty_security_name() {
  !register_named(#"", make_register_tx(zero, [], [test_admin_hash]))
}

/// A bare `(333)` label is a CIP-68 name with an empty body, which is refused.
/// Minting nothing, it also fails the mint rule — so this one alone would not
/// isolate the body rule; the next test does.
test register_rejects_a_bare_label_security_name_minting_nothing() {
  !register_named(#"0014df10", make_register_tx(zero, [], [test_admin_hash]))
}

/// A bare `(333)` label minting its (bare `(100)`) reference NFT ×1 into a
/// well-formed pinned carrier: the mint and custody rules both pass, so only
/// the body rule refuses.
test register_rejects_a_bare_label_security_name_minting_its_reference() {
  !register_named(
    #"0014df10",
    make_register_tx(
      from_asset(test_issuance_policy_id, #"000643b0", 1),
      [make_carrier_for(#"000643b0")],
      [test_admin_hash],
    ),
  )
}

// ── Register: the two-way mint rule ──────────────────────────────────────────

/// A CIP-68 name must mint its reference NFT.
test register_cip68_name_rejects_a_missing_reference_nft() {
  !register_cip68(make_register_tx(zero, [], [test_admin_hash]))
}

/// A plain name mints nothing — not even a reference NFT for "SEC", in a
/// well-formed carrier.
test register_plain_name_rejects_minting_a_reference_nft() {
  !run_withdraw(
    register_redeemer(),
    make_register_tx(
      from_asset(test_issuance_policy_id, #"000643b0534543", 1),
      [make_carrier_for(#"000643b0534543")],
      [test_admin_hash],
    ),
  )
}

/// A `(100)` name with another body is not this token's reference NFT, even
/// alone in a well-formed carrier.
test register_cip68_name_rejects_a_wrong_body_reference() {
  !register_cip68(
    make_register_tx(
      from_asset(test_issuance_policy_id, test_wrong_body_reference_name, 1),
      [make_carrier_for(test_wrong_body_reference_name)],
      [test_admin_hash],
    ),
  )
}

/// The exact reference NFT, well-formed and alone in its carrier, PLUS a second
/// `(100)` name in its own UTxO. Only the exact-shape mint rule refuses: a
/// rule that merely counted the reference name would accept it.
test register_cip68_name_rejects_two_reference_tokens() {
  !register_cip68(
    make_register_tx(
      merge(
        from_asset(test_issuance_policy_id, test_reference_asset_name, 1),
        from_asset(test_issuance_policy_id, test_wrong_body_reference_name, 1),
      ),
      [
        make_reference_nft_output(),
        make_carrier_for(test_wrong_body_reference_name),
      ],
      [test_admin_hash],
    ),
  )
}

/// The reference NFT is an NFT. Two of it would be a second, uncapped supply
/// under the security token's own policy id.
test register_cip68_name_rejects_a_reference_quantity_of_two() {
  !register_cip68(
    make_register_tx(
      from_asset(test_issuance_policy_id, test_reference_asset_name, 2),
      [
        Output {
          ..make_reference_nft_output(),
          value: merge(
            from_lovelace(2_000_000),
            from_asset(test_issuance_policy_id, test_reference_asset_name, 2),
          ),
        },
      ],
      [test_admin_hash],
    ),
  )
}

/// `Register` never mints supply: the first supply is a later `MintBurn`,
/// which applies the power-user, destination and cap rules a registration
/// does not.
test register_plain_name_rejects_minting_supply() {
  !run_withdraw(
    register_redeemer(),
    make_register_tx(
      from_asset(test_issuance_policy_id, test_security_asset_name, 1_000),
      [make_dest_output(1_000)],
      [test_admin_hash],
    ),
  )
}

/// Nor alongside the reference NFT, whose carrier is well-formed.
test register_cip68_name_rejects_minting_supply_alongside_its_reference() {
  !register_cip68(
    make_register_tx(
      merge(
        from_asset(test_issuance_policy_id, test_reference_asset_name, 1),
        from_asset(test_issuance_policy_id, test_cip68_333_name, 1_000),
      ),
      [
        make_reference_nft_output(),
        Output {
          ..make_dest_output(1_000),
          value: merge(
            from_lovelace(2_000_000),
            from_asset(test_issuance_policy_id, test_cip68_333_name, 1_000),
          ),
        },
      ],
      [test_admin_hash],
    ),
  )
}

/// THE CORE PROTECTION. A name that is neither the reference NFT nor anything
/// else `Register` may mint is refused. Without this the extra name would be
/// uncapped, unvetted at mint, and — because the transfer path filters by
/// asset name — movable with no denylist or KYC check at all.
test register_cip68_name_rejects_an_unknown_third_asset_name() {
  !register_cip68(
    make_register_tx(
      merge(
        from_asset(test_issuance_policy_id, test_reference_asset_name, 1),
        from_asset(test_issuance_policy_id, "SHADOW", 1_000_000),
      ),
      [make_reference_nft_output()],
      [test_admin_hash],
    ),
  )
}

// ── Register: the reference NFT's carrier ────────────────────────────────────

/// With no stake credential on the carrier, `cip68_output_is_pinned`'s
/// `expect Some(Inline(_owner)) = output.address.stake_credential` traps —
/// hence `fail`.
test register_rejects_a_reference_nft_without_stake_credential() fail {
  register_cip68(
    make_cip68_register_tx(
      Output {
        ..make_reference_nft_output(),
        address: Address {
          payment_credential: Script(test_plb_hash),
          stake_credential: None,
        },
      },
    ),
  )
}

/// A carrier whose datum is not the CIP-68 three-field constructor: the
/// reference NFT cannot be created holding something a CIP-68 reader cannot
/// parse. `cip68.output_is_well_formed` traps.
test register_rejects_a_reference_nft_with_a_malformed_datum() fail {
  register_cip68(
    make_cip68_register_tx(
      Output {
        ..make_reference_nft_output(),
        datum: InlineDatum(builtin.constr_data(0, [])),
      },
    ),
  )
}

/// A carrier that ALSO holds security tokens. Metadata must never carry value:
/// every compliance scan is scoped to the security asset name and would not
/// look at this UTxO. `cip68.output_is_well_formed` traps.
test register_rejects_a_reference_nft_holding_security_tokens() fail {
  register_cip68(
    make_cip68_register_tx(
      Output {
        ..make_reference_nft_output(),
        value: merge(
          make_reference_nft_output().value,
          from_asset(test_issuance_policy_id, test_cip68_333_name, 10),
        ),
      },
    ),
  )
}

// ── Register: protocol state and authorisation ───────────────────────────────

/// INVARIANT 4: deactivation is terminal. The `!deactivated` conjunct returns
/// False.
test register_fails_when_deactivated() {
  let base = make_register_tx(zero, [], [test_admin_hash])
  !run_withdraw(
    register_redeemer(),
    Transaction { ..base, reference_inputs: [make_gs_ref_input_deactivated()] },
  )
}

test register_fails_without_admin_signature() {
  !run_withdraw(register_redeemer(), make_register_tx(zero, [], []))
}

/// A UTxO carrying a GlobalState-shaped datum but NOT the NFT must not stand in
/// for GlobalState: its datum would choose the admin.
test register_rejects_a_global_state_without_its_nft() fail {
  let base = make_register_tx(zero, [], [test_admin_hash])
  run_withdraw(
    register_redeemer(),
    Transaction {
      ..base,
      reference_inputs: [without_gs_nft(make_gs_ref_input())],
    },
  )
}

/// `Register` reads GlobalState as a reference input only. Here it is spent
/// instead — at input 0, carrying the admin, with the admin signing — and
/// `reference_inputs` is empty, so index 0 does not exist. Trap-only
/// (`|| True`): the empty-list index traps, and a False return must not pass.
test register_fails_when_global_state_is_only_spent() fail {
  run_withdraw(
    register_redeemer(),
    Transaction {
      ..make_register_tx(zero, [], [test_admin_hash]),
      inputs: [make_gs_ref_input()],
      reference_inputs: [],
    },
  ) || True
}

/// The reference index points at reference input 0, the registry node, while
/// the real GlobalState sits at index 1. The GlobalState NFT check traps on the
/// registry node. Trap-only (`|| True`), as above.
test register_fails_when_ref_index_is_not_global_state() fail {
  run_withdraw(
    register_redeemer(),
    Transaction {
      ..make_register_tx(zero, [], [test_admin_hash]),
      reference_inputs: [make_registry_ref_input(), make_gs_ref_input()],
    },
  ) || True
}

/// Pins that the redeemer's GlobalState index is honoured, not assumed 0.
test register_succeeds_with_global_state_at_a_non_zero_reference_index() {
  run_withdraw(
    Register { registry_node_output_index: 0, global_state_ref_input_index: 1 },
    Transaction {
      ..make_register_tx(zero, [], [test_admin_hash]),
      reference_inputs: [
        make_registry_ref_input(),
        make_gs_ref_input(),
        make_denylist_root_ref_input(),
      ],
    },
  )
}

// ── Register: registration structure (INVARIANT 5) ───────────────────────────

/// The decoy node is a genuine registry node for a DIFFERENT token, so it
/// must not be usable to derive this token's issuance policy — otherwise a
/// redeemer could point at an unrelated policy and make every check below
/// vacuous.
test register_fails_when_node_output_names_another_minting_logic() fail {
  let base = make_register_tx(zero, [], [test_admin_hash])
  run_withdraw(
    register_redeemer(),
    Transaction { ..base, outputs: [make_decoy_registry_ref_input().output] },
  )
}

test register_fails_when_unfracking_is_enabled() fail {
  // INVARIANT 5: unfracking would let a holder split this policy out of a
  // shared UTxO without its transfer logic ever running.
  let base = make_register_tx(zero, [], [test_admin_hash])
  run_withdraw(
    register_redeemer(),
    Transaction {
      ..base,
      outputs: [make_registry_node_output_with_unfracking()],
    },
  )
}

test register_fails_when_transfer_logic_is_not_a_script() fail {
  // Field 3 must be script-gated so the transfer side actually runs — a
  // `VerificationKey` here would make `transfer_logic_script` unable to
  // ever execute as transfer logic. POSITIVE CONTROL:
  // `register_plain_name_succeeds_minting_nothing`, whose node (via
  // `make_register_tx` -> `make_registry_ref_input`) differs from this one in
  // exactly this field.
  let base = make_register_tx(zero, [], [test_admin_hash])
  run_withdraw(
    register_redeemer(),
    Transaction {
      ..base,
      outputs: [make_registry_node_output_with_vkey_transfer_logic()],
    },
  )
}

test register_fails_when_third_party_logic_is_not_a_script() fail {
  // Same requirement, field 4. POSITIVE CONTROL: same as above.
  let base = make_register_tx(zero, [], [test_admin_hash])
  run_withdraw(
    register_redeemer(),
    Transaction {
      ..base,
      outputs: [make_registry_node_output_with_vkey_third_party_logic()],
    },
  )
}

/// Registration must declare this deployment as GlobalState in field 6:
/// off-chain readers locate GlobalState through it.
test register_rejects_a_foreign_global_state_cs() fail {
  let node = TestRegistryNode {
    key: test_issuance_policy_id,
    next: #"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    minting_logic_script: Script(test_proxy_hash),
    transfer_logic_script: Script(test_transfer_logic_hash),
    third_party_transfer_logic_script: Script(test_third_party_logic_hash),
    unfracking_logic_script: VerificationKey(#""),
    global_state_cs: #"abababababababababababababababababababababababababababab",
  }
  let base = make_register_tx(zero, [], [test_admin_hash])
  run_withdraw(
    register_redeemer(),
    Transaction {
      ..base,
      outputs: [
        Output { ..make_registry_ref_input().output, datum: InlineDatum(node) },
      ],
    },
  )
}

test register_fails_when_no_registry_nft_is_minted() fail {
  // No registry NFT minted means this is an in-place node UPDATE, not an
  // insert — that path re-points transfer logic and must never be reachable
  // through a registration redeemer.
  let base = make_register_tx(zero, [], [test_admin_hash])
  run_withdraw(register_redeemer(), Transaction { ..base, mint: zero })
}

test register_cannot_smuggle_a_registry_node_update() fail {
  // ATTACK: `registry_spend`'s in-place UPDATE path mints no registry NFT and
  // demands the proxy's withdraw-0, which this validator's approval supplies.
  // Requiring merely that SOME registry NFT is minted would not exclude
  // updates — "some" is satisfiable by bundling an unrelated insert for a
  // DIFFERENT token, while OUR node is simultaneously spent and re-emitted
  // with `transfer_logic_script` re-pointed at a permissive script. The
  // re-emitted node still names our proxy (the base layer freezes that field
  // on update), still forbids unfracking and still pins our GlobalState, so
  // every other structural check passes.
  //
  // Nothing is minted under the issuance policy, so the mint rule passes too.
  // Only the admin signature is needed — so the registry NFT check must be
  // scoped to THIS node.
  let our_node_spent = Input {
    output_reference: test_out_ref(7),
    output: make_registry_ref_input().output,
  }
  let base = make_register_tx(zero, [], [test_admin_hash])
  run_withdraw(
    register_redeemer(),
    Transaction {
      ..base,
      // our node is SPENT (the update), alongside whatever the bundled
      // unrelated insert spends
      inputs: [our_node_spent],
      // the bundled unrelated insert mints a registry NFT, satisfying the
      // "this is an insert" heuristic
      mint: from_asset(test_registry_policy_id, "OtherTokenNode", 1),
    },
  )
}

// ── Steady state: MintBurn mints only `security_asset_name` ─────────────────

/// A clean 1 000-unit mint of the `(333)` CIP-68 security name.
fn cip68_supply_mint_tx() -> Transaction {
  Transaction {
    ..signed_mint_tx(1_000),
    outputs: [
      debited_gs_output(make_gs_input(False), 1_000),
      Output {
        ..make_dest_output(1_000),
        value: merge(
          from_lovelace(2_000_000),
          from_asset(test_issuance_policy_id, test_cip68_333_name, 1_000),
        ),
      },
    ],
    mint: from_asset(test_issuance_policy_id, test_cip68_333_name, 1_000),
  }
}

/// POSITIVE CONTROL: a CIP-68-named token's supply mints exactly as a plain
/// one's does.
test mint_burn_succeeds_for_a_cip68_security_name() {
  run_withdraw_named(
    test_cip68_333_name,
    mint_burn_redeemer(1_000),
    cip68_supply_mint_tx(),
  )
}

/// Steady state mints supply and nothing else. Allowing the reference NFT here
/// would let it be re-minted after the token is live, defeating the once-only
/// property that registration gives it. Differs from
/// `mint_burn_succeeds_for_a_cip68_security_name` in exactly the extra mint
/// and its carrier.
test steady_state_mint_rejects_the_reference_nft() {
  let base = cip68_supply_mint_tx()
  !run_withdraw_named(
    test_cip68_333_name,
    mint_burn_redeemer(1_000),
    Transaction {
      ..base,
      mint: merge(
        base.mint,
        from_asset(test_issuance_policy_id, test_reference_asset_name, 1),
      ),
      outputs: list.concat(base.outputs, [make_reference_nft_output()]),
    },
  )
}

/// A second name beside the supply. POSITIVE CONTROL:
/// `mint_succeeds_with_clean_destination_no_receiver_kyc`.
test mint_burn_rejects_a_second_asset_name() {
  let base = signed_mint_tx(1_000)
  !run_withdraw(
    mint_burn_redeemer(1_000),
    Transaction {
      ..base,
      mint: merge(
        base.mint,
        from_asset(test_issuance_policy_id, "SHADOW", 1_000_000),
      ),
    },
  )
}

// ── A registry INSERT is reachable through Register only ────────────────────
//
// The CIP-113 insert shape: another token's registry node is the covering
// node, spent and re-emitted; our new node is emitted beside it; the new
// node's registry NFT is minted. Each redeemer below is given that shape.

fn covering_node_input() -> Input {
  make_decoy_registry_ref_input()
}

/// Our new node at output 0, the re-emitted covering node at output 1.
fn registry_insert_tx(base: Transaction) -> Transaction {
  Transaction {
    ..base,
    inputs: list.concat(base.inputs, [covering_node_input()]),
    outputs: list.concat(
      [make_registry_ref_input().output, covering_node_input().output],
      base.outputs,
    ),
    mint: merge(base.mint, from_asset(test_registry_policy_id, "Node", 1)),
  }
}

/// POSITIVE CONTROL for the two tests below.
test registry_insert_with_a_register_redeemer_succeeds() {
  let base = make_register_tx(zero, [], [test_admin_hash])
  run_withdraw(
    register_redeemer(),
    registry_insert_tx(Transaction { ..base, outputs: [], mint: zero }),
  )
}

/// A valid supply mint carrying the insert components. INVARIANT 1: the
/// spent covering node trips the MintBurn no-registry-node-spent guard.
test registry_insert_with_a_mint_burn_redeemer_is_rejected() fail {
  let base = signed_mint_tx(1_000)
  // `registry_insert_tx` prepends two outputs, so GlobalState's continuing
  // output is output 2.
  run_withdraw(
    MintBurn {
      global_state_input_index: 0,
      global_state_output_index: 2,
      power_user_node_ref_input_index: 0,
      minted_amount: 1_000,
      destination_actions: [clean_dest_action()],
    },
    registry_insert_tx(base),
  )
}

/// The insert tx under `UpgradeRegistryNode`, aimed at the covering node as
/// the spent node: it names another token's minting logic, so the spent-node
/// identity assertion in `derive_issuance_policy_id_from_registry_node`
/// traps.
test registry_insert_with_an_upgrade_registry_node_redeemer_is_rejected() fail {
  let base = make_register_tx(zero, [], [test_admin_hash])
  let tx = registry_insert_tx(Transaction { ..base, outputs: [], mint: zero })
  run_withdraw(
    UpgradeRegistryNode {
      registry_node_input_index: 1,
      registry_node_output_index: 0,
      global_state_location: GlobalStateReferenced {
        global_state_ref_input_index: 0,
      },
    },
    tx,
  )
}

// ── UpgradeRegistryNode: the CIP-113 transfer-logic upgrade path ────────────
//
// Shape mirrors registry_spend's update branch: the node is SPENT and exactly
// one registry-node output continues it, nothing is minted, GlobalState is
// referenced.

fn make_upgraded_node_output(
  transfer_logic: Credential,
  unfracking: Credential,
  global_state_cs: ByteArray,
) -> Output {
  let node = TestRegistryNode {
    key: test_issuance_policy_id,
    next: #"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    // frozen by the base layer across an update
    minting_logic_script: Script(test_proxy_hash),
    transfer_logic_script: transfer_logic,
    third_party_transfer_logic_script: Script(test_third_party_logic_hash),
    unfracking_logic_script: unfracking,
    global_state_cs,
  }
  Output { ..make_registry_ref_input().output, datum: InlineDatum(node) }
}

// Same shape as `make_upgraded_node_output`, but with the THIRD-PARTY
// transfer-logic field (4) — which that fixture hardcodes to a script —
// swapped for a VerificationKey instead.
fn make_upgraded_node_output_with_vkey_third_party_logic() -> Output {
  let node = TestRegistryNode {
    key: test_issuance_policy_id,
    next: #"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    minting_logic_script: Script(test_proxy_hash),
    transfer_logic_script: Script(test_new_transfer_logic_hash),
    third_party_transfer_logic_script: VerificationKey(
      test_third_party_logic_hash,
    ),
    unfracking_logic_script: VerificationKey(#""),
    global_state_cs: test_gs_policy_id,
  }
  Output { ..make_registry_ref_input().output, datum: InlineDatum(node) }
}

fn make_upgrade_tx(
  node_output: Output,
  gs_ref: Input,
  signatories: List<ByteArray>,
) -> Transaction {
  Transaction {
    ..make_withdraw_tx(
      0,
      True,
      False,
      False,
      make_denylist_root_ref_input(),
      [],
      signatories,
    ),
    inputs: [
      Input {
        output_reference: test_out_ref(7),
        output: make_registry_ref_input().output,
      },
    ],
    reference_inputs: [gs_ref],
    outputs: [node_output],
    mint: zero,
  }
}

fn upgrade_redeemer() -> MintingAuthorityWithdrawRedeemer {
  UpgradeRegistryNode {
    registry_node_input_index: 0,
    registry_node_output_index: 0,
    global_state_location: GlobalStateReferenced {
      global_state_ref_input_index: 0,
    },
  }
}

// A different transfer-logic script — the point of the upgrade.
const test_new_transfer_logic_hash: ByteArray =
  #"0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e"

// ── UpgradeRegistryNode: GlobalState may be spent instead of referenced ─────
//
// `UpgradeRegistryNode` reads GlobalState for the admin credential, the
// deactivation flag and the upgrade lock and nothing else, so it takes a
// `GlobalStateLocation` rather than a fixed reference index. These tests
// exercise the SPENT branch, which the platform does not build today — an
// unverified branch of shared, security-relevant code is exactly what a future
// caller trips over. Contrast `MintBurn`, which keeps a bare index because it
// MUST spend, and `Register`, which only ever references it.
//
// GlobalState is absent from `reference_inputs` in the fixture, as it would
// be in a real transaction that spends it (Conway rejects the overlap). The
// spent input reuses `make_gs_ref_input`'s output so it carries the admin.

fn make_upgrade_tx_gs_spent(node_output: Output) -> Transaction {
  Transaction {
    ..make_upgrade_tx(node_output, make_gs_ref_input(), [test_admin_hash]),
    inputs: [
      Input {
        output_reference: test_out_ref(7),
        output: make_registry_ref_input().output,
      },
      make_gs_ref_input(),
    ],
    reference_inputs: [],
  }
}

fn upgraded_node() -> Output {
  make_upgraded_node_output(
    Script(test_new_transfer_logic_hash),
    VerificationKey(#""),
    test_gs_policy_id,
  )
}

test upgrade_succeeds_when_global_state_is_spent() {
  run_withdraw(
    UpgradeRegistryNode {
      registry_node_input_index: 0,
      registry_node_output_index: 0,
      global_state_location: GlobalStateSpent { global_state_input_index: 1 },
    },
    make_upgrade_tx_gs_spent(upgraded_node()),
  )
}

test upgrade_gs_spent_still_requires_the_admin_signature() {
  // The location changes WHERE the datum is read, never WHETHER its gates
  // apply. Same transaction, admin signature removed.
  !run_withdraw(
    UpgradeRegistryNode {
      registry_node_input_index: 0,
      registry_node_output_index: 0,
      global_state_location: GlobalStateSpent { global_state_input_index: 1 },
    },
    Transaction {
      ..make_upgrade_tx_gs_spent(upgraded_node()),
      extra_signatories: [],
    },
  )
}

test upgrade_gs_spent_fails_when_index_is_not_global_state() fail {
  // Input 0 is the registry node. `GlobalStateSpent` may point anywhere; the
  // GlobalState NFT is still what decides whether the datum is believed.
  run_withdraw(
    UpgradeRegistryNode {
      registry_node_input_index: 0,
      registry_node_output_index: 0,
      global_state_location: GlobalStateSpent { global_state_input_index: 0 },
    },
    make_upgrade_tx_gs_spent(upgraded_node()),
  )
}

test upgrade_repoints_transfer_logic_when_admin_signs() {
  // THE upgrade path for the other scripts: transfer_logic_script is mutable
  // per CIP-113's is_field_updated_registry_node, and registry_spend gates it
  // on our proxy's withdraw-0, which delegates here.
  run_withdraw(
    upgrade_redeemer(),
    make_upgrade_tx(
      make_upgraded_node_output(
        Script(test_new_transfer_logic_hash),
        VerificationKey(#""),
        test_gs_policy_id,
      ),
      make_gs_ref_input(),
      [test_admin_hash],
    ),
  )
}

test upgrade_fails_without_admin_signature() {
  !run_withdraw(
    upgrade_redeemer(),
    make_upgrade_tx(
      make_upgraded_node_output(
        Script(test_new_transfer_logic_hash),
        VerificationKey(#""),
        test_gs_policy_id,
      ),
      make_gs_ref_input(),
      [],
    ),
  )
}

test upgrade_fails_when_upgrades_are_locked() {
  // The one-way lock closes this path permanently.
  !run_withdraw(
    upgrade_redeemer(),
    make_upgrade_tx(
      make_upgraded_node_output(
        Script(test_new_transfer_logic_hash),
        VerificationKey(#""),
        test_gs_policy_id,
      ),
      make_gs_ref_input_locked(),
      [test_admin_hash],
    ),
  )
}

test upgrade_fails_when_deactivated() fail {
  run_withdraw(
    upgrade_redeemer(),
    make_upgrade_tx(
      make_upgraded_node_output(
        Script(test_new_transfer_logic_hash),
        VerificationKey(#""),
        test_gs_policy_id,
      ),
      make_gs_ref_input_deactivated(),
      [test_admin_hash],
    ),
  )
}

test upgrade_cannot_repoint_global_state() fail {
  // CIP-113 lets `global_state_cs` change on update; this deployment does
  // not. Re-pointing it at a GlobalState the caller controls would make every
  // later compliance read meaningless.
  run_withdraw(
    upgrade_redeemer(),
    make_upgrade_tx(
      make_upgraded_node_output(
        Script(test_new_transfer_logic_hash),
        VerificationKey(#""),
        test_pu_policy_id,
      ),
      make_gs_ref_input(),
      [test_admin_hash],
    ),
  )
}

test upgrade_cannot_enable_unfracking() fail {
  // Likewise mutable in CIP-113, likewise refused: unfracking lets a holder
  // split this policy out of a shared UTxO without its transfer logic running.
  run_withdraw(
    upgrade_redeemer(),
    make_upgrade_tx(
      make_upgraded_node_output(
        Script(test_new_transfer_logic_hash),
        Script(test_pu_credential_hash),
        test_gs_policy_id,
      ),
      make_gs_ref_input(),
      [test_admin_hash],
    ),
  )
}

test upgrade_cannot_repoint_transfer_logic_to_a_non_script() fail {
  // Field 3 must stay script-gated. POSITIVE CONTROL:
  // `upgrade_repoints_transfer_logic_when_admin_signs`, whose continuing
  // node differs from this one in exactly this field (`Script` there,
  // `VerificationKey` here, same underlying hash).
  run_withdraw(
    upgrade_redeemer(),
    make_upgrade_tx(
      make_upgraded_node_output(
        VerificationKey(test_new_transfer_logic_hash),
        VerificationKey(#""),
        test_gs_policy_id,
      ),
      make_gs_ref_input(),
      [test_admin_hash],
    ),
  )
}

test upgrade_cannot_repoint_third_party_logic_to_a_non_script() fail {
  // Same requirement, field 4. POSITIVE CONTROL: same as above.
  run_withdraw(
    upgrade_redeemer(),
    make_upgrade_tx(
      make_upgraded_node_output_with_vkey_third_party_logic(),
      make_gs_ref_input(),
      [test_admin_hash],
    ),
  )
}

// `next`-backstop test removed: that property is now delegated to the base
// layer (CIP-113's `registry_spend` already threads `next` unchanged through
// an in-place field update).

// `upgrade_cannot_change_supply` test removed: its subject — the belt-and-
// braces `dict.is_empty(assets.tokens(self.mint, issuance_policy_id))?`
// conjunct — no longer exists. The base layer's `registry_spend` already
// forbids minting or burning the spent node's own token in the same
// transaction, relied upon instead.

test upgrade_fails_when_spent_node_is_another_tokens() fail {
  // Purpose-binding: only THIS token's node (the one naming our proxy) may
  // be upgraded through this validator.
  let base = make_upgrade_tx(
    make_upgraded_node_output(
      Script(test_new_transfer_logic_hash),
      VerificationKey(#""),
      test_gs_policy_id,
    ),
    make_gs_ref_input(),
    [test_admin_hash],
  )
  run_withdraw(
    upgrade_redeemer(),
    Transaction {
      ..base,
      inputs: [
        Input {
          output_reference: test_out_ref(7),
          output: make_decoy_registry_ref_input().output,
        },
      ],
    },
  )
}

test upgrade_cannot_aim_the_field_checks_at_a_decoy_output() fail {
  // ATTACK: `registry_node_output_index` selects the output whose
  // `unfracking_logic_script` / `global_state_cs` get pinned, but nothing
  // asserted that output is actually the registry node. An attacker emits a
  // decoy plain output carrying a COPY of the original (clean) node datum
  // and points the index at it, while the REAL continuing node — the only
  // one carrying the registry NFT, per registry_spend's `expect [cont]` —
  // re-points `global_state_cs` at a GlobalState they control. CIP-113
  // permits that field to change on update, so only our check stands in the
  // way, and it is looking at the decoy.
  //
  // Consequence: every later compliance read (pause, deactivation, denylist
  // policy, TEL, KYC config) resolves against an attacker-authored datum.
  let decoy_clean_datum = Output {
    ..make_upgraded_node_output(
      Script(test_new_transfer_logic_hash),
      VerificationKey(#""),
      test_gs_policy_id,
    ),
    // no registry NFT — just ADA and an inline datum
    value: from_lovelace(2_000_000),
  }
  let real_node_hijacked = make_upgraded_node_output(
    Script(test_new_transfer_logic_hash),
    VerificationKey(#""),
    test_pu_policy_id,
  )
  let base = make_upgrade_tx(
    decoy_clean_datum,
    make_gs_ref_input(),
    [test_admin_hash],
  )
  run_withdraw(
    UpgradeRegistryNode {
      registry_node_input_index: 0,
      registry_node_output_index: 0,
      global_state_location: GlobalStateReferenced {
        global_state_ref_input_index: 0,
      },
    },
    Transaction { ..base, outputs: [decoy_clean_datum, real_node_hijacked] },
  )
}

// ── publish handler ──────────────────────────────────────────────────────────

test publish_accepts_credential_registration() {
  minting_authority_validator.publish(
    test_security_asset_name,
    test_gs_policy_id,
    test_registry_policy_id,
    test_proxy_hash,
    test_issuance_policy_id,
    test_transfer_logic_hash,
    test_third_party_logic_hash,
    builtin.constr_data(0, []),
    RegisterCredential {
      credential: Script(test_authority_hash),
      deposit: Never,
    },
    make_withdraw_tx(
      0,
      True,
      False,
      False,
      make_denylist_root_ref_input(),
      [],
      [],
    ),
  )
}

test publish_rejects_credential_deregistration() {
  !minting_authority_validator.publish(
    test_security_asset_name,
    test_gs_policy_id,
    test_registry_policy_id,
    test_proxy_hash,
    test_issuance_policy_id,
    test_transfer_logic_hash,
    test_third_party_logic_hash,
    builtin.constr_data(0, []),
    UnregisterCredential {
      credential: Script(test_authority_hash),
      refund: Never,
    },
    make_withdraw_tx(
      0,
      True,
      False,
      False,
      make_denylist_root_ref_input(),
      [],
      [],
    ),
  )
}

// ── the GlobalState logic can never stand in for the operator ────────────────
//
// A supply change spends GlobalState, so the logic named in its field 0 runs as
// a withdrawal — and `must_be_signed_by_credential` accepts a withdrawal as a
// signature. A `can_burn` operator whose credential IS that logic hash would be
// satisfied by anyone. Here the operator does not sign; only the logic's
// withdrawal is present.
fn gs_input_with_logic(logic: ByteArray) -> Input {
  let input = make_gs_input(False)
  expect InlineDatum(raw) = input.output.datum
  expect gs: GlobalStateDatum = raw
  Input {
    ..input,
    output: Output {
      ..input.output,
      datum: InlineDatum(
        GlobalStateDatum { ..gs, global_state_script_credential_hash: logic },
      ),
    },
  }
}

test burn_rejects_an_operator_that_is_the_global_state_logic() {
  let amount = -1_000
  let tx = make_withdraw_tx(
    amount,
    False,
    True,
    False,
    make_denylist_root_ref_input(),
    [],
    [],
  )
  !run_withdraw(
    MintBurn {
      global_state_input_index: 0,
      global_state_output_index: 0,
      power_user_node_ref_input_index: 0,
      minted_amount: amount,
      destination_actions: [],
    },
    Transaction {
      ..tx,
      inputs: [gs_input_with_logic(test_pu_credential_hash)],
      withdrawals: [Pair(Script(test_pu_credential_hash), 0)],
    },
  )
}

// ── F08: registry fields 3 and 4 are pinned to this authority's build ──────
//
// Every case below differs from its positive control only in fields 3 and 4.
// Registration resolves through `make_register_tx`, the upgrade through
// `make_upgrade_tx`; `run_withdraw` builds the upgrade authority with
// the NEW transfer script, as the documented upgrade procedure does.

fn registry_node_naming(
  transfer_logic: Credential,
  third_party_logic: Credential,
) -> Output {
  let node = TestRegistryNode {
    key: test_issuance_policy_id,
    next: #"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    minting_logic_script: Script(test_proxy_hash),
    transfer_logic_script: transfer_logic,
    third_party_transfer_logic_script: third_party_logic,
    unfracking_logic_script: VerificationKey(#""),
    global_state_cs: test_gs_policy_id,
  }
  Output { ..make_registry_ref_input().output, datum: InlineDatum(node) }
}

fn register_naming(transfer_logic: Credential, third_party_logic: Credential) {
  run_withdraw(
    register_redeemer(),
    Transaction {
      ..make_register_tx(zero, [], [test_admin_hash]),
      outputs: [registry_node_naming(transfer_logic, third_party_logic)],
    },
  )
}

fn upgrade_naming(transfer_logic: Credential, third_party_logic: Credential) {
  run_withdraw(
    upgrade_redeemer(),
    make_upgrade_tx(
      registry_node_naming(transfer_logic, third_party_logic),
      make_gs_ref_input(),
      [test_admin_hash],
    ),
  )
}

// A script hash this deployment never built.
const test_foreign_script_hash: ByteArray =
  #"bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22"

test registration_accepts_the_pinned_transfer_and_seizure_scripts() {
  register_naming(
    Script(test_transfer_logic_hash),
    Script(test_third_party_logic_hash),
  )
}

// The swap that made seizure permissionless: the transfer logic, which checks
// no operator, would authorise every seizure from field 4.
test registration_rejects_swapped_transfer_and_seizure_scripts() fail {
  register_naming(
    Script(test_third_party_logic_hash),
    Script(test_transfer_logic_hash),
  )
}

test registration_rejects_a_transfer_script_the_authority_was_not_built_with() fail {
  register_naming(
    Script(test_foreign_script_hash),
    Script(test_third_party_logic_hash),
  )
}

test registration_rejects_a_seizure_script_the_authority_was_not_built_with() fail {
  register_naming(
    Script(test_transfer_logic_hash),
    Script(test_foreign_script_hash),
  )
}

test registration_rejects_the_transfer_script_as_the_seizure_script() fail {
  register_naming(
    Script(test_transfer_logic_hash),
    Script(test_transfer_logic_hash),
  )
}

test upgrade_accepts_the_pinned_transfer_and_seizure_scripts() {
  upgrade_naming(
    Script(test_new_transfer_logic_hash),
    Script(test_third_party_logic_hash),
  )
}

test upgrade_rejects_swapped_transfer_and_seizure_scripts() fail {
  upgrade_naming(
    Script(test_third_party_logic_hash),
    Script(test_new_transfer_logic_hash),
  )
}

// Re-pointing needs an authority built with the new script first: this one
// was built with `test_new_transfer_logic_hash`, so the old script is refused.
test upgrade_rejects_a_transfer_script_the_authority_was_not_built_with() fail {
  upgrade_naming(
    Script(test_transfer_logic_hash),
    Script(test_third_party_logic_hash),
  )
}

test upgrade_rejects_a_seizure_script_the_authority_was_not_built_with() fail {
  upgrade_naming(
    Script(test_new_transfer_logic_hash),
    Script(test_foreign_script_hash),
  )
}

// An authority built with one hash in both slots would pin the swap itself, so
// it refuses every registration, even a node that matches its pins.
test an_authority_built_with_one_hash_for_both_scripts_refuses_registration() fail {
  minting_authority_validator.withdraw(
    test_security_asset_name,
    test_gs_policy_id,
    test_registry_policy_id,
    test_proxy_hash,
    test_issuance_policy_id,
    test_transfer_logic_hash,
    test_transfer_logic_hash,
    register_redeemer(),
    Script(test_authority_hash),
    Transaction {
      ..make_register_tx(zero, [], [test_admin_hash]),
      outputs: [
        registry_node_naming(
          Script(test_transfer_logic_hash),
          Script(test_transfer_logic_hash),
        ),
      ],
    },
  )
}

// ── Partial freeze (denylist `frozen_amount`) ─────────────────────────────────
//
// A partial freeze limits sending, never receiving: newly issued tokens may
// land with a partially frozen holder, citing its own node. A fully frozen
// holder is still refused.

fn make_frozen_dest_node_ref_input(frozen_amount: Option<Int>) -> Input {
  let element: Element<Data, Denylist> = Element {
    data: Node {
      data: Denylist { frozen_amount, metadata: builtin.constr_data(0, []) },
    },
    link: None,
  }
  let node = make_denylist_node_ref_input(test_dest_stake_hash)
  Input {
    ..node,
    output: Output { ..node.output, datum: InlineDatum(element) },
  }
}

fn mint_to_frozen_dest(frozen_amount: Option<Int>) -> Bool {
  let amount = 1_000
  run_withdraw(
    MintBurn {
      global_state_input_index: 0,
      global_state_output_index: 0,
      power_user_node_ref_input_index: 0,
      minted_amount: amount,
      destination_actions: [clean_dest_action()],
    },
    make_withdraw_tx(
      amount,
      True,
      False,
      False,
      make_frozen_dest_node_ref_input(frozen_amount),
      [make_dest_output(amount)],
      [test_pu_credential_hash],
    ),
  )
}

test mint_to_a_partially_frozen_destination_succeeds() {
  mint_to_frozen_dest(Some(1))
}

test mint_to_a_fully_frozen_destination_fails() {
  !mint_to_frozen_dest(None)
}

// ── Mint path: GlobalState NFT, registry node, admin and burn role ───────────

fn without_gs_nft(input: Input) -> Input {
  Input {
    ..input,
    output: Output { ..input.output, value: from_lovelace(2_000_000) },
  }
}

fn mint_burn_redeemer(amount: Int) -> MintingAuthorityWithdrawRedeemer {
  MintBurn {
    global_state_input_index: 0,
    global_state_output_index: 0,
    power_user_node_ref_input_index: 0,
    minted_amount: amount,
    destination_actions: [clean_dest_action()],
  }
}

fn signed_mint_tx(amount: Int) -> Transaction {
  make_withdraw_tx(
    amount,
    True,
    False,
    False,
    make_denylist_root_ref_input(),
    [make_dest_output(amount)],
    [test_pu_credential_hash],
  )
}

/// A UTxO carrying a GlobalState-shaped datum but NOT the NFT must not stand in
/// for GlobalState: its datum would choose the operator and denylist lists, and
/// the real GlobalState (and with it the supply cap) would never be spent.
test mint_rejects_a_global_state_input_without_its_nft() fail {
  run_withdraw(
    mint_burn_redeemer(1_000),
    Transaction {
      ..signed_mint_tx(1_000),
      inputs: [without_gs_nft(make_gs_input(False))],
    },
  )
}

/// INVARIANT 1: a mint may not spend a registry node.
test mint_rejects_spending_a_registry_node() fail {
  run_withdraw(
    mint_burn_redeemer(1_000),
    Transaction {
      ..signed_mint_tx(1_000),
      inputs: [make_gs_input(False), make_registry_ref_input()],
    },
  )
}

/// A burn needs can_burn: an operator holding only can_mint may not burn.
test burn_rejects_an_operator_without_can_burn() {
  !run_withdraw(
    MintBurn {
      global_state_input_index: 0,
      global_state_output_index: 0,
      power_user_node_ref_input_index: 0,
      minted_amount: -1_000,
      destination_actions: [],
    },
    make_withdraw_tx(
      -1_000,
      True,
      False,
      False,
      make_denylist_root_ref_input(),
      [],
      [test_pu_credential_hash],
    ),
  )
}

// ── A script that runs in the transaction never signs for a role ─────────────
//
// `must_be_signed_by_credential` accepts a withdraw-0 as a signature. This
// authority and the minting proxy run in every mint and burn, and the
// transfer and seizure scripts it pins can be run by others, so an operator
// or admin keyed at one of them would be "signed" with nobody signing. Each
// test below leaves out every signature and puts the keyed script's
// withdrawal in the transaction; only INVARIANT 8 rejects it.

/// A `can_mint` power-user node keyed at `key`, at the list's own address.
fn pu_node_keyed_at(key: ByteArray) -> Input {
  let pu = PowerUser {
    credential_hash: key,
    is_admin: False,
    can_mint: True,
    can_burn: False,
    can_pause: False,
    can_force_transfer: False,
  }
  let element: Element<Data, PowerUser> = Element {
    data: Node { data: pu },
    link: None,
  }
  let base = make_pu_node_ref_input(True, False)
  Input {
    ..base,
    output: Output {
      ..base.output,
      value: merge(
        from_lovelace(2_000_000),
        from_asset(
          test_pu_policy_id,
          bytearray.concat(constants.linked_list_node_key_prefix, key),
          1,
        ),
      ),
      datum: InlineDatum(element),
    },
  }
}

/// The withdrawals a real mint carries (the proxy and this authority), plus
/// `extra` when it is another script.
fn withdrawals_with(extra: ByteArray) -> Pairs<Credential, Int> {
  let base = [
    Pair(Script(test_proxy_hash), 0),
    Pair(Script(test_authority_hash), 0),
  ]
  if extra == test_proxy_hash || extra == test_authority_hash {
    base
  } else {
    [Pair(Script(extra), 0), ..base]
  }
}

/// A clean 1 000-token mint whose operator node is keyed at `key`, with no
/// signatories and `key`'s withdrawal present.
fn unsigned_mint_by(key: ByteArray) -> Bool {
  let amount = 1_000
  let base = make_withdraw_tx(
    amount,
    True,
    False,
    False,
    make_denylist_root_ref_input(),
    [make_dest_output(amount)],
    [],
  )
  run_withdraw(
    MintBurn {
      global_state_input_index: 0,
      global_state_output_index: 0,
      power_user_node_ref_input_index: 0,
      minted_amount: amount,
      destination_actions: [clean_dest_action()],
    },
    Transaction {
      ..base,
      reference_inputs: [
        pu_node_keyed_at(key),
        make_registry_ref_input(),
        make_denylist_root_ref_input(),
      ],
      withdrawals: withdrawals_with(key),
    },
  )
}

test mint_rejects_an_operator_keyed_at_the_minting_proxy() {
  !unsigned_mint_by(test_proxy_hash)
}

test mint_rejects_an_operator_keyed_at_the_authority_itself() {
  !unsigned_mint_by(test_authority_hash)
}

test mint_rejects_an_operator_keyed_at_the_transfer_logic() {
  !unsigned_mint_by(test_transfer_logic_hash)
}

test mint_rejects_an_operator_keyed_at_the_seizure_logic() {
  !unsigned_mint_by(test_third_party_logic_hash)
}

/// INVARIANT 7. A signed `can_mint` operator and nothing minted: the shape that
/// let a minter run this authority, and so the proxy, beside any GlobalState
/// action. Only the non-zero rule rejects it.
test mint_burn_rejects_a_zero_amount() {
  !run_withdraw(
    MintBurn {
      global_state_input_index: 0,
      global_state_output_index: 0,
      power_user_node_ref_input_index: 0,
      minted_amount: 0,
      destination_actions: [],
    },
    make_withdraw_tx(
      0,
      True,
      False,
      False,
      make_denylist_root_ref_input(),
      [],
      [test_pu_credential_hash],
    ),
  )
}

/// `make_gs_ref_input`'s GlobalState with the admin set to `admin`.
fn gs_input_with_admin(admin: ByteArray, ix: Int) -> Input {
  let base = make_gs_ref_input()
  expect InlineDatum(raw) = base.output.datum
  expect gs_datum: GlobalStateDatum = raw
  Input {
    output_reference: test_out_ref(ix),
    output: Output {
      ..base.output,
      datum: InlineDatum(
        GlobalStateDatum { ..gs_datum, admin_credential_hash: admin },
      ),
    },
  }
}

test upgrade_registry_node_rejects_an_admin_equal_to_the_minting_proxy() {
  !run_withdraw(
    upgrade_redeemer(),
    Transaction {
      ..make_upgrade_tx(
        upgraded_node(),
        gs_input_with_admin(test_proxy_hash, 5),
        [],
      ),
      withdrawals: withdrawals_with(test_proxy_hash),
    },
  )
}

test upgrade_registry_node_rejects_an_admin_equal_to_the_authority_itself() {
  !run_withdraw(
    upgrade_redeemer(),
    Transaction {
      ..make_upgrade_tx(
        upgraded_node(),
        gs_input_with_admin(test_authority_hash, 5),
        [],
      ),
      withdrawals: withdrawals_with(test_authority_hash),
    },
  )
}

test register_rejects_an_admin_equal_to_the_minting_proxy() {
  !run_withdraw(
    register_redeemer(),
    Transaction {
      ..make_register_tx(zero, [], []),
      reference_inputs: [gs_input_with_admin(test_proxy_hash, 5)],
      withdrawals: withdrawals_with(test_proxy_hash),
    },
  )
}

// ── MintBurn debits mintable_amount (INVARIANT 2) ────────────────────────────
//
// Every case is a signed 1 000-unit mint (a `can_mint` operator, one clean
// destination) or burn (a `can_burn` operator, no destination) of the security
// token, built by `debit_tx` and run by `run_debit`. Each passes every other
// `MintBurn` conjunct, so each negative is refused by exactly the one debit
// check its name gives, and pairs with a positive built from the same helpers.
// The debit is the last conjunct: no earlier refusal can stand in for it.

/// `make_gs_input(False)`'s datum with `mintable_amount` set.
fn gs_with_headroom(mintable_amount: Int) -> GlobalStateDatum {
  expect InlineDatum(raw) = make_gs_input(False).output.datum
  expect gs_datum: GlobalStateDatum = raw
  GlobalStateDatum { ..gs_datum, mintable_amount }
}

/// `datum` with `mintable_amount` lowered by `amount` (raised for a burn).
fn debited(datum: GlobalStateDatum, amount: Int) -> GlobalStateDatum {
  GlobalStateDatum { ..datum, mintable_amount: datum.mintable_amount - amount }
}

/// `datum` as Data, with `extra` appended after its last field.
fn with_appended(datum: GlobalStateDatum, extra: List<Data>) -> Data {
  let raw: Data = datum
  builtin.constr_data(0, list.concat(builtin.unconstr_fields(raw), extra))
}

/// The GlobalState UTxO (address, NFT, ADA) carrying `datum`.
fn gs_output_carrying(datum: Data) -> Output {
  Output { ..make_gs_input(False).output, datum: InlineDatum(datum) }
}

/// A mint (`amount` > 0) or burn (`amount` < 0) spending GlobalState with
/// `in_datum` at input 0; `gs_outputs` lead the outputs, followed by the
/// destination of a mint.
fn debit_tx(
  in_datum: Data,
  gs_outputs: List<Output>,
  amount: Int,
) -> Transaction {
  let destinations = if amount > 0 {
    [make_dest_output(amount)]
  } else {
    []
  }
  Transaction {
    ..make_withdraw_tx(
      amount,
      amount > 0,
      amount < 0,
      False,
      make_denylist_root_ref_input(),
      destinations,
      [test_pu_credential_hash],
    ),
    inputs: [
      Input { ..make_gs_input(False), output: gs_output_carrying(in_datum) },
    ],
    outputs: list.concat(gs_outputs, destinations),
  }
}

/// `MintBurn` of `amount` over `tx`, GlobalState spent at input 0, its
/// continuing output named at `global_state_output_index`.
fn run_debit(global_state_output_index: Int, amount: Int, tx: Transaction) {
  run_withdraw(
    MintBurn {
      global_state_input_index: 0,
      global_state_output_index,
      power_user_node_ref_input_index: 0,
      minted_amount: amount,
      destination_actions: if amount > 0 {
        [clean_dest_action()]
      } else {
        []
      },
    },
    tx,
  )
}

/// The common shape: GlobalState in with `in_datum`, out (output 0) with
/// `out_datum`, `amount` minted or burned.
fn debit_case(in_datum: Data, out_datum: Data, amount: Int) -> Bool {
  run_debit(
    0,
    amount,
    debit_tx(in_datum, [gs_output_carrying(out_datum)], amount),
  )
}

test mint_debits_mintable_amount_by_the_minted_amount() {
  let d = gs_with_headroom(1_000_000)
  debit_case(d, debited(d, 1_000), 1_000)
}

test burn_credits_mintable_amount_by_the_burned_amount() {
  let d = gs_with_headroom(1_000_000)
  debit_case(d, debited(d, -1_000), -1_000)
}

test mint_to_exactly_zero_headroom_succeeds() {
  let d = gs_with_headroom(1_000)
  debit_case(d, debited(d, 1_000), 1_000)
}

/// GlobalState's continuing output carries the input datum unchanged: the
/// counter is not debited. Only `only_the_counter_moved` refuses.
test mint_without_the_debit_fails() {
  let d = gs_with_headroom(1_000_000)
  !debit_case(d, d, 1_000)
}

test mint_with_a_wrong_debit_fails() {
  let d = gs_with_headroom(1_000_000)
  !debit_case(d, debited(d, 999), 1_000)
}

/// The output carries exactly the debited value, -1, so only the headroom
/// check refuses.
test mint_beyond_the_headroom_fails() {
  let d = gs_with_headroom(999)
  !debit_case(d, debited(d, 1_000), 1_000)
}

test mint_that_changes_another_core_field_fails() {
  let d = gs_with_headroom(1_000_000)
  !debit_case(
    d,
    GlobalStateDatum {
      ..debited(d, 1_000),
      admin_credential_hash: test_admin_hash,
    },
    1_000,
  )
}

test mint_that_changes_a_tail_field_fails() {
  let d = gs_with_headroom(1_000_000)
  !debit_case(
    d,
    GlobalStateDatum { ..debited(d, 1_000), transfers_paused: True },
    1_000,
  )
}

test mint_that_changes_an_appended_field_fails() {
  let d = gs_with_headroom(1_000_000)
  !debit_case(
    with_appended(d, [builtin.i_data(42), builtin.b_data(#"cafe")]),
    with_appended(
      debited(d, 1_000),
      [builtin.i_data(43), builtin.b_data(#"cafe")],
    ),
    1_000,
  )
}

test mint_keeps_appended_fields_unchanged() {
  let d = gs_with_headroom(1_000_000)
  debit_case(
    with_appended(d, [builtin.i_data(42), builtin.b_data(#"cafe")]),
    with_appended(
      debited(d, 1_000),
      [builtin.i_data(42), builtin.b_data(#"cafe")],
    ),
    1_000,
  )
}

/// The burn direction of `mint_without_the_debit_fails`: 1 000 are burned and
/// the output datum equals the input datum, so the counter is not credited.
/// Only `only_the_counter_moved` refuses.
test burn_without_the_credit_fails() {
  let d = gs_with_headroom(1_000_000)
  !debit_case(d, d, -1_000)
}

test mint_that_moves_global_state_fails() {
  let d = gs_with_headroom(1_000_000)
  !run_debit(
    0,
    1_000,
    debit_tx(
      d,
      [
        Output {
          ..gs_output_carrying(debited(d, 1_000)),
          address: Address {
            payment_credential: Script(test_foreign_script_hash),
            stake_credential: None,
          },
        },
      ],
      1_000,
    ),
  )
}

test mint_that_changes_global_state_tokens_fails() {
  let d = gs_with_headroom(1_000_000)
  let out = gs_output_carrying(debited(d, 1_000))
  !run_debit(
    0,
    1_000,
    debit_tx(
      d,
      [
        Output {
          ..out,
          value: merge(out.value, from_asset(test_foreign_script_hash, "X", 1)),
        },
      ],
      1_000,
    ),
  )
}

test mint_accepts_an_ada_top_up_on_global_state() {
  let d = gs_with_headroom(1_000_000)
  let out = gs_output_carrying(debited(d, 1_000))
  run_debit(
    0,
    1_000,
    debit_tx(
      d,
      [Output { ..out, value: merge(out.value, from_lovelace(3_000_000)) }],
      1_000,
    ),
  )
}

/// The index names a decoy at GlobalState's address, without the NFT, carrying
/// the exact debit; the real GlobalState output (output 1) is undebited. Only
/// `same_tokens` refuses.
test mint_with_the_debit_on_a_decoy_output_fails() {
  let d = gs_with_headroom(1_000_000)
  !run_debit(
    0,
    1_000,
    debit_tx(
      d,
      [
        Output {
          ..gs_output_carrying(debited(d, 1_000)),
          value: from_lovelace(2_000_000),
        },
        gs_output_carrying(d),
      ],
      1_000,
    ),
  )
}

/// GlobalState is only a reference input, a plain UTxO sits at
/// `global_state_input_index`, and the outputs hold a debited copy of
/// GlobalState. The GlobalState NFT check on the spent input traps.
test mint_with_global_state_only_referenced_fails() fail {
  let d = gs_with_headroom(1_000_000)
  let tx = debit_tx(d, [gs_output_carrying(debited(d, 1_000))], 1_000)
  run_debit(
    0,
    1_000,
    Transaction {
      ..tx,
      inputs: [
        Input {
          output_reference: test_out_ref(8),
          output: Output {
            ..make_dest_output(0),
            value: from_lovelace(2_000_000),
          },
        },
      ],
      reference_inputs: list.concat(
        tx.reference_inputs,
        [Input { ..make_gs_input(False), output: gs_output_carrying(d) }],
      ),
    },
  ) || True
}

/// Whatever GlobalState logic is installed (field 0 names another logic, and
/// it runs), a mint whose continuing output RAISES the counter by the amount is
/// refused here.
test a_raised_counter_is_refused_whatever_global_state_logic_is_installed() {
  let d = GlobalStateDatum {
    ..gs_with_headroom(1_000_000),
    global_state_script_credential_hash: test_foreign_script_hash,
  }
  let tx = debit_tx(d, [gs_output_carrying(debited(d, -1_000))], 1_000)
  !run_debit(
    0,
    1_000,
    Transaction {
      ..tx,
      withdrawals: [Pair(Script(test_foreign_script_hash), 0)],
    },
  )
}

// ── Benchmark — the authority's cost by mint destination count ───────────────
//
// `aiken bench -m "minting_authority.{..}"`. A `MintBurn` minting 1_000 to
// each of `n` distinct destinations, denylist-only
// (`requires_receiver_kyc = False`), every action citing the empty denylist
// root (reference input 2), which covers every key. The redeemer and the
// transaction are built in the SAMPLER, so the figures are this validator's
// run alone, not the fixture's construction. Size 0 is measured as one
// destination: a mint that changes no supply is refused.

fn t_bench_mint_dest_hash(i: Int) -> ByteArray {
  bytearray.concat(
    bytearray.from_int_big_endian(i, 4),
    #"3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c",
  )
}

fn t_bench_mint(n: Int) -> (MintingAuthorityWithdrawRedeemer, Transaction) {
  let amount = 1_000
  (
    MintBurn {
      global_state_input_index: 0,
      global_state_output_index: 0,
      power_user_node_ref_input_index: 0,
      minted_amount: amount * n,
      destination_actions: list.repeat(clean_dest_action(), n),
    },
    make_withdraw_tx(
      amount * n,
      True,
      False,
      False,
      make_denylist_root_ref_input(),
      list.map(
        list.range(0, n - 1),
        fn(i) { make_dest_output_for(amount, t_bench_mint_dest_hash(i)) },
      ),
      [test_pu_credential_hash],
    ),
  )
}

fn n_mint_destinations(
  size: Int,
) -> Fuzzer<(MintingAuthorityWithdrawRedeemer, Transaction)> {
  fuzz.constant(
    t_bench_mint(
      if size < 1 {
        1
      } else {
        size
      },
    ),
  )
}

bench mint_cost_by_destination_count(case via n_mint_destinations) {
  let (redeemer, tx) = case
  expect run_withdraw(redeemer, tx)
}

/// The burn counterpart, `burn_succeeds_without_destination_checks`'s shape
/// built in the sampler. A burn has no destinations, so its cost does not
/// grow with the size.
fn a_burn(_size: Int) -> Fuzzer<(MintingAuthorityWithdrawRedeemer, Transaction)> {
  fuzz.constant(
    (
      MintBurn {
        global_state_input_index: 0,
        global_state_output_index: 0,
        power_user_node_ref_input_index: 0,
        minted_amount: -1_000,
        destination_actions: [],
      },
      make_withdraw_tx(
        -1_000,
        False,
        True,
        False,
        make_denylist_root_ref_input(),
        [],
        [test_pu_credential_hash],
      ),
    ),
  )
}

bench burn_cost(case via a_burn) {
  let (redeemer, tx) = case
  expect run_withdraw(redeemer, tx)
}
