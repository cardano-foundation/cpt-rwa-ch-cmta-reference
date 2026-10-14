//// GlobalState — logic (step 3 of 3, see global_state.ak).
////
//// The withdraw-0 script that datum field 0 names. The proxy delegates every
//// GlobalState spend here; this script finds the spent GlobalState input by
//// its NFT, dispatches on the redeemer (admin, pause, mint, trusted
//// entities, KYC flags, rotations…) and checks the continuing output.
//// `RotateGlobalStateScript` hands over to a successor by rewriting field 0.

use aiken/builtin
use aiken/collection/list
use aiken/collection/pairs
use aiken/primitive/bytearray
use cardano/address.{Credential, Script}
use cardano/assets.{quantity_of, without_lovelace}
use cardano/certificate.{Certificate, RegisterCredential}
use cardano/transaction.{InlineDatum, Input, Mint, Output, Transaction}
use constants
use types/global_state.{
  AddTrustedEntity, DeactivateContract, GlobalStateDatum,
  GlobalStateSpendRedeemer, LockUpgrades, MintSecurity, ModifySecurityInfo,
  PauseTransfers, RemoveTrustedEntity, RotateAdmin, RotateGlobalStateScript,
  RotateMintingScript, SetMintableAmount, SetRequiresReceiverKyc,
  SetRequiresSenderKyc, UpdateMemberRootHash, UpdateTrustedEntity,
  decode_global_state, idx_admin_credential_hash, idx_deactivated,
  idx_minting_script_credential_hash, idx_power_user_linked_list_policy_id,
  set_admin_credential_hash, set_deactivated,
  set_global_state_script_credential_hash, set_member_root_hash,
  set_mintable_amount, set_minting_script_credential_hash,
  set_requires_receiver_kyc, set_requires_sender_kyc, set_security_info,
  set_transfers_paused, set_trusted_entity_vkeys, set_upgrades_locked,
}
use types/power_users.{PowerUser}
use utils.{must_be_signed_by_credential, must_run_script_withdrawal}

// ============================================================================
// GlobalState logic (withdraw-0, named by datum field 0)
// ============================================================================
// NOTE: All values in the utxo must be preserved by this validator.
// INVARIANT: the global_state NFT never leaves the proxy. Every branch —
// `RotateGlobalStateScript` included — preserves
// `global_state_output.address == own_input.output.address`; a new branch MUST
// do the same.
//
// INVARIANT: non-Mint branches MUST reject concurrent security-token mints.
// Together with the minting_logic_script input-branch check, this is what
// makes `mintable_amount` a binding supply cap on operators: the only way to
// mint a security token in steady state is through MintSecurity, which
// decrements `mintable_amount`. The cap itself is admin-settable via
// `SetMintableAmount` until `upgrades_locked` — that branch writes the field
// but, like every non-Mint branch, cannot mint alongside the write.
//
// ADMIN: admin credential hash now lives in the input datum (field
// `admin_credential_hash`). No compile-time owner parameter. Rotation via the
// `RotateAdmin` action requires dual signature (old + new).
//
// INVARIANTS ANY REPLACEMENT GS LOGIC MUST PRESERVE (installed through
// `RotateGlobalStateScript`; nothing on chain re-checks them afterwards):
//   1. The NFT stays at the proxy with its full address; non-ADA value is
//      preserved; no reference script on the output.
//   2. `deactivated` is terminal (no action once set) and `upgrades_locked`
//      is one-way and closes rotation, minting-script rotation and
//      `SetMintableAmount`.
//   3. MintSecurity keeps the supply-cap accounting, and every other action
//      rejects security-token mints and movements.
//   4. The datum's 15 known fields keep their order, types and constructor 0,
//      inline: the minting proxy and the power-users and denylist lists decode
//      all of them and can never be redeployed. Trailing fields may be added.
//   5. The logic's own hash is never accepted as the admin, the minting
//      authority or an operator: every GlobalState transaction carries this
//      withdrawal, and `must_be_signed_by_credential` accepts a withdrawal as
//      a signature. Admin and minting authority are kept distinct from field 0
//      when written; an operator credential is refused where the role is USED
//      (PauseTransfers here, mint/burn in the minting authority, seizure in
//      the third-party transfer logic, sanctions in the denylist), so a later rotation cannot reopen it.
//   6. `publish` accepts registration only, so nobody can deregister the
//      stake credential the proxy's withdraw-0 depends on.
//   7. It acts only when it is the input's field 0, except as the incoming
//      side of a rotation.
//   8. `PauseTransfers` must flip `transfers_paused` (F11): a no-op write
//      only churns the UTxO reference and stales the admin's transactions.
//   9. Every write keeps the datum within an aggregate size cap or no larger
//      than before (F09), appended fields included.
validator global_state_logic(
  security_asset_name: ByteArray,
  issuance_policy_id: ByteArray,
  global_state_policy_id: ByteArray,
  /// The POWER-USERS SPEND VALIDATOR's script hash — not the list
  /// policy id. Element authentication ignores the address, so a power-user
  /// NFT carried out of the list into a private wallet keeps authenticating
  /// whatever ROLE FLAGS its holder writes into the datum. Here that would let
  /// a revoked operator keep pausing the protocol. Not circular: the
  /// power-users validators depend on the GlobalState MINT hash, never on this
  /// logic's.
  power_user_list_script_hash: ByteArray,
  /// Aggregate cap on the CBOR-serialised GlobalState datum, in bytes (F09),
  /// checked on every action. A write that does not grow the datum always
  /// passes, so an over-cap datum can be shrunk.
  /// Every GlobalState transaction carries the whole datum in its output, so
  /// this keeps room in the 16 KiB transaction for everything else. 8192 is
  /// the recommended value.
  max_global_state_datum_bytes: Int,
) {
  withdraw(
    redeemer: GlobalStateSpendRedeemer,
    credential: Credential,
    self: Transaction,
  ) {
    expect Script(own_hash) = credential

    // The GlobalState input is the one holding the NFT. Exactly one exists, so
    // the search is unambiguous; reference inputs are never searched — a
    // logic run must govern a SPENT GlobalState.
    expect Some(own_input) = list.find(
      self.inputs,
      fn(input) {
        quantity_of(
          input.output.value,
          global_state_policy_id,
          constants.global_state_asset_name,
        ) == 1
      },
    )
    expect InlineDatum(input_datum_data) = own_input.output.datum
    let input_datum = decode_global_state(input_datum_data)

    // TERMINAL GUARD (irreversibility): once `deactivated` is set, the
    // global_state UTxO can never be spent again — every action is rejected
    // here, before the branch dispatch, so no branch can ever unset the flag.
    // Deactivation is a permanent, fully-frozen tombstone: minting dies
    // (MintSecurity can no longer run) and transfers stay frozen (pause can no
    // longer be lifted).
    //
    // The CMTA functional spec permits deactivation with the existing tokens
    // either *cancelled* (burned first) OR *immobilised* (frozen in place) — the
    // latter is what an insolvency freeze needs: state preserved exactly as-is
    // with no further token-level updates. This validator supports both: it
    // does NOT require supply to be zero at deactivation, so the operator may
    // burn down beforehand or immobilise as-is. It only guarantees the state is
    // final afterwards.
    expect !input_datum.deactivated

    // This withdrawal is present in every transaction it validates, and
    // `must_be_signed_by_credential` accepts a withdrawal as a signature: an
    // admin equal to this hash would let anyone pass every admin check.
    expect input_datum.admin_credential_hash != own_hash

    let global_state_output = utils.safe_list_at(
      self.outputs,
      redeemer.global_state_output_index,
    )
    expect InlineDatum(global_state_output_datum) = global_state_output.datum

    // Raw Data field list of the input datum — taken from the RAW datum, so
    // fields a later logic appended survive every write below. Each branch
    // proves the output datum equals this with exactly one field replaced,
    // sharing every unchanged field as opaque Data — no unwrap/rewrap, and no
    // full-datum re-validation of the output.
    let input_fields = builtin.unconstr_fields(input_datum_data)

    // Aggregate datum cap (F09), for EVERY action: the output fits
    // `max_global_state_datum_bytes` OR is no larger than the input. So no
    // write can push the datum over the cap, a write that leaves its size
    // alone always passes, and a datum already over it (e.g. after a logic
    // with a higher cap) can always be shrunk. The input is serialised only
    // when the output is over the cap.
    let output_size = bytearray.length(
      builtin.serialise_data(global_state_output_datum),
    )
    let datum_within_cap = or {
      output_size <= max_global_state_datum_bytes,
      output_size <= bytearray.length(builtin.serialise_data(input_datum_data)),
    }

    // All branches share these address/NFT preservation invariants.
    let address_preserved = global_state_output.address == own_input.output.address
    // ensuring the nft is preserved is what enforces that the same global state UTxO is carried forward after the spend.
    let nft_preserved = quantity_of(
      global_state_output.value,
      global_state_policy_id,
      constants.global_state_asset_name,
    ) == 1
    // ensuring the token amount in the Utxo is preserverd - excluding lovelace
    let value_preserved = without_lovelace(own_input.output.value) == without_lovelace(
      global_state_output.value,
    )
    // GlobalState is a central state UTxO. It must not carry script bytes that
    // make every transaction touching it heavier.
    let no_reference_script = global_state_output.reference_script == None

    // Non-MintSecurity branches reject concurrent security mint (preserves
    // supply-cap integrity across all non-cap-aware admin flows).
    let no_concurrent_security_mint = quantity_of(
      self.mint,
      issuance_policy_id,
      security_asset_name,
    ) == 0

    // Non-MintSecurity branches additionally forbid the security token from
    // moving through the transaction at all — not merely from being minted or
    // burned. Every validator that reads GlobalState as a SPENT input
    // (transfer, seizure, registry upgrade, the proxy) sees the PRE-state
    // datum, so without this guard a `can_pause` power user could
    // pause-and-transfer, or an admin could flip a KYC flag, remove a trusted
    // entity, change the member root, or deactivate the protocol and still
    // move the security token in the very same transaction — under the rules
    // that were true a moment before the action took effect. No admin action
    // has any legitimate need to move the security token, so forbidding it
    // here costs little and removes the atomicity bypass. `MintSecurity` is
    // exempt: it is the one branch that legitimately mints, burns, and
    // otherwise moves the token.
    //
    // Only the INPUTS are scanned. Every branch that composes this also
    // composes `no_concurrent_security_mint` (nothing minted or burned under
    // the security asset), and the ledger conserves value — every unit in an
    // output comes from an input or from the mint field — so with no unit
    // spent and none minted, no output can carry the token either. Scanning
    // the outputs as well would only re-prove ledger conservation.
    let no_security_token_spent = list.all(
      self.inputs,
      fn(input) {
        quantity_of(input.output.value, issuance_policy_id, security_asset_name) == 0
      },
    )

    and {
      datum_within_cap,
      when redeemer.action is {
        RotateGlobalStateScript { new_global_state_script_hash } ->
          // Both logics run in a rotation. Which side THIS run is comes from the
          // INPUT's field 0, never from the redeemer: the redeemer is the
          // caller's to choose.
          if input_datum.global_state_script_credential_hash == own_hash {
            // OUTGOING — the current logic hands over.
            let output_fields = builtin.unconstr_fields(
              global_state_output_datum,
            )
            // The frozen readers (minting proxy, power-users and denylist lists)
            // decode all 15 known fields with their types; whatever the new logic
            // wants, they must still be able to read the result.
            let output_datum = decode_global_state(global_state_output_datum)
            let unchanged = fn(idx) {
              utils.safe_list_at(output_fields, idx) == utils.safe_list_at(
                input_fields,
                idx,
              )
            }
            and {
              no_concurrent_security_mint,
              no_security_token_spent,
              address_preserved,
              nft_preserved,
              value_preserved,
              no_reference_script,
              // The one-way upgrade lock closes this path too.
              !input_datum.upgrades_locked,
              must_be_signed_by_credential(
                self,
                input_datum.admin_credential_hash,
              ),
              bytearray.length(new_global_state_script_hash) == 28,
              // Never a silent no-op — and the only branch through which the
              // current logic could otherwise rewrite the datum unchecked.
              new_global_state_script_hash != own_hash,
              // The new logic's withdrawal will be in every GlobalState
              // transaction; it must not double as the minting authority (MintSecurity
              // alone would then satisfy the minting proxy) or as the admin.
              new_global_state_script_hash != input_datum.minting_script_credential_hash,
              new_global_state_script_hash != input_datum.admin_credential_hash,
              output_datum.global_state_script_credential_hash == new_global_state_script_hash,
              // What the frozen readers act on is not the rotation's to change.
              // `deactivated` and the admin keep their own rules, the power-users
              // list is fixed for life, and the minting authority has its own
              // rotation.
              unchanged(idx_deactivated),
              unchanged(idx_admin_credential_hash),
              unchanged(idx_power_user_linked_list_policy_id),
              unchanged(idx_minting_script_credential_hash),
              // Anti-brick: the new logic RUNS in this transaction — so its
              // script is producible and its stake credential registered — and,
              // running, checks the datum it is about to govern. Everything else
              // in the output is the new logic's to accept or refuse.
              must_run_script_withdrawal(self, new_global_state_script_hash),
            }
          } else {
            // INCOMING — this logic is being installed. It must be the one named
            // (a bystander logic never acts) and, being this version, it accepts
            // exactly the datum it is handed with only field 0 rewritten to
            // itself: state changes go through its own reviewed actions
            // afterwards. A later version replaces this check with its own.
            and {
              new_global_state_script_hash == own_hash,
              no_concurrent_security_mint,
              no_security_token_spent,
              address_preserved,
              nft_preserved,
              value_preserved,
              no_reference_script,
              builtin.equals_data(
                set_global_state_script_credential_hash(input_fields, own_hash),
                global_state_output_datum,
              ),
            }
          }
        _ -> {
          // Every other action is this logic's only while it is the one installed.
          expect input_datum.global_state_script_credential_hash == own_hash
          when redeemer.action is {
            MintSecurity { issuance_policy_redeemer_index } -> {
              //issuance_logic.mint validator must be called
              let issuance_policy_redeemer = utils.safe_list_at(
                self.redeemers,
                issuance_policy_redeemer_index,
              )
              expect issuance_policy_redeemer.1st == Mint(issuance_policy_id)
              let minted_amount = quantity_of(
                self.mint,
                issuance_policy_id,
                security_asset_name,
              )
              let remaining_amount = input_datum.mintable_amount - minted_amount
              let expected_output_datum = set_mintable_amount(
                input_fields,
                remaining_amount,
              )
              and {
                //Remaining amount must NOT be negative
                remaining_amount >= 0,
                address_preserved,
                nft_preserved,
                value_preserved,
                no_reference_script,
                builtin.equals_data(
                  expected_output_datum,
                  global_state_output_datum,
                ),
              }
            }
            PauseTransfers { transfers_paused, power_user_node_ref_input_index } -> {
              let power_user_node_ref_input = utils.safe_list_at(
                self.reference_inputs,
                power_user_node_ref_input_index,
              )

              let (power_user_credential_hash, power_user_data) = utils.authenticated_power_user(
                power_user_node_ref_input.output,
                input_datum.power_user_linked_list_policy_id,
                power_user_list_script_hash,
              )

              let expected_output_datum = set_transfers_paused(
                input_fields,
                transfers_paused,
              )
              and {
                no_concurrent_security_mint,
                no_security_token_spent,
                address_preserved,
                nft_preserved,
                value_preserved,
                no_reference_script,
                // The flag must flip (F11): a no-op write would only churn the
                // GlobalState UTxO reference and stale the admin's transactions.
                transfers_paused != input_datum.transfers_paused,
                //Must have permission to pause/unpause transfers
                power_user_data.can_pause,
                // Never this logic's own hash: its withdrawal is in this very
                // transaction and would sign for the operator.
                power_user_credential_hash != own_hash,
                //Must be signed by the power user
                must_be_signed_by_credential(self, power_user_credential_hash),
                builtin.equals_data(
                  expected_output_datum,
                  global_state_output_datum,
                ),
              }
            }
            ModifySecurityInfo { new_security_info } -> {
              let expected_output_datum = set_security_info(
                input_fields,
                new_security_info,
              )
              and {
                no_concurrent_security_mint,
                no_security_token_spent,
                address_preserved,
                nft_preserved,
                value_preserved,
                no_reference_script,
                // Datum growth cap — see `constants.max_security_info_bytes`.
                bytearray.length(builtin.serialise_data(new_security_info)) <= constants.max_security_info_bytes,
                //Must be signed by the current admin (from input datum)
                must_be_signed_by_credential(
                  self,
                  input_datum.admin_credential_hash,
                ),
                builtin.equals_data(
                  expected_output_datum,
                  global_state_output_datum,
                ),
              }
            }
            AddTrustedEntity { vkey, metadata } -> {
              // Reject duplicate entry, insert in sorted order
              let has_key = pairs.has_key(
                input_datum.trusted_entity_vkeys,
                vkey,
              )
              let updated_entities = pairs.insert_by_ascending_key(
                input_datum.trusted_entity_vkeys,
                vkey,
                metadata,
                bytearray.compare,
              )
              let expected_output_datum = set_trusted_entity_vkeys(
                input_fields,
                updated_entities,
              )
              and {
                no_concurrent_security_mint,
                no_security_token_spent,
                address_preserved,
                nft_preserved,
                value_preserved,
                no_reference_script,
                must_be_signed_by_credential(
                  self,
                  input_datum.admin_credential_hash,
                ),
                bytearray.length(vkey) == 32,
                !has_key,
                // Datum growth caps — see `constants.max_trusted_entities` /
                // `constants.max_trusted_entity_metadata_bytes`.
                list.length(updated_entities) <= constants.max_trusted_entities,
                bytearray.length(builtin.serialise_data(metadata)) <= constants.max_trusted_entity_metadata_bytes,
                builtin.equals_data(
                  expected_output_datum,
                  global_state_output_datum,
                ),
              }
            }
            RemoveTrustedEntity { vkey } -> {
              let has_key = pairs.has_key(
                input_datum.trusted_entity_vkeys,
                vkey,
              )
              let updated_entities = list.filter(
                input_datum.trusted_entity_vkeys,
                fn(p) { p.1st != vkey },
              )
              let expected_output_datum = set_trusted_entity_vkeys(
                input_fields,
                updated_entities,
              )
              and {
                no_concurrent_security_mint,
                no_security_token_spent,
                address_preserved,
                nft_preserved,
                value_preserved,
                no_reference_script,
                has_key,
                must_be_signed_by_credential(
                  self,
                  input_datum.admin_credential_hash,
                ),
                builtin.equals_data(
                  expected_output_datum,
                  global_state_output_datum,
                ),
              }
            }
            UpdateTrustedEntity { old_vkey, new_vkey, new_metadata } -> {
              let old_exists = pairs.has_key(
                input_datum.trusted_entity_vkeys,
                old_vkey,
              )
              // If renaming (old_vkey != new_vkey), new_vkey must not exist yet.
              // If just updating metadata (old_vkey == new_vkey), this constraint
              // trivially passes — `new_exists_check` becomes True.
              let new_clash_ok = if old_vkey == new_vkey {
                True
              } else {
                !pairs.has_key(input_datum.trusted_entity_vkeys, new_vkey)
              }
              let without_old = list.filter(
                input_datum.trusted_entity_vkeys,
                fn(p) { p.1st != old_vkey },
              )
              let updated_entities = pairs.insert_by_ascending_key(
                without_old,
                new_vkey,
                new_metadata,
                bytearray.compare,
              )
              let expected_output_datum = set_trusted_entity_vkeys(
                input_fields,
                updated_entities,
              )
              and {
                no_concurrent_security_mint,
                no_security_token_spent,
                address_preserved,
                nft_preserved,
                value_preserved,
                no_reference_script,
                old_exists,
                new_clash_ok,
                bytearray.length(new_vkey) == 32,
                // Datum growth cap — see `constants.max_trusted_entity_metadata_bytes`.
                bytearray.length(builtin.serialise_data(new_metadata)) <= constants.max_trusted_entity_metadata_bytes,
                must_be_signed_by_credential(
                  self,
                  input_datum.admin_credential_hash,
                ),
                builtin.equals_data(
                  expected_output_datum,
                  global_state_output_datum,
                ),
              }
            }
            SetRequiresSenderKyc { enabled } -> {
              let expected_output_datum = set_requires_sender_kyc(
                input_fields,
                enabled,
              )
              and {
                no_concurrent_security_mint,
                no_security_token_spent,
                address_preserved,
                nft_preserved,
                value_preserved,
                no_reference_script,
                must_be_signed_by_credential(
                  self,
                  input_datum.admin_credential_hash,
                ),
                builtin.equals_data(
                  expected_output_datum,
                  global_state_output_datum,
                ),
              }
            }
            SetRequiresReceiverKyc { enabled } -> {
              let expected_output_datum = set_requires_receiver_kyc(
                input_fields,
                enabled,
              )
              and {
                no_concurrent_security_mint,
                no_security_token_spent,
                address_preserved,
                nft_preserved,
                value_preserved,
                no_reference_script,
                must_be_signed_by_credential(
                  self,
                  input_datum.admin_credential_hash,
                ),
                builtin.equals_data(
                  expected_output_datum,
                  global_state_output_datum,
                ),
              }
            }
            UpdateMemberRootHash { new_member_root_hash } -> {
              let expected_output_datum = set_member_root_hash(
                input_fields,
                new_member_root_hash,
              )
              let new_root_len = bytearray.length(new_member_root_hash)
              and {
                no_concurrent_security_mint,
                no_security_token_spent,
                address_preserved,
                nft_preserved,
                value_preserved,
                no_reference_script,
                // Keep the membership root well-formed: empty or a 32-byte digest;
                // any other length makes `mpf.from_root` trap on every transfer.
                or {
                  new_root_len == 0,
                  new_root_len == 32,
                },
                must_be_signed_by_credential(
                  self,
                  input_datum.admin_credential_hash,
                ),
                builtin.equals_data(
                  expected_output_datum,
                  global_state_output_datum,
                ),
              }
            }
            RotateAdmin { new_admin_credential_hash } -> {
              let expected_output_datum = set_admin_credential_hash(
                input_fields,
                new_admin_credential_hash,
              )
              and {
                no_concurrent_security_mint,
                no_security_token_spent,
                address_preserved,
                nft_preserved,
                value_preserved,
                no_reference_script,
                bytearray.length(new_admin_credential_hash) == 28,
                // Never this logic's own hash: its withdrawal is in every
                // GlobalState transaction and would sign for the admin.
                new_admin_credential_hash != own_hash,
                //Dual-sig: both old (from input datum) and new admins must sign.
                //Prevents silent takeover; prevents lost-key soft-brick by
                //forcing continuity.
                must_be_signed_by_credential(
                  self,
                  input_datum.admin_credential_hash,
                ),
                must_be_signed_by_credential(self, new_admin_credential_hash),
                builtin.equals_data(
                  expected_output_datum,
                  global_state_output_datum,
                ),
              }
            }
            RotateMintingScript { new_minting_script_credential_hash } -> {
              let expected_output_datum = set_minting_script_credential_hash(
                input_fields,
                new_minting_script_credential_hash,
              )
              and {
                no_concurrent_security_mint,
                no_security_token_spent,
                address_preserved,
                nft_preserved,
                value_preserved,
                no_reference_script,
                bytearray.length(new_minting_script_credential_hash) == 28,
                // Never this logic's own hash: MintSecurity alone would then
                // satisfy the minting proxy, skipping every authority rule.
                new_minting_script_credential_hash != own_hash,
                // The one-way upgrade lock closes this path permanently. See
                // `upgrades_locked` on GlobalStateDatum.
                !input_datum.upgrades_locked,
                // Admin-only, single-signature — see the doc comment on
                // RotateMintingScript: unlike RotateAdmin, the OUTGOING authority's
                // consent is deliberately not required, since replacing a buggy or
                // compromised authority is exactly the case this must still work
                // for. minting_logic_script.ak independently refuses to ever
                // delegate to itself (own-hash self-authorisation guard), so this
                // action does not need to defend against that specific value here.
                must_be_signed_by_credential(
                  self,
                  input_datum.admin_credential_hash,
                ),
                builtin.equals_data(
                  expected_output_datum,
                  global_state_output_datum,
                ),
              }
            }
            LockUpgrades -> {
              let expected_output_datum = set_upgrades_locked(
                input_fields,
                True,
              )
              and {
                no_concurrent_security_mint,
                no_security_token_spent,
                address_preserved,
                nft_preserved,
                value_preserved,
                no_reference_script,
                // One-way: refuse to re-lock, so the action is never a silent
                // no-op and the transition True->True cannot be used to churn the
                // UTxO. Nothing anywhere sets this field back to False — every
                // branch reproduces the datum wholesale and only this branch
                // touches it — so False is reachable exactly once, at genesis.
                !input_datum.upgrades_locked,
                must_be_signed_by_credential(
                  self,
                  input_datum.admin_credential_hash,
                ),
                builtin.equals_data(
                  expected_output_datum,
                  global_state_output_datum,
                ),
              }
            }
            SetMintableAmount { new_mintable_amount } -> {
              let expected_output_datum = set_mintable_amount(
                input_fields,
                new_mintable_amount,
              )
              and {
                // Load-bearing here, not just hygiene: without it a mint could ride
                // along on a cap write and never be decremented from the cap.
                no_concurrent_security_mint,
                no_security_token_spent,
                address_preserved,
                nft_preserved,
                value_preserved,
                no_reference_script,
                new_mintable_amount >= 0,
                // The one-way upgrade lock makes the cap final as well.
                !input_datum.upgrades_locked,
                must_be_signed_by_credential(
                  self,
                  input_datum.admin_credential_hash,
                ),
                builtin.equals_data(
                  expected_output_datum,
                  global_state_output_datum,
                ),
              }
            }
            DeactivateContract -> {
              let expected_output_datum = set_deactivated(input_fields, True)
              and {
                no_concurrent_security_mint,
                no_security_token_spent,
                address_preserved,
                nft_preserved,
                value_preserved,
                no_reference_script,
                //Can only deactivate from a paused state (mirrors CMTAT
                //`deactivateContract`, which requires the contract be paused first).
                input_datum.transfers_paused,
                //Admin must authorise the (irreversible) decommissioning.
                must_be_signed_by_credential(
                  self,
                  input_datum.admin_credential_hash,
                ),
                //Output flips exactly one field: deactivated -> True.
                builtin.equals_data(
                  expected_output_datum,
                  global_state_output_datum,
                ),
              }
            }
            // Handled above, before the installed-logic check.
            RotateGlobalStateScript { .. } -> fail
          }
        }
      },
    }
  }

  // Whitelist RegisterCredential only. Rejecting UnregisterCredential prevents
  // a ~2 ADA griefing DoS: a rubber-stamp publish would allow anyone to
  // de-register this script's stake credential, which would brick every
  // GlobalState spend (the proxy's withdraw-0) until re-registered. Also
  // rejects delegation and DRep/committee cert types — this credential exists
  // solely for withdraw-0.
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
