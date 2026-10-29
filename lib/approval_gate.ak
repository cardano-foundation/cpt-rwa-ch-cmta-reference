use aiken/collection/dict
use aiken/collection/list
use aiken/collection/pairs
use cardano/address.{Address, Credential, Inline, Script, VerificationKey}
use cardano/assets.{quantity_of}
use cardano/transaction.{Input, Output, Transaction, placeholder}
use tests/global_state_fixtures.{
  t_admin, t_operator, t_operator_entry, t_out_ref, t_pu_ll_policy, t_pu_script,
}
use utils

/// The address of every pending transfer: the programmable base, owned by the
/// permanent approval proxy. The scripts recognise a pending transfer by its
/// stake credential alone (`Inline(Script(proxy))`); the CIP-113 base layer
/// keeps every token of the policy at the programmable base.
pub fn vault_address(
  plb_hash: ByteArray,
  approval_proxy_hash: ByteArray,
) -> Address {
  Address(Script(plb_hash), Some(Inline(Script(approval_proxy_hash))))
}

/// Everything the approval logic needs from the inputs, in one pass.
pub type InputScan {
  /// An input outside the vault holds a token of the issuance policy (the
  /// CIP-68 reference NFT included).
  policy_input_seen: Bool,
  /// An input sits at the vault (stake credential `Inline(vault)`), ADA-only
  /// included.
  vault_input_seen: Bool,
  /// Per owner outside the vault: minus the security tokens its inputs hold.
  /// Non-empty exactly when a holder spends security tokens.
  holdings: Pairs<Credential, Int>,
}

pub fn scan_inputs(
  inputs: List<Input>,
  vault: Credential,
  issuance_policy_id: ByteArray,
  security_asset_name: ByteArray,
) -> InputScan {
  let vault_owner = Some(Inline(vault))
  list.foldl(
    inputs,
    InputScan {
      policy_input_seen: False,
      vault_input_seen: False,
      holdings: [],
    },
    fn(input, scan) {
      let utxo = input.output
      if utxo.address.stake_credential == vault_owner {
        InputScan { ..scan, vault_input_seen: True }
      } else {
        // One policy lookup per input, as the transfer logic does.
        let tokens = assets.tokens(utxo.value, issuance_policy_id)
        if dict.is_empty(tokens) {
          scan
        } else {
          when dict.get(tokens, security_asset_name) is {
            Some(quantity) -> {
              expect Some(Inline(owner)) = utxo.address.stake_credential
              InputScan {
                ..scan,
                policy_input_seen: True,
                holdings: add_to(scan.holdings, owner, -quantity),
              }
            }
            None -> InputScan { ..scan, policy_input_seen: True }
          }
        }
      }
    },
  )
}

/// The holder that may create pending transfers in this transaction: the ONE
/// owner of every security-token input outside the vault. `None` for zero or
/// several holders. A transaction that also spends a vault input never gets
/// this far: the approval logic refuses mixing.
pub fn sole_holder(holdings: Pairs<Credential, Int>) -> Option<Credential> {
  when holdings is {
    [Pair(only, _)] -> Some(only)
    _ -> None
  }
}

/// Consent from a FULL credential, keyed on its constructor.
///
/// `VerificationKey(h)` consents by signing. `Script(h)` consents by its
/// withdraw-0 being in the transaction. Deliberately not
/// `utils.must_be_signed_by_credential`, which takes a bare hash and accepts
/// either form: a vault sender is an identity, and a key and a script sharing a
/// hash are different parties.
pub fn credential_authorised(self: Transaction, credential: Credential) -> Bool {
  when credential is {
    VerificationKey(hash) -> list.has(self.extra_signatories, hash)
    Script(_) -> pairs.has_key(self.withdrawals, credential)
  }
}

/// The security tokens this transaction moves to OTHER credentials, net.
///
/// Per credential c (the vault excluded): gain(c) = what outputs give c minus
/// what c's own inputs held (`holdings`, from `scan_inputs`). The movement is
/// the sum of the positive gains.
///
/// NET per credential, not "outputs to non-senders": with the latter a
/// recipient could add a dust input of its own, become a sender, and receive
/// any amount uncounted. A sum, not a max: two recipients of T each move 2T.
/// Change returning to a sender nets to <= 0. Outputs to the vault are
/// excluded — the vault IS the approval route. A transaction that also mints
/// counts the minted outputs as gain, which can only make it stricter.
pub fn net_movement_to_others(
  holdings: Pairs<Credential, Int>,
  outputs: List<Output>,
  vault: Credential,
  issuance_policy_id: ByteArray,
  security_asset_name: ByteArray,
) -> Int {
  let vault_owner = Some(Inline(vault))
  let ledger = list.foldl(
    outputs,
    holdings,
    fn(output, ledger) {
      let quantity = quantity_of(
        output.value,
        issuance_policy_id,
        security_asset_name,
      )
      if quantity > 0 && output.address.stake_credential != vault_owner {
        expect Some(Inline(owner)) = output.address.stake_credential
        add_to(ledger, owner, quantity)
      } else {
        ledger
      }
    },
  )
  list.foldl(
    ledger,
    0,
    fn(entry, total) {
      let Pair(_, gain) = entry
      if gain > 0 {
        total + gain
      } else {
        total
      }
    },
  )
}

fn add_to(
  ledger: Pairs<Credential, Int>,
  owner: Credential,
  delta: Int,
) -> Pairs<Credential, Int> {
  when ledger is {
    [] -> [Pair(owner, delta)]
    [Pair(key, value), ..rest] ->
      if key == owner {
        [Pair(key, value + delta), ..rest]
      } else {
        [Pair(key, value), ..add_to(rest, owner, delta)]
      }
  }
}

/// Did an operator holding `can_approve` sign this transaction with its KEY?
///
/// The entry at `approver_ref_input_index` among the reference inputs is
/// authenticated by `utils.authenticated_power_user`: it carries the list's
/// NFT (policy `power_user_list_policy_id`, GlobalState field 3) and still
/// sits at the list's script address, so a removed operator cannot approve.
///
/// KEY signature only — never `must_be_signed_by_credential`. In a settlement
/// the approval logic, the proxy, the GlobalState logic, the transfer logic
/// (current and retired) and the CIP-113 global logic all run, and anyone can
/// produce their withdrawals; a withdrawal never appears in
/// `extra_signatories`, so none of them can ever approve.
pub fn operator_approved(
  approver_ref_input_index: Option<Int>,
  power_user_list_policy_id: ByteArray,
  power_user_list_script_hash: ByteArray,
  self: Transaction,
) -> Bool {
  when approver_ref_input_index is {
    None -> False
    Some(index) -> {
      let (node_key, power_user) = utils.authenticated_power_user(
        utils.safe_list_at(self.reference_inputs, index).output,
        power_user_list_policy_id,
        power_user_list_script_hash,
      )
      and {
        power_user.can_approve,
        list.has(self.extra_signatories, node_key),
      }
    }
  }
}

// ── operator_approved ────────────────────────────────────────────────────────
// The entry sits at reference index 1; index 0 is an unrelated output.

fn o_tx(
  entry: Output,
  signers: List<ByteArray>,
  withdrawals: Pairs<Credential, Int>,
) -> Transaction {
  Transaction {
    ..placeholder,
    reference_inputs: [
      Input { output_reference: t_out_ref(70), output: t_operator_entry(False) },
      Input { output_reference: t_out_ref(71), output: entry },
    ],
    extra_signatories: signers,
    withdrawals,
  }
}

fn o_approved(index: Option<Int>, tx: Transaction) -> Bool {
  operator_approved(index, t_pu_ll_policy, t_pu_script, tx)
}

test operator_with_can_approve_and_its_key_approves() {
  o_approved(Some(1), o_tx(t_operator_entry(True), [t_operator], []))
}

test operator_without_can_approve_is_refused() {
  !o_approved(Some(1), o_tx(t_operator_entry(False), [t_operator], []))
}

test operator_path_needs_an_entry_index() {
  !o_approved(None, o_tx(t_operator_entry(True), [t_operator], []))
}

test operator_withdrawal_is_not_a_signature() {
  // A script withdrawal of the operator's hash (anyone can produce a free
  // script's) never counts; the same shape with the key signature does.
  let withdrawal = [Pair(Script(t_operator), 0)]
  and {
    !o_approved(Some(1), o_tx(t_operator_entry(True), [], withdrawal)),
    o_approved(Some(1), o_tx(t_operator_entry(True), [t_operator], withdrawal)),
  }
}

test operator_must_sign_with_its_own_key() {
  !o_approved(Some(1), o_tx(t_operator_entry(True), [t_admin], []))
}

test operator_entry_without_the_list_nft_is_refused() fail {
  // Same entry, its NFT replaced by one of another policy.
  let entry = t_operator_entry(True)
  o_approved(
    Some(1),
    o_tx(
      Output {
        ..entry,
        value: assets.merge(
          assets.from_lovelace(2_000_000),
          assets.from_asset(t_pu_script, #"01", 1),
        ),
      },
      [t_operator],
      [],
    ),
  )
}

test revoked_operator_entry_off_the_list_address_is_refused() fail {
  // Same entry, moved out of the list to another script, so only the
  // list-address check can refuse it.
  let entry = t_operator_entry(True)
  o_approved(
    Some(1),
    o_tx(
      Output { ..entry, address: Address(Script(t_operator), None) },
      [t_operator],
      [],
    ),
  )
}
