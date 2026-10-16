//// GlobalState — spend proxy (step 2 of 3, see global_state.ak).
////
//// Guards the GlobalState NFT forever. It knows nothing about the datum
//// except field 0, the hash of the current GlobalState logic, and lets the
//// UTxO be spent only when that script runs as a withdraw-0 in the same
//// transaction. Upgrading the logic therefore never moves the NFT.

use aiken/builtin
use aiken/primitive/bytearray
use cardano/address.{Address, Credential, Script}
use cardano/transaction.{
  Input, Output, OutputReference, Transaction, find_input,
}
use tests/global_state_fixtures.{
  t_datum, t_gs_logic, t_gs_script_hash, t_new_gs_logic, t_out_ref, t_tx,
}
use types/global_state.{GlobalStateDatum}
use utils.{must_run_script_withdrawal}

// ============================================================================
// Spend proxy
// ============================================================================
// The permanent home of the GlobalState NFT. Like `minting_logic_script.ak`
// for the minting path, it decides as little as possible: it reads field 0 of
// the datum it guards — `global_state_script_credential_hash` — and requires
// that credential's withdraw-0 in the same transaction. Every GlobalState rule
// lives in the script field 0 names (`global_state_logic` in global_state_logic.ak, or whatever
// `RotateGlobalStateScript` has since installed).
//
// Unparameterised on purpose: the GlobalState mint can then take this hash as
// a parameter (no circularity) and bind the NFT to it at genesis. The address
// is therefore shared by every deployment — GlobalState is located by its NFT,
// never by address.
//
// No NFT check here: a stray UTxO sent to this address can only be spent with
// the withdraw-0 of whatever its OWN field 0 names, which governs nothing but
// that UTxO.
validator global_state_proxy {
  spend(
    datum: Option<Data>,
    _redeemer: Data,
    own_out_ref: OutputReference,
    self: Transaction,
  ) {
    expect Some(datum) = datum
    expect Some(own_input) = find_input(self.inputs, own_out_ref)
    expect Script(own_hash) = own_input.output.address.payment_credential
    // Field 0 only, decoded by hand: this file must not depend on the rest of
    // the datum's shape.
    let constr = builtin.un_constr_data(datum)
    expect builtin.fst_pair(constr) == 0
    expect [logic_raw, ..] = builtin.snd_pair(constr)
    let logic_hash = builtin.un_b_data(logic_raw)

    and {
      (bytearray.length(logic_hash) == 28)?,
      // Self-delegation would be trivially satisfiable by this very spend's
      // own presence.
      (logic_hash != own_hash)?,
      // A genuine withdraw-0, NOT `must_be_signed_by_credential`: the latter
      // also accepts a key signature, which would satisfy this gate without
      // the logic ever running — a total bypass of every GlobalState rule.
      must_run_script_withdrawal(self, logic_hash)?,
    }
  }

  else(_) {
    fail
  }
}

// ============================================================================
// Tests
// ============================================================================

// ── global_state_proxy — the delegation gate ─────────────────────────────────

fn proxy_tx(withdrawals: Pairs<Credential, Int>) -> Transaction {
  Transaction {
    ..t_tx(t_datum(False, False), t_datum(False, False), []),
    withdrawals,
  }
}

fn run_proxy(datum: Data, tx: Transaction) -> Bool {
  global_state_proxy.spend(
    Some(datum),
    builtin.constr_data(0, []),
    t_out_ref(0),
    tx,
  )
}

fn t_datum_data() -> Data {
  let d: Data = t_datum(False, False)
  d
}

test proxy_succeeds_with_the_named_withdrawal() {
  run_proxy(t_datum_data(), proxy_tx([Pair(Script(t_gs_logic), 0)]))
}

test proxy_fails_without_the_logic_withdrawal() {
  !run_proxy(t_datum_data(), proxy_tx([]))
}

test proxy_fails_with_a_different_withdrawal() {
  !run_proxy(t_datum_data(), proxy_tx([Pair(Script(t_new_gs_logic), 0)]))
}

// A key signature for the named hash is not the logic running.
test proxy_fails_when_the_logic_is_merely_signed_for() {
  !run_proxy(
    t_datum_data(),
    Transaction { ..proxy_tx([]), extra_signatories: [t_gs_logic] },
  )
}

// The proxy's own withdrawal IS present, so only the self-delegation guard can
// reject this.
test proxy_fails_when_field_0_is_its_own_hash() {
  let datum: Data = GlobalStateDatum {
    ..t_datum(False, False),
    global_state_script_credential_hash: t_gs_script_hash,
  }
  !run_proxy(datum, proxy_tx([Pair(Script(t_gs_script_hash), 0)]))
}

test proxy_fails_on_a_malformed_field_0() fail {
  let raw: Data = t_datum(False, False)
  let fields = utils.replace_data_field(
    builtin.unconstr_fields(raw),
    0,
    builtin.i_data(1),
  )
  run_proxy(
    builtin.constr_data(0, fields),
    proxy_tx([Pair(Script(t_gs_logic), 0)]),
  )
}

test proxy_fails_on_a_short_field_0() {
  let datum: Data = GlobalStateDatum {
    ..t_datum(False, False),
    global_state_script_credential_hash: #"9a9a",
  }
  !run_proxy(datum, proxy_tx([Pair(Script(#"9a9a"), 0)]))
}
