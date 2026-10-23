/// A node in the denylist linked list, keyed by a user's 28-byte credential
/// HASH (both credential forms of that hash are covered).
///
/// `frozen_amount` says how much of the holder's security-token balance is
/// frozen (CMTAT `freezePartialTokens` semantics):
///
/// * `None` — FULLY frozen ("sanctioned"): the holder can neither send nor
///   receive the security token. This is what every entry meant before the
///   field existed.
/// * `Some(f)`, `f > 0` — PARTIALLY frozen: the holder may receive freely, and
///   may send only in a transaction that pays at least `f` of the security
///   token back to outputs whose inline stake credential hash is the node key.
///   Either credential form of that hash counts: paid to the holder's own form,
///   the holder still holds at least `f` afterwards; paid to the other form, the
///   tokens sit where only seizure can reach them. Enforced by the transfer
///   logic; the seizure path deliberately ignores it (a forced transfer is an
///   override).
///
/// `Some(f)` with `f <= 0` is never written: `AddToDenylist` and
/// `UpdateDenylistEntry` both reject it, so it cannot reach a reader.
///
/// `f` is NOT checked against the holder's balance — no write can see it. An
/// `f` above what the holder holds blocks every send until the holder's
/// balance reaches `f` (receiving still works), so it acts as a full freeze on
/// the sending side.
///
/// The pay-back output makes the holder a destination of its own transaction,
/// so with `requires_receiver_kyc` set a partially frozen holder needs valid
/// KYC to send even when `requires_sender_kyc` is off.
///
/// `metadata` (reason_hash, added_at, jurisdiction, …) is for off-chain
/// indexing and auditability only; on-chain validators bound its size and
/// otherwise never inspect it.
pub type Denylist {
  frozen_amount: Option<Int>,
  metadata: Data,
}

/// Spend redeemer.
///
/// - `StateTransition` — the element is being inserted next to or removed;
///   all checks are delegated to the mint validator, which must run (a
///   list-policy mint or burn is required).
/// - `UpdateDenylistEntry` — rewrite ONE node's data in place (its frozen
///   amount and/or metadata), keeping its key, link, NFT and address. No
///   list-policy mint may occur. Gated like Add/Remove: a power user holding
///   `is_admin`, signed by that user. The two variants can never share a
///   transaction: one requires a list-policy mint, the other forbids it.
pub type SpendRedeemer {
  StateTransition
  UpdateDenylistEntry {
    own_input_index: Int,
    own_output_index: Int,
    global_state_ref_input_index: Int,
    power_user_node_ref_input_index: Int,
  }
}

/// Mint redeemer. Add/Remove are gated by a power user holding `is_admin`;
/// Deinit by the GS admin credential; Init is nonce-gated. Each gated action
/// carries a reference-input index to the GS UTxO. Add/Remove additionally
/// carry `power_user_node_ref_input_index`, pointing at the power-user linked-
/// list node (a reference input) whose `is_admin` flag + signature authorise
/// the sanction; the power-user list policy id is read from the GS datum.
pub type MintRedeemer {
  Init { root_output_index: Int }
  Deinit { global_state_ref_input_index: Int }
  AddToDenylist {
    user_pkh: ByteArray,
    anchor_node_output_index: Int,
    appended_node_output_index: Int,
    global_state_ref_input_index: Int,
    power_user_node_ref_input_index: Int,
  }
  RemoveFromDenylist {
    user_pkh: ByteArray,
    anchor_node_input_index: Int,
    anchor_node_output_index: Int,
    global_state_ref_input_index: Int,
    power_user_node_ref_input_index: Int,
  }
}

/// The one well-formedness rule on a frozen amount, applied at every WRITE of
/// node data (insert and in-place update): absent, or strictly positive.
pub fn valid_frozen_amount(frozen_amount: Option<Int>) -> Bool {
  when frozen_amount is {
    None -> True
    Some(amount) -> amount > 0
  }
}
