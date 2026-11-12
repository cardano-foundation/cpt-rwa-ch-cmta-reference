//Asset name of the global state NFT
pub const global_state_asset_name = "GlobalState"

//Linked list constants (matching v1.2.0 defaults for on-chain compatibility)
pub const linked_list_root_key = #""

pub const linked_list_node_key_prefix = "Node"

pub const linked_list_node_key_prefix_length = 4

// Indexes of the fields in the registry node which are used to verify the correctness of the registry node 
// and extract the hashed params for deriving the issuance policy id
// It is derived by index to allow the extension of the registry node in the future without breaking the logic of deriving the issuance policy id from the registry node
pub const minting_logic_script_registry_node_index = 2

pub const transfer_logic_script_registry_node_index = 3

pub const third_party_transfer_logic_script_registry_node_index = 4

// Added in CIP-113 v0.4.0. `VerificationKey(#"")` (core's `empty_vkey`) means
// unfracking is FORBIDDEN for the policy — the least-permission default. This
// repo ships no unfracking hook, so registration must leave it unset.
pub const unfracking_logic_script_registry_node_index = 5

// The GlobalState NFT policy the registry node declares for this token. v0.4.0
// pushed it from 5 to 6 when `unfracking_logic_script` was inserted ahead of it.
pub const global_state_cs_registry_node_index = 6

// ============================================================================
// Datum growth caps (defence in depth)
// ============================================================================
// Each bound is enforced both at genesis (`sanitise_initial_datum`) and on
// every spend branch able to grow the corresponding field. They bound single
// entries only: at their maxima the datum would still serialise to ~40 KB,
// past the ~16 KiB transaction limit. The joint bound is the
// `max_global_state_datum_bytes` parameter of the GlobalState mint and logic
// (F09).

// Maximum number of entries the trusted-entity list may hold.
pub const max_trusted_entities = 64

// Maximum serialised (CBOR) size, in bytes, of the `security_info` field.
pub const max_security_info_bytes = 4096

// Maximum serialised (CBOR) size, in bytes, of a single trusted entity's
// metadata value.
pub const max_trusted_entity_metadata_bytes = 512

// Maximum serialised (CBOR) size, in bytes, of a single denylist entry's
// metadata value.
pub const max_denylist_metadata_bytes = 512

// ============================================================================
// CIP-67 asset-name labels (CIP-68)
// ============================================================================
// CIP-67 encodes an asset-name label as four bytes: `0x00 | label(20 bits) |
// checksum(8 bits) | 0x00`. The first four bytes of `security_asset_name`
// alone decide which of four classes the token is in:
//
//   * a CIP-68 USER-token label — `(222)` NFT, `(333)` FT, `(444)` RFT. The
//     token is a CIP-68 token, and its `(100)` reference NFT is
//     `cip68_reference_label` followed by the same body;
//   * the `(100)` reference label itself. Never a valid security name: the
//     supply would be its own metadata token;
//   * anything else — a PLAIN name, which has no reference NFT at all.
//
// The reference name is DERIVED from `security_asset_name` (see
// `cip68.reference_name`), never configured. A separately configured name
// could disagree with the security name and point the shape and custody
// rules at a token CIP-68 readers never look up; a derived one cannot, and
// it gives each CIP-68 token exactly one metadata name.
//
// Only that exact name is protected. Another `(100)`-labelled name under the
// issuance policy is not metadata of this token, and no rule here treats it as
// such.

/// Length, in bytes, of a CIP-67 label. Every label below has this length;
/// `cip68_labels_have_the_fixed_length` in `lib/cip68.ak` is the tripwire.
pub const cip67_label_length = 4

/// `(100)` — the CIP-68 reference (metadata) NFT label.
pub const cip68_reference_label: ByteArray = #"000643b0"

/// `(222)` — the CIP-68 NFT user-token label.
pub const cip68_nft_label = #"000de140"

/// `(333)` — the CIP-68 fungible user-token label.
pub const cip68_ft_label = #"0014df10"

/// `(444)` — the CIP-68 rich-fungible user-token label.
pub const cip68_rft_label = #"001bc280"
