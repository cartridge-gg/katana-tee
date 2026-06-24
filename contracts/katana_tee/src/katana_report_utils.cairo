use core::integer::{u128_byte_reverse, u512};
use core::poseidon::poseidon_hash_span;

/// Domain tag for the v1 Katana TEE report-data schema. Mirrors the Rust constant
/// `KATANA_TEE_REPORT_VERSION` so the on-chain commitment matches byte-for-byte.
pub const KATANA_TEE_REPORT_VERSION: felt252 = 'KatanaTeeReport1';

/// Mode tag for appchain settlement attestations.
pub const KATANA_TEE_APPCHAIN_MODE: felt252 = 'KatanaTeeAppchain';

/// Verify the v1 attestation `report_data` (64 bytes), which Katana fills as:
///
/// ```text
/// report_data = commitment.to_bytes_be() ++ katana_tee_config_hash.to_bytes_be()
/// ```
///
/// In appchain mode the commitment is:
///
/// ```text
/// commitment = Poseidon(
///     'KatanaTeeReport1', 'KatanaTeeAppchain',
///     prev_state_root, state_root, prev_block_hash, block_hash,
///     prev_block_number, block_number, messages_commitment, katana_tee_config_hash,
/// )
/// ```
///
/// The first 32 bytes of report_data bind that commitment; the second 32 bytes expose
/// the config hash directly. SP1 proves the report is authentic; this checks both:
/// the recomputed commitment must match the first half, and the config hash must equal
/// the value pinned at deploy time (and present in the second half).
pub fn verify_katana_report_data(
    report_data: u512,
    prev_state_root: felt252,
    state_root: felt252,
    prev_block_hash: felt252,
    block_hash: felt252,
    prev_block_number: felt252,
    block_number: felt252,
    messages_commitment: felt252,
    expected_config_hash: felt252,
) -> bool {
    // First half (limb0/limb1): the appchain state commitment.
    let expected_commitment = u256 {
        low: u128_byte_reverse(report_data.limb1), high: u128_byte_reverse(report_data.limb0),
    };

    let commitment = poseidon_hash_span(
        array![
            KATANA_TEE_REPORT_VERSION,
            KATANA_TEE_APPCHAIN_MODE,
            prev_state_root,
            state_root,
            prev_block_hash,
            block_hash,
            prev_block_number,
            block_number,
            messages_commitment,
            expected_config_hash,
        ]
            .span(),
    );

    assert(commitment.into() == expected_commitment, 'Commitment mismatch');

    // Second half (limb2/limb3): the katana_tee_config_hash, pinned at deploy time.
    let report_config_hash = u256 {
        low: u128_byte_reverse(report_data.limb3), high: u128_byte_reverse(report_data.limb2),
    };

    assert(report_config_hash == expected_config_hash.into(), 'Config hash mismatch');

    return true;
}
