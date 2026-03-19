use core::integer::{u128_byte_reverse, u512};
use core::poseidon::poseidon_hash_span;


/// Verify that report_data matches the Poseidon commitment and runtime args hash.
///
/// report_data layout (64 bytes, represented as u512 with 4 x u128 limbs):
///   [0..32]  = Poseidon(state_root, block_hash, fork_block_number, events_commitment)
///   [32..64] = SHA-256 hash of security-critical runtime arguments
///
/// The TEE hardware embeds both hashes in the attestation report's report_data field.
/// SP1 proves the report is authentic; this function verifies both hash bindings.
pub fn verify_katana_report_data(
    report_data: u512,
    state_root: felt252,
    block_hash: felt252,
    fork_block_number: u64,
    events_commitment: felt252,
    args_hash: u256,
) -> bool {
    // Verify first 32 bytes: Poseidon commitment to blockchain state
    let expected_commitment = u256 {
        low: u128_byte_reverse(report_data.limb1), high: u128_byte_reverse(report_data.limb0),
    };

    let commitment = poseidon_hash_span(
        array![state_root, block_hash, fork_block_number.into(), events_commitment].span(),
    );

    assert(commitment.into() == expected_commitment, 'Commitment mismatch');

    // Verify second 32 bytes: SHA-256 hash of runtime arguments
    let actual_args_hash = u256 {
        low: u128_byte_reverse(report_data.limb3), high: u128_byte_reverse(report_data.limb2),
    };

    assert(actual_args_hash == args_hash, 'Args hash mismatch');

    return true;
}
