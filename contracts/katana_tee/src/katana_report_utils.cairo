use core::integer::{u128_byte_reverse, u512};
use core::poseidon::poseidon_hash_span;
use core::sha256::compute_sha256_byte_array;

const POW_2_32: u128 = 0x100000000;
const POW_2_64: u128 = 0x10000000000000000;
const POW_2_96: u128 = 0x1000000000000000000000000;

fn u32_array_to_u256(words: [u32; 8]) -> u256 {
    let [w0, w1, w2, w3, w4, w5, w6, w7] = words;
    let high: felt252 = w0.into() * POW_2_96.into()
        + w1.into() * POW_2_64.into()
        + w2.into() * POW_2_32.into()
        + w3.into();
    let low: felt252 = w4.into() * POW_2_96.into()
        + w5.into() * POW_2_64.into()
        + w6.into() * POW_2_32.into()
        + w7.into();

    u256 { low: low.try_into().unwrap(), high: high.try_into().unwrap() }
}

/// Compute the canonical SHA-256 hash of Katana runtime args attested in report_data[32..64].
///
/// This mirrors the measured hypervisor init path, which sorts and hashes:
///   --fork.block,<n>
///   --fork.no-dev-genesis
///   --fork.provider,<url>
///   --tee.provider,sev-snp
pub fn compute_katana_args_hash(fork_provider_url: @ByteArray, fork_block_number: u64) -> u256 {
    let canonical_args = format!(
        "--fork.block,{},--fork.no-dev-genesis,--fork.provider,{},--tee.provider,sev-snp",
        fork_block_number,
        fork_provider_url,
    );
    let digest_words = compute_sha256_byte_array(@canonical_args);
    u32_array_to_u256(digest_words)
}

/// Verify that report_data matches the Poseidon commitment and runtime args hash.
///
/// report_data layout (64 bytes, represented as u512 with 4 x u128 limbs):
///   [0..32]  = Poseidon(state_root, block_hash, fork_block_number, events_commitment, fork_state_root)
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
    fork_state_root: felt252,
    args_hash: u256,
) -> bool {
    // Verify first 32 bytes: Poseidon commitment to blockchain state
    let expected_commitment = u256 {
        low: u128_byte_reverse(report_data.limb1), high: u128_byte_reverse(report_data.limb0),
    };

    let commitment = poseidon_hash_span(
        array![
            state_root,
            block_hash,
            fork_block_number.into(),
            events_commitment,
            fork_state_root,
        ]
            .span(),
    );

    assert(commitment.into() == expected_commitment, 'Commitment mismatch');

    // Verify second 32 bytes: SHA-256 hash of runtime arguments
    let actual_args_hash = u256 {
        low: u128_byte_reverse(report_data.limb3), high: u128_byte_reverse(report_data.limb2),
    };

    assert(actual_args_hash == args_hash, 'Args hash mismatch');

    return true;
}
