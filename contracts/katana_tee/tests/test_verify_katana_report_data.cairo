//! Unit tests for verify_katana_report_data function.

use core::integer::{u128_byte_reverse, u512};
use core::poseidon::poseidon_hash_span;
use katana_tee::katana_report_utils::{compute_katana_args_hash, verify_katana_report_data};

fn zero_u256() -> u256 {
    u256 { low: 0, high: 0 }
}

fn build_report_data(
    prev_state_root: felt252,
    state_root: felt252,
    prev_block_hash: felt252,
    block_hash: felt252,
    prev_block_number: u64,
    block_number: u64,
    fork_block_number: u64,
    events_commitment: felt252,
    fork_state_root: felt252,
    args_hash: u256,
) -> u512 {
    let commitment = poseidon_hash_span(
        array![
            prev_state_root, state_root, prev_block_hash, block_hash,
            prev_block_number.into(), block_number.into(), fork_block_number.into(),
            events_commitment, fork_state_root,
        ].span(),
    );
    let commitment_u256: u256 = commitment.into();
    u512 {
        limb0: u128_byte_reverse(commitment_u256.high),
        limb1: u128_byte_reverse(commitment_u256.low),
        limb2: u128_byte_reverse(args_hash.high),
        limb3: u128_byte_reverse(args_hash.low),
    }
}

/// Test case 1: Large values
#[test]
fn test_verify_katana_report_data_case_1() {
    let prev_state_root: felt252 = 0x0123456789abcdef0123456789abcdef;
    let state_root: felt252 = 0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef;
    let prev_block_hash: felt252 = 0x00aabbccdd;
    let block_hash: felt252 = 0x00fedcba9876543210fedcba9876543210fedcba9876543210fedcba98765432;
    let prev_block_number: u64 = 99;
    let block_number: u64 = 100;
    let fork_block_number: u64 = 0;
    let events_commitment: felt252 = 0x0;

    let report_data = build_report_data(
        prev_state_root, state_root, prev_block_hash, block_hash,
        prev_block_number, block_number, fork_block_number, events_commitment, 0, zero_u256(),
    );
    let result = verify_katana_report_data(
        report_data, prev_state_root, state_root, prev_block_hash, block_hash,
        prev_block_number, block_number, fork_block_number, events_commitment, 0, zero_u256(),
    );
    assert(result, 'Verification should pass');
}

/// Test case 2: Small values
#[test]
fn test_verify_katana_report_data_case_2() {
    let report_data = build_report_data(0xA, 0x1, 0xB, 0x2, 1, 2, 0, 0x3, 0, zero_u256());
    let result = verify_katana_report_data(
        report_data, 0xA, 0x1, 0xB, 0x2, 1, 2, 0, 0x3, 0, zero_u256(),
    );
    assert(result, 'Verification should pass');
}

/// Test case 3: Realistic block data
#[test]
fn test_verify_katana_report_data_case_3() {
    let prev_state_root: felt252 = 0x03a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5;
    let state_root: felt252 = 0x04b1a39276c1df7ca78febcb6850f3649e826a3f6618e6ab30b48dcc948de1ad;
    let prev_block_hash: felt252 = 0x05aabbcc;
    let block_hash: felt252 = 0x06c5e8a47fb34d21c08e4eb6a91fa7bce3f2d5a490c8b7e1d26f43098a5bc7e2;
    let events_commitment: felt252 = 0x01a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1;

    let report_data = build_report_data(
        prev_state_root, state_root, prev_block_hash, block_hash,
        8000000, 8000001, 0, events_commitment, 0, zero_u256(),
    );
    let result = verify_katana_report_data(
        report_data, prev_state_root, state_root, prev_block_hash, block_hash,
        8000000, 8000001, 0, events_commitment, 0, zero_u256(),
    );
    assert(result, 'Verification should pass');
}

/// Test case 4: With non-zero fork_block_number
#[test]
fn test_verify_katana_report_data_with_fork_block() {
    let report_data = build_report_data(
        0xA0, 0x111, 0xB0, 0x222, 99, 100, 12345, 0xabc, 0x444, zero_u256(),
    );
    let result = verify_katana_report_data(
        report_data, 0xA0, 0x111, 0xB0, 0x222, 99, 100, 12345, 0xabc, 0x444, zero_u256(),
    );
    assert(result, 'Verification should pass');
}

/// Test case 5: Commitment mismatch (should panic)
#[test]
#[should_panic(expected: 'Commitment mismatch')]
fn test_verify_katana_report_data_mismatch() {
    let report_data = build_report_data(0xA, 0x1, 0xB, 0x2, 1, 2, 0, 0x0, 0, zero_u256());
    // Pass wrong state_root (0x3 instead of 0x1)
    verify_katana_report_data(
        report_data, 0xA, 0x3, 0xB, 0x2, 1, 2, 0, 0x0, 0, zero_u256(),
    );
}

/// Test case 6: Fork block mismatch (should panic)
#[test]
#[should_panic(expected: 'Commitment mismatch')]
fn test_verify_katana_report_data_fork_block_mismatch() {
    let report_data = build_report_data(0xA, 0x1, 0xB, 0x2, 1, 2, 100, 0x0, 0, zero_u256());
    // Pass wrong fork_block (200 instead of 100)
    verify_katana_report_data(
        report_data, 0xA, 0x1, 0xB, 0x2, 1, 2, 200, 0x0, 0, zero_u256(),
    );
}

/// Test case 7: Events commitment mismatch (should panic)
#[test]
#[should_panic(expected: 'Commitment mismatch')]
fn test_verify_katana_report_data_events_commitment_mismatch() {
    let report_data = build_report_data(0xA, 0x1, 0xB, 0x2, 1, 2, 0, 0xaaa, 0, zero_u256());
    // Pass wrong events_commitment (0xbbb instead of 0xaaa)
    verify_katana_report_data(
        report_data, 0xA, 0x1, 0xB, 0x2, 1, 2, 0, 0xbbb, 0, zero_u256(),
    );
}

#[test]
fn test_verify_katana_report_data_with_nonzero_args_hash() {
    let args_hash = u256 {
        low: 0x11223344556677889900aabbccddeeff, high: 0xffeeddccbbaa00998877665544332211,
    };
    let report_data = build_report_data(
        0xA0, 0x123, 0xB0, 0x456, 10, 11, 77, 0x789, 0x999, args_hash,
    );
    assert(
        verify_katana_report_data(
            report_data, 0xA0, 0x123, 0xB0, 0x456, 10, 11, 77, 0x789, 0x999, args_hash,
        ),
        'Verification should pass',
    );
}

#[test]
fn test_compute_katana_args_hash_matches_hypervisor_canonical_string() {
    let fork_provider_url: ByteArray = "https://x.io";
    let hash = compute_katana_args_hash(@fork_provider_url, 42);

    assert(hash.high == 0x6d371494d4009a6ed584ee4a5c5320c1, 'Wrong args hash high');
    assert(hash.low == 0x52f22be087ef17c135a35ef9f1535088, 'Wrong args hash low');
}

/// Test that a non-zero args hash limb mismatches the expected zero args hash.
#[test]
#[should_panic(expected: 'Args hash mismatch')]
fn test_verify_katana_report_data_limb2_nonzero() {
    let report_data = build_report_data(0xA, 0x123, 0xB, 0x456, 1, 2, 0, 0x0, 0, zero_u256());
    let report_data = u512 { limb0: report_data.limb0, limb1: report_data.limb1, limb2: 1, limb3: 0 };

    verify_katana_report_data(report_data, 0xA, 0x123, 0xB, 0x456, 1, 2, 0, 0x0, 0, zero_u256());
}

/// Test that a non-zero args hash limb mismatches the expected zero args hash.
#[test]
#[should_panic(expected: 'Args hash mismatch')]
fn test_verify_katana_report_data_limb3_nonzero() {
    let report_data = build_report_data(0xA, 0x123, 0xB, 0x456, 1, 2, 0, 0x0, 0, zero_u256());
    let report_data = u512 { limb0: report_data.limb0, limb1: report_data.limb1, limb2: 0, limb3: 1 };

    verify_katana_report_data(report_data, 0xA, 0x123, 0xB, 0x456, 1, 2, 0, 0x0, 0, zero_u256());
}

// ── Golden vector: cross-language schema guard ──────────────────────────
//
// This test uses the SAME inputs and SAME expected hash as:
//   - sharding_operator/build.rs (compile-time check)
//   - sharding_operator/src/shard/verification.rs (Rust test)
//
// If you change the Poseidon schema (add/remove/reorder elements),
// you MUST update ALL three locations.
//
// Schema (9-element): Poseidon([prev_state_root, state_root, prev_block_hash, block_hash,
//   prev_block_number, block_number, fork_block_number, events_commitment, fork_state_root])
// Inputs: [0xA0, 0x111, 0xB0, 0x222, 99, 100, 42, 0x333, 0x444]

/// 9-element schema: Poseidon([prev_state_root, state_root, prev_block_hash, block_hash,
///   prev_block_number, block_number, fork_block_number, events_commitment, fork_state_root])
#[test]
fn test_report_data_commitment_golden_vector() {
    let hash = poseidon_hash_span(
        array![0xA0, 0x111, 0xB0, 0x222, 99, 100, 42, 0x333, 0x444].span(),
    );
    assert(
        hash == 0x00ce9048450cfe38b4daae537d51a44205fc2db09513d9f038b3f1078a8c050c,
        'golden vector mismatch',
    );
}

/// Schema guard: 9-element hash must differ from old 8-element (without fork_state_root).
#[test]
fn test_golden_vector_9_elements_differs_from_8() {
    let hash_9 = poseidon_hash_span(
        array![0xA0, 0x111, 0xB0, 0x222, 99, 100, 42, 0x333, 0x444].span(),
    );
    let hash_8 = poseidon_hash_span(
        array![0xA0, 0x111, 0xB0, 0x222, 99, 100, 42, 0x333].span(),
    );
    assert(hash_9 != hash_8, '9elem must differ from 8elem');
}
