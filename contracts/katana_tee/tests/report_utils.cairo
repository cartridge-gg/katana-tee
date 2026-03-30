use core::integer::{u128_byte_reverse, u512};
use core::poseidon::poseidon_hash_span;
use katana_tee::katana_report_utils::verify_katana_report_data;

fn zero_u256() -> u256 {
    u256 { low: 0, high: 0 }
}

#[test]
fn test_verify_katana_report_data_layout() {
    let prev_state_root: felt252 = 0xA;
    let state_root: felt252 = 1;
    let prev_block_hash: felt252 = 0xB;
    let block_hash: felt252 = 2;
    let prev_block_number: u64 = 1;
    let block_number: u64 = 2;
    let fork_block_number: u64 = 0;
    let events_commitment: felt252 = 0;
    let fork_state_root: felt252 = 0;
    let commitment = poseidon_hash_span(
        array![
            prev_state_root, state_root, prev_block_hash, block_hash,
            prev_block_number.into(), block_number.into(), fork_block_number.into(),
            events_commitment, fork_state_root,
        ].span(),
    );
    let commitment_u256: u256 = commitment.into();
    let args_hash = zero_u256();

    let report_data = u512 {
        limb0: u128_byte_reverse(commitment_u256.high),
        limb1: u128_byte_reverse(commitment_u256.low),
        limb2: u128_byte_reverse(args_hash.high),
        limb3: u128_byte_reverse(args_hash.low),
    };

    assert(
        verify_katana_report_data(
            report_data, prev_state_root, state_root, prev_block_hash, block_hash,
            prev_block_number, block_number, fork_block_number,
            events_commitment, fork_state_root, zero_u256(),
        ),
        'Verification should succeed',
    );
}

#[test]
fn test_verify_katana_report_data_with_fork_block() {
    let prev_state_root: felt252 = 0xA0;
    let state_root: felt252 = 0x123;
    let prev_block_hash: felt252 = 0xB0;
    let block_hash: felt252 = 0x456;
    let prev_block_number: u64 = 10;
    let block_number: u64 = 11;
    let fork_block_number: u64 = 42;
    let events_commitment: felt252 = 0x789;
    let fork_state_root: felt252 = 0x999;
    let commitment = poseidon_hash_span(
        array![
            prev_state_root, state_root, prev_block_hash, block_hash,
            prev_block_number.into(), block_number.into(), fork_block_number.into(),
            events_commitment, fork_state_root,
        ].span(),
    );
    let commitment_u256: u256 = commitment.into();
    let args_hash = zero_u256();

    let report_data = u512 {
        limb0: u128_byte_reverse(commitment_u256.high),
        limb1: u128_byte_reverse(commitment_u256.low),
        limb2: u128_byte_reverse(args_hash.high),
        limb3: u128_byte_reverse(args_hash.low),
    };

    assert(
        verify_katana_report_data(
            report_data, prev_state_root, state_root, prev_block_hash, block_hash,
            prev_block_number, block_number, fork_block_number,
            events_commitment, fork_state_root, zero_u256(),
        ),
        'Verification should succeed',
    );
}
