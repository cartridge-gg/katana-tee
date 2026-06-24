//! Unit tests for verify_katana_report_data (v1 appchain report_data).

use core::integer::{u128_byte_reverse, u512};
use core::poseidon::poseidon_hash_span;
use katana_tee::katana_report_utils::{
    KATANA_TEE_APPCHAIN_MODE, KATANA_TEE_REPORT_VERSION, verify_katana_report_data,
};

const CONFIG_HASH: felt252 = 0x001e6daca26d3d6429b176987b51f016baf1fc998f1961d02594e2ab307a61d1;
// Felt::MAX, used by Katana as the genesis prev_block_number sentinel.
const PREV_BLOCK_GENESIS: felt252 =
    0x800000000000011000000000000000000000000000000000000000000000000;

/// Build a v1 appchain report_data: commitment in the first half, config hash in the second.
fn build_report_data(
    prev_state_root: felt252,
    state_root: felt252,
    prev_block_hash: felt252,
    block_hash: felt252,
    prev_block_number: felt252,
    block_number: felt252,
    messages_commitment: felt252,
    config_hash: felt252,
) -> u512 {
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
            config_hash,
        ]
            .span(),
    );
    let commitment_u256: u256 = commitment.into();
    let config_u256: u256 = config_hash.into();
    u512 {
        limb0: u128_byte_reverse(commitment_u256.high),
        limb1: u128_byte_reverse(commitment_u256.low),
        limb2: u128_byte_reverse(config_u256.high),
        limb3: u128_byte_reverse(config_u256.low),
    }
}

#[test]
fn test_happy_path_genesis() {
    let rd = build_report_data(
        0x0, 0x20, 0x0, 0x40, PREV_BLOCK_GENESIS, 0x0, 0x50, CONFIG_HASH,
    );
    let ok = verify_katana_report_data(
        rd, 0x0, 0x20, 0x0, 0x40, PREV_BLOCK_GENESIS, 0x0, 0x50, CONFIG_HASH,
    );
    assert(ok, 'should pass');
}

#[test]
fn test_happy_path_non_genesis() {
    let rd = build_report_data(0x11, 0x22, 0x33, 0x44, 0x5, 0x6, 0x77, CONFIG_HASH);
    let ok = verify_katana_report_data(
        rd, 0x11, 0x22, 0x33, 0x44, 0x5, 0x6, 0x77, CONFIG_HASH,
    );
    assert(ok, 'should pass');
}

#[test]
#[should_panic(expected: 'Commitment mismatch')]
fn test_commitment_mismatch() {
    let rd = build_report_data(0x10, 0x20, 0x30, 0x40, 0x0, 0x1, 0x50, CONFIG_HASH);
    // Wrong state_root (0x21 instead of 0x20).
    verify_katana_report_data(rd, 0x10, 0x21, 0x30, 0x40, 0x0, 0x1, 0x50, CONFIG_HASH);
}

#[test]
#[should_panic(expected: 'Commitment mismatch')]
fn test_messages_commitment_mismatch() {
    let rd = build_report_data(0x10, 0x20, 0x30, 0x40, 0x0, 0x1, 0x50, CONFIG_HASH);
    // Wrong messages_commitment (0x51 instead of 0x50).
    verify_katana_report_data(rd, 0x10, 0x20, 0x30, 0x40, 0x0, 0x1, 0x51, CONFIG_HASH);
}

#[test]
#[should_panic(expected: 'Config hash mismatch')]
fn test_config_hash_mismatch() {
    // The config hash is part of the commitment, so to isolate the second-half
    // check we keep a valid commitment (built with CONFIG_HASH) but corrupt only
    // the second half of report_data.
    let base = build_report_data(0x10, 0x20, 0x30, 0x40, 0x0, 0x1, 0x50, CONFIG_HASH);
    let wrong: u256 = 0xdeadbeef;
    let rd = u512 {
        limb0: base.limb0,
        limb1: base.limb1,
        limb2: u128_byte_reverse(wrong.high),
        limb3: u128_byte_reverse(wrong.low),
    };
    verify_katana_report_data(rd, 0x10, 0x20, 0x30, 0x40, 0x0, 0x1, 0x50, CONFIG_HASH);
}
