use core::integer::{u128_byte_reverse, u512};
use core::poseidon::poseidon_hash_span;
use katana_tee::katana_report_utils::{
    KATANA_TEE_APPCHAIN_MODE, KATANA_TEE_REPORT_VERSION, verify_katana_report_data,
};

/// Build a v1 appchain report_data with config hash 0 (second half zero).
fn build(
    prev_state_root: felt252,
    state_root: felt252,
    prev_block_hash: felt252,
    block_hash: felt252,
    prev_block_number: felt252,
    block_number: felt252,
    messages_commitment: felt252,
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
            0,
        ]
            .span(),
    );
    let c: u256 = commitment.into();
    u512 {
        limb0: u128_byte_reverse(c.high), limb1: u128_byte_reverse(c.low), limb2: 0, limb3: 0,
    }
}

#[test]
fn test_verify_katana_report_data_layout() {
    let rd = build(0x0, 0x2, 0x0, 0x4, 0x0, 0x0, 0x0);
    assert(
        verify_katana_report_data(rd, 0x0, 0x2, 0x0, 0x4, 0x0, 0x0, 0x0, 0),
        'Verification should succeed',
    );
}

#[test]
fn test_verify_katana_report_data_nonzero_fields() {
    let rd = build(0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7);
    assert(
        verify_katana_report_data(rd, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0),
        'Verification should succeed',
    );
}
