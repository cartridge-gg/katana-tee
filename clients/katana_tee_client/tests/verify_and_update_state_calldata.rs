//! Unit coverage for the `verify_and_update_state` calldata layout.
//!
//! This is the on-chain settlement encoding. The felt ordering must match the
//! `KatanaTee` Cairo entrypoint `(sp1_proof: Array<felt252>, prev_state_root,
//! state_root, prev_block_hash, block_hash, prev_block_number, block_number: u64,
//! messages_commitment)` exactly — a silent reorder corrupts settlement.

use katana_tee_client::starknet::build_verify_and_update_state_calldata;
use starknet_rust_core::types::Felt;

#[test]
fn calldata_layout_is_exact() {
    let sp1_proof = vec![Felt::from(11u64), Felt::from(22u64), Felt::from(33u64)];
    let prev_state_root = Felt::from(0xA0u64);
    let state_root = Felt::from(0xAAu64);
    let prev_block_hash = Felt::from(0xB0u64);
    let block_hash = Felt::from(0xBBu64);
    let prev_block_number = Felt::from(0xF0u64);
    let block_number = Felt::from(7u64);
    let messages_commitment = Felt::from(0xCCu64);

    let calldata = build_verify_and_update_state_calldata(
        &sp1_proof,
        prev_state_root,
        state_root,
        prev_block_hash,
        block_hash,
        prev_block_number,
        block_number,
        messages_commitment,
    );

    let expected = vec![
        Felt::from(3u64), // Array<felt252> length prefix
        Felt::from(11u64),
        Felt::from(22u64),
        Felt::from(33u64),
        prev_state_root,
        state_root,
        prev_block_hash,
        block_hash,
        prev_block_number,
        block_number,
        messages_commitment,
    ];
    assert_eq!(calldata, expected);
}

#[test]
fn empty_proof_still_orders_tail_fields() {
    let calldata = build_verify_and_update_state_calldata(
        &[],
        Felt::from(1u64),
        Felt::from(2u64),
        Felt::from(3u64),
        Felt::from(4u64),
        Felt::from(5u64),
        Felt::from(6u64),
        Felt::from(7u64),
    );

    assert_eq!(
        calldata,
        vec![
            Felt::ZERO, // empty proof -> length 0
            Felt::from(1u64),
            Felt::from(2u64),
            Felt::from(3u64),
            Felt::from(4u64),
            Felt::from(5u64),
            Felt::from(6u64),
            Felt::from(7u64),
        ]
    );
}
