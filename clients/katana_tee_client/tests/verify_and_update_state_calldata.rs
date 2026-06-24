//! Unit coverage for the `verify_and_update_state` calldata layout.
//!
//! This is the on-chain settlement encoding (the production
//! `KatanaTeeStarknetClient::verify_and_update_state` previously had 0% test
//! coverage). The felt ordering must match the `KatanaTee` Cairo entrypoint
//! `(sp1_proof: Array<felt252>, state_root, block_hash, block_number: u64,
//! fork_block_number: u64, events_commitment)` exactly — a silent reorder
//! corrupts settlement.

use katana_tee_client::starknet::build_verify_and_update_state_calldata;
use starknet_rust_core::types::Felt;

#[test]
fn calldata_layout_is_exact() {
    let sp1_proof = vec![Felt::from(11u64), Felt::from(22u64), Felt::from(33u64)];
    let state_root = Felt::from(0xAAu64);
    let block_hash = Felt::from(0xBBu64);
    let block_number = Felt::from(7u64);
    let fork_block_number = Felt::from(5u64);
    let events_commitment = Felt::from(0xCCu64);

    let calldata = build_verify_and_update_state_calldata(
        &sp1_proof,
        state_root,
        block_hash,
        block_number,
        fork_block_number,
        events_commitment,
    );

    let expected = vec![
        Felt::from(3u64), // Array<felt252> length prefix
        Felt::from(11u64),
        Felt::from(22u64),
        Felt::from(33u64),
        state_root,
        block_hash,
        block_number,
        fork_block_number,
        events_commitment,
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
        ]
    );
}
