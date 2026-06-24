//! Live read-only verification of a locally-generated SP1 Groth16 proof against the
//! canonical AMD TEE registry on Starknet **Sepolia**.
//!
//! This issues a `starknet_call` to `verify_sp1_proof` on the already-deployed registry
//! (no fork, no transaction, no gas, no state change) and asserts it returns `Result::Ok`,
//! i.e. the real Garaga SP1 Groth16 verification, the program-id check, journal decode, and
//! AMD cert-chain validation all pass on-chain.
//!
//! The proof in `tests/fixtures/sepolia_block_0/` was generated with `katana-tee prove
//! --prover cpu` from a Katana TEE attestation (block 0).
//!
//! Network test — ignored by default. Run with:
//!   cargo test -p amd_tee_registry_client --test verify_sepolia -- --ignored
//! Override the endpoint with `SEPOLIA_RPC_URL` (defaults to the public Cartridge RPC).

use amd_tee_registry_client::{OnchainProof, StarknetCalldata, StarknetRegistryClient};

/// Canonical AMD TEE registry on Starknet Sepolia (see `deployments/sepolia.json`).
const CANONICAL_SEPOLIA_REGISTRY: &str =
    "0x01258ed7b2d3435097f9290d100d706d7f9f65db2725609cd7697669cac3bc3a";

const PROOF_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/fixtures/sepolia_block_0/proof.json"
);

#[tokio::test]
#[ignore = "network: hits live Sepolia RPC"]
async fn verify_sp1_proof_on_canonical_sepolia_registry() {
    let rpc = std::env::var("SEPOLIA_RPC_URL")
        .unwrap_or_else(|_| "https://api.cartridge.gg/x/starknet/sepolia".to_string());

    let proof_bytes = std::fs::read(PROOF_PATH).expect("read proof fixture");
    let proof = OnchainProof::decode_json(&proof_bytes).expect("decode proof json");

    // Garaga calldata in length-prefixed span form ([span_len, e0, e1, ...]) — exactly the
    // `Array<felt252>` the registry forwards to the Garaga verifier.
    let sp1_proof = StarknetCalldata::from_proof(&proof)
        .expect("build Garaga calldata")
        .to_felts()
        .expect("calldata to felts");

    let client = StarknetRegistryClient::from_hex(&rpc, CANONICAL_SEPOLIA_REGISTRY)
        .expect("build registry client");

    let journal = client
        .verify_sp1_proof(sp1_proof)
        .await
        .expect("verify_sp1_proof should return Ok against the canonical Sepolia registry");

    assert!(!journal.is_empty(), "expected a non-empty VerifierJournal");
    println!(
        "verified ✓ — VerifierJournal returned {} felts",
        journal.len()
    );
}
