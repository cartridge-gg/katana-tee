//! Offline regression guard for the self-generated Garaga **SP1 v6.1.0** verifier
//! calldata path (`StarknetCalldata::from_proof` → Garaga `from_sp1` /
//! `get_sp1_vk` / `get_groth16_calldata`).
//!
//! Before this, the v6 calldata conversion was only exercised by a `#[ignore]`
//! network test, so a regression in the (hand-ported) Garaga v6 universal VK or
//! serialization would not be caught in CI. The fixture is a real v6.1.0 network
//! proof whose calldata was verified on-chain against the canonical Sepolia
//! registry (`registry.verify_sp1_proof` returned `Ok`), so this golden locks a
//! known-good output.
//!
//! To regenerate after an intentional verifier change: `BLESS=1 cargo test -p
//! amd_tee_registry_client --test calldata_v6_golden` then review the diff.

use amd_tee_registry_client::{OnchainProof, StarknetCalldata};

const PROOF_JSON: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/testdata/v6/proof.json");
const GOLDEN: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/testdata/v6/calldata_golden.txt"
);
const V6_PROGRAM_ID: &str = "0x00ed032fe45bc3492eb4f75fcb5c670f6be4a0e152ea8d8dbe56992f0433f65f";

fn build_calldata() -> StarknetCalldata {
    let data = std::fs::read(PROOF_JSON).expect("read v6 proof fixture");
    let proof = OnchainProof::decode_json(&data).expect("decode v6 proof");
    assert_eq!(
        proof.zkvm_version, "v6.1.0",
        "fixture must be a v6.1.0 proof"
    );
    assert_eq!(
        format!("{:#x}", proof.program_id.verifier_id),
        V6_PROGRAM_ID,
        "fixture program id must match the canonical v6 registry"
    );
    StarknetCalldata::from_proof(&proof).expect("from_proof must succeed for a valid v6 proof")
}

#[test]
fn from_proof_matches_committed_golden() {
    let produced: Vec<String> = build_calldata().to_hex_strings();

    if std::env::var("BLESS").is_ok() {
        std::fs::write(GOLDEN, format!("{}\n", produced.join("\n"))).expect("write golden");
    }

    let golden = std::fs::read_to_string(GOLDEN).expect("read committed golden");
    let expected: Vec<&str> = golden.lines().collect();
    let produced_refs: Vec<&str> = produced.iter().map(String::as_str).collect();

    assert_eq!(
        produced_refs, expected,
        "Garaga v6.1.0 calldata drifted from the committed golden — \
         a VK/serialization change? Re-bless only if intentional."
    );
}

#[test]
fn from_proof_is_deterministic_and_nontrivial() {
    let a = build_calldata().to_hex_strings();
    let b = build_calldata().to_hex_strings();
    assert_eq!(a, b, "from_proof must be deterministic");
    // A Groth16 proof with 5 public inputs plus MSM/ECIP hints is well over 20 felts.
    assert!(a.len() > 20, "calldata unexpectedly small: {}", a.len());
}
