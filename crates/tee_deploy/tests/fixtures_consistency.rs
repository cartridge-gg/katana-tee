use std::fs;
use std::path::PathBuf;

use serde::Deserialize;

#[derive(Deserialize)]
struct MeasurementFixture {
    high_bits: String,
    low_bits: String,
    mid_bits: String,
}

#[derive(Deserialize)]
struct Sp1ProgramIdFixture {
    high_bits: String,
    low_bits: String,
}

#[derive(Deserialize)]
struct AttestationFixture {
    quote: String,
}

#[derive(Deserialize)]
struct ProofFixture {
    program_id: ProgramId,
}

#[derive(Deserialize)]
struct ProgramId {
    verifier_id: String,
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("failed to resolve repo root")
}

fn parse_u128_hex_or_dec(value: &str) -> u128 {
    let trimmed = value.trim();
    if trimmed.starts_with("0x") || trimmed.starts_with("0X") {
        u128::from_str_radix(trimmed.trim_start_matches("0x").trim_start_matches("0X"), 16)
            .expect("invalid hex u128")
    } else {
        trimmed.parse::<u128>().expect("invalid decimal u128")
    }
}

fn normalize_hex_32bytes(value: &str) -> String {
    let raw = value.trim().trim_start_matches("0x").trim_start_matches("0X");
    format!("0x{:0>64}", raw.to_ascii_lowercase())
}

fn decode_hex_bytes(value: &str) -> Vec<u8> {
    let raw = value.trim().trim_start_matches("0x").trim_start_matches("0X");
    assert!(raw.len() % 2 == 0, "hex string length must be even");
    (0..raw.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&raw[i..i + 2], 16).expect("invalid hex byte"))
        .collect()
}

#[test]
fn sp1_program_id_fixture_matches_current_sp1_proof_fixture() {
    let root = repo_root();
    let sp1_path = root.join("tests/fixtures/sp1_program_id.json");
    let proof_path = root.join("tests/fixtures/sp1_proof.json");

    let sp1_fixture: Sp1ProgramIdFixture =
        serde_json::from_str(&fs::read_to_string(&sp1_path).expect("read sp1_program_id.json"))
            .expect("parse sp1_program_id.json");
    let proof_fixture: ProofFixture =
        serde_json::from_str(&fs::read_to_string(&proof_path).expect("read sp1_proof.json"))
            .expect("parse sp1_proof.json");

    let expected = format!(
        "0x{:032x}{:032x}",
        parse_u128_hex_or_dec(&sp1_fixture.high_bits),
        parse_u128_hex_or_dec(&sp1_fixture.low_bits)
    );
    let actual = normalize_hex_32bytes(&proof_fixture.program_id.verifier_id);

    assert_eq!(
        actual, expected,
        "sp1_program_id.json should match tests/fixtures/sp1_proof.json program_id.verifier_id"
    );
}

#[test]
fn measurement_fixture_matches_block_1_and_block_2_quote_measurements() {
    let root = repo_root();
    let measurement_path = root.join("tests/fixtures/measurement.json");

    let measurement: MeasurementFixture = serde_json::from_str(
        &fs::read_to_string(&measurement_path).expect("read measurement.json"),
    )
    .expect("parse measurement.json");

    let expected = (
        parse_u128_hex_or_dec(&measurement.low_bits),
        parse_u128_hex_or_dec(&measurement.mid_bits),
        parse_u128_hex_or_dec(&measurement.high_bits),
    );

    let mut matched_blocks = vec![];
    for block in [0_u8, 1_u8, 2_u8] {
        let path = root.join(format!("tests/fixtures/block_{block}/attestation.json"));
        let fixture: AttestationFixture =
            serde_json::from_str(&fs::read_to_string(&path).expect("read attestation.json"))
                .expect("parse attestation.json");
        let quote_bytes = decode_hex_bytes(&fixture.quote);
        assert!(
            quote_bytes.len() >= 0x90 + 48,
            "quote in block_{block} is too short to contain measurement"
        );
        let measurement_bytes = &quote_bytes[0x90..0x90 + 48];
        let low = u128::from_le_bytes(measurement_bytes[0..16].try_into().expect("low"));
        let mid = u128::from_le_bytes(measurement_bytes[16..32].try_into().expect("mid"));
        let high = u128::from_le_bytes(measurement_bytes[32..48].try_into().expect("high"));
        if (low, mid, high) == expected {
            matched_blocks.push(block);
        }
    }

    assert!(
        matched_blocks.contains(&1),
        "measurement.json should match block_1 quote measurement"
    );
    assert!(
        matched_blocks.contains(&2),
        "measurement.json should match block_2 quote measurement"
    );
}
