//! Hermetic coverage for `AMDTEERegistry::verify_sp1_proof`.
//!
//! Uses `MockGaragaVerifier` (a library-called echo of `(vk, public_inputs)`) so
//! every branch of the security gate can be exercised without a real Groth16
//! proof or the on-chain Garaga class:
//!   - the `vk == sp1_program_id` gate (the single check stopping a
//!     valid-but-wrong-program proof),
//!   - verifier `Err` propagation,
//!   - `journal.result != Success`,
//!   - `trusted_certs_prefix_len == 0`,
//!   - invalid processor model,
//!   - root cert not set / root cert mismatch / certs too short,
//!   - untrusted intermediate cert,
//!   - the happy path (prefix_len 1 and 2) and the cert-cache side effect.

use amd_tee_registry::cert_cache::CertCacheComponent::{
    ICertCacheDispatcher, ICertCacheDispatcherTrait,
};
use amd_tee_registry::tee_registry::{IAMDTeeRegistryDispatcher, IAMDTeeRegistryDispatcherTrait};
use amd_tee_registry::tee_types::VerificationResult;
use snforge_std::{ContractClassTrait, DeclareResultTrait, declare};
use starknet::ContractAddress;

const PROGRAM_ID: u256 = 0xABCD;
const GENOA_ROOT: u256 = 0x6001;
const TRUSTED_INTERMEDIATE: u256 = 0x7001;
const PROC_MILAN: u128 = 0;
const PROC_GENOA: u128 = 1;
const RESULT_SUCCESS: u128 = 0;
const RESULT_ROOT_NOT_TRUSTED: u128 = 1;

fn u(v: u128) -> u256 {
    u256 { low: v, high: 0 }
}

/// Deploy the registry wired to the mock verifier, with a single Genoa root cert
/// and a single trusted intermediate.
fn deploy_registry() -> ContractAddress {
    let registry = declare("AMDTEERegistry").unwrap().contract_class();
    let mock_class_hash: felt252 = (*declare("MockGaragaVerifier")
        .unwrap()
        .contract_class()
        .class_hash)
        .into();

    let mut calldata: Array<felt252> = array![];
    // verifier_class_hash
    calldata.append(mock_class_hash);
    // sp1_program_id (u256)
    calldata.append(PROGRAM_ID.low.into());
    calldata.append(PROGRAM_ID.high.into());
    // max_time_diff
    calldata.append(86400);
    // trusted_certs: Span<u256> = [TRUSTED_INTERMEDIATE]
    calldata.append(1);
    calldata.append(TRUSTED_INTERMEDIATE.low.into());
    calldata.append(TRUSTED_INTERMEDIATE.high.into());
    // processor_models: Span<ProcessorType> = [Genoa]
    calldata.append(1);
    calldata.append(1); // ProcessorType::Genoa
    // root_certs: Span<u256> = [GENOA_ROOT]
    calldata.append(1);
    calldata.append(GENOA_ROOT.low.into());
    calldata.append(GENOA_ROOT.high.into());

    let (addr, _) = registry.deploy(@calldata).unwrap();
    addr
}

/// Build SP1 public inputs (Solidity-ABI `VerifierJournal`) decodable by
/// `decode_verifier_journal`, parameterized over the fields the gate inspects.
fn make_public_inputs(
    result_u8: u128, processor_u8: u128, prefix_len: u128, certs: Span<u256>,
) -> Array<u256> {
    let c: u128 = certs.len().into();
    let certs_offset: u128 = 1536; // 320 (head) + 1216 (rawReport block)
    let cert_serials_offset: u128 = certs_offset + (1 + c) * 32;

    let mut words: Array<u256> = array![];
    words.append(u(0x20)); // ABI offset pointer

    // head, slots 0..9
    words.append(u(result_u8)); // 0 result
    words.append(u(42)); // 1 timestamp
    words.append(u(processor_u8)); // 2 processorModel
    words.append(u(320)); // 3 rawReport offset (bytes)
    words.append(u(certs_offset)); // 4 certs offset
    words.append(u(cert_serials_offset)); // 5 certSerials offset
    words.append(u(prefix_len)); // 6 trustedCertsPrefixLen
    words.append(u(0)); // 7 storageCommitment
    words.append(u(100)); // 8 forkBlockNumber
    words.append(u(200)); // 9 endBlockNumber

    // rawReport block: length (bytes) + 37 zero words (1184 bytes = 296 u32 = 37 u256)
    words.append(u(1184));
    let mut i: usize = 0;
    while i < 37 {
        words.append(u(0));
        i += 1;
    }

    // certs block: length + entries
    words.append(u(c));
    let mut j: usize = 0;
    while j < certs.len() {
        words.append(*certs.at(j));
        j += 1;
    }

    // certSerials block: one serial
    words.append(u(1));
    words.append(u(0xdead));

    words
}

/// Encode a successful verifier echo: `Ok((vk, public_inputs))`, prefixed with
/// the span length so `library_call` deserializes the registry's `sp1_proof` as
/// the verifier's `full_proof: Span<felt252>`.
fn proof_ok(vk: u256, public_inputs: Span<u256>) -> Array<felt252> {
    let mut full: Array<felt252> = array![];
    full.append(1); // is_ok
    full.append(vk.low.into());
    full.append(vk.high.into());
    full.append(0); // err_code (unused)
    full.append(public_inputs.len().into());
    let mut i: usize = 0;
    while i < public_inputs.len() {
        let w = *public_inputs.at(i);
        full.append(w.low.into());
        full.append(w.high.into());
        i += 1;
    }
    with_len_prefix(full)
}

/// Encode a failing verifier echo: `Err(err_code)`.
fn proof_err(err_code: felt252) -> Array<felt252> {
    with_len_prefix(array![0, 0, 0, err_code])
}

fn with_len_prefix(full: Array<felt252>) -> Array<felt252> {
    let mut out: Array<felt252> = array![];
    out.append(full.len().into());
    let mut k: usize = 0;
    while k < full.len() {
        out.append(*full.at(k));
        k += 1;
    }
    out
}

// --- The security gate -------------------------------------------------------

#[test]
#[should_panic(expected: 'Wrong program')]
fn vk_mismatch_panics() {
    let registry = IAMDTeeRegistryDispatcher { contract_address: deploy_registry() };
    // vk != sp1_program_id -> the gate must abort before any journal handling.
    let proof = proof_ok(PROGRAM_ID + 1, array![].span());
    registry.verify_sp1_proof(proof);
}

#[test]
fn verifier_err_propagates() {
    let registry = IAMDTeeRegistryDispatcher { contract_address: deploy_registry() };
    let result = registry.verify_sp1_proof(proof_err('crypto failed'));
    match result {
        Result::Ok(_) => panic!("expected Err"),
        Result::Err(e) => assert(e == 'crypto failed', 'wrong error propagated'),
    }
}

#[test]
fn journal_result_not_success_errors() {
    let registry = IAMDTeeRegistryDispatcher { contract_address: deploy_registry() };
    let pi = make_public_inputs(RESULT_ROOT_NOT_TRUSTED, PROC_GENOA, 1, array![GENOA_ROOT].span());
    let result = registry.verify_sp1_proof(proof_ok(PROGRAM_ID, pi.span()));
    match result {
        Result::Ok(_) => panic!("expected Err"),
        Result::Err(e) => assert(e == 'SP1 program returned an error', 'wrong error'),
    }
}

#[test]
fn prefix_len_zero_errors() {
    let registry = IAMDTeeRegistryDispatcher { contract_address: deploy_registry() };
    let pi = make_public_inputs(RESULT_SUCCESS, PROC_GENOA, 0, array![GENOA_ROOT].span());
    let result = registry.verify_sp1_proof(proof_ok(PROGRAM_ID, pi.span()));
    match result {
        Result::Ok(_) => panic!("expected Err"),
        Result::Err(e) => assert(e == 'Trusted certs len must be >= 1', 'wrong error'),
    }
}

#[test]
fn invalid_processor_model_errors() {
    let registry = IAMDTeeRegistryDispatcher { contract_address: deploy_registry() };
    // processor_model = 99 -> not a valid ProcessorType.
    let pi = make_public_inputs(RESULT_SUCCESS, 99, 1, array![GENOA_ROOT].span());
    let result = registry.verify_sp1_proof(proof_ok(PROGRAM_ID, pi.span()));
    match result {
        Result::Ok(_) => panic!("expected Err"),
        Result::Err(e) => assert(e == 'Invalid processor model', 'wrong error'),
    }
}

#[test]
fn root_cert_not_set_errors() {
    let registry = IAMDTeeRegistryDispatcher { contract_address: deploy_registry() };
    // Registry only set a Genoa root; a Milan journal has no configured root.
    let pi = make_public_inputs(RESULT_SUCCESS, PROC_MILAN, 1, array![GENOA_ROOT].span());
    let result = registry.verify_sp1_proof(proof_ok(PROGRAM_ID, pi.span()));
    match result {
        Result::Ok(_) => panic!("expected Err"),
        Result::Err(e) => assert(e == 'Root cert not set for processor', 'wrong error'),
    }
}

#[test]
fn certs_too_short_errors() {
    let registry = IAMDTeeRegistryDispatcher { contract_address: deploy_registry() };
    // prefix_len 2 but only 1 cert present.
    let pi = make_public_inputs(RESULT_SUCCESS, PROC_GENOA, 2, array![GENOA_ROOT].span());
    let result = registry.verify_sp1_proof(proof_ok(PROGRAM_ID, pi.span()));
    match result {
        Result::Ok(_) => panic!("expected Err"),
        Result::Err(e) => assert(e == 'Certificates array too short', 'wrong error'),
    }
}

#[test]
fn root_cert_mismatch_errors() {
    let registry = IAMDTeeRegistryDispatcher { contract_address: deploy_registry() };
    // certs[0] != the configured Genoa root.
    let pi = make_public_inputs(RESULT_SUCCESS, PROC_GENOA, 1, array![u(0x9999)].span());
    let result = registry.verify_sp1_proof(proof_ok(PROGRAM_ID, pi.span()));
    match result {
        Result::Ok(_) => panic!("expected Err"),
        Result::Err(e) => assert(e == 'Root certificate mismatch', 'wrong error'),
    }
}

#[test]
fn untrusted_intermediate_errors() {
    let registry = IAMDTeeRegistryDispatcher { contract_address: deploy_registry() };
    // prefix_len 2: certs[0] is the root, certs[1] is an untrusted intermediate.
    let pi = make_public_inputs(
        RESULT_SUCCESS, PROC_GENOA, 2, array![GENOA_ROOT, u(0x9999)].span(),
    );
    let result = registry.verify_sp1_proof(proof_ok(PROGRAM_ID, pi.span()));
    match result {
        Result::Ok(_) => panic!("expected Err"),
        Result::Err(e) => assert(e == 'Untrusted intermediate cert', 'wrong error'),
    }
}

// --- Happy paths -------------------------------------------------------------

#[test]
fn happy_path_prefix_one() {
    let registry = IAMDTeeRegistryDispatcher { contract_address: deploy_registry() };
    let pi = make_public_inputs(RESULT_SUCCESS, PROC_GENOA, 1, array![GENOA_ROOT].span());
    let result = registry.verify_sp1_proof(proof_ok(PROGRAM_ID, pi.span()));
    match result {
        Result::Ok(journal) => {
            assert(journal.result == VerificationResult::Success, 'not success');
            assert(journal.processor_model == 1, 'wrong processor');
            assert(journal.fork_block_number == 100, 'wrong fork block');
            assert(journal.end_block_number == 200, 'wrong end block');
            assert(journal.trusted_certs_prefix_len == 1, 'wrong prefix');
        },
        Result::Err(_) => panic!("expected Ok"),
    }
}

#[test]
fn happy_path_prefix_two_with_trusted_intermediate() {
    let contract_address = deploy_registry();
    let registry = IAMDTeeRegistryDispatcher { contract_address };
    let pi = make_public_inputs(
        RESULT_SUCCESS, PROC_GENOA, 2, array![GENOA_ROOT, TRUSTED_INTERMEDIATE].span(),
    );
    let result = registry.verify_sp1_proof(proof_ok(PROGRAM_ID, pi.span()));
    match result {
        Result::Ok(journal) => assert(journal.end_block_number == 200, 'wrong end block'),
        Result::Err(_) => panic!("expected Ok"),
    }
}

/// A successful prefix-1 verification caches the full presented chain, so a
/// previously-unknown intermediate becomes trusted afterwards (the cache side
/// effect of `cache_new_cert`).
#[test]
fn happy_path_caches_new_certs() {
    let contract_address = deploy_registry();
    let registry = IAMDTeeRegistryDispatcher { contract_address };
    let cache = ICertCacheDispatcher { contract_address };

    let new_intermediate = u(0x8002);
    assert(!cache.is_trusted_intermediate_cert(new_intermediate), 'should start untrusted');

    // prefix_len 1 means only certs[0] (root) is checked, but the whole chain is cached.
    let pi = make_public_inputs(
        RESULT_SUCCESS, PROC_GENOA, 1, array![GENOA_ROOT, new_intermediate].span(),
    );
    let result = registry.verify_sp1_proof(proof_ok(PROGRAM_ID, pi.span()));
    assert(result.is_ok(), 'verify should succeed');

    assert(cache.is_trusted_intermediate_cert(new_intermediate), 'should be cached');
}
