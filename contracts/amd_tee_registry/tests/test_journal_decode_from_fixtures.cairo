use amd_tee_registry::journal_decode::decode_verifier_journal;
use amd_tee_registry::tee_types::{AttestationCore, DecodedJournal, ShardProof};

mod test_journal_decode_fixtures;
use test_journal_decode_fixtures::{get_fixture_expected, get_fixture_inputs};

/// Compare DecodedJournal structs field by field for better error messages.
fn assert_journal_eq(actual: DecodedJournal, expected: DecodedJournal) {
    // AttestationCore
    assert(actual.attestation.result == expected.attestation.result, 'result mismatch');
    assert(actual.attestation.timestamp == expected.attestation.timestamp, 'timestamp mismatch');
    assert(
        actual.attestation.processor_model == expected.attestation.processor_model,
        'processor_model mismatch',
    );
    assert(
        actual.attestation.trusted_certs_prefix_len == expected.attestation.trusted_certs_prefix_len,
        'trusted_prefix mismatch',
    );

    assert(
        actual.attestation.raw_report.len() == expected.attestation.raw_report.len(),
        'raw_report len mismatch',
    );
    let mut i: u32 = 0;
    while i < actual.attestation.raw_report.len() {
        assert(
            *actual.attestation.raw_report.at(i) == *expected.attestation.raw_report.at(i),
            'raw_report elem mismatch',
        );
        i += 1;
    }

    assert(actual.attestation.certs.len() == expected.attestation.certs.len(), 'certs len mismatch');
    let mut j: u32 = 0;
    while j < actual.attestation.certs.len() {
        assert(
            *actual.attestation.certs.at(j) == *expected.attestation.certs.at(j),
            'certs elem mismatch',
        );
        j += 1;
    }

    assert(
        actual.attestation.cert_serials.len() == expected.attestation.cert_serials.len(),
        'serials len mismatch',
    );
    let mut k: u32 = 0;
    while k < actual.attestation.cert_serials.len() {
        assert(
            *actual.attestation.cert_serials.at(k) == *expected.attestation.cert_serials.at(k),
            'serials elem mismatch',
        );
        k += 1;
    };

    // ShardProof
    assert(
        actual.shard.storage_commitment == expected.shard.storage_commitment,
        'storage commitment mismatch',
    );
    assert(
        actual.shard.events_commitment == expected.shard.events_commitment,
        'events commitment mismatch',
    );
    assert(
        actual.shard.fork_block_number == expected.shard.fork_block_number,
        'fork block mismatch',
    );
    assert(
        actual.shard.end_block_number == expected.shard.end_block_number,
        'end block mismatch',
    );
    assert(
        actual.shard.event_game_contract == expected.shard.event_game_contract,
        'event game contract mismatch',
    );
    assert(
        actual.shard.event_shard_id == expected.shard.event_shard_id,
        'event shard id mismatch',
    );
    assert(
        actual.shard.initial_storage_commitment == expected.shard.initial_storage_commitment,
        'initial commitment mismatch',
    );
    assert(
        actual.shard.fork_state_root == expected.shard.fork_state_root,
        'fork state root mismatch',
    );
}

#[test]
fn test_decode_fixture() {
    let inputs = get_fixture_inputs();
    let expected = get_fixture_expected();
    let result = decode_verifier_journal(inputs.span());
    assert_journal_eq(result, expected);
}
