use amd_tee_registry::journal_decode::decode_verifier_journal;
use amd_tee_registry::tee_types::{ATTESTATION_REPORT_SIZE_U32, VerificationResult};

fn u256_from_u128(value: u128) -> u256 {
    u256 { low: value, high: 0 }
}

/// Nested ABI layout (after 0x20 wrapper):
///   Word 0:   offset to AttestationCore (= 224 = 7*32)
///   Word 1-8: ShardProof inline (8 fields)
///   Word 9-15: AttestationCore header
///   Word 16+: dynamic data (rawReport, certs, certSerials)
///
/// AttestationCore dynamic offsets are relative to word 9:
///   rawReport:   224 bytes  → absolute word 16  (9 + 224/32 = 16)
///   certs:       1440 bytes → absolute word 54  (9 + 1440/32 = 54)  [16 + 1(len) + 37(data) = 54]
///   certSerials: 1504 bytes → absolute word 56  (9 + 1504/32 = 56)  [54 + 1(len) + 1(data) = 56]
#[test]
fn test_decode_nested_journal() {
    let mut words: Array<u256> = array![];

    // ABI wrapper
    words.append(u256_from_u128(0x20));

    // ── Outer head ──
    words.append(u256_from_u128(288)); // offset to AttestationCore (9 * 32)

    // ShardProof inline (words 1-8)
    words.append(u256_from_u128(0xabc));  // storageCommitment
    words.append(u256_from_u128(0x1234)); // eventsCommitment
    words.append(u256_from_u128(100));    // forkBlockNumber
    words.append(u256_from_u128(200));    // endBlockNumber
    words.append(u256_from_u128(0x42));   // eventGameContract
    words.append(u256_from_u128(0x99));   // eventShardId
    words.append(u256_from_u128(0xbeef)); // initialStorageCommitment
    words.append(u256_from_u128(0xcafe)); // forkStateRoot

    // ── AttestationCore header (words 9-15) ──
    words.append(u256_from_u128(0));    // result = Success
    words.append(u256_from_u128(42));   // timestamp
    words.append(u256_from_u128(1));    // processorModel = Genoa
    words.append(u256_from_u128(224));  // rawReport offset (relative to word 9)
    words.append(u256_from_u128(1440)); // certs offset (relative)
    words.append(u256_from_u128(1504)); // certSerials offset (relative)
    words.append(u256_from_u128(2));    // trustedCertsPrefixLen

    // ── rawReport at word 16 ──
    words.append(u256_from_u128(1184)); // length in bytes (296 u32 = 1184 bytes)
    let mut i: usize = 0;
    while i < 37 { // ceil(1184/32) = 37 words
        words.append(u256_from_u128(0));
        i += 1;
    }

    // ── certs at word 54 ──
    words.append(u256_from_u128(1));      // length = 1
    words.append(u256_from_u128(0x5678)); // cert[0]

    // ── certSerials at word 56 ──
    words.append(u256_from_u128(1));      // length = 1
    words.append(u256_from_u128(0xdead)); // serial[0]

    let journal = decode_verifier_journal(words.span());

    // ShardProof
    assert(journal.shard.storage_commitment == 0xabc, 'Wrong storage commitment');
    assert(journal.shard.events_commitment == 0x1234, 'Wrong events commitment');
    assert(journal.shard.fork_block_number == 100, 'Wrong fork block number');
    assert(journal.shard.end_block_number == 200, 'Wrong end block number');
    assert(journal.shard.event_game_contract == 0x42, 'Wrong event game contract');
    assert(journal.shard.event_shard_id == 0x99, 'Wrong event shard id');
    assert(journal.shard.initial_storage_commitment == 0xbeef, 'Wrong initial commitment');
    assert(journal.shard.fork_state_root == 0xcafe, 'Wrong fork state root');

    // AttestationCore
    assert(journal.attestation.result == VerificationResult::Success, 'Wrong result');
    assert(journal.attestation.timestamp == 42, 'Wrong timestamp');
    assert(journal.attestation.processor_model == 1, 'Wrong processor model');
    assert(journal.attestation.trusted_certs_prefix_len == 2, 'Wrong trusted prefix');
    assert(
        journal.attestation.raw_report.len() == ATTESTATION_REPORT_SIZE_U32.into(),
        'Wrong raw report size',
    );
    assert(journal.attestation.certs.len() == 1, 'Wrong cert count');
    assert(*journal.attestation.certs.at(0) == u256_from_u128(0x5678), 'Wrong cert value');
    assert(journal.attestation.cert_serials.len() == 1, 'Wrong serial count');
    assert(*journal.attestation.cert_serials.at(0) == 0xdead, 'Wrong serial value');
}
