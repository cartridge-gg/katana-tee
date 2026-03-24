use amd_tee_registry::byte_utils::Bytes48;
use amd_tee_registry::tee_types::{
    ATTESTATION_REPORT_SIZE_U32, OFF_MEASUREMENT, OFF_REPORT_DATA,
};
use core::integer::{u128_byte_reverse, u512};
use core::poseidon::poseidon_hash_span;
use katana_tee::katana_report_utils::compute_katana_args_hash;
use katana_tee::{IKatanaTeeDispatcher, IKatanaTeeDispatcherTrait};
use snforge_std::{ContractClassTrait, DeclareResultTrait, declare};
use starknet::ContractAddress;
use storage_commitment::{IStorageCommitmentDispatcher, IStorageCommitmentDispatcherTrait};

const TEST_STATE_ROOT: felt252 = 0x123456789abcdef;
const TEST_BLOCK_HASH: felt252 = 0xfedcba987654321;
const TEST_BLOCK_NUMBER: u64 = 777;
const TEST_FORK_BLOCK_NUMBER: u64 = 42;
const TEST_END_BLOCK_NUMBER: u64 = 123;
const TEST_EVENTS_COMMITMENT: felt252 = 0x789abc;
const TEST_STORAGE_COMMITMENT: felt252 = 0x456def;

const TEST_MEASUREMENT_LOW: u128 = 0x11112222333344445555666677778888;
const TEST_MEASUREMENT_MID: u128 = 0x9999aaaabbbbccccddddeeeeffff0000;
const TEST_MEASUREMENT_HIGH: u128 = 0x1234567890abcdef1234567890abcdef;

const TEST_FORK_PROVIDER_URL_WORD: felt252 = 0x68747470733a2f2f7270632e6578616d706c65;
const TEST_FORK_PROVIDER_URL_LEN: felt252 = 19;
const WRONG_FORK_PROVIDER_URL_WORD: felt252 = 0x68747470733a2f2f7270632e626164;
const WRONG_FORK_PROVIDER_URL_LEN: felt252 = 15;
const TEST_SHARD_ID: felt252 = 0x10;

fn test_measurement() -> Bytes48 {
    Bytes48 {
        low_bits: TEST_MEASUREMENT_LOW,
        mid_bits: TEST_MEASUREMENT_MID,
        high_bits: TEST_MEASUREMENT_HIGH,
    }
}

fn test_args_hash() -> u256 {
    let fork_provider_url: ByteArray = "https://rpc.example";
    compute_katana_args_hash(@fork_provider_url, TEST_FORK_BLOCK_NUMBER)
}

fn build_report_data(
    state_root: felt252,
    block_hash: felt252,
    fork_block_number: u64,
    events_commitment: felt252,
    args_hash: u256,
) -> u512 {
    let commitment = poseidon_hash_span(
        array![state_root, block_hash, fork_block_number.into(), events_commitment].span(),
    );
    let commitment_u256: u256 = commitment.into();
    u512 {
        limb0: u128_byte_reverse(commitment_u256.high),
        limb1: u128_byte_reverse(commitment_u256.low),
        limb2: u128_byte_reverse(args_hash.high),
        limb3: u128_byte_reverse(args_hash.low),
    }
}

fn append_u128_le_words(ref data: Array<u32>, value: u128) {
    let w0: u32 = (value % 0x100000000).try_into().unwrap();
    let w1: u32 = ((value / 0x100000000) % 0x100000000).try_into().unwrap();
    let w2: u32 = ((value / 0x10000000000000000) % 0x100000000).try_into().unwrap();
    let w3: u32 = (value / 0x1000000000000000000000000).try_into().unwrap();
    data.append(w0);
    data.append(w1);
    data.append(w2);
    data.append(w3);
}

fn build_mock_raw_report() -> Array<u32> {
    let report_data = build_report_data(
        TEST_STATE_ROOT,
        TEST_BLOCK_HASH,
        TEST_FORK_BLOCK_NUMBER,
        TEST_EVENTS_COMMITMENT,
        test_args_hash(),
    );
    let measurement = test_measurement();

    let mut raw_report: Array<u32> = array![];
    let mut i: u32 = 0;
    while i < OFF_REPORT_DATA {
        raw_report.append(0);
        i += 1;
    }

    append_u128_le_words(ref raw_report, report_data.limb0);
    append_u128_le_words(ref raw_report, report_data.limb1);
    append_u128_le_words(ref raw_report, report_data.limb2);
    append_u128_le_words(ref raw_report, report_data.limb3);

    assert(raw_report.len() == OFF_MEASUREMENT, 'Bad report-data layout');

    append_u128_le_words(ref raw_report, measurement.low_bits);
    append_u128_le_words(ref raw_report, measurement.mid_bits);
    append_u128_le_words(ref raw_report, measurement.high_bits);

    while raw_report.len() < ATTESTATION_REPORT_SIZE_U32 {
        raw_report.append(0);
    }

    raw_report
}

fn append_short_byte_array(ref calldata: Array<felt252>, pending_word: felt252, pending_len: felt252) {
    calldata.append(0);
    calldata.append(pending_word);
    calldata.append(pending_len);
}

#[starknet::contract]
mod MockAmdTeeRegistry {
    use super::{
        TEST_END_BLOCK_NUMBER, TEST_EVENTS_COMMITMENT, TEST_FORK_BLOCK_NUMBER,
        TEST_STORAGE_COMMITMENT, build_mock_raw_report,
    };
    use amd_tee_registry::tee_registry::IAMDTeeRegistry;
    use amd_tee_registry::tee_types::{VerificationResult, VerifierJournal};

    #[storage]
    struct Storage {}

    #[constructor]
    fn constructor(ref self: ContractState) {}

    #[abi(embed_v0)]
    impl MockAmdTeeRegistryImpl of IAMDTeeRegistry<ContractState> {
        fn verify_sp1_proof(
            ref self: ContractState, sp1_proof: Array<felt252>,
        ) -> Result<VerifierJournal, felt252> {
            let _ = sp1_proof;
            let raw_report = build_mock_raw_report();
            let certs: Array<u256> = array![];
            let cert_serials: Array<felt252> = array![];

            Result::Ok(
                VerifierJournal {
                    result: VerificationResult::Success,
                    timestamp: 0,
                    processor_model: 1,
                    raw_report: raw_report.span(),
                    certs,
                    cert_serials,
                    trusted_certs_prefix_len: 0,
                    storage_commitment: TEST_STORAGE_COMMITMENT,
                    events_commitment: TEST_EVENTS_COMMITMENT,
                    fork_block_number: TEST_FORK_BLOCK_NUMBER,
                    end_block_number: TEST_END_BLOCK_NUMBER,
                },
            )
        }
    }
}

#[starknet::contract]
mod MockShardAttestationConfig {
    use katana_tee::IShardAttestationConfig;
    use starknet::storage::{StoragePointerReadAccess, StoragePointerWriteAccess};

    #[storage]
    struct Storage {
        fork_block_number: u64,
    }

    #[constructor]
    fn constructor(ref self: ContractState, fork_block_number: u64) {
        self.fork_block_number.write(fork_block_number);
    }

    #[abi(embed_v0)]
    impl MockShardAttestationConfigImpl of IShardAttestationConfig<ContractState> {
        fn get_shard_attestation_fork_block_number(
            self: @ContractState, shard_id: felt252,
        ) -> u64 {
            let _ = shard_id;
            self.fork_block_number.read()
        }
    }
}

#[starknet::contract]
mod MockStorageCommitment {
    use starknet::storage::{
        Map, StorageMapReadAccess, StorageMapWriteAccess, StoragePointerReadAccess,
        StoragePointerWriteAccess,
    };
    use starknet::ContractAddress;
    use storage_commitment::{ContractInfo, IStorageCommitment};

    #[storage]
    struct Storage {
        commitments: Map<felt252, bool>,
        authorized_caller: ContractAddress,
        contract_infos: Map<ContractAddress, ContractInfo>,
    }

    #[constructor]
    fn constructor(ref self: ContractState) {}

    #[abi(embed_v0)]
    impl MockStorageCommitmentImpl of IStorageCommitment<ContractState> {
        fn register_verified_commitment(ref self: ContractState, commitment: felt252) {
            self.commitments.write(commitment, true);
        }

        fn set_authorized_caller(ref self: ContractState, caller: ContractAddress) {
            self.authorized_caller.write(caller);
        }

        fn get_authorized_caller(self: @ContractState) -> ContractAddress {
            self.authorized_caller.read()
        }

        fn verify(
            ref self: ContractState,
            storage_commitment: felt252,
            contract_address: ContractAddress,
            global_state_root: felt252,
            end_block_number: u64,
        ) -> bool {
            let _ = end_block_number;
            let registered = self.commitments.read(storage_commitment);
            if registered {
                self.commitments.write(storage_commitment, false);
                let info = self.contract_infos.read(contract_address);
                self
                    .contract_infos
                    .write(
                        contract_address,
                        ContractInfo {
                            nonce: info.nonce + 1, latest_global_state_root: global_state_root,
                        },
                    );
            }
            registered
        }

        fn is_registered(self: @ContractState, commitment: felt252) -> bool {
            self.commitments.read(commitment)
        }

        fn get_nonce(self: @ContractState, contract_address: ContractAddress) -> u64 {
            self.contract_infos.read(contract_address).nonce
        }

        fn get_latest_global_state_root(
            self: @ContractState, contract_address: ContractAddress,
        ) -> felt252 {
            self.contract_infos.read(contract_address).latest_global_state_root
        }
    }
}

fn deploy_mock_registry() -> ContractAddress {
    let contract = declare("MockAmdTeeRegistry").unwrap().contract_class();
    let calldata: Array<felt252> = array![];
    let (contract_address, _) = contract.deploy(@calldata).unwrap();
    contract_address
}

fn deploy_mock_attestation_config(fork_block_number: u64) -> ContractAddress {
    let contract = declare("MockShardAttestationConfig").unwrap().contract_class();
    let calldata: Array<felt252> = array![fork_block_number.into()];
    let (contract_address, _) = contract.deploy(@calldata).unwrap();
    contract_address
}

fn deploy_storage_commitment_registry() -> ContractAddress {
    let contract = declare("MockStorageCommitment").unwrap().contract_class();
    let calldata: Array<felt252> = array![];
    let (contract_address, _) = contract.deploy(@calldata).unwrap();
    contract_address
}

fn deploy_katana_tee_and_storage_commitment_registry(
    registry_address: ContractAddress, fork_provider_url_word: felt252, fork_provider_url_len: felt252,
) -> (ContractAddress, ContractAddress) {
    let contract = declare("KatanaTee").unwrap().contract_class();
    let storage_commitment_registry = deploy_storage_commitment_registry();
    let measurement = test_measurement();

    let mut calldata: Array<felt252> = array![];
    calldata.append(registry_address.into());
    calldata.append(storage_commitment_registry.into());
    calldata.append(measurement.low_bits.into());
    calldata.append(measurement.mid_bits.into());
    calldata.append(measurement.high_bits.into());
    append_short_byte_array(ref calldata, fork_provider_url_word, fork_provider_url_len);

    let (katana_contract_address, _) = contract.deploy(@calldata).unwrap();

    (katana_contract_address, storage_commitment_registry)
}

#[test]
fn test_verify_and_update_state_full_flow_with_mocks() {
    let registry_address = deploy_mock_registry();
    let (katana_address, storage_commitment_registry_address) =
        deploy_katana_tee_and_storage_commitment_registry(
            registry_address, TEST_FORK_PROVIDER_URL_WORD, TEST_FORK_PROVIDER_URL_LEN,
        );
    let attestation_config_contract = deploy_mock_attestation_config(TEST_FORK_BLOCK_NUMBER);

    let katana_dispatcher = IKatanaTeeDispatcher { contract_address: katana_address };
    let storage_commitment_dispatcher = IStorageCommitmentDispatcher {
        contract_address: storage_commitment_registry_address,
    };

    let sp1_proof: Array<felt252> = array![];
    let (result, end_block_number) = katana_dispatcher
        .verify_and_update_state(
            sp1_proof,
            TEST_STATE_ROOT,
            TEST_BLOCK_HASH,
            TEST_BLOCK_NUMBER,
            attestation_config_contract,
            TEST_SHARD_ID,
        )
        .unwrap();

    assert(result == true, 'Verify true');
    assert(end_block_number == TEST_END_BLOCK_NUMBER, 'Wrong end block');

    let (latest_block_number, latest_state_root, latest_block_hash) =
        katana_dispatcher.get_latest_state();
    assert(latest_block_number == TEST_BLOCK_NUMBER, 'Wrong latest block number');
    assert(latest_state_root == TEST_STATE_ROOT, 'Wrong latest state root');
    assert(latest_block_hash == TEST_BLOCK_HASH, 'Wrong latest block hash');

    assert(
        storage_commitment_dispatcher.is_registered(TEST_STORAGE_COMMITMENT),
        'Commitment not registered',
    );
}

#[test]
#[should_panic(expected: 'Fork block mismatch')]
fn test_verify_and_update_state_rejects_wrong_fork_block_policy() {
    let registry_address = deploy_mock_registry();
    let (katana_address, _) = deploy_katana_tee_and_storage_commitment_registry(
        registry_address, TEST_FORK_PROVIDER_URL_WORD, TEST_FORK_PROVIDER_URL_LEN,
    );
    let attestation_config_contract = deploy_mock_attestation_config(TEST_FORK_BLOCK_NUMBER + 1);

    let katana_dispatcher = IKatanaTeeDispatcher { contract_address: katana_address };
    let sp1_proof: Array<felt252> = array![];

    katana_dispatcher
        .verify_and_update_state(
            sp1_proof,
            TEST_STATE_ROOT,
            TEST_BLOCK_HASH,
            TEST_BLOCK_NUMBER,
            attestation_config_contract,
            TEST_SHARD_ID,
        )
        .unwrap();
}

#[test]
#[should_panic(expected: 'Args hash mismatch')]
fn test_verify_and_update_state_rejects_wrong_fork_provider_policy() {
    let registry_address = deploy_mock_registry();
    let (katana_address, _) = deploy_katana_tee_and_storage_commitment_registry(
        registry_address, WRONG_FORK_PROVIDER_URL_WORD, WRONG_FORK_PROVIDER_URL_LEN,
    );
    let attestation_config_contract = deploy_mock_attestation_config(TEST_FORK_BLOCK_NUMBER);

    let katana_dispatcher = IKatanaTeeDispatcher { contract_address: katana_address };
    let sp1_proof: Array<felt252> = array![];

    katana_dispatcher
        .verify_and_update_state(
            sp1_proof,
            TEST_STATE_ROOT,
            TEST_BLOCK_HASH,
            TEST_BLOCK_NUMBER,
            attestation_config_contract,
            TEST_SHARD_ID,
        )
        .unwrap();
}
