pub mod katana_report_utils;
use amd_tee_registry::byte_utils::Bytes48;
use amd_tee_registry::tee_types::VerifierJournal;
use starknet::ContractAddress;

#[starknet::interface]
pub trait IShardAttestationConfig<TContractState> {
    fn get_shard_attestation_fork_block_number(
        self: @TContractState, shard_id: felt252,
    ) -> u64;
}

/// Interface for the Katana TEE contract.
#[starknet::interface]
pub trait IKatanaTee<TContractState> {
    /// Verify an SP1 proof by calling the AMD TEE Registry contract.
    /// Returns the public inputs if verification succeeds.
    fn verify_sp1_proof(
        self: @TContractState, sp1_proof: Array<felt252>,
    ) -> Result<VerifierJournal, felt252>;

    /// Verify proof and update the latest verified sequencer state.
    /// Also registers the storage commitment from the SP1 journal.
    /// Returns (success, end_block_number) where end_block_number comes from SP1 journal.
    fn verify_and_update_state(
        ref self: TContractState,
        sp1_proof: Array<felt252>,
        state_root: felt252,
        block_hash: felt252,
        block_number: u64,
        attestation_config_contract: ContractAddress,
        shard_id: felt252,
    ) -> Result<(bool, u64), felt252>;

    /// Get the AMD TEE Registry contract address.
    fn get_registry_address(self: @TContractState) -> ContractAddress;

    /// Get the latest verified sequencer state.
    fn get_latest_state(self: @TContractState) -> (u64, felt252, felt252);

    /// Get the measurement.
    fn get_measurement(self: @TContractState) -> Bytes48;

    /// Get the configured fork provider URL used for on-chain args-hash recomputation.
    fn get_fork_provider_url(self: @TContractState) -> ByteArray;
}

/// Katana TEE contract that delegates SP1 proof verification to the AMD TEE Registry.
#[starknet::contract]
pub mod KatanaTee {
    use amd_tee_registry::byte_utils::Bytes48;
    use amd_tee_registry::tee_registry::{IAMDTeeRegistryDispatcher, IAMDTeeRegistryDispatcherTrait};
    use amd_tee_registry::tee_types::{
        RawAttestationReport, RawAttestationReportTrait, VerifierJournal,
    };
    use starknet::ContractAddress;
    use starknet::storage::{StoragePointerReadAccess, StoragePointerWriteAccess};
    use storage_commitment::{IStorageCommitmentDispatcher, IStorageCommitmentDispatcherTrait};
    use crate::{IShardAttestationConfigDispatcher, IShardAttestationConfigDispatcherTrait};
    use crate::katana_report_utils::{compute_katana_args_hash, verify_katana_report_data};

    #[storage]
    struct Storage {
        /// Address of the AMD TEE Registry contract
        registry_address: ContractAddress,
        /// Latest verified state root
        latest_state_root: felt252,
        /// Latest verified block hash
        latest_block_hash: felt252,
        /// Latest verified block number
        latest_block_number: u64,
        /// Storage commitment registry contract address
        storage_commitment_registry: ContractAddress,
        /// Expected TEE measurement
        measurement: Bytes48,
        /// Fork provider URL committed at deploy time and used in canonical args-hash recomputation.
        fork_provider_url: ByteArray,
    }


    #[constructor]
    fn constructor(
        ref self: ContractState,
        registry_address: ContractAddress,
        storage_commitment_registry: ContractAddress,
        measurement: Bytes48,
        fork_provider_url: ByteArray,
    ) {
        assert(fork_provider_url.len() != 0, 'Fork provider required');
        self.registry_address.write(registry_address);
        self.storage_commitment_registry.write(storage_commitment_registry);
        self.measurement.write(measurement);
        self.fork_provider_url.write(fork_provider_url);
    }

    fn load_expected_attestation_policy(
        self: @ContractState,
        attestation_config_contract: ContractAddress,
        shard_id: felt252,
    ) -> (u64, u256) {
        let attestation_config = IShardAttestationConfigDispatcher {
            contract_address: attestation_config_contract,
        };
        let expected_fork_block_number = attestation_config
            .get_shard_attestation_fork_block_number(shard_id);
        let fork_provider_url = self.fork_provider_url.read();
        let expected_args_hash = compute_katana_args_hash(
            @fork_provider_url, expected_fork_block_number,
        );
        (expected_fork_block_number, expected_args_hash)
    }

    #[abi(embed_v0)]
    impl KatanaTeeImpl of super::IKatanaTee<ContractState> {
        /// Verify an SP1 proof by forwarding to the AMD TEE Registry.
        fn verify_sp1_proof(
            self: @ContractState, sp1_proof: Array<felt252>,
        ) -> Result<VerifierJournal, felt252> {
            let registry = IAMDTeeRegistryDispatcher {
                contract_address: self.registry_address.read(),
            };
            registry.verify_sp1_proof(sp1_proof)
        }

        /// Verify proof, validate report data, and update the latest state.
        fn verify_and_update_state(
            ref self: ContractState,
            sp1_proof: Array<felt252>,
            state_root: felt252,
            block_hash: felt252,
            block_number: u64,
            attestation_config_contract: ContractAddress,
            shard_id: felt252,
        ) -> Result<(bool, u64), felt252> {
            let registry = IAMDTeeRegistryDispatcher {
                contract_address: self.registry_address.read(),
            };
            match registry.verify_sp1_proof(sp1_proof) {
                Result::Ok(journal) => {
                    let raw_report = RawAttestationReport { raw: journal.raw_report };
                    let (expected_fork_block_number, expected_args_hash) = load_expected_attestation_policy(
                        @self, attestation_config_contract, shard_id,
                    );

                    let measurement = raw_report.measurement();
                    assert(measurement == self.get_measurement(), 'Measurement mismatch');

                    let proven_events_commitment = journal.events_commitment;
                    assert(
                        journal.fork_block_number == expected_fork_block_number,
                        'Fork block mismatch',
                    );

                    let report_data = raw_report.report_data();
                    verify_katana_report_data(
                        report_data,
                        state_root,
                        block_hash,
                        expected_fork_block_number,
                        proven_events_commitment,
                        expected_args_hash,
                    );

                    self.latest_state_root.write(state_root);
                    self.latest_block_hash.write(block_hash);
                    self.latest_block_number.write(block_number);

                    IStorageCommitmentDispatcher {
                        contract_address: self.storage_commitment_registry.read(),
                    }
                        .register_verified_commitment(journal.storage_commitment);

                    Result::Ok((true, journal.end_block_number))
                },
                Result::Err(error) => Result::Err(error),
            }
        }

        /// Get the AMD TEE Registry contract address.
        fn get_registry_address(self: @ContractState) -> ContractAddress {
            self.registry_address.read()
        }

        /// Get the latest verified sequencer state.
        fn get_latest_state(self: @ContractState) -> (u64, felt252, felt252) {
            (
                self.latest_block_number.read(),
                self.latest_state_root.read(),
                self.latest_block_hash.read(),
            )
        }

        /// Get the measurement.
        fn get_measurement(self: @ContractState) -> Bytes48 {
            self.measurement.read()
        }

        fn get_fork_provider_url(self: @ContractState) -> ByteArray {
            self.fork_provider_url.read()
        }
    }
}
