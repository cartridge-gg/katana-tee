pub mod katana_report_utils;
use amd_tee_registry::byte_utils::Bytes48;
use amd_tee_registry::tee_types::VerifierJournal;
use starknet::ContractAddress;

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
    ///
    /// `fork_provider_url` and `fork_block_number` are passed in calldata so the
    /// contract can recompute the expected args hash on-chain. The caller cannot
    /// lie about these values because the recomputed hash must match
    /// `report_data[32..64]` attested by the TEE hardware.
    ///
    /// Returns (success, end_block_number) where end_block_number comes from SP1 journal.
    fn verify_and_update_state(
        ref self: TContractState,
        sp1_proof: Array<felt252>,
        state_root: felt252,
        block_hash: felt252,
        block_number: u64,
        fork_provider_url: ByteArray,
        fork_block_number: u64,
    ) -> Result<(bool, u64), felt252>;

    /// Get the AMD TEE Registry contract address.
    fn get_registry_address(self: @TContractState) -> ContractAddress;

    /// Get the latest verified sequencer state.
    fn get_latest_state(self: @TContractState) -> (u64, felt252, felt252);

    /// Get the measurement.
    fn get_measurement(self: @TContractState) -> Bytes48;
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
    }

    #[constructor]
    fn constructor(
        ref self: ContractState,
        registry_address: ContractAddress,
        storage_commitment_registry: ContractAddress,
        measurement: Bytes48,
    ) {
        self.registry_address.write(registry_address);
        self.storage_commitment_registry.write(storage_commitment_registry);
        self.measurement.write(measurement);
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
            fork_provider_url: ByteArray,
            fork_block_number: u64,
        ) -> Result<(bool, u64), felt252> {
            let registry = IAMDTeeRegistryDispatcher {
                contract_address: self.registry_address.read(),
            };
            match registry.verify_sp1_proof(sp1_proof) {
                Result::Ok(journal) => {
                    let raw_report = RawAttestationReport { raw: journal.raw_report };

                    let measurement = raw_report.measurement();
                    assert(measurement == self.get_measurement(), 'Measurement mismatch');

                    assert(
                        journal.fork_block_number == fork_block_number,
                        'Fork block mismatch',
                    );

                    // Recompute expected args hash from calldata — the caller cannot
                    // lie because the result must match report_data[32..64] attested
                    // by TEE hardware.
                    let expected_args_hash = compute_katana_args_hash(
                        @fork_provider_url, fork_block_number,
                    );

                    let report_data = raw_report.report_data();
                    verify_katana_report_data(
                        report_data,
                        state_root,
                        block_hash,
                        fork_block_number,
                        journal.events_commitment,
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
    }
}
