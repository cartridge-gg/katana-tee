pub mod katana_report_utils;
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
    /// Returns (success, end_block_number) where end_block_number comes from SP1 journal.
    ///
    /// The fields recompute the v1 appchain report_data commitment; `prev_block_number`
    /// is a felt because it carries Felt::MAX as the genesis sentinel.
    fn verify_and_update_state(
        ref self: TContractState,
        sp1_proof: Array<felt252>,
        prev_state_root: felt252,
        state_root: felt252,
        prev_block_hash: felt252,
        block_hash: felt252,
        prev_block_number: felt252,
        block_number: u64,
        messages_commitment: felt252,
    ) -> Result<(bool, u64), felt252>;

    /// Get the AMD TEE Registry contract address.
    fn get_registry_address(self: @TContractState) -> ContractAddress;

    /// Get the latest verified sequencer state.
    fn get_latest_state(self: @TContractState) -> (u64, felt252, felt252);

    /// Get the pinned katana_tee_config_hash.
    fn get_katana_tee_config_hash(self: @TContractState) -> felt252;
}

/// Katana TEE contract that delegates SP1 proof verification to the AMD TEE Registry.
#[starknet::contract]
pub mod KatanaTee {
    use amd_tee_registry::journal_decode::decode_verifier_journal;
    use amd_tee_registry::tee_registry::{IAMDTeeRegistryDispatcher, IAMDTeeRegistryDispatcherTrait};
    use amd_tee_registry::tee_types::{
        RawAttestationReport, RawAttestationReportTrait, VerifierJournal,
    };
    use starknet::ContractAddress;
    use starknet::storage::{StoragePointerReadAccess, StoragePointerWriteAccess};
    use storage_commitment::{IStorageCommitmentDispatcher, IStorageCommitmentDispatcherTrait};
    use crate::katana_report_utils::verify_katana_report_data;

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
        /// Pinned katana_tee_config_hash. Attestations must carry this value in the
        /// second half of report_data (it binds the node's chain config: version,
        /// chain id, fee token). Set at deploy time.
        katana_tee_config_hash: felt252,
    }


    #[constructor]
    fn constructor(
        ref self: ContractState,
        registry_address: ContractAddress,
        storage_commitment_registry: ContractAddress,
        katana_tee_config_hash: felt252,
    ) {
        self.registry_address.write(registry_address);
        self.storage_commitment_registry.write(storage_commitment_registry);
        self.katana_tee_config_hash.write(katana_tee_config_hash);
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
            prev_state_root: felt252,
            state_root: felt252,
            prev_block_hash: felt252,
            block_hash: felt252,
            prev_block_number: felt252,
            block_number: u64,
            messages_commitment: felt252,
        ) -> Result<(bool, u64), felt252> {
            let registry = IAMDTeeRegistryDispatcher {
                contract_address: self.registry_address.read(),
            };
            match registry.verify_sp1_proof(sp1_proof) {
                Result::Ok(journal) => {
                    let raw_report = RawAttestationReport { raw: journal.raw_report };
                    let report_data = raw_report.report_data();
                    verify_katana_report_data(
                        report_data,
                        prev_state_root,
                        state_root,
                        prev_block_hash,
                        block_hash,
                        prev_block_number,
                        block_number.into(),
                        messages_commitment,
                        self.katana_tee_config_hash.read(),
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

        /// Get the pinned katana_tee_config_hash.
        fn get_katana_tee_config_hash(self: @ContractState) -> felt252 {
            self.katana_tee_config_hash.read()
        }
    }
}
