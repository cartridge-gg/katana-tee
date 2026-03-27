use crate::tee_types::DecodedJournal;

#[starknet::interface]
pub trait IAMDTeeRegistry<TContractState> {
    /// Verify a SP1 proof.
    fn verify_sp1_proof(
        ref self: TContractState, sp1_proof: Array<felt252>,
    ) -> Result<DecodedJournal, felt252>;
}

#[starknet::contract]
pub mod AMDTEERegistry {
    use core::traits::TryInto;
    use starknet::storage::{StoragePointerReadAccess, StoragePointerWriteAccess};
    use starknet::syscalls::library_call_syscall;
    use starknet::{ClassHash, ContractAddress, SyscallResultTrait, get_block_timestamp};
    use crate::cert_cache::CertCacheComponent;
    use crate::journal_decode::decode_verifier_journal;
    use crate::tee_types::{DecodedJournal, ProcessorType, VerificationResult};

    // Embed the certificate cache component
    component!(path: CertCacheComponent, storage: cert_cache, event: CertCacheEvent);

    // Expose CertCache external functions
    #[abi(embed_v0)]
    impl CertCacheImpl = CertCacheComponent::CertCacheImpl<ContractState>;

    // Access to internal functions
    impl CertCacheInternalImpl = CertCacheComponent::InternalImpl<ContractState>;

    #[storage]
    struct Storage {
        balance: felt252,
        verifier_class_hash: ClassHash,
        sp1_program_id: u256,
        max_time_diff: u64,
        #[substorage(v0)]
        cert_cache: CertCacheComponent::Storage,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        #[flat]
        CertCacheEvent: CertCacheComponent::Event,
    }

    #[constructor]
    fn constructor(
        ref self: ContractState,
        verifier_class_hash: ClassHash,
        sp1_program_id: u256,
        max_time_diff: u64,
        trusted_certs: Span<u256>,
        processor_models: Span<ProcessorType>,
        root_certs: Span<u256>,
    ) {
        self.verifier_class_hash.write(verifier_class_hash);
        self.sp1_program_id.write(sp1_program_id);
        self.max_time_diff.write(max_time_diff);

        // Initialize trusted intermediate certificates
        self.cert_cache.initialize_trusted_certs(trusted_certs);

        // Initialize root certificates for each processor model
        assert!(processor_models.len() == root_certs.len(), "Array length mismatch");

        for (root_cert, processor_model) in core::iter::zip(root_certs, processor_models) {
            self.cert_cache.set_root_cert(*processor_model, *root_cert);
        }
    }

    #[abi(embed_v0)]
    impl AMDTEERegistryImpl of super::IAMDTeeRegistry<ContractState> {
        fn verify_sp1_proof(
            ref self: ContractState, sp1_proof: Array<felt252>,
        ) -> Result<DecodedJournal, felt252> {
            let mut result_serialized = library_call_syscall(
                self.verifier_class_hash.read(),
                selector!("verify_sp1_groth16_proof_bn254"),
                sp1_proof.span(),
            )
                .unwrap_syscall();

            let result = Serde::<
                Result<(u256, Span<u256>), felt252>,
            >::deserialize(ref result_serialized)
                .unwrap();

            match result {
                Result::Ok((
                    vk, public_inputs,
                )) => {
                    assert(vk == self.sp1_program_id.read(), 'Wrong program');

                    let journal = decode_verifier_journal(public_inputs);

                    if journal.attestation.result != VerificationResult::Success {
                        return Result::Err('SP1 program returned an error');
                    }
                    if journal.attestation.trusted_certs_prefix_len == 0 {
                        return Result::Err('Trusted certs len must be >= 1');
                    }

                    let processor_model: ProcessorType = processor_type_from_u8(
                        journal.attestation.processor_model,
                    )?;

                    let expected_root_cert = self.cert_cache.get_root_cert(processor_model);
                    if expected_root_cert == 0 {
                        return Result::Err('Root cert not set for processor');
                    }

                    let certs: Span<u256> = journal.attestation.certs.span();
                    let trusted_len: usize = journal.attestation.trusted_certs_prefix_len.into();
                    if certs.len() < trusted_len {
                        return Result::Err('Certificates array too short');
                    }
                    if *certs.at(0) != expected_root_cert {
                        return Result::Err('Root certificate mismatch');
                    }

                    for cert_hash in certs.slice(1, trusted_len - 1) {
                        if !self.cert_cache.is_trusted_intermediate_cert(*cert_hash) {
                            return Result::Err('Untrusted intermediate cert');
                        }
                    }

                    let _current_timestamp = get_block_timestamp();
                    // if journal.attestation.timestamp > current_timestamp {
                    //     return Result::Err('Timestamp is in the future');
                    // }
                    // if current_timestamp - journal.attestation.timestamp > self.max_time_diff.read() {
                    //     return Result::Err('Timestamp is too old');
                    // }

                    let trusted_len_u32: u32 = journal.attestation.trusted_certs_prefix_len.into();
                    self.cert_cache.cache_new_cert(certs, trusted_len_u32);

                    Result::Ok(journal)
                },
                Result::Err(error) => {
                    Result::Err(error)
                },
            }
        }
    }

    fn processor_type_from_u8(value: u8) -> Result<ProcessorType, felt252> {
        match value {
            0 => Result::Ok(ProcessorType::Milan),
            1 => Result::Ok(ProcessorType::Genoa),
            2 => Result::Ok(ProcessorType::Bergamo),
            3 => Result::Ok(ProcessorType::Siena),
            _ => Result::Err('Invalid processor model'),
        }
    }
}
