//! Test-only mock of the Garaga SP1 Groth16 verifier.
//!
//! **NOT FOR PRODUCTION.** It performs NO cryptographic verification. It simply
//! echoes back a `Result<(vk, public_inputs), error>` that is encoded directly in
//! its calldata, so tests can drive every branch of
//! `AMDTEERegistry::verify_sp1_proof` hermetically — the `vk == sp1_program_id`
//! gate, the journal handling, and the cert-chain checks — without a real Groth16
//! proof or the on-chain Garaga class.
//!
//! It is invoked the same way the real verifier is: via `library_call_syscall`
//! with the `verify_sp1_groth16_proof_bn254` selector, returning
//! `Result<(u256, Span<u256>), felt252>`.
//!
//! Calldata layout (the `full_proof` span the registry forwards), all `felt252`:
//!   `[ is_ok, vk_low, vk_high, err_code, n_pub, p0_low, p0_high, p1_low, p1_high, ... ]`
//! - `is_ok == 0` -> returns `Err(err_code)`
//! - `is_ok != 0` -> returns `Ok((u256{vk_low, vk_high}, [n_pub u256 public inputs]))`

#[starknet::interface]
pub trait IMockVerifier<TContractState> {
    fn verify_sp1_groth16_proof_bn254(
        self: @TContractState, full_proof: Span<felt252>,
    ) -> Result<(u256, Span<u256>), felt252>;
}

#[starknet::contract]
pub mod MockGaragaVerifier {
    #[storage]
    struct Storage {}

    #[abi(embed_v0)]
    impl MockVerifierImpl of super::IMockVerifier<ContractState> {
        fn verify_sp1_groth16_proof_bn254(
            self: @ContractState, mut full_proof: Span<felt252>,
        ) -> Result<(u256, Span<u256>), felt252> {
            let is_ok = *full_proof.pop_front().unwrap();
            let vk_low = *full_proof.pop_front().unwrap();
            let vk_high = *full_proof.pop_front().unwrap();
            let err_code = *full_proof.pop_front().unwrap();

            if is_ok == 0 {
                return Result::Err(err_code);
            }

            let vk = u256 { low: vk_low.try_into().unwrap(), high: vk_high.try_into().unwrap() };

            let n: u32 = (*full_proof.pop_front().unwrap()).try_into().unwrap();
            let mut public_inputs: Array<u256> = array![];
            let mut i: u32 = 0;
            while i < n {
                let lo = *full_proof.pop_front().unwrap();
                let hi = *full_proof.pop_front().unwrap();
                public_inputs
                    .append(u256 { low: lo.try_into().unwrap(), high: hi.try_into().unwrap() });
                i += 1;
            }

            Result::Ok((vk, public_inputs.span()))
        }
    }
}
