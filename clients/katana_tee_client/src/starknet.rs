//! Starknet contract I/O for Katana TEE.
//!
//! This module contains the minimal Starknet JSON-RPC + account invocation helpers needed by the
//! CLI to:
//! - read the registry address from the `katana_tee` contract
//! - invoke `verify_and_update_state` on the `katana_tee` contract

use crate::Error;
use starknet_rust_accounts::{Account, ExecutionEncoding, SingleOwnerAccount};
use starknet_rust_core::types::{BlockId, BlockTag, Call, Felt, FunctionCall};
use starknet_rust_core::utils::get_selector_from_name;
use starknet_rust_providers::jsonrpc::{HttpTransport, JsonRpcClient};
use starknet_rust_providers::Provider;
use starknet_rust_signers::{LocalWallet, SigningKey};
use url::Url;

/// A convenient account type alias for this crate's CLI.
pub type KatanaAccount = SingleOwnerAccount<JsonRpcClient<HttpTransport>, LocalWallet>;

/// Build a `SingleOwnerAccount` from a Starknet RPC URL + account credentials.
///
/// This fetches the chain ID from the RPC to avoid requiring users to specify it.
pub async fn build_single_owner_account(
    rpc_url: &str,
    account_address: Felt,
    private_key: Felt,
    encoding: ExecutionEncoding,
) -> Result<KatanaAccount, Error> {
    let url = Url::parse(rpc_url).map_err(|e| {
        Error::Registry(amd_tee_registry_client::Error::Starknet(format!(
            "Invalid Starknet RPC URL: {e}"
        )))
    })?;
    let transport = HttpTransport::new(url);
    let provider = JsonRpcClient::new(transport);

    let chain_id = provider.chain_id().await.map_err(|e| {
        Error::Registry(amd_tee_registry_client::Error::Starknet(format!(
            "Failed to fetch chain_id: {e}"
        )))
    })?;

    let signer = LocalWallet::from(SigningKey::from_secret_scalar(private_key));
    Ok(SingleOwnerAccount::new(
        provider,
        signer,
        account_address,
        chain_id,
        encoding,
    ))
}

/// Minimal Starknet client for interacting with the `katana_tee` contract.
#[derive(Debug, Clone)]
pub struct KatanaTeeStarknetClient {
    provider: JsonRpcClient<HttpTransport>,
    contract_address: Felt,
}

impl KatanaTeeStarknetClient {
    /// Create a new client from RPC URL and contract address.
    pub fn new(rpc_url: &str, contract_address: Felt) -> Result<Self, Error> {
        let url = Url::parse(rpc_url).map_err(|e| {
            Error::Registry(amd_tee_registry_client::Error::Starknet(format!(
                "Invalid Starknet RPC URL: {e}"
            )))
        })?;
        let transport = HttpTransport::new(url);
        let provider = JsonRpcClient::new(transport);
        Ok(Self {
            provider,
            contract_address,
        })
    }

    /// The `katana_tee` contract address.
    pub fn contract_address(&self) -> Felt {
        self.contract_address
    }

    /// Read the registry address configured in the `katana_tee` contract.
    pub async fn get_registry_address(&self) -> Result<Felt, Error> {
        let selector = get_selector_from_name("get_registry_address").map_err(|e| {
            Error::Registry(amd_tee_registry_client::Error::Starknet(format!(
                "Selector error: {e}"
            )))
        })?;

        let call = FunctionCall {
            contract_address: self.contract_address,
            entry_point_selector: selector,
            calldata: vec![],
        };

        let result = self
            .provider
            .call(&call, BlockId::Tag(BlockTag::Latest))
            .await
            .map_err(|e| {
                Error::Registry(amd_tee_registry_client::Error::Starknet(format!(
                    "RPC call failed: {e}"
                )))
            })?;

        if result.len() != 1 {
            return Err(Error::Registry(amd_tee_registry_client::Error::Starknet(
                format!(
                    "Unexpected get_registry_address return length: {}",
                    result.len()
                ),
            )));
        }

        Ok(result[0])
    }

    /// Invoke `verify_and_update_state` on the `katana_tee` contract.
    ///
    /// `fork_provider_url` and `fork_block_number` are passed in calldata so the
    /// contract can recompute the expected args hash on-chain. The caller cannot
    /// lie because the result must match `report_data[32..64]` attested by TEE.
    ///
    /// Returns the transaction hash.
    pub async fn verify_and_update_state(
        &self,
        account: &KatanaAccount,
        sp1_proof: Vec<Felt>,
        state_root: Felt,
        block_hash: Felt,
        block_number: u64,
        fork_provider_url: &str,
        fork_block_number: u64,
    ) -> Result<Felt, Error> {
        let selector = get_selector_from_name("verify_and_update_state").map_err(|e| {
            Error::Registry(amd_tee_registry_client::Error::Starknet(format!(
                "Selector error: {e}"
            )))
        })?;

        // Encode fork_provider_url as Cairo ByteArray:
        // [num_full_words, ...full_words (31-byte chunks as felt), pending_word, pending_len]
        let url_bytes = fork_provider_url.as_bytes();
        let full_chunks = url_bytes.len() / 31;
        let pending_len = url_bytes.len() % 31;

        let mut calldata: Vec<Felt> = Vec::with_capacity(sp1_proof.len() + full_chunks + 8);
        calldata.push(Felt::from(sp1_proof.len() as u64));
        calldata.extend_from_slice(&sp1_proof);
        calldata.push(state_root);
        calldata.push(block_hash);
        calldata.push(Felt::from(block_number));

        // ByteArray serialization
        calldata.push(Felt::from(full_chunks as u64));
        for i in 0..full_chunks {
            let chunk = &url_bytes[i * 31..(i + 1) * 31];
            calldata.push(Felt::from_bytes_be_slice(chunk));
        }
        if pending_len > 0 {
            let pending = &url_bytes[full_chunks * 31..];
            calldata.push(Felt::from_bytes_be_slice(pending));
        } else {
            calldata.push(Felt::ZERO);
        }
        calldata.push(Felt::from(pending_len as u64));

        calldata.push(Felt::from(fork_block_number));

        let call = Call {
            to: self.contract_address,
            selector,
            calldata,
        };

        let res = account.execute_v3(vec![call]).send().await.map_err(|e| {
            Error::Registry(amd_tee_registry_client::Error::Starknet(format!(
                "Transaction send failed: {e}"
            )))
        })?;

        Ok(res.transaction_hash)
    }
}
