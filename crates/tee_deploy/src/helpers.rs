use std::error::Error as StdError;
use std::str::FromStr;
use std::sync::Arc;

use starknet_rust::accounts::{ExecutionEncoding, SingleOwnerAccount};
use starknet_rust::core::types::Felt;
use starknet_rust::providers::{JsonRpcClient, Provider, Url, jsonrpc::HttpTransport};
use starknet_rust::signers::{LocalWallet, SigningKey};

type BoxError = Box<dyn StdError + Send + Sync>;

pub type StarknetProvider = Arc<JsonRpcClient<HttpTransport>>;
pub type StarknetAccount = SingleOwnerAccount<StarknetProvider, LocalWallet>;

pub const POLLING_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

/// Errors from Starknet setup, argument parsing, and transaction watching.
#[derive(Debug, thiserror::Error)]
pub enum StarknetError {
    #[error("placeholder value used for {field}: '{input}'. Replace it with a real hex value")]
    PlaceholderValue {
        field: &'static str,
        input: String,
    },

    #[error("invalid hex for {field}: '{input}'")]
    InvalidHex {
        field: &'static str,
        input: String,
        #[source]
        source: BoxError,
    },

    #[error("invalid provider URL")]
    InvalidUrl(#[source] BoxError),

    #[error("failed to fetch chain ID")]
    ChainId(#[source] BoxError),

    #[error("selector computation failed")]
    Selector(#[source] BoxError),

    #[error("on-chain call failed")]
    CallFailed(#[source] BoxError),

    #[error("transaction {tx_hash:#x} reverted: {reason}")]
    TransactionReverted { tx_hash: Felt, reason: String },

    #[error("provider unreachable after {attempts} errors watching tx {tx_hash:#x}")]
    ProviderUnreachable { attempts: u32, tx_hash: Felt },
}

pub fn parse_hex_arg(input: &str, field: &'static str) -> Result<Felt, StarknetError> {
    validate_hex_arg(input, field)?;
    Felt::from_hex(input).map_err(|e| StarknetError::InvalidHex {
        field,
        input: input.to_string(),
        source: Box::new(e),
    })
}

pub fn validate_hex_arg(input: &str, field: &'static str) -> Result<(), StarknetError> {
    if looks_like_placeholder(input) {
        return Err(StarknetError::PlaceholderValue {
            field,
            input: input.to_string(),
        });
    }

    Felt::from_hex(input)
        .map(|_| ())
        .map_err(|e| StarknetError::InvalidHex {
            field,
            input: input.to_string(),
            source: Box::new(e),
        })
}

pub fn validate_optional_hex_arg(
    input: &Option<String>,
    field: &'static str,
) -> Result<(), StarknetError> {
    if let Some(value) = input {
        validate_hex_arg(value, field)?;
    }
    Ok(())
}

pub async fn setup_provider_and_account(
    provider_url: &str,
    private_key: &str,
    address: &str,
) -> Result<(StarknetProvider, StarknetAccount), StarknetError> {
    let provider = Arc::new(JsonRpcClient::new(HttpTransport::new(
        Url::from_str(provider_url).map_err(|e| StarknetError::InvalidUrl(Box::new(e)))?,
    )));

    let signer = LocalWallet::from_signing_key(SigningKey::from_secret_scalar(parse_hex_arg(
        private_key,
        "--private-key",
    )?));

    let address = parse_hex_arg(address, "--address")?;

    let chain_id = provider
        .chain_id()
        .await
        .map_err(|e| StarknetError::ChainId(Box::new(e)))?;

    let account = SingleOwnerAccount::new(
        provider.clone(),
        signer,
        address,
        chain_id,
        ExecutionEncoding::New,
    );

    Ok((provider, account))
}

/// Wait for a transaction receipt in a confirmed block and surface revert reasons.
pub async fn watch_tx(
    provider: &StarknetProvider,
    transaction_hash: Felt,
    interval: std::time::Duration,
) -> Result<starknet_rust::core::types::TransactionReceiptWithBlockInfo, StarknetError> {
    let mut consecutive_errors: u32 = 0;
    const MAX_CONSECUTIVE_ERRORS: u32 = 30;

    loop {
        match provider.get_transaction_receipt(transaction_hash).await {
            Ok(receipt) if receipt.block.is_block() => {
                if let Some(reason) = receipt.receipt.execution_result().revert_reason() {
                    return Err(StarknetError::TransactionReverted {
                        tx_hash: transaction_hash,
                        reason: reason.to_string(),
                    });
                }
                return Ok(receipt);
            }
            Ok(_) => {
                consecutive_errors = 0;
                tokio::time::sleep(interval).await;
            }
            Err(e) => {
                consecutive_errors += 1;
                if consecutive_errors >= MAX_CONSECUTIVE_ERRORS {
                    return Err(StarknetError::ProviderUnreachable {
                        attempts: MAX_CONSECUTIVE_ERRORS,
                        tx_hash: transaction_hash,
                    });
                }

                if consecutive_errors <= 3 {
                    tracing::debug!(
                        errors = consecutive_errors,
                        "Waiting for receipt for {:#x}: {e}",
                        transaction_hash
                    );
                } else {
                    tracing::warn!(
                        errors = consecutive_errors,
                        "Error fetching receipt for {:#x}: {e}",
                        transaction_hash
                    );
                }

                tokio::time::sleep(interval).await;
            }
        }
    }
}

fn looks_like_placeholder(input: &str) -> bool {
    let trimmed = input.trim();
    trimmed.contains("...")
        || trimmed.eq_ignore_ascii_case("0x...")
        || trimmed.eq_ignore_ascii_case("<private-key>")
        || trimmed.eq_ignore_ascii_case("<address>")
        || trimmed.eq_ignore_ascii_case("changeme")
}
