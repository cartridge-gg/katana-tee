//! Declare and deploy AMDTeeRegistry and KatanaTee on Starknet.
//!
//! Run `scarb build` from repo root first. Before deploy, SP1 program ID is computed
//! via `cargo run -p snp-attest-cli --release -- program-id --sp1` in the SDK dir
//! (unless overridden with --sp1-program-id or --no-fetch-sp1-program-id).

use std::path::Path;
use std::process::Command;
use std::str::FromStr;
use std::sync::Arc;

use super::declare::declare_contract;
use super::deploy;
use crate::helpers::{watch_tx, POLLING_INTERVAL};
use crate::state::DeploymentState;
use anyhow::{Context, Result};
use clap::Args;
use rand::random;
use starknet_core::types::{Call, Felt};
use starknet_core::utils::get_selector_from_name;
use starknet_rust::{
    accounts::{Account, SingleOwnerAccount},
    providers::{jsonrpc::HttpTransport, JsonRpcClient, Provider, Url},
    signers::{LocalWallet, SigningKey},
};
use tracing::{info, warn};

// Self-generated Garaga SP1 v6.1.0 Groth16 verifier, declared on Sepolia.
const GARAGA_CLASS_HASH: &str =
    "0x051908349a7875e0234da7e55cd08492d3c53930deaf851bf284a1cadaad4332";
/// Fallback SP1 program ID (low/high) when snp-attest-cli is not runnable.
/// SP1 v6.1.0 program ID 0x00ed032fe45bc3492eb4f75fcb5c670f6be4a0e152ea8d8dbe56992f0433f65f
/// (high = first 16 bytes, low = last 16 bytes).
const SP1_LOW_FALLBACK: &str = "0x6be4a0e152ea8d8dbe56992f0433f65f";
const SP1_HIGH_FALLBACK: &str = "0x00ed032fe45bc3492eb4f75fcb5c670f";
const MAX_TIME_DIFF: u64 = 86400;
const MILAN_LOW: &str = "326103188097639633505521426987620764621";
const MILAN_HIGH: &str = "140650959549381881311165088169387222174";
const GENOA_LOW: &str = "122279190577630630319986709203695547121";
const GENOA_HIGH: &str = "101548849195620556729999786649524856654";

#[derive(Args, Debug, Clone)]
pub struct InitArgs {
    /// Private key for signing transactions
    #[arg(short, long, env = "PRIVATE_KEY")]
    pub private_key: String,

    /// Account address
    #[arg(short, long, env = "ACCOUNT_ADDRESS")]
    pub address: String,

    /// RPC provider URL
    #[arg(short = 'u', long, env = "PROVIDER_URL")]
    pub provider_url: String,

    /// Salt for deployment (optional; random if not set)
    #[arg(long)]
    pub salt: Option<String>,

    /// Path to AMDTeeRegistry Sierra contract class JSON (run `scarb build` from repo root first)
    #[arg(
        long,
        default_value = "target/dev/amd_tee_registry_AMDTEERegistry.contract_class.json"
    )]
    pub amd_contract_class_path: String,

    /// Path to KatanaTee Sierra contract class JSON (run `scarb build` from repo root first)
    #[arg(
        long,
        default_value = "target/dev/katana_tee_KatanaTee.contract_class.json"
    )]
    pub katana_contract_class_path: String,

    /// Path to StorageCommitment Sierra contract class JSON (run `scarb build` from repo root first)
    #[arg(
        long,
        default_value = "target/dev/storage_commitment_StorageCommitment.contract_class.json"
    )]
    pub storage_commitment_contract_class_path: String,

    /// SP1 program ID (onchain bytes32) as hex; if unset, computed via snp-attest-cli in SDK dir
    #[arg(long)]
    pub sp1_program_id: Option<String>,

    /// Do not run snp-attest-cli to fetch SP1 program ID; use fallback (requires --sp1-program-id or fallback constants)
    #[arg(long)]
    pub no_fetch_sp1_program_id: bool,

    /// Path to amd-sev-snp-attestation-sdk (for `cargo run -p snp-attest-cli -- program-id --sp1`). Default: ./crates/amd-sev-snp-attestation-sdk
    #[arg(long)]
    pub sdk_path: Option<String>,
}

pub async fn run_init(args: InitArgs) -> Result<()> {
    let provider = Arc::new(JsonRpcClient::new(HttpTransport::new(
        Url::from_str(&args.provider_url).context("invalid provider URL")?,
    )));

    let signer: LocalWallet = LocalWallet::from_signing_key(SigningKey::from_secret_scalar(
        Felt::from_hex(&args.private_key).context("invalid private key")?,
    ));

    let address = Felt::from_hex(&args.address).context("invalid address")?;

    let chain_id = provider
        .chain_id()
        .await
        .context("failed to fetch chain id")?;

    let encoding = starknet_rust::accounts::ExecutionEncoding::New;
    let mut account: SingleOwnerAccount<Arc<JsonRpcClient<HttpTransport>>, LocalWallet> =
        SingleOwnerAccount::new(provider.clone(), signer, address, chain_id, encoding);
    // Use pre-confirmed block for nonce to avoid nonce mismatch after waiting for tx confirmation
    account.set_block_id(starknet_core::types::BlockId::Tag(
        starknet_core::types::BlockTag::PreConfirmed,
    ));

    // Declare AMDTeeRegistry
    let (maybe_tx, amd_class_hash) = declare_contract(&account, &args.amd_contract_class_path)
        .await
        .map_err(|e| anyhow::anyhow!("declare AMDTeeRegistry: {}", e))?;

    if let Some(tx) = maybe_tx {
        info!("Waiting for AMDTeeRegistry declaration to be confirmed...");
        let _ = watch_tx(&provider, tx.transaction_hash, POLLING_INTERVAL).await;
    }

    // Declare KatanaTee
    let (maybe_tx, katana_class_hash) =
        declare_contract(&account, &args.katana_contract_class_path)
            .await
            .map_err(|e| anyhow::anyhow!("declare KatanaTee: {}", e))?;

    if let Some(ref tx) = maybe_tx {
        info!("Waiting for KatanaTee declaration to be confirmed...");
        let _ = watch_tx(&provider, tx.transaction_hash, POLLING_INTERVAL).await;
    }

    // Declare StorageCommitment
    let (maybe_tx, storage_commitment_class_hash) =
        declare_contract(&account, &args.storage_commitment_contract_class_path)
            .await
            .map_err(|e| anyhow::anyhow!("declare StorageCommitment: {}", e))?;

    if let Some(ref tx) = maybe_tx {
        info!("Waiting for StorageCommitment declaration to be confirmed...");
        let _ = watch_tx(&provider, tx.transaction_hash, POLLING_INTERVAL).await;
    }

    info!(
        "Declared contracts: AMDTeeRegistry {:?}, KatanaTee {:?}, StorageCommitment {:?}",
        amd_class_hash, katana_class_hash, storage_commitment_class_hash
    );

    let salt = if let Some(ref salt_hex) = args.salt {
        Felt::from_hex(salt_hex).context("invalid salt hex format")?
    } else {
        let random_bytes: [u8; 32] = random();
        let hex_string = format!(
            "0x{}",
            random_bytes
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>()
        );
        Felt::from_hex_unchecked(&hex_string)
    };
    info!("Using salt for deployment: {:#064x}", salt);

    let (sp1_low, sp1_high) = resolve_sp1_program_id(&args)?;
    info!(
        "SP1 program ID: low {:#064x}, high {:#064x}",
        sp1_low, sp1_high
    );

    // AMDTeeRegistry constructor calldata:
    // verifier_class_hash, sp1_program_id (low, high), max_time_diff,
    // trusted_certs (len 0), processor_models (len 2: Milan=0, Genoa=1), root_certs (len 2: milan u256, genoa u256)
    let amd_calldata = vec![
        Felt::from_hex(GARAGA_CLASS_HASH).unwrap(),
        sp1_low,
        sp1_high,
        Felt::from(MAX_TIME_DIFF),
        Felt::ZERO,       // trusted_certs len
        Felt::from(2u64), // processor_models len
        Felt::ZERO,       // Milan
        Felt::ONE,        // Genoa
        Felt::from(2u64), // root_certs len
        Felt::from_dec_str(MILAN_LOW).unwrap(),
        Felt::from_dec_str(MILAN_HIGH).unwrap(),
        Felt::from_dec_str(GENOA_LOW).unwrap(),
        Felt::from_dec_str(GENOA_HIGH).unwrap(),
    ];

    let (maybe_tx, amd_address) =
        deploy::deploy(&account, amd_class_hash, amd_calldata, Some(salt), false)
            .await
            .map_err(|e| anyhow::anyhow!("deploy AMDTeeRegistry: {}", e))?;

    info!(
        "Deployed AMDTeeRegistry: {:?}, tx_hash: {:?}",
        amd_address, maybe_tx
    );

    if let Some(ref tx_result) = maybe_tx {
        info!("Waiting for AMDTeeRegistry deployment to be confirmed...");
        let _ = watch_tx(&provider, tx_result.transaction_hash, POLLING_INTERVAL).await;
    }

    // Deploy StorageCommitment (constructor takes deployer address for access control)
    let storage_commitment_calldata = vec![address];

    let (maybe_tx, storage_commitment_address) = deploy::deploy(
        &account,
        storage_commitment_class_hash,
        storage_commitment_calldata,
        Some(salt),
        false,
    )
    .await
    .map_err(|e| anyhow::anyhow!("deploy StorageCommitment: {}", e))?;

    info!(
        "Deployed StorageCommitment: {:?}, tx_hash: {:?}",
        storage_commitment_address, maybe_tx
    );

    if let Some(ref tx_result) = maybe_tx {
        info!("Waiting for StorageCommitment deployment to be confirmed...");
        let _ = watch_tx(&provider, tx_result.transaction_hash, POLLING_INTERVAL).await;
    }

    // KatanaTee constructor: registry_address, storage_commitment_registry
    let katana_calldata = vec![amd_address, storage_commitment_address];

    let (maybe_tx, katana_address) = deploy::deploy(
        &account,
        katana_class_hash,
        katana_calldata,
        Some(salt),
        false,
    )
    .await
    .map_err(|e| anyhow::anyhow!("deploy KatanaTee: {}", e))?;

    info!(
        "Deployed KatanaTee: {:?}, tx_hash: {:?}",
        katana_address, maybe_tx
    );

    let deployment_block = if let Some(tx_result) = maybe_tx {
        info!("Waiting for KatanaTee deployment to be confirmed...");
        let receipt = watch_tx(&provider, tx_result.transaction_hash, POLLING_INTERVAL)
            .await
            .map_err(|e| anyhow::anyhow!("wait for KatanaTee deployment: {}", e))?;
        let block_number = receipt.block.block_number();
        info!("KatanaTee deployed at block: {}", block_number);
        Some(block_number)
    } else {
        info!("KatanaTee was already deployed, deployment block unknown");
        None
    };

    // Authorize KatanaTee as the only caller allowed to register commitments
    // on StorageCommitment. This must happen after both contracts are deployed.
    info!(
        "Setting KatanaTee ({:#064x}) as authorized caller on StorageCommitment ({:#064x})...",
        katana_address, storage_commitment_address
    );
    let set_authorized_tx = account
        .execute_v3(vec![Call {
            to: storage_commitment_address,
            selector: get_selector_from_name("set_authorized_caller")
                .expect("valid ASCII selector"),
            calldata: vec![katana_address],
        }])
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("set_authorized_caller on StorageCommitment: {}", e))?;

    info!("Waiting for set_authorized_caller tx to be confirmed...");
    let _ = watch_tx(
        &provider,
        set_authorized_tx.transaction_hash,
        POLLING_INTERVAL,
    )
    .await;
    info!("StorageCommitment authorized caller set to KatanaTee");

    let state = DeploymentState {
        deployment_block,
        amd_tee_registry_address: Some(format!("{:#064x}", amd_address)),
        katana_tee_address: Some(format!("{:#064x}", katana_address)),
        storage_commitment_address: Some(format!("{:#064x}", storage_commitment_address)),
    };

    state
        .save()
        .map_err(|e| anyhow::anyhow!("save deployment state: {}", e))?;
    info!("Deployment state saved to {}", crate::state::STATE_FILE);
    info!("  - AMDTeeRegistry: {:#064x}", amd_address);
    info!(
        "  - StorageCommitment: {:#064x}",
        storage_commitment_address
    );
    info!("  - KatanaTee: {:#064x}", katana_address);
    if let Some(block) = deployment_block {
        info!("  - Deployment block: {}", block);
    }
    Ok(())
}

/// Resolve SP1 program ID: from --sp1-program-id, or by running snp-attest-cli, or fallback constants.
/// Returns (low, high) as u256 for constructor calldata (low = last 16 bytes, high = first 16 bytes).
fn resolve_sp1_program_id(args: &InitArgs) -> Result<(Felt, Felt)> {
    if let Some(ref hex_id) = args.sp1_program_id {
        info!("Using SP1 program ID from --sp1-program-id argument");
        return parse_program_id_hex(hex_id).context("invalid --sp1-program-id hex");
    }

    // The hardcoded fallback may not match the deployed SP1 circuit, so it is only
    // used when the operator explicitly opts in with --no-fetch-sp1-program-id.
    if args.no_fetch_sp1_program_id {
        warn!(
            "Using HARDCODED FALLBACK SP1 program ID (--no-fetch-sp1-program-id). This may not \
             match the current SP1 circuit; pass --sp1-program-id to be sure. Fallback: high={} low={}",
            SP1_HIGH_FALLBACK, SP1_LOW_FALLBACK
        );
        return fallback_sp1_program_id();
    }

    // Default: fetch from snp-attest-cli. A failure is fatal rather than silently
    // deploying a registry pinned to a possibly-stale fallback program ID.
    let (low, high) = fetch_sp1_program_id_from_cli(args.sdk_path.as_deref()).context(
        "failed to fetch SP1 program ID from snp-attest-cli; pass --sp1-program-id explicitly, \
         or --no-fetch-sp1-program-id to accept the hardcoded fallback",
    )?;
    info!("Using SP1 program ID fetched from snp-attest-cli");
    Ok((low, high))
}

/// The hardcoded fallback SP1 program ID, split into (low, high) felts.
fn fallback_sp1_program_id() -> Result<(Felt, Felt)> {
    Ok((
        Felt::from_hex(SP1_LOW_FALLBACK).context("fallback SP1 low")?,
        Felt::from_hex(SP1_HIGH_FALLBACK).context("fallback SP1 high")?,
    ))
}

/// Parse "0x" + 64 hex chars into (low, high) felt. Low = last 16 bytes, high = first 16 bytes.
fn parse_program_id_hex(hex_id: &str) -> Result<(Felt, Felt)> {
    let s = hex_id.strip_prefix("0x").unwrap_or(hex_id);
    let s = s.trim();
    anyhow::ensure!(
        s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()),
        "SP1 program ID must be 32 bytes (64 hex chars)"
    );
    let low_hex = format!("0x{}", &s[32..]);
    let high_hex = format!("0x{}", &s[..32]);
    Ok((
        Felt::from_hex(&low_hex).context("SP1 low")?,
        Felt::from_hex(&high_hex).context("SP1 high")?,
    ))
}

/// Run `cargo run -p snp-attest-cli --release -- program-id --sp1` in SDK dir and parse onchain representation.
fn fetch_sp1_program_id_from_cli(sdk_path_opt: Option<&str>) -> Result<(Felt, Felt)> {
    let sdk_path = match sdk_path_opt {
        Some(p) => Path::new(p).to_path_buf(),
        None => {
            let cwd = std::env::current_dir().context("current_dir")?;
            let default = cwd.join("crates").join("amd-sev-snp-attestation-sdk");
            if default.exists() {
                default
            } else {
                anyhow::bail!(
                    "SDK path not found: {}. Set --sdk-path or run from repo root",
                    default.display()
                );
            }
        }
    };
    let output = Command::new("cargo")
        .args([
            "run",
            "-p",
            "snp-attest-cli",
            "--release",
            "--",
            "program-id",
            "--sp1",
        ])
        .current_dir(&sdk_path)
        .output()
        .context("run snp-attest-cli")?;
    anyhow::ensure!(
        output.status.success(),
        "snp-attest-cli failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let prefix = "ProgramID (Onchain Representation): ";
    let line = stdout
        .lines()
        .find(|l| l.starts_with(prefix))
        .context("snp-attest-cli output missing onchain program ID line")?;
    let hex_id = line.strip_prefix(prefix).context("prefix")?.trim();
    parse_program_id_hex(hex_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The canonical v6.1.0 SP1 program ID (onchain representation).
    const V6_PROGRAM_ID: &str =
        "0x00ed032fe45bc3492eb4f75fcb5c670f6be4a0e152ea8d8dbe56992f0433f65f";

    fn base_args() -> InitArgs {
        InitArgs {
            private_key: String::new(),
            address: String::new(),
            provider_url: String::new(),
            salt: None,
            amd_contract_class_path: String::new(),
            katana_contract_class_path: String::new(),
            storage_commitment_contract_class_path: String::new(),
            sp1_program_id: None,
            no_fetch_sp1_program_id: false,
            sdk_path: None,
        }
    }

    #[test]
    fn parse_program_id_splits_low_high() {
        let (low, high) = parse_program_id_hex(V6_PROGRAM_ID).unwrap();
        // high = first 16 bytes, low = last 16 bytes.
        assert_eq!(
            high,
            Felt::from_hex("0x00ed032fe45bc3492eb4f75fcb5c670f").unwrap()
        );
        assert_eq!(
            low,
            Felt::from_hex("0x6be4a0e152ea8d8dbe56992f0433f65f").unwrap()
        );
    }

    #[test]
    fn parse_program_id_accepts_without_0x_prefix() {
        let with = parse_program_id_hex(V6_PROGRAM_ID).unwrap();
        let without = parse_program_id_hex(V6_PROGRAM_ID.strip_prefix("0x").unwrap()).unwrap();
        assert_eq!(with, without);
    }

    #[test]
    fn parse_program_id_rejects_bad_input() {
        assert!(parse_program_id_hex("0x1234").is_err(), "too short");
        assert!(parse_program_id_hex(&"f".repeat(63)).is_err(), "63 chars");
        assert!(parse_program_id_hex(&"f".repeat(65)).is_err(), "65 chars");
        let mut non_hex = "z".to_string();
        non_hex.push_str(&"0".repeat(63));
        assert!(parse_program_id_hex(&non_hex).is_err(), "non-hex digit");
    }

    #[test]
    fn fallback_matches_the_v6_program_id() {
        // The fallback constants must be a correct split of the canonical v6 ID.
        assert_eq!(
            fallback_sp1_program_id().unwrap(),
            parse_program_id_hex(V6_PROGRAM_ID).unwrap()
        );
    }

    #[test]
    fn resolve_prefers_explicit_program_id() {
        let mut args = base_args();
        args.sp1_program_id = Some(V6_PROGRAM_ID.to_string());
        // Even with a bogus sdk_path, the explicit value wins without touching the CLI.
        args.sdk_path = Some("/nonexistent/sdk".to_string());
        assert_eq!(
            resolve_sp1_program_id(&args).unwrap(),
            parse_program_id_hex(V6_PROGRAM_ID).unwrap()
        );
    }

    #[test]
    fn resolve_uses_fallback_only_when_opted_in() {
        let mut args = base_args();
        args.no_fetch_sp1_program_id = true;
        assert_eq!(
            resolve_sp1_program_id(&args).unwrap(),
            fallback_sp1_program_id().unwrap()
        );
    }

    #[test]
    fn resolve_fails_loudly_when_cli_unavailable() {
        // Default path (no explicit id, no opt-in) must error rather than silently
        // falling back when the CLI can't be run.
        let mut args = base_args();
        args.sdk_path = Some("/nonexistent/sdk/path/xyz".to_string());
        assert!(resolve_sp1_program_id(&args).is_err());
    }
}
