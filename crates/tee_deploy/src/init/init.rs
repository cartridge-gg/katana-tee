//! Declare and deploy AMDTeeRegistry and KatanaTee on Starknet.
//!
//! Missing Cairo contract artifacts are built automatically with `scarb build`.
//! Before deploy, SP1 program ID is computed via
//! `cargo run -p snp-attest-cli --release -- program-id --sp1` in the SDK dir
//! (unless overridden with --sp1-program-id or --no-fetch-sp1-program-id).

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use super::declare::declare_contract;
use super::deploy;
use super::error::InitError;
use crate::helpers::{
    POLLING_INTERVAL, StarknetAccount, StarknetProvider, parse_hex_arg, setup_provider_and_account,
    validate_hex_arg, validate_optional_hex_arg, watch_tx,
};
use crate::state::DeploymentState;
use clap::Args;
use rand::random;
use starknet_core::types::{Call, Felt};
use starknet_core::utils::get_selector_from_name;
use starknet_rust::accounts::Account;
use tracing::info;

const GARAGA_CLASS_HASH: &str = "0x4b22453df42037dd61390736454e8390910adfbbc1fa9d85613e6f375f4de22";
const MAX_TIME_DIFF: u64 = 86400;
const MILAN_LOW: &str = "326103188097639633505521426987620764621";
const MILAN_HIGH: &str = "140650959549381881311165088169387222174";
const GENOA_LOW: &str = "122279190577630630319986709203695547121";
const GENOA_HIGH: &str = "101548849195620556729999786649524856654";
const MEASUREMENT_LOW: &str = "0x34d8a0707c0c05f3981f72417a566530";
const MEASUREMENT_MID: &str = "0xb57365ef3473d3a5638074691e9b53d1";
const MEASUREMENT_HIGH: &str = "0x15e6b5f30c6d211c0f87dcb7dce00218";
const DEFAULT_AMD_CLASS_PATH: &str = "target/dev/amd_tee_registry_AMDTEERegistry.contract_class.json";
const DEFAULT_KATANA_CLASS_PATH: &str = "target/dev/katana_tee_KatanaTee.contract_class.json";
const DEFAULT_STORAGE_COMMITMENT_CLASS_PATH: &str =
    "target/dev/storage_commitment_StorageCommitment.contract_class.json";
const DEFAULT_SDK_PATH: &str = "crates/amd-sev-snp-attestation-sdk";

#[derive(Debug, Clone)]
pub struct InitConfig {
    pub private_key: String,
    pub address: String,
    pub provider_url: String,
    pub salt: Option<Felt>,
    pub amd_contract_class_path: PathBuf,
    pub katana_contract_class_path: PathBuf,
    pub storage_commitment_contract_class_path: PathBuf,
    pub sp1_program_id: Option<String>,
    pub no_fetch_sp1_program_id: bool,
    pub sdk_path: Option<PathBuf>,
    pub reuse_existing_sp1_elf: bool,
}

#[derive(Debug, Clone)]
pub struct InitOutcome {
    pub deployment_block: Option<u64>,
    pub amd_tee_registry_address: String,
    pub katana_tee_address: String,
    pub storage_commitment_address: String,
}

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

    /// Path to AMDTeeRegistry Sierra contract class JSON
    #[arg(
        long,
        default_value = DEFAULT_AMD_CLASS_PATH
    )]
    pub amd_contract_class_path: String,

    /// Path to KatanaTee Sierra contract class JSON
    #[arg(
        long,
        default_value = DEFAULT_KATANA_CLASS_PATH
    )]
    pub katana_contract_class_path: String,

    /// Path to StorageCommitment Sierra contract class JSON
    #[arg(
        long,
        default_value = DEFAULT_STORAGE_COMMITMENT_CLASS_PATH
    )]
    pub storage_commitment_contract_class_path: String,

    /// SP1 program ID (onchain bytes32) as hex; if unset, computed via snp-attest-cli in SDK dir
    #[arg(long)]
    pub sp1_program_id: Option<String>,

    /// Do not run snp-attest-cli to fetch SP1 program ID; requires --sp1-program-id
    #[arg(long)]
    pub no_fetch_sp1_program_id: bool,

    /// Path to amd-sev-snp-attestation-sdk (for `cargo run -p snp-attest-cli -- program-id --sp1`). Default: ./crates/amd-sev-snp-attestation-sdk
    #[arg(long)]
    pub sdk_path: Option<String>,

    /// Reuse the existing SP1 ELF instead of forcing a fresh rebuild before
    /// auto-fetching the program ID. Unsafe if guest code changed since the ELF
    /// was last built.
    #[arg(long, default_value_t = false)]
    pub reuse_existing_sp1_elf: bool,
}

impl InitArgs {
    pub fn validate(&self) -> Result<(), InitError> {
        validate_hex_arg(&self.private_key, "--private-key")?;
        validate_hex_arg(&self.address, "--address")?;
        validate_optional_hex_arg(&self.salt, "--salt")?;

        if let Some(ref program_id) = self.sp1_program_id {
            parse_program_id_hex(program_id)?;
        }

        if self.no_fetch_sp1_program_id && self.sp1_program_id.is_none() {
            return Err(InitError::InvalidArgument {
                field: "--no-fetch-sp1-program-id",
                message: "requires --sp1-program-id because no fallback is allowed".to_string(),
            });
        }

        Ok(())
    }

    pub fn into_config(self) -> Result<InitConfig, InitError> {
        self.validate()?;
        let (amd_contract_class_path, katana_contract_class_path, storage_commitment_contract_class_path) =
            resolve_contract_class_paths(&self)?;

        Ok(InitConfig {
            private_key: self.private_key,
            address: self.address,
            provider_url: self.provider_url,
            salt: resolve_salt(self.salt.as_ref())?,
            amd_contract_class_path,
            katana_contract_class_path,
            storage_commitment_contract_class_path,
            sp1_program_id: self.sp1_program_id,
            no_fetch_sp1_program_id: self.no_fetch_sp1_program_id,
            sdk_path: Some(resolve_sdk_path(self.sdk_path.as_deref())?),
            reuse_existing_sp1_elf: self.reuse_existing_sp1_elf,
        })
    }
}

pub async fn run_init(args: InitArgs) -> Result<InitOutcome, InitError> {
    run_init_config(args.into_config()?).await
}

pub async fn run_init_config(config: InitConfig) -> Result<InitOutcome, InitError> {
    let (provider, mut account) = setup_provider_and_account(
        &config.provider_url,
        &config.private_key,
        &config.address,
    )
    .await?;
    // Use pre-confirmed block for nonce to avoid nonce mismatch after waiting for tx confirmation.
    account.set_block_id(starknet_core::types::BlockId::Tag(
        starknet_core::types::BlockTag::PreConfirmed,
    ));

    let address = parse_hex_arg(&config.address, "--address")?;
    let salt = config.salt.unwrap_or_else(random_salt);

    let amd_class_hash = declare_with_wait(
        &provider,
        &account,
        "AMDTeeRegistry",
        &config.amd_contract_class_path,
    )
    .await?;
    let katana_class_hash =
        declare_with_wait(&provider, &account, "KatanaTee", &config.katana_contract_class_path)
            .await?;
    let storage_commitment_class_hash = declare_with_wait(
        &provider,
        &account,
        "StorageCommitment",
        &config.storage_commitment_contract_class_path,
    )
    .await?;

    info!(
        amd_tee_registry = %format!("{:#x}", amd_class_hash),
        katana_tee = %format!("{:#x}", katana_class_hash),
        storage_commitment = %format!("{:#x}", storage_commitment_class_hash),
        "Declared contract classes"
    );
    info!("Using salt for deployment: {:#064x}", salt);

    let (sp1_low, sp1_high) = resolve_sp1_program_id(&config)?;
    info!(
        "SP1 program ID: low {:#064x}, high {:#064x}",
        sp1_low, sp1_high
    );

    let amd_calldata = vec![
        Felt::from_hex(GARAGA_CLASS_HASH).expect("valid constant"),
        sp1_low,
        sp1_high,
        Felt::from(MAX_TIME_DIFF),
        Felt::ZERO,
        Felt::from(2u64),
        Felt::ZERO,
        Felt::ONE,
        Felt::from(2u64),
        Felt::from_dec_str(MILAN_LOW).expect("valid constant"),
        Felt::from_dec_str(MILAN_HIGH).expect("valid constant"),
        Felt::from_dec_str(GENOA_LOW).expect("valid constant"),
        Felt::from_dec_str(GENOA_HIGH).expect("valid constant"),
    ];

    let (amd_address, _) = deploy_with_wait(
        &provider,
        &account,
        "AMDTeeRegistry",
        amd_class_hash,
        amd_calldata,
        Some(salt),
    )
    .await?;

    let storage_commitment_calldata = vec![address];
    let (storage_commitment_address, _) = deploy_with_wait(
        &provider,
        &account,
        "StorageCommitment",
        storage_commitment_class_hash,
        storage_commitment_calldata,
        Some(salt),
    )
    .await?;

    let katana_calldata = vec![
        amd_address,
        storage_commitment_address,
        Felt::from_hex(MEASUREMENT_LOW).expect("valid constant"),
        Felt::from_hex(MEASUREMENT_MID).expect("valid constant"),
        Felt::from_hex(MEASUREMENT_HIGH).expect("valid constant"),
    ];

    let (katana_address, deployment_block) = deploy_with_wait(
        &provider,
        &account,
        "KatanaTee",
        katana_class_hash,
        katana_calldata,
        Some(salt),
    )
    .await?;

    set_authorized_caller(&provider, &account, storage_commitment_address, katana_address).await?;

    let state = DeploymentState {
        deployment_block,
        amd_tee_registry_address: Some(format!("{:#064x}", amd_address)),
        katana_tee_address: Some(format!("{:#064x}", katana_address)),
        storage_commitment_address: Some(format!("{:#064x}", storage_commitment_address)),
    };

    state
        .save()
        .map_err(InitError::StateSave)?;

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

    Ok(InitOutcome {
        deployment_block,
        amd_tee_registry_address: format!("{:#064x}", amd_address),
        katana_tee_address: format!("{:#064x}", katana_address),
        storage_commitment_address: format!("{:#064x}", storage_commitment_address),
    })
}

async fn declare_with_wait(
    provider: &StarknetProvider,
    account: &StarknetAccount,
    label: &'static str,
    class_path: &Path,
) -> Result<Felt, InitError> {
    let (maybe_tx, class_hash) =
        declare_contract(account, class_path.to_string_lossy().as_ref()).await?;
    if let Some(tx) = maybe_tx {
        info!("Waiting for {label} declaration...");
        let _ = watch_tx(provider, tx.transaction_hash, POLLING_INTERVAL).await?;
    } else {
        info!("{label} was already declared");
    }
    Ok(class_hash)
}

async fn deploy_with_wait(
    provider: &StarknetProvider,
    account: &StarknetAccount,
    label: &'static str,
    class_hash: Felt,
    constructor_calldata: Vec<Felt>,
    salt: Option<Felt>,
) -> Result<(Felt, Option<u64>), InitError> {
    let (maybe_tx, address) = deploy::deploy(account, class_hash, constructor_calldata, salt, false).await?;

    info!("{label} address: {:#064x}", address);

    let deployment_block = if let Some(tx_result) = maybe_tx {
        info!(
            tx_hash = %format!("{:#x}", tx_result.transaction_hash),
            "Waiting for {label} deployment..."
        );
        let receipt = watch_tx(provider, tx_result.transaction_hash, POLLING_INTERVAL).await?;
        let block_number = receipt.block.block_number();
        info!("{label} deployed at block: {}", block_number);
        Some(block_number)
    } else {
        info!("{label} was already deployed, deployment block unknown");
        None
    };

    Ok((address, deployment_block))
}

async fn set_authorized_caller(
    provider: &StarknetProvider,
    account: &StarknetAccount,
    storage_commitment_address: Felt,
    katana_address: Felt,
) -> Result<(), InitError> {
    let selector =
        get_selector_from_name("set_authorized_caller").map_err(|e| InitError::Call(Box::new(e)))?;

    info!(
        "Setting KatanaTee ({:#064x}) as authorized caller on StorageCommitment ({:#064x})...",
        katana_address, storage_commitment_address
    );

    let tx = account
        .execute_v3(vec![Call {
            to: storage_commitment_address,
            selector,
            calldata: vec![katana_address],
        }])
        .send()
        .await
        .map_err(|e| InitError::Call(Box::new(e)))?;

    info!(
        tx_hash = %format!("{:#x}", tx.transaction_hash),
        "Waiting for set_authorized_caller confirmation..."
    );
    let _ = watch_tx(provider, tx.transaction_hash, POLLING_INTERVAL).await?;
    info!("StorageCommitment authorized caller set to KatanaTee");
    Ok(())
}

fn resolve_salt(salt_hex: Option<&String>) -> Result<Option<Felt>, InitError> {
    if let Some(value) = salt_hex {
        return parse_hex_arg(value, "--salt")
            .map(Some)
            .map_err(InitError::from);
    }

    Ok(None)
}

fn random_salt() -> Felt {
    let random_bytes: [u8; 32] = random();
    let hex_string = format!(
        "0x{}",
        random_bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    );
    Felt::from_hex_unchecked(&hex_string)
}

/// Resolve SP1 program ID: from --sp1-program-id, or by running snp-attest-cli.
/// Returns `(low, high)` as u256 calldata limbs.
fn resolve_sp1_program_id(config: &InitConfig) -> Result<(Felt, Felt), InitError> {
    if let Some(ref hex_id) = config.sp1_program_id {
        info!("Using SP1 program ID from --sp1-program-id");
        return parse_program_id_hex(hex_id);
    }

    if config.no_fetch_sp1_program_id {
        return Err(InitError::InvalidArgument {
            field: "--no-fetch-sp1-program-id",
            message: "requires --sp1-program-id because no fallback is allowed".to_string(),
        });
    }

    let (low, high) =
        fetch_sp1_program_id_from_cli(config.sdk_path.as_deref(), !config.reuse_existing_sp1_elf)?;
    info!("Using SP1 program ID fetched from snp-attest-cli");
    Ok((low, high))
}

/// Parse `0x` + 64 hex chars into `(low, high)` Cairo `u256` limbs.
fn parse_program_id_hex(hex_id: &str) -> Result<(Felt, Felt), InitError> {
    let trimmed = hex_id.trim();
    if trimmed.contains("...") {
        return Err(InitError::InvalidArgument {
            field: "--sp1-program-id",
            message: format!(
                "placeholder value '{}' cannot be used; expected 32-byte hex value",
                trimmed
            ),
        });
    }

    let s = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    if s.len() != 64 || !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(InitError::InvalidArgument {
            field: "--sp1-program-id",
            message: "expected 32-byte hex value (64 hex chars, optional 0x prefix)"
                .to_string(),
        });
    }

    let low_hex = format!("0x{}", &s[32..]);
    let high_hex = format!("0x{}", &s[..32]);
    let low = Felt::from_hex(&low_hex).map_err(|e| InitError::InvalidArgument {
        field: "--sp1-program-id",
        message: format!("invalid low limb: {e}"),
    })?;
    let high = Felt::from_hex(&high_hex).map_err(|e| InitError::InvalidArgument {
        field: "--sp1-program-id",
        message: format!("invalid high limb: {e}"),
    })?;

    Ok((low, high))
}

/// Run `cargo run -p snp-attest-cli --release -- program-id --sp1` in SDK dir.
fn fetch_sp1_program_id_from_cli(
    sdk_path_opt: Option<&Path>,
    force_rebuild: bool,
) -> Result<(Felt, Felt), InitError> {
    let sdk_path = sdk_path_opt
        .map(Path::to_path_buf)
        .unwrap_or_else(|| tee_repo_root().join(DEFAULT_SDK_PATH));

    if force_rebuild {
        rebuild_sp1_program_artifacts(&sdk_path)?;
    } else {
        info!("Reusing existing SP1 ELF/program artifacts without rebuild");
    }

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
        .map_err(|e| InitError::Sp1ProgramId(format!("failed to run snp-attest-cli: {e}")))?;

    if !output.status.success() {
        return Err(InitError::Sp1ProgramId(format!(
            "snp-attest-cli failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let prefix = "ProgramID (Onchain Representation): ";
    let line = stdout.lines().find(|line| line.starts_with(prefix)).ok_or_else(|| {
        InitError::Sp1ProgramId(
            "snp-attest-cli output missing 'ProgramID (Onchain Representation)' line"
                .to_string(),
        )
    })?;
    let hex_id = line.strip_prefix(prefix).unwrap_or("").trim();
    parse_program_id_hex(hex_id)
}

fn resolve_contract_class_paths(args: &InitArgs) -> Result<(PathBuf, PathBuf, PathBuf), InitError> {
    let uses_default_artifacts = args.amd_contract_class_path == DEFAULT_AMD_CLASS_PATH
        || args.katana_contract_class_path == DEFAULT_KATANA_CLASS_PATH
        || args.storage_commitment_contract_class_path
            == DEFAULT_STORAGE_COMMITMENT_CLASS_PATH;
    let missing_artifact = try_resolve_existing_path(&args.amd_contract_class_path).is_none()
        || try_resolve_existing_path(&args.katana_contract_class_path).is_none()
        || try_resolve_existing_path(&args.storage_commitment_contract_class_path).is_none();

    if uses_default_artifacts || missing_artifact {
        build_contract_artifacts()?;
    }

    Ok((
        resolve_existing_path(&args.amd_contract_class_path, "--amd-contract-class-path")?,
        resolve_existing_path(
            &args.katana_contract_class_path,
            "--katana-contract-class-path",
        )?,
        resolve_existing_path(
            &args.storage_commitment_contract_class_path,
            "--storage-commitment-contract-class-path",
        )?,
    ))
}

fn try_resolve_existing_path(input: &str) -> Option<PathBuf> {
    let direct = PathBuf::from(input);
    if direct.exists() {
        return Some(direct);
    }

    let repo_relative = tee_repo_root().join(input);
    if repo_relative.exists() {
        return Some(repo_relative);
    }

    None
}

fn resolve_existing_path(input: &str, field: &'static str) -> Result<PathBuf, InitError> {
    try_resolve_existing_path(input).ok_or_else(|| InitError::InvalidArgument {
        field,
        message: format!(
            "path '{}' was not found relative to the current directory or katana-tee repo root ({})",
            input,
            tee_repo_root().display()
        ),
    })
}

fn resolve_sdk_path(input: Option<&str>) -> Result<PathBuf, InitError> {
    match input {
        Some(path) => resolve_existing_path(path, "--sdk-path"),
        None => {
            let default = tee_repo_root().join(DEFAULT_SDK_PATH);
            if default.exists() {
                Ok(default)
            } else {
                Err(InitError::Sp1ProgramId(format!(
                    "SDK path not found: {}. Pass --sdk-path explicitly",
                    default.display()
                )))
            }
        }
    }
}

fn tee_repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("tee_deploy crate should live under katana-tee/crates/tee_deploy")
        .to_path_buf()
}

fn build_contract_artifacts() -> Result<(), InitError> {
    let repo_root = tee_repo_root();
    info!(
        repo_root = %repo_root.display(),
        "Building Cairo contract artifacts with scarb"
    );

    let output = Command::new("scarb")
        .args(["build"])
        .current_dir(&repo_root)
        .output()
        .map_err(|e| InitError::ContractBuild(format!("failed to run scarb build: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let details = if stderr.is_empty() { stdout } else { stderr };

        return Err(InitError::ContractBuild(format!(
            "scarb build failed from {}: {}",
            repo_root.display(),
            details
        )));
    }

    Ok(())
}

fn rebuild_sp1_program_artifacts(sdk_path: &Path) -> Result<(), InitError> {
    let elf_path = sdk_path
        .join("crates")
        .join("sp1-methods")
        .join("elf")
        .join("sp1-verifier-elf");

    info!(
        elf = %elf_path.display(),
        "Forcing fresh SP1 ELF rebuild before fetching program ID"
    );

    if elf_path.exists() {
        fs::remove_file(&elf_path).map_err(|e| {
            InitError::Sp1ProgramId(format!(
                "failed to remove stale SP1 ELF at {}: {e}",
                elf_path.display()
            ))
        })?;
    }

    let clean_output = Command::new("cargo")
        .args([
            "clean",
            "-p",
            "sp1-methods",
            "-p",
            "amd-sev-snp-attestation-prover",
            "-p",
            "snp-attest-cli",
        ])
        .current_dir(sdk_path)
        .output()
        .map_err(|e| InitError::Sp1ProgramId(format!("failed to run cargo clean for SP1 crates: {e}")))?;

    if !clean_output.status.success() {
        return Err(InitError::Sp1ProgramId(format!(
            "cargo clean failed: {}",
            String::from_utf8_lossy(&clean_output.stderr).trim()
        )));
    }

    Ok(())
}
