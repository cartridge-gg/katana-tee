use crate::helpers::StarknetError;
use std::error::Error as StdError;

type BoxError = Box<dyn StdError + Send + Sync>;

/// Errors from declaration, deployment, validation, and state persistence.
#[derive(Debug, thiserror::Error)]
pub enum InitError {
    #[error("failed to read contract class '{path}'")]
    ReadClass {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse contract class")]
    ParseClass(#[source] serde_json::Error),

    #[error("failed to flatten Sierra class")]
    FlattenClass(#[source] BoxError),

    #[error("CASM compilation failed: {0}")]
    CasmCompilation(String),

    #[error("contract declaration failed")]
    Declare(#[source] BoxError),

    #[error("contract deployment failed")]
    Deploy(#[source] BoxError),

    #[error("failed to parse argument {field}: {message}")]
    InvalidArgument {
        field: &'static str,
        message: String,
    },

    #[error("failed to fetch SP1 program ID: {0}")]
    Sp1ProgramId(String),

    #[error("failed to build Cairo contract artifacts: {0}")]
    ContractBuild(String),

    #[error("on-chain call failed")]
    Call(#[source] BoxError),

    #[error("failed to save deployment state")]
    StateSave(#[source] BoxError),

    #[error(transparent)]
    Starknet(#[from] StarknetError),
}
