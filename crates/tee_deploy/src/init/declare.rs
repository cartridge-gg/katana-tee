use super::error::InitError;
use crate::helpers::StarknetAccount;
use std::{fs, sync::Arc};

use cairo_lang_starknet_classes::{
    casm_contract_class::CasmContractClass, contract_class::ContractClass,
};
use starknet_api::contract_class::compiled_class_hash::{HashVersion, HashableCompiledClass};
use starknet_core::types::{Felt, contract::SierraClass};
use starknet_rust::{accounts::Account, core::types::DeclareTransactionResult};
use tracing::{info, warn};

pub async fn declare_contract(
    account: &StarknetAccount,
    contract_class_path: &str,
) -> Result<(Option<DeclareTransactionResult>, Felt), InitError> {
    let contract_class_bytes = fs::read(contract_class_path).map_err(|e| InitError::ReadClass {
        path: contract_class_path.to_string(),
        source: e,
    })?;

    let deserialized_class: SierraClass =
        serde_json::from_slice(&contract_class_bytes).map_err(InitError::ParseClass)?;

    let flattened = Arc::new(
        deserialized_class
            .flatten()
            .map_err(|e| InitError::FlattenClass(Box::new(e)))?,
    );
    let class_hash = flattened.class_hash();
    info!(path = contract_class_path, class_hash = %format!("{:#x}", class_hash), "Prepared contract declaration");

    let casm_class_hash = casm_class_hash_from_bytes(&contract_class_bytes, true)?;

    match account.declare_v3(flattened, casm_class_hash).send().await {
        Ok(tx) => {
            info!(tx_hash = %format!("{:#x}", tx.transaction_hash), "Declaration transaction sent");
            Ok((Some(tx), class_hash))
        }
        Err(error) => {
            let error_msg = format!("{error:?}");
            if error_msg.contains("is already declared") {
                warn!(class_hash = %format!("{:#x}", class_hash), "Class is already declared");
                Ok((None, class_hash))
            } else {
                Err(InitError::Declare(Box::new(error)))
            }
        }
    }
}

fn casm_class_hash_from_bytes(data: &[u8], use_blake2s: bool) -> Result<Felt, InitError> {
    let sierra_class: ContractClass =
        serde_json::from_slice(data).map_err(InitError::ParseClass)?;
    let casm_class = CasmContractClass::from_contract_class(sierra_class, false, usize::MAX)
        .map_err(|e| InitError::CasmCompilation(e.to_string()))?;

    let hash_version = if use_blake2s {
        HashVersion::V2
    } else {
        HashVersion::V1
    };
    let hash = casm_class.hash(&hash_version);

    Ok(Felt::from_bytes_be(&hash.0.to_bytes_be()))
}
