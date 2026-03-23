use super::error::InitError;
use crate::helpers::StarknetAccount;

use starknet_core::{
    types::{Felt, InvokeTransactionResult},
    utils::get_udc_deployed_address,
};
use starknet_rust::contract::{ContractFactory, UdcSelector};
use tracing::{info, warn};

pub async fn deploy(
    account: &StarknetAccount,
    class_hash: Felt,
    constructor_calldata: Vec<Felt>,
    salt: Option<Felt>,
    unique: bool,
) -> Result<(Option<InvokeTransactionResult>, Felt), InitError> {
    let contract_factory = ContractFactory::new_with_udc(class_hash, account, UdcSelector::New);
    let salt = salt.unwrap_or(Felt::ZERO);
    let address = get_udc_deployed_address(
        salt,
        class_hash,
        &starknet_core::utils::UdcUniqueness::NotUnique,
        &constructor_calldata,
    );
    info!(class_hash = %format!("{:#x}", class_hash), address = %format!("{:#x}", address), "Prepared contract deployment");

    match contract_factory
        .deploy_v3(constructor_calldata, salt, unique)
        .send()
        .await
    {
        Ok(tx) => Ok((Some(tx), address)),
        Err(error) => {
            let msg = format!("{error:?}");
            if msg.contains("already deployed at address") {
                warn!(address = %format!("{:#x}", address), "Contract already deployed");
                Ok((None, address))
            } else {
                Err(InitError::Deploy(Box::new(error)))
            }
        }
    }
}
