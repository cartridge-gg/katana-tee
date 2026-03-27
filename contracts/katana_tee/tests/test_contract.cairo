use katana_tee::{IKatanaTeeDispatcher, IKatanaTeeDispatcherTrait};
use snforge_std::{ContractClassTrait, DeclareResultTrait, declare};
use starknet::ContractAddress;

const TEST_MEASUREMENT_LOW: u128 = 0x11112222333344445555666677778888;
const TEST_MEASUREMENT_MID: u128 = 0x9999aaaabbbbccccddddeeeeffff0000;
const TEST_MEASUREMENT_HIGH: u128 = 0x1234567890abcdef1234567890abcdef;
fn deploy_contract(
    registry_address: ContractAddress, storage_commitment_registry: ContractAddress,
) -> ContractAddress {
    let contract = declare("KatanaTee").unwrap().contract_class();

    // Constructor: registry_address, storage_commitment_registry, measurement (Bytes48: low, mid, high)
    let mut calldata: Array<felt252> = array![];
    calldata.append(registry_address.into());
    calldata.append(storage_commitment_registry.into());
    calldata.append(TEST_MEASUREMENT_LOW.into());
    calldata.append(TEST_MEASUREMENT_MID.into());
    calldata.append(TEST_MEASUREMENT_HIGH.into());

    let (contract_address, _) = contract.deploy(@calldata).unwrap();
    contract_address
}

#[test]
fn test_get_registry_address() {
    let registry_address: ContractAddress = 0x1234.try_into().unwrap();
    let storage_commitment_registry: ContractAddress = 0x5678.try_into().unwrap();

    let contract_address = deploy_contract(registry_address, storage_commitment_registry);
    let dispatcher = IKatanaTeeDispatcher { contract_address };

    let returned_registry = dispatcher.get_registry_address();
    assert(returned_registry == registry_address, 'Wrong registry address');
}

#[test]
fn test_get_measurement() {
    let registry_address: ContractAddress = 0x1234.try_into().unwrap();
    let storage_commitment_registry: ContractAddress = 0x5678.try_into().unwrap();

    let contract_address = deploy_contract(registry_address, storage_commitment_registry);
    let dispatcher = IKatanaTeeDispatcher { contract_address };

    let measurement = dispatcher.get_measurement();
    assert(measurement.low_bits == TEST_MEASUREMENT_LOW, 'Wrong measurement low');
    assert(measurement.mid_bits == TEST_MEASUREMENT_MID, 'Wrong measurement mid');
    assert(measurement.high_bits == TEST_MEASUREMENT_HIGH, 'Wrong measurement high');
}
