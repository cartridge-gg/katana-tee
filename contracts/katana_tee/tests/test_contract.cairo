use katana_tee::{IKatanaTeeDispatcher, IKatanaTeeDispatcherTrait};
use snforge_std::fs::{FileParser, FileTrait};
use snforge_std::{ContractClassTrait, DeclareResultTrait, declare};
use starknet::ContractAddress;

/// Measurement config loaded from tests/fixtures/measurement.json
/// Fields must be in alphabetical order (FileParser sorts JSON keys alphabetically)
#[derive(Drop, Serde)]
struct MeasurementConfig {
    high_bits: felt252,
    low_bits: felt252,
    mid_bits: felt252,
}

fn load_measurement() -> MeasurementConfig {
    let file = FileTrait::new("../../tests/fixtures/measurement.json");
    FileParser::<MeasurementConfig>::parse_json(@file).expect('Failed: measurement.json')
}

fn deploy_contract(registry_address: ContractAddress) -> ContractAddress {
    let contract = declare("KatanaTee").unwrap().contract_class();
    let m = load_measurement();

    // Constructor calldata: registry_address, measurement (Bytes48 Serde order: low, mid, high)
    let mut calldata: Array<felt252> = array![];
    calldata.append(registry_address.into());
    calldata.append(m.low_bits);
    calldata.append(m.mid_bits);
    calldata.append(m.high_bits);

    let (contract_address, _) = contract.deploy(@calldata).unwrap();
    contract_address
}

#[test]
fn test_get_registry_address() {
    let registry_address: ContractAddress = 0x1234.try_into().unwrap();

    let contract_address = deploy_contract(registry_address);
    let dispatcher = IKatanaTeeDispatcher { contract_address };

    let returned_registry = dispatcher.get_registry_address();
    assert(returned_registry == registry_address, 'Wrong registry address');
}
