# Katana TEE

Verify that [Katana](https://book.dojoengine.org/toolchain/katana) is running inside an AMD SEV-SNP Trusted Execution Environment, proven with SP1 and verified on Starknet.

## System Architecture

```
 katana-server                              katana-tee
 (github.com/feltroidprime/katana-server)   (this repo)
 ┌──────────────────────────┐               ┌───────────────────────────────────┐
 │  Reproducible TEE VM     │               │  Rust CLI + Cairo Contracts       │
 │                          │               │                                   │
 │  - Builds Katana image   │   attestation │  - Fetches SEV-SNP attestation    │
 │  - Launches AMD SEV-SNP  │◄──────────────┤  - Generates SP1 Groth16 proof    │
 │  - Runs Katana sequencer │   (RPC call)  │  - Submits proof to Starknet      │
 │  - Serves attestation    │               │  - Verifies on-chain              │
 └──────────────────────────┘               └───────────────────────────────────┘
         │                                              │
         │ RPC (blocks, state)                          │ verify_and_update_state()
         ▼                                              ▼
   Users / dApps                                  Starknet L1
                                             (Garaga SP1 verifier)
```

**katana-server** builds a reproducible VM image and runs Katana inside AMD SEV-SNP. It exposes both the standard Katana RPC and an attestation endpoint (`katana_getAttestation`).

**katana-tee** (this repo) fetches that attestation, proves it in a ZK circuit via SP1, and verifies the proof on Starknet through Cairo smart contracts.

## Repository Layout

| Path | Description |
|------|-------------|
| `contracts/amd_tee_registry/` | AMD TEE Registry contract (SP1 proof verification + certificate cache) |
| `contracts/katana_tee/` | Katana TEE contract (measurement check + state updates) |
| `contracts/scripts/` | Deployment scripts (sncast) |
| `clients/amd_tee_registry_client/` | Core proving library (Rust) |
| `clients/katana_tee_client/` | CLI + Starknet integration (Rust) |
| `crates/` | Git submodules (AMD SDK, Katana, Starknet, Garaga) |
| `tests/e2e/` | End-to-end test scripts |
| `tests/fixtures/` | Test fixtures (attestations, proofs, root certs) |

## Prerequisites

- `asdf` (recommended) with `.tool-versions`
- Rust toolchain (stable)
- Scarb + Starknet Foundry (`snforge`, `sncast`)
- `starknet-devnet` for local testing

```bash
asdf install
```

## Setup

```bash
git submodule update --init --recursive
cp .env.example .env
```

Edit `.env` and set any RPCs/keys you need. **Do not commit `.env`** (it is gitignored).

### SP1 Prover Network Configuration

To generate proofs via the SP1 network, you need to configure your requester account:

```bash
# In .env
NETWORK_ADDRESS=0x...    # Your Secp256k1 requester account address
NETWORK_PRIVATE_KEY=...  # Your requester account private key
```

**Setup steps:**
1. Generate a Secp256k1 key pair (e.g., via `cast wallet new` or Metamask)
2. Acquire PROVE tokens on Ethereum Mainnet
3. Deposit PROVE into the Succinct Prover Network via the [Explorer](https://explorer.succinct.xyz)

For detailed instructions, see the [Succinct Prover Network Quickstart](https://docs.succinct.xyz/docs/sp1/prover-network/quickstart).

## How It Works

The end-to-end flow has three phases:

**1. TEE Attestation**
The Katana sequencer runs inside an AMD SEV-SNP confidential VM. The VM hardware produces a signed attestation report containing the VM's measurement (a hash of the launched image) and report data (state root + block hash). The CLI fetches this report via `katana_getAttestation`.

**2. SP1 Proof Generation**
An SP1 program verifies the attestation report's signature chain (AMD root cert -> ASK -> VCEK -> report) inside a ZK circuit. The Succinct Prover Network generates a Groth16 proof, which is compact enough for on-chain verification.

**3. Starknet Verification**
The proof is submitted to the KatanaTee contract, which:
- Forwards it to AMDTEERegistry for SP1 proof verification (via the Garaga verifier)
- Checks the measurement matches the expected TEE image
- Validates that `report_data` contains the claimed state root and block hash
- Updates on-chain state with the verified block

### Certificate Cache

The AMDTEERegistry caches intermediate certificates (ASK) on-chain to reduce verification cost:

1. **First proof:** `prefix_len=1` - only the root cert (ARK) is on-chain; ASK gets cached after verification
2. **Subsequent proofs:** `prefix_len=2` - uses the cached ASK, skipping one level of chain verification

## Smart Contracts

### AMDTEERegistry

Verifies SP1 Groth16 proofs of AMD SEV-SNP attestation reports. Manages a cache of trusted intermediate certificates.

```
IAMDTeeRegistry
├── verify_sp1_proof(sp1_proof) -> Result<VerifierJournal, felt252>
│
│   (via CertCache component)
├── is_trusted_intermediate_cert(cert_hash) -> bool
├── get_root_cert(processor_model) -> u256
└── check_trusted_intermediate_certs(cert_hashes, processor_model) -> u32
```

Constructor parameters: `verifier_class_hash`, `sp1_program_id`, `max_time_diff`, `trusted_certs`, `processor_models`, `root_certs`.

### KatanaTee

Application-level contract that delegates proof verification to AMDTEERegistry and manages verified sequencer state.

```
IKatanaTee
├── verify_sp1_proof(sp1_proof) -> Result<VerifierJournal, felt252>
├── verify_and_update_state(sp1_proof, state_root, block_hash, block_number) -> Result<bool, felt252>
├── get_registry_address() -> ContractAddress
├── get_latest_state() -> (block_number, state_root, block_hash)
└── get_measurement() -> Bytes48
```

Constructor parameters: `registry_address`, `measurement`.

## CLI Reference

The `katana-tee` CLI provides all client functionality:

| Command | Description |
|---------|-------------|
| `fetch` | Fetch TEE attestation from Katana RPC |
| `execute` | Execute SP1 program in mock mode (fast) |
| `prove` | Generate SP1 Groth16 proof |
| `pipeline` | Full pipeline: fetch -> prove -> calldata -> submit |
| `calldata` | Generate Starknet calldata from proof file |
| `info` | Display proof file details |
| `fetch-root-certs` | Fetch AMD root certificates from KDS |
| `generate-cairo-fixtures` | Generate Cairo test fixtures from proofs |

```bash
# Build the CLI
cargo build -p katana_tee_client --release

# Get help
katana-tee --help
katana-tee prove --help
```

## Testing

```bash
make test              # Full suite: Rust + Cairo + E2E
make test-e2e-reuse    # E2E with existing proofs (skip SP1 network, faster)
make test-fork         # Fork-based Cairo tests (requires MAINNET_RPC_URL)
```

Individual test suites:

```bash
make test-rust         # cargo test --all-targets
make test-cairo        # snforge test --workspace
make test-e2e          # tests/e2e/run_e2e_tests.sh (fresh proofs)
```

See [`docs/testing.md`](docs/testing.md) for details on test modes, fixtures, and E2E configuration.

## Makefile Targets

Run `make help` for the full list. Key targets:

```bash
# CLI
make build             # Build the CLI
make fetch             # Fetch attestation from RPC
make prove             # Generate Groth16 proof via SP1 network
make prove-mock        # Generate mock proof (testing)

# TEE VM
make tee-start         # Start TEE VM
make tee-stop          # Stop TEE VM
make tee-status        # Check TEE VM status

# Fixtures
make generate-cairo-fixtures  # Regenerate Cairo fixtures from proofs
make fetch-root-certs         # Fetch AMD root certs from KDS
```

## Deployment

Start a local devnet forking mainnet (so the Garaga verifier is available):

```bash
make devnet-mainnet
```

Deploy contracts:

```bash
sncast --account "$STARKNET_ACCOUNT" script run deployment --network devnet --package deployment --no-state-file
```

## Deploy contracts to Sepolia

The Rust deployer (`crates/tee_deploy`) declares + deploys `AMDTeeRegistry`,
`KatanaTee`, and `StorageCommitment`, wires `set_authorized_caller`, and computes
the SP1 program ID via `snp-attest-cli` (run from repo root). Set a funded account
in `.env` (`SEPOLIA_RPC_URL`, `SEPOLIA_ACCOUNT_ADDRESS`, `SEPOLIA_ACCOUNT_PRIVATE_KEY`),
then:

```bash
make deploy-sepolia
```

Record the resulting addresses in `deployments/sepolia.json` (the canonical
deployment for Sepolia) — see [Deployments](#deployments) below.

## Deployments

Canonical contract addresses per network. Each network's full record (class
hashes, SP1 program ID, Garaga verifier class hash, deployment block) lives in
`deployments/<network>.json`.

### Sepolia

Source: [`deployments/sepolia.json`](deployments/sepolia.json) · deployed at block `11119511`.

| Contract          | Address |
|-------------------|---------|
| AMDTeeRegistry    | `0x01258ed7b2d3435097f9290d100d706d7f9f65db2725609cd7697669cac3bc3a` |
| KatanaTee         | `0x070477aa68dc1e6cf201fd98ba09a65c03df98c50da14df53c6111b4a28f514c` |
| StorageCommitment | `0x06dce12f2ca63d83580ab050a76f6089d1d78c91c5833a440e672542111fdc82` |

Explorer: [StarkScan](https://sepolia.starkscan.co/contract/0x01258ed7b2d3435097f9290d100d706d7f9f65db2725609cd7697669cac3bc3a)

## Run the end-to-end pipeline (Rust CLI)

This will: fetch quote → query cache → prove → calldata → invoke `katana_tee.verify_and_update_state`.

```bash
cargo run -p katana_tee_client --bin katana-tee -- pipeline \
  --rpc http://localhost:5050 \
  --registry 0x<amd_tee_registry_address> \
  --katana-tee 0x<katana_tee_address> \
  --account-address 0x<starknet_account_address> \
  --account-private-key 0x<starknet_private_key>
```

Use `--dry-run --calldata-output calldata.txt` to generate calldata without submitting a transaction.

## Remote TEE VM Helper

Use `./katana-tee-setup.sh` to start/stop the remote TEE VM and print the RPC URL. See `setup.md` for details.

## AMD Processor Root Certificates

AMD SEV-SNP uses different root certificates (ARK) per processor family. Only **two unique root certificates** are needed:

| Processor | Series | Root Cert |
|-----------|--------|-----------|
| Milan     | 7003   | Unique (Milan) |
| Genoa     | 9004   | Unique (Genoa) |
| Bergamo   | 97x4   | Shares Genoa |
| Siena     | 8004   | Shares Genoa |

The `tests/fixtures/root_certs.json` file contains these two root certificate hashes.

## Licensing

- Project license: `LICENSE` (Apache-2.0)
- Third-party notices: `THIRD_PARTY_NOTICES.md`
