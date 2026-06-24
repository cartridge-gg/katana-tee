# Katana TEE

This repository contains:
- Cairo contracts for verifying AMD SEV-SNP attestation proofs on Starknet (via Garaga SP1 Groth16 verifier)
- Rust clients to fetch Katana TEE quotes, prove them with SP1, generate Starknet calldata, and invoke the on-chain verifier

## Repository layout

- `contracts/amd_tee_registry/` - AMD TEE registry verifier contract + tests
- `contracts/katana_tee/` - Katana TEE contract (uses registry) + tests
- `contracts/scripts/` - Deployment scripts (sncast)
- `clients/amd_tee_registry_client/` - Core proving library (Rust)
- `clients/katana_tee_client/` - CLI + Starknet integration (Rust)
- `crates/` - Git submodules (AMD SDK, Katana, Starknet, Garaga)
- `tests/e2e/` - End-to-end test scripts
- `tests/fixtures/` - Test fixtures (attestations, proofs, root certs)

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

## One-command full test suite

```bash
make test
```

This runs:
- Rust tests (`cargo test --all-targets`)
- Cairo tests (`snforge test --workspace`)
- E2E tests (`tests/e2e/run_e2e_tests.sh`)

To reuse existing proofs (skip SP1 network, faster):

```bash
make test-e2e-reuse
```

## Delivery verification checklist

- `git submodule update --init --recursive`
- `make test`
- Optional: `make test-fork` (requires `MAINNET_RPC_URL`)

## Optional test modes

```bash
make test-fork   # fork-based Cairo tests (requires MAINNET_RPC_URL)
make e2e-live    # live E2E (requires TEE access + SP1 prover network)
```

## CLI Reference

The `katana-tee` CLI provides all client functionality:

| Command | Description |
|---------|-------------|
| `fetch` | Fetch TEE attestation from Katana RPC |
| `execute` | Execute SP1 program in mock mode (fast) |
| `prove` | Generate SP1 Groth16 proof |
| `pipeline` | Full pipeline: fetch → prove → calldata → submit |
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

## Makefile Targets

For quick access to common operations:

```bash
# Full help
make help

# Common targets
make test              # Full test suite (rust + cairo + e2e)
make test-e2e-reuse    # E2E with existing proofs (fast)
make test-fork         # Fork-based Cairo tests (needs MAINNET_RPC_URL)

make fetch             # Fetch attestation from RPC
make prove             # Generate Groth16 proof via SP1 network
make prove-mock        # Generate mock proof (testing)

make tee-start         # Start TEE VM
make tee-stop          # Stop TEE VM
make tee-status        # Check TEE VM status

make generate-cairo-fixtures  # Regenerate Cairo fixtures from proofs
make fetch-root-certs         # Fetch AMD root certs from KDS
```

## Local devnet (fork mainnet)

```bash
make devnet-mainnet
```

## Deploy contracts to devnet

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

Source: [`deployments/sepolia.json`](deployments/sepolia.json) · deployed at block `11128351` · SP1 circuit `v6.1.0`.

| Contract          | Address |
|-------------------|---------|
| AMDTeeRegistry    | `0x06ef2e9da38576240174cd4740d9e323f855dc1ce8094362f122ed7278bf32b` |
| KatanaTee         | `0x06176b325e53547123b42b7cbd63c4a55d39bf3059a59f54cb9af2262312f133` |
| StorageCommitment | `0x0685d3fd6d93ef8ba976621090302c65b198d76cfe9208941e9d6ff39b20ccba` |

Verifier: self-generated Garaga SP1 v6.1.0 Groth16 verifier, class `0x051908349a7875e0234da7e55cd08492d3c53930deaf851bf284a1cadaad4332`.

Explorer: [Voyager](https://sepolia.voyager.online/contract/0x06ef2e9da38576240174cd4740d9e323f855dc1ce8094362f122ed7278bf32b)

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

To only generate proof + calldata (no transaction):

```bash
cargo run -p katana_tee_client --bin katana-tee -- pipeline \
  --rpc http://localhost:5050 \
  --registry 0x<amd_tee_registry_address> \
  --katana-tee 0x<katana_tee_address> \
  --dry-run \
  --calldata-output calldata.txt
```

For all CLI options, run `katana-tee --help` or `katana-tee <subcommand> --help`.

## Remote TEE VM helper

Use `./katana-tee-setup.sh` to start/stop the remote TEE VM and print the RPC URL. See `setup.md` for details.

## AMD Processor Root Certificates

AMD SEV-SNP attestation uses different root certificates (ARK - AMD Root Key)
for different processor families. However, not all processor types have unique
root certificates.

### Root Certificate Families

| Processor Type | Series | KDS Endpoint | Root Cert |
|----------------|--------|--------------|-----------|
| Milan          | 7003   | Milan        | Unique    |
| Genoa          | 9004   | Genoa        | Unique    |
| Bergamo        | 97x4   | Genoa        | Shares with Genoa |
| Siena          | 8004   | Genoa        | Shares with Genoa |

**Source:** [`crates/amd-sev-snp-attestation-sdk/crates/sev-snp/src/cpu.rs:16-22`](crates/amd-sev-snp-attestation-sdk/crates/sev-snp/src/cpu.rs#L16-L22)

This means only **two unique root certificates** need to be fetched and stored:
- **Milan** - for Milan processors
- **Genoa** - for Genoa, Bergamo, and Siena processors

The `tests/fixtures/root_certs.json` file contains only these two root certificate
hashes, which is correct and complete for all supported processor types.

### Certificate Cache Flow

1. **Live Mode (Initial Deployment):** Contract deployed with only root certs
2. **First Proof (Block 0):** `prefix_len=1`, ASK gets cached after verification
3. **Subsequent Proofs:** `prefix_len=2`, uses cached ASK for reduced verification cost

## Licensing

- Project license: `LICENSE` (Apache-2.0)
- Third-party notices: `THIRD_PARTY_NOTICES.md`

## Maintenance

- Submodule migration plan: `docs/submodules_migration.md`