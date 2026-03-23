# Attestation Range Binding and API Clarification Implementation Plan

## Overview
This plan introduces a safer and clearer attestation model for the Katana TEE flow by separating metadata-only block range fields from cryptographically attested inputs. The implementation is staged to avoid breaking the current ecosystem while making room for a future V2 quote format that can bind a start/base block and end block explicitly.

## Goals
- Clarify the semantics of `prev_block_number`, `block_number`, and `fork_block_number` across `katana`, `katana-tee`, and `sharding_operator`.
- Prevent engineers from treating metadata-only fields as if they were hardware-attested.
- Introduce a forward-compatible path for cryptographically binding an attestation range or transition when needed.
- Preserve the current settlement and event-proof security model during migration.
- Minimize breakage for existing RPC clients, fixtures, tests, and deployed contracts.

## Non-Goals
- This plan does not redesign the full sharding settlement protocol.
- This plan does not replace the existing storage commitment or event inclusion model.
- This plan does not require immediate removal of legacy RPC fields in the first rollout.
- This plan does not attempt to prove full block-to-block state transition correctness inside SP1.

## Assumptions and Constraints
- Current security-critical attested fields are `state_root`, `block_hash`, `fork_block_number`, `events_commitment`, and `args_hash`.
- Current `prev_block_number`, `prev_block_hash`, and `prev_state_root` are response metadata only and are not included in `report_data`.
- In `sharding_operator`, the value currently passed as `prev_block` is semantically closer to `start_block_number` or `fork_block_number` than to “parent block”.
- Existing contracts and fixtures likely assume the current `report_data = Poseidon(state_root, block_hash, fork_block_number, events_commitment)` layout.
- Backward compatibility is important because the change crosses RPC, prover, SP1 guest, on-chain verification, and operational tooling.

## Requirements

### Functional
- Define and document canonical meanings for:
  - `end_block_number`: attested block that contains the state root and event commitment
  - `fork_block_number`: chain fork anchor already bound into attestation
  - `start_block_number` or `base_block_number`: optional start/range anchor for future flows
- Rename metadata fields in clients and operator code to reflect true semantics.
- Preserve legacy RPC compatibility while introducing a V2 API or versioned response format.
- Add an optional V2 attestation mode that can cryptographically bind both a start/base anchor and an end anchor.
- Ensure SP1, AMD registry decoding, and `katana_tee` verification understand the chosen V2 binding layout.
- Ensure `sharding_operator` can operate in both legacy mode and V2 mode during migration.

### Non-Functional
- No silent security regressions during migration.
- Clear observability so operators can distinguish legacy metadata-only quotes from V2 bound quotes.
- Maintain deterministic fixtures and test vectors for both legacy and V2 flows.
- Keep RPC and proving ergonomics simple enough for CLI and automation use.

## Technical Design

### Data Model
- Legacy model:
  - `prev_block_number`, `prev_block_hash`, `prev_state_root` remain metadata only.
  - `block_number` remains a transport field and on-chain state update parameter, but is not part of quote binding.
- Normalized model:
  - Introduce explicit names in internal types:
    - `attested_block_number`
    - `start_block_number` or `base_block_number`
    - `fork_block_number`
  - Introduce an attestation version enum in shared Rust types and, if needed, Cairo/Solidity decoding helpers.
- V2 model:
  - Add a versioned commitment layout, for example:
    - `Poseidon(attested_state_root, attested_block_hash, fork_block_number, events_commitment, start_block_hash_or_root, start_block_number)`
  - Prefer binding a start hash/root over binding only a start number.
  - Keep `args_hash` in the second 32 bytes unless a new report-data layout is adopted with explicit version tagging.

### API Design
- Keep `tee_generateQuote(prev_block_id, block_id)` working initially.
- Add one of:
  - `tee_generateQuoteV2(start_block_id, end_block_id)`
  - `tee_generateQuote(range_spec)`
  - `tee_generateQuote(block_id, options)`
- Response should include:
  - `attestationVersion`
  - `attestedBlockNumber`
  - `forkBlockNumber`
  - `eventsCommitment`
  - `startBlockNumber` or `baseBlockNumber` when applicable
  - explicit marker showing whether start/base info is metadata-only or cryptographically bound
- Deprecate `prev_*` naming in client-facing types after migration.

### Architecture
- Legacy flow:
  - `sharding_operator` requests quote with two numbers.
  - `katana` fetches both blocks, but binds only end-block state plus `fork_block_number` and `events_commitment`.
  - SP1 verifies attestation and event proof.
  - `katana_tee` verifies `report_data` against the legacy layout.
- Target flow:
  - `sharding_operator` requests a versioned quote.
  - `katana` constructs a versioned commitment layout and embeds it in `report_data`.
  - SP1 guest and registry emit version-aware journal data.
  - `katana_tee` verifies the matching layout on-chain.
  - storage commitment and settlement consume the resulting verified range semantics.

### UX Flow (if applicable)
- CLI and operator logs should say:
  - whether the quote is `legacy` or `v2`
  - what block is attested
  - what block is used as start/base anchor
  - whether the start/base anchor is metadata-only or TEE-bound
- Error messages should clearly distinguish:
  - missing start/base block data
  - invalid start/end ordering
  - attestation version mismatch
  - unsupported quote format

---

## Implementation Plan

### Serial Dependencies (Must Complete First)

These tasks create foundations that other work depends on. Complete in order.

#### Phase 0: Terminology, Versioning, and Security Model
**Prerequisite for:** All subsequent phases

| Task | Description | Output |
|------|-------------|--------|
| 0.1 | Write an ADR/RFC that defines the semantics of `attested`, `start/base`, `fork`, `end`, and `legacy metadata-only` fields. | Approved terminology document |
| 0.2 | Choose the migration shape: legacy-only cleanup first, or legacy + V2 dual-mode support. | Recorded migration decision |
| 0.3 | Choose the V2 binding payload layout and whether it binds start number only or start hash/root plus number. | Finalized report-data spec |
| 0.4 | Define version encoding and compatibility behavior across Rust, SP1, Cairo, and contract interfaces. | Shared versioning contract |
| 0.5 | Define acceptance criteria for “safe enough to roll out” including test coverage and fixture updates. | Release gate checklist |

#### Phase 1: Shared Type and Naming Cleanup
**Prerequisite for:** RPC changes, operator changes, SP1 integration

| Task | Description | Output |
|------|-------------|--------|
| 1.1 | Audit all `prev_block*` usages across `katana-tee`, `katana`, and `sharding_operator`. | Usage inventory |
| 1.2 | Introduce normalized shared names in Rust types and adapters while preserving backward compatibility at the RPC edge. | Updated internal DTOs |
| 1.3 | Add inline docs and log labels explicitly stating which fields are attested versus metadata-only. | Safer code comments and tracing |
| 1.4 | Add compatibility mappers between legacy response fields and normalized internal types. | Adapters for old/new formats |

---

### Parallel Workstreams

These workstreams can be executed independently after Phase 1.

#### Workstream A: Katana RPC and Quote Generation
**Dependencies:** Phase 0, Phase 1
**Can parallelize with:** Workstreams B, C, D

| Task | Description | Output |
|------|-------------|--------|
| A.1 | Add explicit versioning to the TEE RPC API and response structs. | Versioned RPC types |
| A.2 | Implement legacy mode labeling so clients know `prev_*` is metadata-only. | Safer legacy responses |
| A.3 | Implement V2 quote generation path in `katana` with the chosen commitment layout. | New `report_data` generator |
| A.4 | Add validation for start/base and end block lookup, ordering, and missing-header failure cases. | Hardened RPC behavior |
| A.5 | Update tests and fixtures for legacy and V2 quote generation. | Dual-mode RPC coverage |

#### Workstream B: Prover, SP1 Guest, and AMD Registry Compatibility
**Dependencies:** Phase 0, Phase 1
**Can parallelize with:** Workstreams A, C, D

| Task | Description | Output |
|------|-------------|--------|
| B.1 | Extend prover input types to carry attestation version and optional bound start/base anchor fields. | Updated `VerifierInput` model |
| B.2 | Update SP1 guest logic to decode and validate version-aware report binding rules. | Version-aware guest verifier |
| B.3 | Decide whether journal output needs extra range fields beyond `forkBlockNumber` and `endBlockNumber`. | Updated journal schema or explicit no-change decision |
| B.4 | Update AMD TEE registry decoding, fixture generation, and tests for the chosen journal format. | Registry compatibility layer |
| B.5 | Regenerate test fixtures for both legacy and V2 proofs. | Stable proof fixtures |

#### Workstream C: On-Chain KatanaTee and Storage Commitment Integration
**Dependencies:** Phase 0, Phase 1
**Can parallelize with:** Workstreams A, B, D

| Task | Description | Output |
|------|-------------|--------|
| C.1 | Update `katana_report_utils.cairo` to support version-aware report-data verification. | Versioned report verifier |
| C.2 | Update `KatanaTee.verify_and_update_state` to accept versioned inputs or route by quote version. | Backward-compatible contract API |
| C.3 | Decide whether storage commitment hashing should remain keyed by `global_state_root + end_block_number` only, or also include start/base anchor in V2. | Commitment model decision |
| C.4 | If commitment semantics change, update `storage_commitment` contract and replay-protection documentation. | Updated on-chain commitment flow |
| C.5 | Add contract tests for legacy success, V2 success, and mixed-version failure modes. | Cairo test coverage |

#### Workstream D: Sharding Operator, CLI, and Operational Tooling
**Dependencies:** Phase 0, Phase 1
**Can parallelize with:** Workstreams A, B, C

| Task | Description | Output |
|------|-------------|--------|
| D.1 | Rename operator variables from `prev_block` to `start_block` or `base_block` where that is the true meaning. | Clearer operator code |
| D.2 | Add dual-mode client handling so the operator can consume both legacy and V2 responses. | Migration-safe operator client |
| D.3 | Update CLI flags and help text to reflect semantic meaning rather than legacy naming. | Better operator UX |
| D.4 | Add logs and telemetry distinguishing legacy metadata-only quotes from V2 bound quotes. | Operational visibility |
| D.5 | Update docs, runbooks, and fixture capture scripts. | Migration-ready tooling docs |

---

### Merge Phase

After parallel workstreams complete, these tasks integrate the work.

#### Phase N: Integration
**Dependencies:** Workstreams A, B, C, D

| Task | Description | Output |
|------|-------------|--------|
| N.1 | Wire end-to-end legacy flow across RPC, prover, SP1, contracts, and operator after refactor. | Green legacy integration path |
| N.2 | Wire end-to-end V2 flow across the same stack. | Green V2 integration path |
| N.3 | Validate mixed deployment scenarios: new client with old node, old client with new node, and version mismatch handling. | Compatibility matrix |
| N.4 | Gate rollout behind feature flag or config switch in operator and, if needed, in `katana`. | Controlled rollout mechanism |
| N.5 | Decide deprecation timeline for `prev_*` RPC fields and old CLI flags. | Published deprecation plan |

#### Phase N+1: Cleanup and Deprecation
**Dependencies:** Stable V2 rollout, compatibility window complete

| Task | Description | Output |
|------|-------------|--------|
| N+1.1 | Remove or hide legacy-only internal names after migration window. | Cleaned internal API |
| N+1.2 | Remove deprecated docs and compatibility adapters that are no longer needed. | Reduced maintenance surface |
| N+1.3 | Freeze the final spec and publish reference fixtures. | Stable long-term contract |

---

## Testing and Validation

- Unit tests for all renamed/shared type mappers and versioned quote parsing.
- RPC tests covering:
  - legacy response shape
  - V2 response shape
  - invalid start/end ordering
  - missing start/base block
  - unsupported version requests
- SP1 tests covering:
  - legacy attestation verification
  - V2 attestation verification
  - event-proof binding still working in both modes
  - failure on tampered start/base-bound values
- Contract tests covering:
  - legacy report-data verification
  - V2 report-data verification
  - rejection of wrong version/layout combinations
- End-to-end integration tests from quote fetch through proof generation to on-chain verification.
- Manual validation with captured fixtures from a live TEE-enabled Katana instance.

## Rollout and Migration

- Stage 1: semantics cleanup only
  - rename internal variables
  - improve docs/logging
  - keep legacy RPC and contracts unchanged
- Stage 2: add V2 dual-mode support
  - new RPC response/versioning
  - new prover and contract handling
  - operator can choose legacy or V2
- Stage 3: canary rollout
  - enable V2 in non-production or test shard paths
  - compare outputs, proof success rate, and on-chain verification behavior
- Stage 4: production migration
  - switch operator default to V2
  - keep legacy fallback for a bounded window
- Stage 5: deprecate legacy
  - remove `prev_*` semantics from public docs
  - eventually remove legacy RPC path after consumers migrate

Rollback plan:
- Keep legacy quote generation path available until V2 is proven stable.
- Guard V2 with config flags so the operator can immediately fall back to legacy.
- Avoid changing storage commitment semantics and report-data layout in the same deploy unless dual verification is available.

## Verification Checklist

- `cargo test -p katana_tee_client`
- `cargo test -p amd_tee_registry_client`
- `cargo test -p katana-rpc-api`
- `cargo test -p katana-rpc-server tee -- --nocapture`
- `cargo test -p katana-rpc-server forking -- --nocapture`
- `cargo test` in `/home/michal/Repos/sharding_operator` for operator/client integration coverage
- Contract test suites for:
  - `/home/michal/Repos/katana-tee/contracts/katana_tee`
  - `/home/michal/Repos/katana-tee/contracts/storage_commitment`
  - `/home/michal/Repos/katana-tee/contracts/amd_tee_registry`
- Run fixture generation and ensure legacy and V2 fixtures both decode and verify.
- Manual RPC checks:
  - fetch a legacy quote and confirm response labels it as metadata-only for start/base info
  - fetch a V2 quote and confirm tampering with bound start/base values causes proof or contract verification failure
- End-to-end manual test:
  - quote fetch
  - SP1 proof generation
  - on-chain `verify_and_update_state`
  - storage commitment registration and verification

## Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Engineers continue to treat `prev_*` as attested even after partial cleanup | Med | High | Rename internal fields early, add explicit docs/logs, label legacy response mode |
| Breaking compatibility across RPC clients and operators | High | High | Dual-mode support, adapters, staged deprecation |
| V2 report-data layout becomes too large or awkward for current 64-byte assumptions | Med | High | Finalize compact binding format in Phase 0 before implementation |
| On-chain and SP1 version handling diverge | Med | High | Shared version spec, common fixtures, integration tests |
| Changing commitment semantics invalidates downstream verification assumptions | Med | High | Keep storage commitment unchanged unless strictly necessary; decide explicitly in Phase C.3 |
| Fixture churn slows development | High | Med | Separate legacy and V2 fixture pipelines and check them into CI |
| Rollout obscures root cause when failures happen across many components | Med | Med | Feature flags, versioned logs, canary rollout, compatibility matrix |

## Open Questions

- [ ] Should V2 bind only `start_block_number`, or must it also bind `start_block_hash` or `start_state_root` to have real security value?
- [ ] Should `block_number` itself become cryptographically bound in V2, or is binding the end block hash/root sufficient?
- [ ] Should journal output include the attested block number explicitly, not just `forkBlockNumber` and `endBlockNumber`?
- [ ] Should `storage_commitment` remain keyed by `global_state_root + end_block_number`, or should V2 range semantics also affect commitment replay protection?
- [ ] Is a new RPC method cleaner than overloading `tee_generateQuote` with options/versioning?
- [ ] What is the expected migration window for external consumers of the current `prev_*` fields?

## Decision Log

| Decision | Rationale | Alternatives Considered |
|----------|-----------|------------------------|
| Treat current `prev_*` fields as metadata, not as security inputs | Matches current implementation and avoids false guarantees | Pretend current fields are attested |
| Do terminology cleanup before cryptographic redesign | Low-risk improvement that reduces confusion immediately | Implement V2 first without cleanup |
| Prefer dual-mode migration over flag-day replacement | The change spans many components and external interfaces | Immediate breaking switch |
| Require an explicit Phase 0 decision on V2 binding payload | Security value depends on binding the right data, not just more fields | Ad-hoc implementation during coding |
