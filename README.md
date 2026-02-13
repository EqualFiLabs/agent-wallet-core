# Agent Wallet Core

Protocol-agnostic NFT-bound smart account core for ERC-6551 + ERC-6900 + ERC-4337 flows, with ERC-8128 session
authorization modules and ERC-8004 identity integration helpers.


## Standards Coverage

- ERC-6551: token-bound account surfaces (`token`, `owner`, `nonce`, `isValidSigner`, `execute`)
- ERC-6900: modular account + execution/validation module interfaces
- ERC-4337: `validateUserOp` and `executeUserOp` integration
- ERC-1271: smart-contract signature validation path
- ERC-6492: counterfactual signature wrapper support (via `OwnerValidationModule`)
- ERC-8128: SIWA v2 policy registry + gateway and AA session validation modules
- ERC-8004: identity registry integration helpers (via `ERC8004IdentityAdapter`)
- ERC-165: interface introspection
- ERC-721 receiver support

## Repository Layout

- `src/core/`
  - `NFTBoundMSCA.sol`: abstract modular account implementation
  - `ERC721BoundMSCA.sol`: account owner from `IERC721.ownerOf`
  - `ResolverBoundMSCA.sol`: account owner from `IOwnerResolver`
  - `ERC8128PolicyRegistry.sol`: unified onchain policy registry for ERC-8128 v2 modules
  - `BeaconProxy.sol`: optional beacon-mode account proxy
  - `BeaconGovernance.sol`: timelock queue/execute/cancel upgrade helper
  - `DirectDeploymentFactory.sol`: helper for direct (non-beacon) deployment
- `src/modules/validation/`
  - `OwnerValidationModule.sol`: owner auth with EIP-712 + ERC-6492 + ERC-1271 paths
  - `SessionKeyValidationModule.sol`: scoped session key auth/policies
  - `ERC8128GatewayValidationModuleV2.sol`: ERC-8128 gateway (`validateSignature`) session validation
  - `ERC8128AAValidationModuleV2.sol`: ERC-8128 ERC-4337 (`validateUserOp`) session validation
- `src/libraries/`
  - `MSCAStorage.sol`: ERC-7201 namespaced storage slot
  - `ExecutionFlowLib.sol`: hook routing, depth/gas/recursion guards
  - `ValidationFlowLib.sol`, `ExecutionManagementLib.sol`, `ValidationManagementLib.sol`
  - `TokenDataLib.sol`: ERC-6551 footer extraction
  - `EIP712DomainLib.sol`: canonical domain serialize/parse helper
  - `ERC8128CoreLib.sol`, `ERC8128Types.sol`: ERC-8128 v2 hashing, auth types, and signer helpers
- `src/adapters/`
  - `IOwnerResolver.sol`, `ERC721OwnerResolver.sol`
  - `ERC8004IdentityAdapter.sol`: optional identity registration helper
- `src/interfaces/`
  - ERC-6900, ERC-6551, ERC-165, and registry interfaces

## Core Account Behavior

### Ownership

- `NFTBoundMSCA` delegates ownership to abstract `_owner()`.
- `ERC721BoundMSCA` resolves owner from bound token `(chainId, tokenContract, tokenId)`.
- `ResolverBoundMSCA` resolves owner via `IOwnerResolver`.
- `ResolverBoundMSCA` supports owner-configurable resolver updater role for governance/timelock flows.

### Bootstrap Lifecycle

- Accounts start with bootstrap enabled (`_bootstrapActive = true`).
- Bootstrap can be disabled once via `disableBootstrap()`.
- Disable is irreversible and emits `BootstrapDisabled`.

### Module Management

- Supports install/uninstall for execution and validation modules.
- Prevents module self-modification.
- Enforces selector conflict checks for native account selectors.

### Runtime Envelope Validation

- Fallback runtime validation path enforces strict ABI envelope shape for `(bytes data, bytes authorization)`.
- Invalid fallback payloads fail early before decode/execution.

### Hook Safety

`ExecutionFlowLib` enforces:

- Max hook depth: `8`
- Max cumulative hook gas budget: `13_000_000`
- Recursion guard during hook execution

## Validation Modules

### OwnerValidationModule

- Module ID: `agent.wallet.owner-validation.1.0.0`
- Validates user ops and signatures against current account owner
- EIP-712 typed digesting per account
- ERC-6492 counterfactual signature wrapper support
- ERC-1271 delegation support for smart contract owners
- For ERC-6492 signatures, the module can execute wrapped factory calldata and then validate the inner signature

### SessionKeyValidationModule

- Module ID: `agent.wallet.session-validation.1.0.0`
- Session policy shape checks:
  - non-empty selector policy
  - execution selectors require target allowlist
- Time-window checks (`validAfter`/`validUntil`)
- Per-key nonce revocation + epoch-based bulk revocation
- Per-policy budget tracking and enforcement
- Runtime replay protection via consumed replay digests

### ERC8128GatewayValidationModuleV2

- Module ID: `agent.wallet.erc8128-gateway-validation.2.0.0`
- ERC-6900 gateway validation module for ERC-1271-style signatures
- Validates policy activity, epoch/policy nonce binding, session windows, and scope proofs

### ERC8128AAValidationModuleV2

- Module ID: `agent.wallet.erc8128-aa-validation.2.0.0`
- ERC-6900 validation module for ERC-4337 `validateUserOp`
- Supports install-time selector/TTL presets and per-call Merkle-scoped claim validation

## Optional Components

### ERC8004IdentityAdapter

Optional helper adapter (not an ERC-6900 module) to:

- build canonical ERC-8004 calldata for register/update calls
- decode registration result payloads
- record verified `account -> agentId` mappings
- expose mapping helper views
- integrate with ERC-8004 Identity Registry ownership checks (`ownerOf(agentId)`)

This repository does not implement full ERC-8004 registries (identity/reputation/validation). It provides account-side
integration helpers for identity registration flows.

### Beacon Mode

- `BeaconProxy` delegates to implementation from an `IBeacon`
- `BeaconGovernance` provides timelocked queue/execute/cancel for:
  - beacon implementation upgrades
  - resolver target updates

### Direct Mode

- Deploy immutable account implementations directly
- Helpers:
  - `DirectDeploymentFactory`
  - `script/DirectDeploymentHelpers.s.sol`

## Build and Test

### Requirements

- Foundry (`forge`, `cast`, `anvil`)
- Solidity `0.8.33` (configured in `foundry.toml`)

### Commands

```bash
forge build
forge test -vv
```

Fuzz run count is configured at `256` in `foundry.toml`.

Continuous integration also runs `forge test -vv` in GitHub Actions:

- `.github/workflows/forge-test.yml`

## Integrating as a Submodule

Example consumer wiring:

```bash
git submodule add https://github.com/EqualFiLabs/agent-wallet-core lib/agent-wallet-core
```

Add a remapping in the consumer repository:

```text
@agent-wallet-core/=lib/agent-wallet-core/src/
```

Then import from the submodule namespace, for example:

```solidity
import {ERC721BoundMSCA} from "@agent-wallet-core/core/ERC721BoundMSCA.sol";
import {IERC6900ExecutionModule} from "@agent-wallet-core/interfaces/IERC6900ExecutionModule.sol";
```

## Security Notes

- Modules are powerful and should be treated as trusted code.
- Use strict install governance and review module manifests carefully.
- Session keys should be scoped tightly (targets, selectors, limits, expirations).
- Prefer timelocked governance for upgradeable deployments.
