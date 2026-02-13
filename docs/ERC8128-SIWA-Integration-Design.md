# ERC-8128 Signed HTTP Requests with Ethereum Integration Design

Status: Draft

## Summary

This document describes how Agent Wallet Core integrates with [ERC-8128](https://eips.ethereum.org/EIPS/eip-8128) (Signed HTTP Requests with Ethereum) to provide session-based delegation for smart contract accounts authenticating HTTP requests. ERC-8128 defines how Ethereum accounts sign and verify HTTP requests using [RFC 9421 HTTP Message Signatures](https://www.rfc-editor.org/rfc/rfc9421). When the signing account is a Smart Contract Account (SCA), the verifier calls `isValidSignature` (ERC-1271) on the account to validate the request. This architecture provides the onchain policy and validation layer that makes SCA-based ERC-8128 signing practical.

The v2 design unifies two validation paths — gateway (ERC-1271) and account abstraction (ERC-4337) — under a single onchain policy registry and a shared cryptographic envelope. Both paths read from the same policy state, share the same revocation model, and use the same EIP-712 typed-data scheme for inner session delegation signatures.

Core outcomes:
- single policy registry and revocation model across gateway and AA validation
- canonical `SessionAuthV2` envelope with explicit mode binding
- EIP-712 typed signing for inner session delegation (does not replace ERC-8128 outer HTTP signatures)
- per-call AA scope verification including `executeBatch(...)` via Merkle multiproof
- guardian emergency controls, install-time presets, and normalized eventing

## Scope

In scope:
- ERC-8128 gateway signature path (`validateSignature` / ERC-1271)
- ERC-4337 path (`validateUserOp`) with AA call constraints
- unified policy storage, revocation, and digest conventions
- security model and test strategy

Out of scope:
- ERC-8128 outer HTTP signature construction and verification (handled by the offchain gateway)
- RFC 9421 parsing, canonicalization, and replay store implementation
- v1 backward compatibility (this is a clean-break v2)
- trustless onchain reconstruction of raw HTTP traffic

## Design Goals

1. Consistency: identical policy semantics across gateway and AA modules.
2. Safety: bounded delegation blast radius for both API and onchain execution.
3. Explicitness: payloads bind mode, module, account, chain, and policy epoch/nonce.
4. Efficiency: compact policy storage (Merkle root), scalable batch verification (multiproof).
5. Operability: emergency controls and deterministic revocation propagation.

## Non-Goals

1. One module for all paths at runtime. Dedicated modules are kept, but they share policy and logic.
2. Hidden defaults. Security-sensitive behavior is explicit and testable.
3. Replacing ERC-8128 HTTP signature construction or verification.

## ERC-8128 Compliance Profile

This v2 design is an extension around ERC-8128, not a replacement for ERC-8128 core verification semantics.

### Relationship to ERC-8128

ERC-8128 defines how an Ethereum account signs and verifies HTTP requests:
1. The client selects HTTP request components (method, authority, path, query, content-digest) and constructs a signature base `M` per RFC 9421.
2. The client computes `H = keccak256("\x19Ethereum Signed Message:\n" || len(M) || M)` and signs `H`.
3. The verifier reconstructs `M`, recomputes `H`, and verifies the signature — either by ECDSA recovery (EOA) or by calling `isValidSignature(H, sig)` on the SCA (ERC-1271).

This architecture handles step 3 for SCAs. When the gateway calls `isValidSignature`, the account delegates to the gateway validation module, which validates the session delegation envelope and returns the ERC-1271 magic value if the session key is authorized.

```mermaid
sequenceDiagram
    participant Client as HTTP Client
    participant Gateway as API Gateway<br/>(ERC-8128 Verifier)
    participant SCA as Smart Contract Account<br/>(ERC-1271)
    participant Module as Gateway Validation Module
    participant Registry as Policy Registry

    Note over Client,Gateway: ERC-8128 outer signature flow
    Client->>Gateway: HTTP request with Signature-Input + Signature headers
    Gateway->>Gateway: Parse RFC 9421 Signature-Input for label
    Gateway->>Gateway: Reconstruct signature base M from request
    Gateway->>Gateway: Compute H = keccak256(ERC-191 prefix || M)
    Gateway->>Gateway: Parse keyid → chain-id + address
    Gateway->>Gateway: Determine account type (EOA or SCA)

    Note over Gateway,Registry: SCA verification path (this architecture)
    Gateway->>SCA: isValidSignature(H, sessionAuthEnvelope)
    SCA->>Module: validateSignature(account, entityId, caller, H, envelope)
    Module->>Module: Decode SessionAuthV2 envelope
    Module->>Module: Verify mode == gateway, requestHash == H
    Module->>Registry: getPolicy(account, entityId, sessionKey)
    Registry-->>Module: policy, epoch, policyNonce
    Module->>Registry: isPolicyActive(account, entityId, sessionKey)
    Registry-->>Module: active status
    Module->>Module: Validate time windows, TTL, claims hash
    Module->>Module: Verify gateway claims (scope leaf, Merkle proof)
    Module->>Module: Verify EIP-712 session signature
    Module-->>SCA: ERC-1271 magic value (or invalid)
    SCA-->>Gateway: ERC-1271 result
    Gateway-->>Client: HTTP response
```

### Conformance Matrix

| ERC-8128 Requirement | Enforcement Location | Notes |
|---|---|---|
| Request-Bound minimum covered components | Gateway verifier (offchain) | RFC 9421 parsing and policy checks |
| Non-Replayable signatures MUST include `nonce` | Gateway verifier + `GatewayClaimsV2.nonceHash` | Nonce binding verified in module |
| Verifier MUST enforce (`keyid`, `nonce`) uniqueness | Gateway replay store (offchain) | Atomic check+insert in gateway |
| Verifier MUST reject Non-Replayable when validity exceeds retention window | Gateway replay policy (offchain) | Retention-window guard |
| Baseline: MUST accept Request-Bound + Non-Replayable | Gateway acceptance policy (offchain) | Preserved in v2 |
| `keyid` MUST be `erc8128:<chain-id>:<address>` | Gateway verifier + account resolution | Chain-scoped SCA/EOA resolution |
| `created`/`expires` time-window enforcement | Gateway verifier (outer) + module (inner) | Both layers enforce |
| Signature base `M` via RFC 9421, `H` via ERC-191 | Gateway verifier (offchain) | v2 does not alter `M`/`H` construction |
| EOA verification via ERC-191 | Gateway verifier (offchain) | Standard ECDSA recovery |
| SCA verification via ERC-1271 | Gateway verifier → module (onchain) | This architecture |
| Replayable acceptance requires early invalidation | Gateway replay policy (offchain) | Policy-driven |
| Invalidation endpoints require Request-Bound auth | Gateway/API policy layer | Deployment requirement |

## Architecture

### System Context

```mermaid
graph TB
    subgraph "Offchain"
        Client["HTTP Client<br/>(ERC-8128 Signer)"]
        Gateway["API Gateway<br/>(ERC-8128 Verifier)"]
        Bundler["ERC-4337 Bundler"]
    end

    subgraph "Onchain — Agent Wallet Core"
        SCA["Smart Contract Account<br/>(ERC-6551 + ERC-6900)"]
        GatewayMod["ERC8128GatewayValidationModuleV2<br/>(ERC-1271 path)"]
        AAMod["ERC8128AAValidationModuleV2<br/>(ERC-4337 path)"]
        Registry["ERC8128PolicyRegistry<br/>(shared policy state)"]
        CoreLib["ERC8128CoreLib<br/>(shared helpers)"]
    end

    subgraph "External"
        EntryPoint["ERC-4337 EntryPoint"]
    end

    Client -->|"HTTP request with<br/>ERC-8128 signature"| Gateway
    Gateway -->|"isValidSignature(H, envelope)"| SCA
    SCA -->|"validateSignature"| GatewayMod
    GatewayMod -->|"reads policy"| Registry
    GatewayMod -->|"uses"| CoreLib

    Client -->|"submits UserOp"| Bundler
    Bundler -->|"handleOps"| EntryPoint
    EntryPoint -->|"validateUserOp"| SCA
    SCA -->|"validateUserOp"| AAMod
    AAMod -->|"reads policy"| Registry
    AAMod -->|"uses"| CoreLib
```

### Component Responsibilities

```mermaid
graph LR
    subgraph "Policy Plane"
        Registry["ERC8128PolicyRegistry"]
    end

    subgraph "Validation Modules"
        GW["ERC8128GatewayValidationModuleV2"]
        AA["ERC8128AAValidationModuleV2"]
    end

    subgraph "Shared Library"
        Core["ERC8128CoreLib"]
        Types["ERC8128Types"]
    end

    GW -->|"reads"| Registry
    AA -->|"reads"| Registry
    GW -->|"uses"| Core
    AA -->|"uses"| Core
    GW -->|"uses"| Types
    AA -->|"uses"| Types
    Core -->|"uses"| Types
```

| Component | Responsibility |
|---|---|
| `ERC8128PolicyRegistry` | Canonical onchain registry for session policy state. Stores epoch, per-key policy nonce, policy config, scope roots, budget/rate controls. Emits all revocation/rotation/config events. |
| `ERC8128GatewayValidationModuleV2` | ERC-6900 validation module for the ERC-1271 path (`validateSignature`). Validates gateway-oriented claims against registry + scope proof. Rejects `validateUserOp` and `validateRuntime`. |
| `ERC8128AAValidationModuleV2` | ERC-6900 validation module for the ERC-4337 path (`validateUserOp`). Validates AA call claims (single or batch) against registry + Merkle proof/multiproof. Rejects `validateSignature` and `validateRuntime`. |
| `ERC8128CoreLib` | Shared pure/view helpers: key derivation, EIP-712 domain/struct hashing, scope leaf computation, claims hashing, session signer verification, validation data packing. |
| `ERC8128Types` | Canonical struct definitions: `SessionPolicyV2`, `SessionAuthV2`, `GatewayClaimsV2`, `AAClaimsV2`, `AACallClaimV2`, `ParsedCall`. |

### Contract Dependency Graph

```mermaid
classDiagram
    class ERC8128PolicyRegistry {
        +setPolicy(account, entityId, sessionKey, ...)
        +revokeSessionKey(account, entityId, sessionKey)
        +revokeAllSessionKeys(account, entityId)
        +rotateScopeRoot(account, entityId, sessionKey, newRoot)
        +setGuardian(account, entityId, guardian, enabled)
        +pausePolicy(account, entityId, sessionKey)
        +pauseEntity(account, entityId)
        +pauseAccount(account)
        +getPolicy(account, entityId, sessionKey) SessionPolicyV2
        +getEpoch(account, entityId) uint64
        +isGuardian(account, entityId, guardian) bool
        +isPolicyActive(account, entityId, sessionKey) bool
    }

    class ERC8128GatewayValidationModuleV2 {
        +registry: ERC8128PolicyRegistry
        +validateSignature(account, entityId, caller, hash, sig) bytes4
        +validateUserOp() → SIG_VALIDATION_FAILED
        +validateRuntime() → revert
        +moduleId() string
    }

    class ERC8128AAValidationModuleV2 {
        +registry: ERC8128PolicyRegistry
        +validateUserOp(entityId, userOp, userOpHash) uint256
        +validateSignature() → ERC1271_INVALID
        +validateRuntime() → revert
        +onInstall(data) — InstallPresetConfig
        +onUninstall(data) — UninstallPresetConfig
        +parseCalls(callData) ParsedCall[]
        +moduleId() string
    }

    class ERC8128CoreLib {
        <<library>>
        +domainSeparator(verifyingContract) bytes32
        +sessionAuthorizationHash(...) bytes32
        +computeDigest(domainSep, structHash) bytes32
        +basePolicyKey(account, entityId, sessionKey, epoch) bytes32
        +resolvedPolicyKey(baseKey, policyNonce) bytes32
        +computeGatewayScopeLeaf(...) bytes32
        +computeAAScopeLeaf(...) bytes32
        +computeGatewayClaimsHash(claims) bytes32
        +computeAAClaimsHash(claims) bytes32
        +isValidSessionSigner(sessionKey, digest, sig) bool
        +packValidationData(aggregator, validUntil, validAfter) uint256
    }

    class IERC6900ValidationModule {
        <<interface>>
        +validateUserOp(entityId, userOp, userOpHash) uint256
        +validateSignature(account, entityId, caller, hash, sig) bytes4
        +validateRuntime(account, entityId, sender, value, data, auth)
    }

    ERC8128GatewayValidationModuleV2 ..|> IERC6900ValidationModule
    ERC8128AAValidationModuleV2 ..|> IERC6900ValidationModule
    ERC8128GatewayValidationModuleV2 --> ERC8128PolicyRegistry : reads
    ERC8128AAValidationModuleV2 --> ERC8128PolicyRegistry : reads
    ERC8128GatewayValidationModuleV2 --> ERC8128CoreLib : uses
    ERC8128AAValidationModuleV2 --> ERC8128CoreLib : uses
```

## Canonical Data Model

### Struct Definitions

```solidity
struct SessionPolicyV2 {
    bool active;
    uint48 validAfter;
    uint48 validUntil;       // 0 = unbounded
    uint32 maxTtlSeconds;
    bytes32 scopeRoot;       // Merkle root of allowed scope leaves
    uint64 maxCallsPerPeriod;
    uint128 maxValuePerPeriod;
    uint48 periodSeconds;
    bool paused;
}

struct SessionAuthV2 {
    uint8 mode;              // 0 = gateway, 1 = AA
    address sessionKey;
    uint64 epoch;
    uint64 policyNonce;
    uint48 created;
    uint48 expires;
    bytes32 requestHash;     // gateway: H from ERC-8128, AA: userOpHash
    bytes32 claimsHash;      // keccak256(abi.encode(mode-specific claims))
    bytes sessionSignature;  // EIP-712 typed-data signature by sessionKey
    bytes claims;            // ABI-encoded mode-specific claims
}

struct GatewayClaimsV2 {
    uint16 methodBit;
    bytes32 authorityHash;
    bytes32 pathPrefixHash;
    bool isReadOnly;
    bool allowReplayable;
    bool allowClassBound;
    uint32 maxBodyBytes;
    bool isReplayable;
    bool isClassBound;
    bytes32 nonceHash;
    bytes32 scopeLeaf;
    bytes32[] scopeProof;
}

struct AACallClaimV2 {
    address target;
    bytes4 selector;
    uint256 valueLimit;
    bool allowDelegateCall;
    bytes32 scopeLeaf;
    bytes32[] scopeProof;    // used for single-call proofs
}

struct AAClaimsV2 {
    AACallClaimV2[] callClaims;
    bytes32[] multiproof;    // used for batch Merkle multiproof
    bool[] proofFlags;
    bytes32 leafOrderHash;   // optional: binds call ordering
}
```

### Policy Keying

Policy state is keyed by a two-level hash:

```
basePolicyKey  = keccak256(account, entityId, sessionKey, epoch)
resolvedPolicyKey = keccak256(basePolicyKey, policyNonce)
```

This enables two revocation granularities:
- Incrementing `epoch` invalidates all session keys for an `(account, entityId)` pair.
- Incrementing `policyNonce` invalidates a single session key without affecting others.

```mermaid
graph TD
    A["account + entityId + sessionKey + epoch"] -->|keccak256| B["basePolicyKey"]
    B -->|"+ policyNonce"| C["resolvedPolicyKey"]
    C -->|"maps to"| D["SessionPolicyV2"]

    E["revokeAllSessionKeys"] -->|"epoch++"| A
    F["revokeSessionKey"] -->|"policyNonce++"| B
```

## Cryptographic Scheme

### Two-Layer Signature Model

The architecture uses a two-layer signature model. The outer layer is ERC-8128 (handled by the offchain gateway). The inner layer is EIP-712 (handled by the onchain modules).

```mermaid
graph TB
    subgraph "Outer Layer — ERC-8128 (Offchain Gateway)"
        M["RFC 9421 Signature Base M"]
        H["H = keccak256(ERC-191 prefix || M)"]
        OuterSig["Outer Signature over H<br/>(EOA: ECDSA, SCA: ERC-1271)"]
    end

    subgraph "Inner Layer — EIP-712 (Onchain Module)"
        Domain["EIP-712 Domain Separator<br/>name=AgentWalletERC8128, version=2<br/>chainId, verifyingContract=module"]
        Struct["SessionAuthorizationV2 struct hash<br/>(mode, account, entityId, sessionKey,<br/>epoch, policyNonce, created, expires,<br/>requestHash, claimsHash)"]
        Digest["digest = keccak256(0x1901 || domainSep || structHash)"]
        InnerSig["Session Signature over digest<br/>(EOA sessionKey: ECDSA,<br/>SCA sessionKey: ERC-1271)"]
    end

    M --> H
    H --> OuterSig
    OuterSig -->|"SCA path: isValidSignature(H, envelope)"| Domain
    Domain --> Digest
    Struct --> Digest
    Digest --> InnerSig
```

### EIP-712 Domain

```
name            = "AgentWalletERC8128"
version         = "2"
chainId         = block.chainid
verifyingContract = module address
```

The `verifyingContract` is the module address (gateway or AA), not the account address. This prevents cross-module replay: a session signature created for the gateway module cannot be accepted by the AA module, and vice versa.

### EIP-712 Typed Struct

```
SessionAuthorizationV2(
    uint8 mode,
    address account,
    uint32 entityId,
    address sessionKey,
    uint64 epoch,
    uint64 policyNonce,
    uint48 created,
    uint48 expires,
    bytes32 requestHash,
    bytes32 claimsHash
)
```

### Mandatory Bindings

The inner signature binds:
- `mode` — prevents gateway ↔ AA replay
- `account` — prevents cross-account replay
- `entityId` — prevents cross-entity replay
- `verifyingContract` (via domain) — prevents cross-module replay
- `chainId` (via domain) — prevents cross-chain replay
- `requestHash` — binds to the specific outer request (`H` for gateway, `userOpHash` for AA)
- `claimsHash` — binds to the exact claims payload, preventing claim tampering

## Validation Flows

### Gateway Validation (ERC-1271 Path)

The gateway module handles `validateSignature` calls from the account when an offchain ERC-8128 verifier calls `isValidSignature(H, sig)`.

```mermaid
flowchart TD
    A["validateSignature(account, entityId, caller, H, signature)"] --> B["Decode SessionAuthV2 from signature"]
    B -->|"decode fails"| INVALID
    B --> C{"mode == 0 (gateway)?"}
    C -->|No| INVALID
    C -->|Yes| D{"requestHash == H?"}
    D -->|No| INVALID
    D -->|Yes| E{"sessionKey != address(0)?"}
    E -->|No| INVALID
    E -->|Yes| F["Decode GatewayClaimsV2 from auth.claims"]
    F -->|"decode fails"| INVALID
    F --> G{"claimsHash == hash(claims)?"}
    G -->|No| INVALID
    G -->|Yes| H["Load policy from registry"]
    H --> I{"isPolicyActive?"}
    I -->|No| INVALID
    I -->|Yes| J{"epoch + policyNonce match?"}
    J -->|No| INVALID
    J -->|Yes| K{"Within policy time window?"}
    K -->|No| INVALID
    K -->|Yes| L{"created < expires?<br/>TTL within maxTtlSeconds?"}
    L -->|No| INVALID
    L -->|Yes| M{"Replay/class-bound<br/>constraints valid?"}
    M -->|No| INVALID
    M -->|Yes| N{"Scope leaf preimage<br/>matches recomputed leaf?"}
    N -->|No| INVALID
    N -->|Yes| O{"Merkle proof verifies<br/>against policy.scopeRoot?"}
    O -->|No| INVALID
    O -->|Yes| P["Compute EIP-712 digest"]
    P --> Q{"Session signature valid<br/>for sessionKey?"}
    Q -->|No| INVALID
    Q -->|Yes| VALID["Return ERC1271_MAGICVALUE"]

    INVALID["Return ERC1271_INVALID"]
```

### Gateway Claims Constraints

The gateway module enforces these constraints on `GatewayClaimsV2`:

| Constraint | Rule |
|---|---|
| Non-replayable nonce binding | If `!isReplayable`, then `nonceHash != bytes32(0)` |
| Replayable permission | If `isReplayable`, then `allowReplayable` must be true |
| Class-bound permission | If `isClassBound`, then `allowClassBound` must be true |
| Read-only enforcement | If `isReplayable` or `isClassBound`, then `isReadOnly` must be true |
| Scope leaf integrity | Recomputed leaf from preimage fields must match `scopeLeaf` |
| Scope membership | `scopeLeaf` must verify against `policy.scopeRoot` via Merkle proof |

### Scope Leaf Construction (Gateway)

```
scopeLeaf = keccak256(abi.encode(
    "AW_ERC8128_SCOPE_LEAF_V2",
    methodBit,
    authorityHash,
    pathPrefixHash,
    isReadOnly,
    allowReplayable,
    allowClassBound,
    maxBodyBytes
))
```

### AA Validation (ERC-4337 Path)

The AA module handles `validateUserOp` calls from the account during ERC-4337 UserOperation validation.

```mermaid
flowchart TD
    A["validateUserOp(entityId, userOp, userOpHash)"] --> B["Decode SessionAuthV2 from userOp.signature"]
    B -->|"decode fails"| FAILED
    B --> C{"mode == 1 (AA)?"}
    C -->|No| FAILED
    C -->|Yes| D{"requestHash == userOpHash?"}
    D -->|No| FAILED
    D -->|Yes| E{"sessionKey != address(0)?"}
    E -->|No| FAILED
    E -->|Yes| F{"Install preset initialized?<br/>Top-level selector allowed?"}
    F -->|No| FAILED
    F -->|Yes| G["Parse calls from userOp.callData"]
    G -->|"unsupported or empty"| FAILED
    G --> H["Decode AAClaimsV2 from auth.claims"]
    H -->|"decode fails"| FAILED
    H --> I{"claimsHash == hash(claims)?"}
    I -->|No| FAILED
    I -->|Yes| J{"callClaims.length == parsedCalls.length?"}
    J -->|No| FAILED
    J -->|Yes| K["Load policy from registry"]
    K --> L{"isPolicyActive?<br/>epoch + policyNonce match?<br/>Time windows valid?<br/>TTL within bounds?"}
    L -->|No| FAILED
    L -->|Yes| M["For each call: verify target, selector,<br/>value ≤ valueLimit, delegatecall constraints,<br/>scope leaf integrity"]
    M -->|"any mismatch"| FAILED
    M --> N{"Batch? Verify multiproof<br/>Single? Verify per-leaf proof"}
    N -->|"proof fails"| FAILED
    N -->|Yes| O{"leafOrderHash binding<br/>(if non-zero)?"}
    O -->|"mismatch"| FAILED
    O -->|Yes| P["Compute EIP-712 digest"]
    P --> Q{"Session signature valid?"}
    Q -->|No| FAILED
    Q -->|Yes| R["Pack validationData<br/>(validAfter, validUntil)"]

    FAILED["Return SIG_VALIDATION_FAILED"]
```

### Supported Execution Selectors (AA)

The AA module parses calls from three execution selectors:

| Selector | Signature | Behavior |
|---|---|---|
| `execute` | `execute(address,uint256,bytes)` | Single call, no delegatecall |
| `execute` (with operation) | `execute(address,uint256,bytes,uint8)` | Single call, operation 0=CALL, 1=DELEGATECALL. Delegatecall with value > 0 is rejected. |
| `executeBatch` | `executeBatch((address,uint256,bytes)[])` | Batch calls, no delegatecall. Uses Merkle multiproof for scope verification. |

### Scope Leaf Construction (AA)

```
scopeLeaf = keccak256(abi.encode(
    "AW_ERC8128_AA_SCOPE_LEAF_V2",
    target,
    selector,
    valueLimit,
    allowDelegateCall
))
```

### AA Install Presets

The AA module requires an install-time preset configuration before it will accept any `validateUserOp` calls. This provides secure defaults and prevents unconstrained session validation.

```solidity
struct InstallPresetConfig {
    address account;
    uint32 entityId;
    bytes4[] allowedSelectors;    // top-level selectors the module will accept
    bool defaultAllowDelegateCall;
    uint32 minTtlSeconds;         // minimum session TTL
    uint32 maxTtlSeconds;         // maximum session TTL (0 = no upper bound)
}
```

The preset is installed by the account itself (`msg.sender == config.account`) and enforces:
- only listed top-level selectors are accepted
- TTL must fall within `[minTtlSeconds, maxTtlSeconds]`
- delegatecall is blocked unless explicitly allowed per-claim or via `defaultAllowDelegateCall`

## Policy Registry

### Overview

`ERC8128PolicyRegistry` is the single source of truth for all session policy state. Both validation modules read from it. All policy mutations (set, revoke, rotate, pause) are performed through the registry by the account owner or authorized guardians.

### Authorization Model

```mermaid
flowchart TD
    A["Policy mutation called"] --> B{"Which operation?"}
    B -->|"setPolicy, revokeSessionKey,<br/>revokeAllSessionKeys,<br/>rotateScopeRoot, setGuardian"| C["Require account owner"]
    B -->|"pausePolicy, pauseEntity,<br/>pauseAccount"| D["Require guardian OR owner"]

    C --> E["Resolve owner via<br/>IERC6551Account(account).owner()"]
    E --> F{"msg.sender == owner?"}
    F -->|No| G["revert NotAccountOwner"]
    F -->|Yes| H["Execute operation"]

    D --> I["Resolve owner"]
    I --> J{"msg.sender == owner?"}
    J -->|Yes| H
    J -->|No| K{"isGuardian(account, entityId, msg.sender)<br/>OR isGuardian(account, 0, msg.sender)?"}
    K -->|No| L["revert Unauthorized"]
    K -->|Yes| H
```

### Revocation Model

```mermaid
sequenceDiagram
    participant Owner as Account Owner
    participant Registry as ERC8128PolicyRegistry
    participant GW as Gateway Module
    participant AA as AA Module

    Note over Owner,AA: Single session key revocation
    Owner->>Registry: revokeSessionKey(account, entityId, sessionKey)
    Registry->>Registry: policyNonce++ for basePolicyKey
    Registry-->>Registry: emit PolicyRevokedV2
    Note over GW,AA: Both modules now reject: auth.policyNonce != current

    Note over Owner,AA: Mass revocation (all session keys for entity)
    Owner->>Registry: revokeAllSessionKeys(account, entityId)
    Registry->>Registry: epoch++ for (account, entityId)
    Registry-->>Registry: emit EpochRevokedV2
    Note over GW,AA: Both modules now reject: auth.epoch != current

    Note over Owner,AA: Scope rotation (invalidates old scope proofs)
    Owner->>Registry: rotateScopeRoot(account, entityId, sessionKey, newRoot)
    Registry->>Registry: Update policy.scopeRoot
    Registry-->>Registry: emit ScopeRootRotatedV2
    Note over GW,AA: Both modules now reject: old Merkle proofs fail
```

### Guardian Emergency Controls

Guardians provide an emergency pause mechanism that does not require the account owner's private key. This is useful for incident response when a session key may be compromised.

| Function | Scope | Authorization |
|---|---|---|
| `pausePolicy(account, entityId, sessionKey)` | Single session key | Guardian for entityId or entity 0, or owner |
| `pauseEntity(account, entityId)` | All session keys for entity | Guardian for entityId or entity 0, or owner |
| `pauseAccount(account)` | All session keys for account | Guardian for entity 0, or owner |

Guardian assignment is entity-scoped. A guardian assigned to `entityId = 0` has cross-entity pause authority for that account.

```mermaid
graph TD
    subgraph "Pause Hierarchy"
        AccountPause["pauseAccount<br/>Affects: all entities, all keys"]
        EntityPause["pauseEntity<br/>Affects: all keys for entity"]
        PolicyPause["pausePolicy<br/>Affects: single key"]
    end

    AccountPause --> EntityPause
    EntityPause --> PolicyPause

    subgraph "isPolicyActive checks"
        Check1["policy.active?"]
        Check2["policy.paused?"]
        Check3["entityPaused[account][entityId]?"]
        Check4["accountPaused[account]?"]
    end

    Check1 -->|"all must pass"| Check2
    Check2 --> Check3
    Check3 --> Check4
```

### Events

| Event | Parameters | Emitted When |
|---|---|---|
| `PolicySetV2` | account, entityId, sessionKey, policyNonce, validAfter, validUntil, maxTtlSeconds, scopeRoot, maxCallsPerPeriod, maxValuePerPeriod, periodSeconds | New policy created |
| `PolicyRevokedV2` | account, entityId, sessionKey, policyNonce | Session key revoked (policyNonce incremented) |
| `EpochRevokedV2` | account, entityId, epoch | All session keys revoked (epoch incremented) |
| `ScopeRootRotatedV2` | account, entityId, sessionKey, policyNonce, scopeRoot | Scope root updated |
| `GuardianPauseSetV2` | account, entityId, sessionKey, paused | Pause state changed |

## Shared Core Library

`ERC8128CoreLib` provides deterministic, pure/view helpers used by both modules. This eliminates logic duplication and ensures both validation paths compute identical digests, keys, and leaves.

### Key Functions

| Function | Purpose |
|---|---|
| `domainSeparator(verifyingContract)` | EIP-712 domain separator for current chain |
| `domainSeparatorForChain(chainId, verifyingContract)` | EIP-712 domain separator for arbitrary chain |
| `sessionAuthorizationHash(...)` | EIP-712 struct hash for `SessionAuthorizationV2` |
| `computeDigest(domainSep, structHash)` | Final EIP-712 digest: `keccak256(0x1901 \|\| domainSep \|\| structHash)` |
| `basePolicyKey(account, entityId, sessionKey, epoch)` | First-level policy key |
| `resolvedPolicyKey(baseKey, policyNonce)` | Second-level policy key |
| `computeGatewayScopeLeaf(...)` | Tagged scope leaf for gateway claims |
| `computeAAScopeLeaf(...)` | Tagged scope leaf for AA claims |
| `computeGatewayClaimsHash(claims)` | Hash commitment for gateway claims |
| `computeAAClaimsHash(claims)` | Hash commitment for AA claims |
| `isValidSessionSigner(sessionKey, digest, sig)` | Verify session signature (EOA via ECDSA recovery, SCA via ERC-1271) |
| `packValidationData(aggregator, validUntil, validAfter)` | Pack ERC-4337 validation data |
| `serializeDomain(verifyingContract)` / `parseDomain(encoded)` | EIP-712 domain string round-trip |

### Session Signer Verification

The library supports both EOA and SCA session keys:

```mermaid
flowchart TD
    A["isValidSessionSigner(sessionKey, digest, signature)"] --> B{"sessionKey.code.length == 0?"}
    B -->|"Yes (EOA)"| C["ECDSA.tryRecover(digest, signature)"]
    C --> D{"recovered == sessionKey?"}
    D -->|Yes| E["return true"]
    D -->|No| F["return false"]

    B -->|"No (SCA)"| G["staticcall sessionKey.isValidSignature(digest, signature)"]
    G --> H{"returns ERC1271_MAGICVALUE?"}
    H -->|Yes| E
    H -->|No| F
```

## Security Considerations

### Cross-Module Replay Prevention

A session signature is bound to a specific module via the EIP-712 `verifyingContract` field. A signature created for the gateway module produces a different digest than one created for the AA module, even with identical parameters. This prevents:

- A gateway session envelope from being accepted by the AA module
- An AA session envelope from being accepted by the gateway module
- A session envelope signed against one deployment from being accepted by another

### Cross-Mode Replay Prevention

The `mode` field (0 = gateway, 1 = AA) is included in the EIP-712 struct hash. Each module checks that the mode matches its expected value before proceeding with validation. A gateway envelope with `mode = 0` is rejected by the AA module (which expects `mode = 1`), and vice versa.

### Claims Hash Binding

The `claimsHash` field in `SessionAuthV2` is a `keccak256` commitment to the ABI-encoded claims payload. The session signature covers `claimsHash` via the EIP-712 struct. If any field in the claims is tampered with after signing, the recomputed hash will not match `claimsHash`, and validation fails before the session signature is even checked.

### Request Hash Binding

The `requestHash` field binds the session envelope to a specific outer request:
- For gateway: `requestHash` must equal `H` (the ERC-8128 hash passed to `isValidSignature`)
- For AA: `requestHash` must equal `userOpHash` (the ERC-4337 UserOperation hash)

This prevents a session envelope from being reused across different requests.

### Scope Leaf Integrity

Scope leaves are recomputed from their preimage fields and compared against the claimed `scopeLeaf`. This prevents an attacker from substituting a valid Merkle proof for a different leaf. The tagged prefix (`AW_ERC8128_SCOPE_LEAF_V2` / `AW_ERC8128_AA_SCOPE_LEAF_V2`) prevents cross-domain leaf collisions between gateway and AA scope trees.

### Trust Assumptions

1. The offchain gateway is trusted to correctly implement ERC-8128 outer signature verification (RFC 9421 parsing, ERC-191 hashing, replay store).
2. The `IERC6551Account.owner()` implementation is trusted to return the correct owner for authorization checks in the registry.
3. The ERC-4337 EntryPoint is trusted to correctly invoke `validateUserOp` and enforce the returned validation data.
4. OpenZeppelin's `MerkleProof` and `ECDSA` libraries are trusted for cryptographic correctness.

### Attack Surface

| Vector | Mitigation |
|---|---|
| Session key compromise | Revoke via `revokeSessionKey` or `pausePolicy`. Guardian can pause without owner key. |
| Mass session key compromise | `revokeAllSessionKeys` increments epoch, invalidating all keys for the entity. |
| Scope escalation | Merkle proof verification against `scopeRoot`. Leaf preimage recomputation prevents substitution. |
| Cross-module replay | EIP-712 `verifyingContract` binding to module address. |
| Cross-mode replay | `mode` field in EIP-712 struct hash + module-level mode check. |
| Cross-chain replay | EIP-712 `chainId` binding. |
| Claims tampering | `claimsHash` commitment in signed struct. |
| Delegatecall abuse (AA) | Per-claim `allowDelegateCall` flag + install preset `defaultAllowDelegateCall`. Delegatecall with value > 0 rejected. |
| Unbounded session TTL | `maxTtlSeconds` in policy + `minTtlSeconds`/`maxTtlSeconds` in AA install preset. |
| Stale policy after rotation | Scope root rotation invalidates old proofs. Epoch/nonce rotation invalidates old signatures. |

## Interaction with Other Standards

### ERC-8128 (Signed HTTP Requests with Ethereum)

This architecture is the SCA verification backend for ERC-8128. The offchain gateway handles all ERC-8128 concerns (RFC 9421 parsing, signature base construction, ERC-191 hashing, replay store, nonce enforcement). When the `keyid` in the ERC-8128 signature resolves to an SCA, the gateway calls `isValidSignature(H, sig)` on the account, which delegates to the gateway validation module.

### ERC-6900 (Modular Smart Contract Accounts)

Both validation modules implement `IERC6900ValidationModule` and are installed into the account's module registry. They participate in the ERC-6900 validation flow:
- Gateway module: `validateSignature` (ERC-1271 path)
- AA module: `validateUserOp` (ERC-4337 path)

Neither module implements `validateRuntime` (both revert).

### ERC-6551 (Token Bound Accounts)

The policy registry uses `IERC6551Account(account).owner()` to authorize policy mutations. This means the registry works with any account that implements the ERC-6551 `owner()` interface, including `ERC721BoundMSCA` and `ResolverBoundMSCA`.

### ERC-4337 (Account Abstraction)

The AA module returns packed validation data compatible with the ERC-4337 EntryPoint:
- `validAfter` = max(auth.created, policy.validAfter)
- `validUntil` = min(auth.expires, policy.validUntil) (or auth.expires if policy.validUntil == 0)
- `aggregator` = address(0) (no aggregator)

### ERC-1271 (Standard Signature Validation)

The gateway module returns `0x1626ba7e` (ERC-1271 magic value) on success and `0xffffffff` on failure. The account's ERC-1271 implementation delegates to the module via the ERC-6900 validation flow.

### ERC-8004 (Agent Identity Registry)

ERC-8004 agent identity and ERC-8128 HTTP authentication are complementary. An API gateway can resolve which agent identity is associated with a wallet making ERC-8128 authenticated requests by calling `ERC8004IdentityAdapter.getAgentId(account)` after verifying the ERC-8128 signature.

```mermaid
sequenceDiagram
    participant Agent as Agent Runtime
    participant Gateway as API Gateway
    participant SCA as Smart Contract Account
    participant Module as Gateway Validation Module
    participant Adapter as ERC8004IdentityAdapter

    Agent->>Gateway: HTTP request with ERC-8128 signature<br/>keyid=erc8128:1:0xAccount
    Gateway->>Gateway: Verify outer ERC-8128 signature
    Gateway->>SCA: isValidSignature(H, sessionAuthEnvelope)
    SCA->>Module: validateSignature(...)
    Module-->>SCA: ERC1271_MAGICVALUE
    SCA-->>Gateway: valid
    Gateway->>Adapter: getAgentId(0xAccount)
    Adapter-->>Gateway: agentId
    Gateway->>Gateway: Apply agent-specific policies
    Gateway-->>Agent: HTTP response
```

## Testing Strategy

### Test Organization

| Test File | Focus |
|---|---|
| `test/core/ERC8128PolicyRegistry.t.sol` | Policy storage, authorization, revocation, guardian controls |
| `test/libraries/ERC8128CoreLib.t.sol` | Digest computation, key derivation, scope leaves, signer verification |
| `test/modules/ERC8128GatewayValidationModuleV2.t.sol` | Gateway validation happy path and tamper rejection |
| `test/modules/ERC8128AAValidationModuleV2.t.sol` | AA validation, call parsing, multiproof, install presets |
| `test/modules/ERC8128V2CrossCutting.t.sol` | Cross-module revocation, scope rotation, replay prevention, claims/request hash binding |
| `test/modules/ERC8128V2UnitConformance.t.sol` | Interface conformance, edge cases, event emission |
| `test/gateway/ERC8128GatewayConformance.t.sol` | Gateway parity vectors (created/expires/nonce/body checks) |

### Property Tests (Fuzz)

| Property | Description |
|---|---|
| P1: Policy storage round-trip | Any valid policy written to the registry can be read back with identical fields. |
| P2: Non-owner authorization rejection | No non-owner caller can perform any policy mutation. |
| P3: Invalid time window rejection | `validUntil > 0 && validUntil <= validAfter` always reverts. |
| P4: Session key revocation invalidates both modules | After `revokeSessionKey`, both gateway and AA reject previously valid envelopes. |
| P5: Epoch revocation invalidates all session keys | After `revokeAllSessionKeys`, all session keys for the entity are rejected by both modules. |
| P6: Scope root rotation updates active policy | After `rotateScopeRoot`, old proofs fail and new proofs succeed on both modules. |
| P7: Guardian pause enforcement | Guardians can pause at policy/entity/account level; outsiders cannot. |
| P8: Guardian role management round-trip | Guardian assignment and revocation correctly gates pause authority. |
| P9: EIP-712 digest computation determinism | Domain separator, struct hash, and final digest match manual computation for all inputs. |
| P10: EIP-712 domain serialization round-trip | `serialize → parse → serialize` produces identical output. |
| P11: Scope leaf and claims hash determinism | All leaf and hash computations match manual `keccak256(abi.encode(...))` for all inputs. |
| P12: Valid gateway session signature acceptance | A correctly constructed gateway envelope is accepted. |
| P13: Gateway validation rejection on tampered fields | Tampering any field (mode, requestHash, epoch, policyNonce, nonce, replay flags, proof, signer, callHash) causes rejection. |
| P14: Valid AA session signature acceptance | A correctly constructed AA envelope is accepted with correct validationData. |
| P15: AA claim constraint enforcement | Mismatched cardinality, exceeded value limits, unauthorized delegatecall, and wrong targets are rejected. |
| P16: AA multiproof verification | Valid batch multiproofs are accepted; invalid multiproofs are rejected. |
| P17: Call parsing correctness | `execute`, `execute(…,uint8)`, and `executeBatch` are parsed correctly; unsupported selectors return `supported = false`. |
| P18: Cross-module and cross-mode replay prevention | Gateway envelopes are rejected by AA; AA envelopes signed with wrong domain are rejected. |
| P19: Install preset enforcement | Without preset: rejected. Wrong selector preset: rejected. Correct preset: accepted. After uninstall: rejected. |
| P20: Claims hash binding | Tampering claims payload (without re-signing) causes rejection on both modules. |
| P21: Request hash binding | Presenting a valid envelope against a different request/userOp hash causes rejection. |

### Gateway Conformance Vectors

The gateway conformance test suite (`ERC8128GatewayConformance.t.sol`) validates parity between offchain gateway parsing and onchain session envelope fields:

| Vector | Validates |
|---|---|
| Created mismatch | Reject when `Signature-Input.created != SessionAuth.created` |
| Expires mismatch | Reject when `Signature-Input.expires != SessionAuth.expires` |
| Nonce hash mismatch | Reject non-replayable request when parsed nonce hash differs |
| Body bytes exceeded | Reject when request body length exceeds `maxBodyBytes` |
| Request hash mismatch | Reject when outer `H` differs from `SessionAuth.requestHash` |
| Matching inputs | Accept when all fields match and ERC-1271 returns magic value |

## Deployment

### Deployment Order

1. Deploy `ERC8128PolicyRegistry`.
2. Deploy `ERC8128GatewayValidationModuleV2(registryAddress)`.
3. Deploy `ERC8128AAValidationModuleV2(registryAddress)`.
4. Install modules in target accounts via ERC-6900 module installation.
5. For AA module: call `onInstall` with `InstallPresetConfig` from the account.
6. Set policies via `registry.setPolicy(...)` from the account owner.
7. Optionally assign guardians via `registry.setGuardian(...)`.
8. Update offchain gateway to issue `SessionAuthV2` envelopes and verify via ERC-1271.

### Constructor Validation

Both modules revert with `InvalidRegistry(address(0))` if constructed with a zero-address registry. This prevents misconfiguration.

## Open Questions

1. Should AA claim matching be strict order or canonical sorted matching?
2. Should batch semantics permit extra claims not used by the current request?
3. Should guardian pauses be global fail-closed for both gateway and AA by default?
4. Should per-period rate limits be enforced onchain for AA only, or both paths via gateway parity telemetry?
