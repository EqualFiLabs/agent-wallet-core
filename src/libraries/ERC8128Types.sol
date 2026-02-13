// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

struct SessionPolicyV2 {
    bool active;
    uint48 validAfter;
    uint48 validUntil;
    uint32 maxTtlSeconds;
    bytes32 scopeRoot;
    uint64 maxCallsPerPeriod;
    uint128 maxValuePerPeriod;
    uint48 periodSeconds;
    bool paused;
}

struct SessionAuthV2 {
    uint8 mode;
    address sessionKey;
    uint64 epoch;
    uint64 policyNonce;
    uint48 created;
    uint48 expires;
    bytes32 requestHash;
    bytes32 claimsHash;
    bytes sessionSignature;
    bytes claims;
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
    bytes32[] scopeProof;
}

struct AAClaimsV2 {
    AACallClaimV2[] callClaims;
    bytes32[] multiproof;
    bool[] proofFlags;
    bytes32 leafOrderHash;
}

struct ParsedCall {
    address target;
    uint256 value;
    bytes data;
    bytes4 selector;
    bool isDelegateCall;
}
