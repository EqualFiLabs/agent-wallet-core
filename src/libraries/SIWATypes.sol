// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

struct SIWAAuthV1 {
    address signer;
    uint48 created;
    uint48 expires;
    bytes32 requestHash;
    bytes32 claimsHash;
    bytes signature;
    bytes claims;
}

struct SIWAClaimsV1 {
    uint256 agentId;
    address registryAddress;
    uint256 registryChainId;
}
