// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title IOwnerResolver
/// @notice Resolves controlling owner for NFT-bound account authorization
interface IOwnerResolver {
    function resolveOwner(
        uint256 chainId,
        address tokenContract,
        uint256 tokenId
    ) external view returns (address owner);
}
