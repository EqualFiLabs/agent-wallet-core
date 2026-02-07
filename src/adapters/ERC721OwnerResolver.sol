// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IERC721} from "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import {IOwnerResolver} from "./IOwnerResolver.sol";

/// @title ERC721OwnerResolver
/// @notice Reference owner resolver using standard ERC-721 ownerOf semantics
contract ERC721OwnerResolver is IOwnerResolver {
    function resolveOwner(uint256 chainId, address tokenContract, uint256 tokenId) external view returns (address owner) {
        if (chainId != block.chainid || tokenContract == address(0)) {
            return address(0);
        }

        try IERC721(tokenContract).ownerOf(tokenId) returns (address tokenOwner) {
            return tokenOwner;
        } catch {
            return address(0);
        }
    }
}
