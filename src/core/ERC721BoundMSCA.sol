// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IERC721} from "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import {NFTBoundMSCA} from "./NFTBoundMSCA.sol";

/// @title ERC721BoundMSCA
/// @notice NFT-bound modular account with ownership resolved from ERC-721 ownerOf
contract ERC721BoundMSCA is NFTBoundMSCA {
    string internal constant ACCOUNT_ID = "agent.wallet.erc721-bound-msca.1.0.0";

    constructor(address entryPoint_) NFTBoundMSCA(entryPoint_) {}

    function accountId() external pure virtual override returns (string memory) {
        return ACCOUNT_ID;
    }

    function _owner() internal view virtual override returns (address) {
        (uint256 chainId, address tokenContract, uint256 tokenId) = token();
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
