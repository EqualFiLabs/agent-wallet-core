// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IOwnerResolver} from "../adapters/IOwnerResolver.sol";
import {NFTBoundMSCA} from "./NFTBoundMSCA.sol";

/// @title ResolverBoundMSCA
/// @notice NFT-bound modular account with ownership resolved from an IOwnerResolver
contract ResolverBoundMSCA is NFTBoundMSCA {
    string internal constant ACCOUNT_ID = "agent.wallet.resolver-bound-msca.1.0.0";
    bytes32 internal constant RESOLVER_SLOT =
        bytes32(uint256(keccak256("agent.wallet.core.resolver-bound-msca.resolver.v1")) - 1);

    error InvalidResolver(address resolver);

    constructor(address entryPoint_, address resolver_) NFTBoundMSCA(entryPoint_) {
        if (resolver_ == address(0)) {
            revert InvalidResolver(resolver_);
        }
        _setResolver(resolver_);
    }

    function accountId() external pure virtual override returns (string memory) {
        return ACCOUNT_ID;
    }

    function resolver() public view returns (address resolver_) {
        bytes32 slot = RESOLVER_SLOT;
        assembly {
            resolver_ := sload(slot)
        }
    }

    function _owner() internal view virtual override returns (address) {
        (uint256 chainId, address tokenContract, uint256 tokenId) = token();
        address resolver_ = resolver();
        if (resolver_ == address(0)) {
            return address(0);
        }
        return IOwnerResolver(resolver_).resolveOwner(chainId, tokenContract, tokenId);
    }

    function _setResolver(address resolver_) internal {
        bytes32 slot = RESOLVER_SLOT;
        assembly {
            sstore(slot, resolver_)
        }
    }
}
