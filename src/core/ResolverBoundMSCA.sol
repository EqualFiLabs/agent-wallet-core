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
    bytes32 internal constant RESOLVER_UPDATER_SLOT =
        bytes32(uint256(keccak256("agent.wallet.core.resolver-bound-msca.resolver-updater.v1")) - 1);

    error InvalidResolver(address resolver);
    error UnauthorizedResolverUpdater(address caller);

    event ResolverUpdated(address indexed oldResolver, address indexed newResolver, address indexed updater);
    event ResolverUpdaterSet(address indexed updater, address indexed caller);

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

    function resolverUpdater() public view returns (address updater_) {
        bytes32 slot = RESOLVER_UPDATER_SLOT;
        assembly {
            updater_ := sload(slot)
        }
    }

    function setResolver(address resolver_) external {
        if (resolver_ == address(0)) {
            revert InvalidResolver(resolver_);
        }

        address updater_ = resolverUpdater();
        if (msg.sender != _owner() && msg.sender != updater_) {
            revert UnauthorizedResolverUpdater(msg.sender);
        }

        address oldResolver = resolver();
        _setResolver(resolver_);
        emit ResolverUpdated(oldResolver, resolver_, msg.sender);
    }

    function setResolverUpdater(address updater_) external {
        _requireOwner();
        _setResolverUpdater(updater_);
        emit ResolverUpdaterSet(updater_, msg.sender);
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

    function _setResolverUpdater(address updater_) internal {
        bytes32 slot = RESOLVER_UPDATER_SLOT;
        assembly {
            sstore(slot, updater_)
        }
    }
}
