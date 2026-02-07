// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ERC721BoundMSCA} from "./ERC721BoundMSCA.sol";
import {ResolverBoundMSCA} from "./ResolverBoundMSCA.sol";

/// @title DirectDeploymentFactory
/// @notice Helper for direct (non-beacon) account deployment mode
contract DirectDeploymentFactory {
    event ERC721BoundAccountDeployed(address indexed account, address indexed entryPoint);
    event ResolverBoundAccountDeployed(address indexed account, address indexed entryPoint, address indexed resolver);

    function deployERC721BoundAccount(address entryPoint) external returns (address account) {
        account = address(new ERC721BoundMSCA(entryPoint));
        emit ERC721BoundAccountDeployed(account, entryPoint);
    }

    function deployResolverBoundAccount(address entryPoint, address resolver) external returns (address account) {
        account = address(new ResolverBoundMSCA(entryPoint, resolver));
        emit ResolverBoundAccountDeployed(account, entryPoint, resolver);
    }
}
