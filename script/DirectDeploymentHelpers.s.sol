// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script} from "forge-std/Script.sol";

import {ERC721BoundMSCA} from "../src/core/ERC721BoundMSCA.sol";
import {ResolverBoundMSCA} from "../src/core/ResolverBoundMSCA.sol";

/// @title DirectDeploymentHelpers
/// @notice Example helper script for direct (non-beacon) deployment mode
contract DirectDeploymentHelpers is Script {
    event DirectERC721BoundDeployed(address indexed account, address indexed entryPoint);
    event DirectResolverBoundDeployed(address indexed account, address indexed entryPoint, address indexed resolver);

    function deployERC721BoundMSCA(address entryPoint) public returns (address account) {
        account = address(new ERC721BoundMSCA(entryPoint));
        emit DirectERC721BoundDeployed(account, entryPoint);
    }

    function deployResolverBoundMSCA(address entryPoint, address resolver) public returns (address account) {
        account = address(new ResolverBoundMSCA(entryPoint, resolver));
        emit DirectResolverBoundDeployed(account, entryPoint, resolver);
    }

    /// @dev Intentionally no-op by default; projects can call helper methods from custom scripts.
    function run() external {}
}
