// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";

import {DirectDeploymentFactory} from "../../src/core/DirectDeploymentFactory.sol";
import {ERC721BoundMSCA} from "../../src/core/ERC721BoundMSCA.sol";
import {ResolverBoundMSCA} from "../../src/core/ResolverBoundMSCA.sol";

contract DirectDeploymentFactoryTest is Test {
    function test_DeploysDirectERC721AndResolverBoundAccounts() public {
        DirectDeploymentFactory factory = new DirectDeploymentFactory();

        address entryPoint = makeAddr("entryPoint");
        address resolver = makeAddr("resolver");

        address erc721Account = factory.deployERC721BoundAccount(entryPoint);
        assertEq(ERC721BoundMSCA(payable(erc721Account)).entryPoint(), entryPoint);

        address resolverAccount = factory.deployResolverBoundAccount(entryPoint, resolver);
        assertEq(ResolverBoundMSCA(payable(resolverAccount)).entryPoint(), entryPoint);
        assertEq(ResolverBoundMSCA(payable(resolverAccount)).resolver(), resolver);
    }
}
