// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";

import {ResolverBoundMSCATestHarness, MockOwnerResolver} from "../mocks/CoreTestMocks.sol";

contract ResolverBoundMSCATest is Test {
    address internal entryPoint;
    MockOwnerResolver internal resolver;
    ResolverBoundMSCATestHarness internal account;

    function setUp() public {
        entryPoint = makeAddr("entryPoint");
        resolver = new MockOwnerResolver();
        account = new ResolverBoundMSCATestHarness(entryPoint, address(resolver), block.chainid, address(0xBEEF), 1);
    }

    // **Feature: standalone-nft-agent-wallet, Property 2: Resolver ownership resolution consistency**
    function testFuzz_Property2_ResolverOwnershipResolutionConsistency(
        uint256 chainId,
        address tokenContract,
        uint256 tokenId,
        address resolvedOwner
    ) public {
        account.setTokenData(chainId, tokenContract, tokenId);
        resolver.setOwner(chainId, tokenContract, tokenId, resolvedOwner);

        assertEq(account.owner(), resolvedOwner);
    }
}
