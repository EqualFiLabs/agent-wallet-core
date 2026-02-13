// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";

import {BeaconGovernance} from "../../src/core/BeaconGovernance.sol";
import {ResolverBoundMSCA} from "../../src/core/ResolverBoundMSCA.sol";
import {ResolverBoundMSCATestHarness, MockOwnerResolver} from "../mocks/CoreTestMocks.sol";

contract ResolverBoundMSCATest is Test {
    address internal entryPoint;
    address internal owner;
    address internal stranger;
    MockOwnerResolver internal resolver;
    ResolverBoundMSCATestHarness internal account;

    function setUp() public {
        entryPoint = makeAddr("entryPoint");
        owner = makeAddr("owner");
        stranger = makeAddr("stranger");
        resolver = new MockOwnerResolver();
        account = new ResolverBoundMSCATestHarness(entryPoint, address(resolver), block.chainid, address(0xBEEF), 1);
        resolver.setOwner(block.chainid, address(0xBEEF), 1, owner);
    }

    function test_Constructor_RevertsWhenResolverIsZeroAddress() public {
        vm.expectRevert(abi.encodeWithSelector(ResolverBoundMSCA.InvalidResolver.selector, address(0)));
        new ResolverBoundMSCATestHarness(entryPoint, address(0), block.chainid, address(0xBEEF), 1);
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

    function test_SetResolver_RevertsWhenCallerIsUnauthorized() public {
        MockOwnerResolver newResolver = new MockOwnerResolver();

        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(ResolverBoundMSCA.UnauthorizedResolverUpdater.selector, stranger));
        account.setResolver(address(newResolver));
    }

    function test_SetResolver_AllowsOwnerDirectUpdate() public {
        MockOwnerResolver newResolver = new MockOwnerResolver();

        vm.prank(owner);
        account.setResolver(address(newResolver));

        assertEq(account.resolver(), address(newResolver));
    }

    function test_SetResolver_AllowsBeaconGovernanceTimelockUpdate() public {
        BeaconGovernance governance = new BeaconGovernance(address(this), 1);
        MockOwnerResolver newResolver = new MockOwnerResolver();
        bytes32 salt = keccak256("resolver-update");

        vm.prank(owner);
        account.setResolverUpdater(address(governance));
        assertEq(account.resolverUpdater(), address(governance));

        bytes32 opId = governance.queueResolverUpdate(address(account), address(newResolver), salt);

        vm.warp(block.timestamp + 1);
        governance.execute(opId);

        assertEq(account.resolver(), address(newResolver));
    }
}
