// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";

import {BeaconGovernance} from "../../src/core/BeaconGovernance.sol";

contract GovernanceMockBeacon {
    address public implementation;

    constructor(address implementation_) {
        implementation = implementation_;
    }

    function upgradeTo(address implementation_) external {
        implementation = implementation_;
    }
}

contract GovernanceMockResolverManager {
    address public resolver;

    function setResolver(address resolver_) external {
        resolver = resolver_;
    }
}

contract BeaconGovernanceTest is Test {
    event OperationQueued(
        bytes32 indexed opId, bytes32 indexed opType, address indexed target, bytes data, uint64 executeAfter
    );
    event OperationExecuted(bytes32 indexed opId, bytes32 indexed opType, address indexed target, bytes data);
    event OperationCancelled(bytes32 indexed opId, bytes32 indexed opType, address indexed target, bytes data);

    // **Feature: standalone-nft-agent-wallet, Property 23: Timelock-governed upgrade delay enforcement**
    function testFuzz_Property23_TimelockGovernedUpgradeDelayEnforcement(uint32 delaySeed, bytes32 saltA, bytes32 saltB)
        public
    {
        uint64 delay = uint64(bound(uint256(delaySeed), 1, 30 days));
        BeaconGovernance governance = new BeaconGovernance(address(this), delay);

        GovernanceMockBeacon beacon = new GovernanceMockBeacon(address(0x1111));
        GovernanceMockResolverManager resolverManager = new GovernanceMockResolverManager();

        address nextImplementation = address(0x2222);
        address nextResolver = address(0x3333);

        bytes memory beaconData = abi.encodeCall(GovernanceMockBeacon.upgradeTo, (nextImplementation));
        bytes32 beaconOpId = keccak256(abi.encode(governance.BEACON_UPGRADE_OP(), address(beacon), beaconData, saltA));
        uint64 expectedBeaconExecuteAfter = uint64(block.timestamp) + delay;

        vm.expectEmit(true, true, true, true);
        emit OperationQueued(
            beaconOpId, governance.BEACON_UPGRADE_OP(), address(beacon), beaconData, expectedBeaconExecuteAfter
        );
        bytes32 queuedBeaconOpId = governance.queueBeaconUpgrade(address(beacon), nextImplementation, saltA);
        assertEq(queuedBeaconOpId, beaconOpId);
        assertEq(beacon.implementation(), address(0x1111));

        vm.expectRevert(
            abi.encodeWithSelector(
                BeaconGovernance.OperationNotReady.selector, beaconOpId, expectedBeaconExecuteAfter, uint64(block.timestamp)
            )
        );
        governance.execute(beaconOpId);

        vm.warp(expectedBeaconExecuteAfter);
        vm.expectEmit(true, true, true, true);
        emit OperationExecuted(beaconOpId, governance.BEACON_UPGRADE_OP(), address(beacon), beaconData);
        governance.execute(beaconOpId);
        assertEq(beacon.implementation(), nextImplementation);

        bytes memory resolverData = abi.encodeCall(GovernanceMockResolverManager.setResolver, (nextResolver));
        bytes32 resolverOpId =
            keccak256(abi.encode(governance.RESOLVER_UPDATE_OP(), address(resolverManager), resolverData, saltB));
        uint64 expectedResolverExecuteAfter = expectedBeaconExecuteAfter + delay;

        vm.expectEmit(true, true, true, true);
        emit OperationQueued(
            resolverOpId,
            governance.RESOLVER_UPDATE_OP(),
            address(resolverManager),
            resolverData,
            expectedResolverExecuteAfter
        );
        bytes32 queuedResolverOpId = governance.queueResolverUpdate(address(resolverManager), nextResolver, saltB);
        assertEq(queuedResolverOpId, resolverOpId);

        vm.expectEmit(true, true, true, true);
        emit OperationCancelled(resolverOpId, governance.RESOLVER_UPDATE_OP(), address(resolverManager), resolverData);
        governance.cancel(resolverOpId);

        vm.expectRevert(abi.encodeWithSelector(BeaconGovernance.OperationNotQueued.selector, resolverOpId));
        governance.execute(resolverOpId);

        bytes32 saltC = keccak256(abi.encodePacked(saltB, "requeue"));
        bytes32 resolverOpId2 =
            keccak256(abi.encode(governance.RESOLVER_UPDATE_OP(), address(resolverManager), resolverData, saltC));
        uint64 expectedResolverExecuteAfter2 = expectedResolverExecuteAfter;

        governance.queueResolverUpdate(address(resolverManager), nextResolver, saltC);
        vm.warp(expectedResolverExecuteAfter2);
        vm.expectEmit(true, true, true, true);
        emit OperationExecuted(resolverOpId2, governance.RESOLVER_UPDATE_OP(), address(resolverManager), resolverData);
        governance.execute(resolverOpId2);
        assertEq(resolverManager.resolver(), nextResolver);
    }
}
