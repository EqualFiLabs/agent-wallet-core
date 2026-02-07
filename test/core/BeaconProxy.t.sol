// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {IBeacon} from "@openzeppelin/contracts/proxy/beacon/IBeacon.sol";

import {BeaconProxy} from "../../src/core/BeaconProxy.sol";

contract MockImplementationV1 {
    function version() external pure returns (uint256) {
        return 1;
    }
}

contract MockImplementationV2 {
    function version() external pure returns (uint256) {
        return 2;
    }
}

contract MockUpgradeableBeacon is IBeacon {
    address private _implementation;

    constructor(address implementation_) {
        _implementation = implementation_;
    }

    function implementation() external view returns (address) {
        return _implementation;
    }

    function upgradeTo(address implementation_) external {
        _implementation = implementation_;
    }
}

contract BeaconProxyTest is Test {
    // **Feature: standalone-nft-agent-wallet, Property 21: Beacon proxy construction validation**
    function testFuzz_Property21_BeaconProxyConstructionValidation(address nonContractBeacon) public {
        vm.assume(nonContractBeacon.code.length == 0);
        vm.expectRevert(abi.encodeWithSelector(BeaconProxy.BeaconNotContract.selector, nonContractBeacon));
        new BeaconProxy(nonContractBeacon);
    }

    function test_BeaconProxy_DelegatesThroughCurrentBeaconImplementation() public {
        MockImplementationV1 impl1 = new MockImplementationV1();
        MockImplementationV2 impl2 = new MockImplementationV2();
        MockUpgradeableBeacon beacon = new MockUpgradeableBeacon(address(impl1));
        BeaconProxy proxy = new BeaconProxy(address(beacon));

        (bool okV1, bytes memory dataV1) = address(proxy).call(abi.encodeWithSignature("version()"));
        assertTrue(okV1);
        assertEq(abi.decode(dataV1, (uint256)), 1);

        beacon.upgradeTo(address(impl2));

        (bool okV2, bytes memory dataV2) = address(proxy).call(abi.encodeWithSignature("version()"));
        assertTrue(okV2);
        assertEq(abi.decode(dataV2, (uint256)), 2);
    }
}
