// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IBeacon} from "@openzeppelin/contracts/proxy/beacon/IBeacon.sol";

/// @title BeaconProxy
/// @notice Optional beacon-backed ERC-6551 implementation proxy
contract BeaconProxy {
    address internal immutable BEACON;

    error BeaconNotContract(address beaconAddress);

    constructor(address beaconAddress) {
        if (beaconAddress.code.length == 0) {
            revert BeaconNotContract(beaconAddress);
        }
        BEACON = beaconAddress;
    }

    function beacon() external view returns (address) {
        return BEACON;
    }

    fallback() external payable {
        _delegate();
    }

    receive() external payable {
        _delegate();
    }

    function _delegate() internal {
        address implementation = IBeacon(BEACON).implementation();
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), implementation, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}
