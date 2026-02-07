// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";

import {IERC6551Account} from "../../src/interfaces/IERC6551Account.sol";

contract Mock6551Account is IERC6551Account {
    address private _owner;

    constructor(address owner_) {
        _owner = owner_;
    }

    function setOwner(address owner_) external {
        _owner = owner_;
    }

    function token() external view returns (uint256 chainId, address tokenContract, uint256 tokenId) {
        return (block.chainid, address(0xBEEF), 1);
    }

    function owner() external view returns (address) {
        return _owner;
    }

    function nonce() external pure returns (uint256) {
        return 0;
    }

    function isValidSigner(address, bytes calldata) external pure returns (bytes4 magicValue) {
        return bytes4(0xffffffff);
    }
}

contract Mock1271Owner is IERC1271 {
    address public signer;

    constructor(address signer_) {
        signer = signer_;
    }

    function isValidSignature(bytes32 hash, bytes memory signature) external view returns (bytes4) {
        (address recovered, ECDSA.RecoverError err, ) = ECDSA.tryRecover(hash, signature);
        if (err == ECDSA.RecoverError.NoError && recovered == signer) {
            return IERC1271.isValidSignature.selector;
        }
        return 0xffffffff;
    }
}

contract Mock1271Factory {
    event Deployed(address indexed deployed);

    function deploy(bytes32 salt, address signer) external returns (address deployed) {
        deployed = address(new Mock1271Owner{salt: salt}(signer));
        emit Deployed(deployed);
    }

    function computeAddress(bytes32 salt, address signer) external view returns (address predicted) {
        bytes memory initCode = abi.encodePacked(type(Mock1271Owner).creationCode, abi.encode(signer));
        bytes32 hash = keccak256(abi.encodePacked(bytes1(0xff), address(this), salt, keccak256(initCode)));
        predicted = address(uint160(uint256(hash)));
    }
}
