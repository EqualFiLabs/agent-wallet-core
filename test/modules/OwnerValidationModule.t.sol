// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";

import {OwnerValidationModule} from "../../src/modules/validation/OwnerValidationModule.sol";
import {Mock6551Account, Mock1271Factory, Mock1271Owner} from "../mocks/OwnerValidationMocks.sol";

contract OwnerValidationModuleTest is Test {
    bytes32 internal constant EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 internal constant USER_OP_TYPEHASH = keccak256("UserOp(bytes32 userOpHash)");
    bytes32 internal constant MESSAGE_TYPEHASH = keccak256("Message(bytes32 hash)");
    bytes32 internal constant ERC6492_MAGIC_VALUE =
        0x6492649264926492649264926492649264926492649264926492649264926492;

    uint256 internal constant SECP256K1_N =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
    bytes4 internal constant ERC1271_MAGICVALUE = 0x1626ba7e;
    string internal constant NAME = "Agent Wallet Owner Validation";
    string internal constant VERSION = "1.0.0";

    OwnerValidationModule internal module;

    function setUp() public {
        module = new OwnerValidationModule();
    }

    // **Feature: standalone-nft-agent-wallet, Property 7: Owner signature validation correctness**
    function testFuzz_Property7_OwnerSignatureValidationCorrectness(
        uint256 ownerKey,
        uint256 otherKey,
        bool useContractOwner,
        bytes32 userOpHash,
        bytes32 messageHash
    ) public {
        ownerKey = bound(ownerKey, 1, SECP256K1_N - 1);
        otherKey = bound(otherKey, 1, SECP256K1_N - 1);
        vm.assume(ownerKey != otherKey);

        address ownerSigner = vm.addr(ownerKey);

        address configuredOwner = ownerSigner;
        if (useContractOwner) {
            configuredOwner = address(new Mock1271Owner(ownerSigner));
        }

        Mock6551Account account = new Mock6551Account(configuredOwner);

        bytes32 userOpDigest = _hashUserOp(address(account), userOpHash);
        bytes memory validUserOpSignature = _sign(ownerKey, userOpDigest);
        bytes memory invalidUserOpSignature = _sign(otherKey, userOpDigest);

        PackedUserOperation memory validUserOp = _buildUserOp(address(account), validUserOpSignature);
        PackedUserOperation memory invalidUserOp = _buildUserOp(address(account), invalidUserOpSignature);

        assertEq(module.validateUserOp(0, validUserOp, userOpHash), 0);
        assertEq(module.validateUserOp(0, invalidUserOp, userOpHash), 1);

        bytes32 messageDigest = _hashMessage(address(account), messageHash);
        bytes memory validMessageSignature = _sign(ownerKey, messageDigest);
        bytes memory invalidMessageSignature = _sign(otherKey, messageDigest);

        assertEq(
            module.validateSignature(address(account), 0, address(0), messageHash, validMessageSignature),
            ERC1271_MAGICVALUE
        );
        assertEq(
            module.validateSignature(address(account), 0, address(0), messageHash, invalidMessageSignature),
            bytes4(0xffffffff)
        );
    }

    // **Feature: standalone-nft-agent-wallet, Property 8: Owner runtime authorization**
    function testFuzz_Property8_OwnerRuntimeAuthorization(address owner_, address sender_) public {
        Mock6551Account account = new Mock6551Account(owner_);

        if (sender_ == owner_) {
            module.validateRuntime(address(account), 0, sender_, 0, "", "");
        } else {
            vm.expectRevert(abi.encodeWithSelector(OwnerValidationModule.UnauthorizedCaller.selector, sender_));
            module.validateRuntime(address(account), 0, sender_, 0, "", "");
        }
    }

    // **Feature: standalone-nft-agent-wallet, Property 9: ERC-6492 counterfactual signature validation**
    function testFuzz_Property9_ERC6492CounterfactualSignatureValidation(
        uint256 signerKeySeed,
        bytes32 userOpHash,
        bytes32 salt
    ) public {
        uint256 signerKey = bound(signerKeySeed, 1, SECP256K1_N - 1);
        address signer = vm.addr(signerKey);

        Mock1271Factory factory = new Mock1271Factory();
        address predictedOwner = factory.computeAddress(salt, signer);
        assertEq(predictedOwner.code.length, 0);

        Mock6551Account account = new Mock6551Account(predictedOwner);

        bytes32 digest = _hashUserOp(address(account), userOpHash);
        bytes memory innerSignature = _sign(signerKey, digest);
        bytes memory factoryCalldata = abi.encodeCall(Mock1271Factory.deploy, (salt, signer));
        bytes memory wrapped = abi.encode(address(factory), factoryCalldata, innerSignature);
        bytes memory wrapped6492Signature = bytes.concat(wrapped, bytes32(ERC6492_MAGIC_VALUE));

        PackedUserOperation memory userOp = _buildUserOp(address(account), wrapped6492Signature);

        assertEq(module.validateUserOp(0, userOp, userOpHash), 0);
        assertGt(predictedOwner.code.length, 0);

        bytes32 messageHash = keccak256(abi.encodePacked("message", signer, userOpHash));
        bytes32 messageDigest = _hashMessage(address(account), messageHash);
        bytes memory messageInnerSignature = _sign(signerKey, messageDigest);
        bytes memory wrappedMessage = abi.encode(address(factory), factoryCalldata, messageInnerSignature);
        bytes memory wrappedMessage6492 = bytes.concat(wrappedMessage, bytes32(ERC6492_MAGIC_VALUE));

        assertEq(
            module.validateSignature(address(account), 0, address(0), messageHash, wrappedMessage6492),
            ERC1271_MAGICVALUE
        );
    }

    function _hashDomain(address account) internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                keccak256(bytes(NAME)),
                keccak256(bytes(VERSION)),
                block.chainid,
                account
            )
        );
    }

    function _hashUserOp(address account, bytes32 userOpHash) internal view returns (bytes32) {
        bytes32 structHash = keccak256(abi.encode(USER_OP_TYPEHASH, userOpHash));
        return keccak256(abi.encodePacked("\x19\x01", _hashDomain(account), structHash));
    }

    function _hashMessage(address account, bytes32 hash) internal view returns (bytes32) {
        bytes32 structHash = keccak256(abi.encode(MESSAGE_TYPEHASH, hash));
        return keccak256(abi.encodePacked("\x19\x01", _hashDomain(account), structHash));
    }

    function _buildUserOp(address sender, bytes memory signature) internal pure returns (PackedUserOperation memory userOp) {
        userOp.sender = sender;
        userOp.nonce = 0;
        userOp.initCode = bytes("");
        userOp.callData = bytes("");
        userOp.accountGasLimits = bytes32(0);
        userOp.preVerificationGas = 0;
        userOp.gasFees = bytes32(0);
        userOp.paymasterAndData = bytes("");
        userOp.signature = signature;
    }

    function _sign(uint256 privateKey, bytes32 digest) internal pure returns (bytes memory signature) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        signature = abi.encodePacked(r, s, v);
    }
}
