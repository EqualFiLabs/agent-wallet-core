// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";

import {OwnerValidationModule} from "../../src/modules/validation/OwnerValidationModule.sol";
import {
    Mock6551Account,
    Mock1271Factory,
    Mock1271Owner,
    Mock1271CallTrackingFactory,
    Mock1271RevertingFactory,
    Mock1271WrongAddressFactory
} from "../mocks/OwnerValidationMocks.sol";

contract OwnerValidationModuleTest is Test {
    bytes32 internal constant EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 internal constant USER_OP_TYPEHASH = keccak256("UserOp(bytes32 userOpHash)");
    bytes32 internal constant MESSAGE_TYPEHASH = keccak256("Message(bytes32 hash)");
    bytes32 internal constant ERC6492_MAGIC_VALUE =
        0x6492649264926492649264926492649264926492649264926492649264926492;
    uint256 internal constant ERC6492_MIN_LENGTH = 192;
    uint256 internal constant ERC4337_VERIFICATION_GAS_BOUND = 1_500_000;

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

    function test_ERC6492_AlreadyDeployedOwner_ShortCircuitWithoutFactoryCall() public {
        uint256 signerKey = 0xB0B;
        address signer = vm.addr(signerKey);
        bytes32 salt = keccak256("erc6492-short-circuit");
        bytes32 userOpHash = keccak256("erc6492-short-circuit-user-op");

        Mock1271CallTrackingFactory factory = new Mock1271CallTrackingFactory();
        address predictedOwner = factory.computeAddress(salt, signer);
        factory.deploy(salt, signer);
        assertEq(factory.deployCalls(), 1);

        Mock6551Account account = new Mock6551Account(predictedOwner);
        bytes32 digest = _hashUserOp(address(account), userOpHash);
        bytes memory innerSig = _sign(signerKey, digest);
        bytes memory wrapped6492Signature =
            _wrapERC6492(address(factory), abi.encodeCall(Mock1271CallTrackingFactory.deploy, (salt, signer)), innerSig);

        PackedUserOperation memory userOp = _buildUserOp(address(account), wrapped6492Signature);

        assertEq(module.validateUserOp(0, userOp, userOpHash), 0);
        assertEq(factory.deployCalls(), 1);
    }

    function test_ERC6492_FactoryReverts_ReturnsInvalid() public {
        uint256 signerKey = 0xC0FFEE;
        address signer = vm.addr(signerKey);
        bytes32 userOpHash = keccak256("erc6492-factory-revert");
        bytes32 salt = keccak256("erc6492-factory-revert-salt");

        Mock1271RevertingFactory factory = new Mock1271RevertingFactory();
        address undeployedOwner = makeAddr("undeployed-owner");
        Mock6551Account account = new Mock6551Account(undeployedOwner);

        bytes32 digest = _hashUserOp(address(account), userOpHash);
        bytes memory innerSig = _sign(signerKey, digest);
        bytes memory wrapped6492Signature =
            _wrapERC6492(address(factory), abi.encodeCall(Mock1271RevertingFactory.deploy, (salt, signer)), innerSig);

        PackedUserOperation memory userOp = _buildUserOp(address(account), wrapped6492Signature);
        assertEq(module.validateUserOp(0, userOp, userOpHash), 1);
    }

    function test_ERC6492_FactoryHasNoCode_ReturnsInvalid() public {
        uint256 signerKey = 0xCAFE;
        bytes32 userOpHash = keccak256("erc6492-no-code-factory");

        address noCodeFactory = makeAddr("eoa-factory");
        assertEq(noCodeFactory.code.length, 0);

        Mock6551Account account = new Mock6551Account(makeAddr("undeployed-owner"));
        bytes32 digest = _hashUserOp(address(account), userOpHash);
        bytes memory innerSig = _sign(signerKey, digest);
        bytes memory wrapped6492Signature = _wrapERC6492(noCodeFactory, hex"1234", innerSig);

        PackedUserOperation memory userOp = _buildUserOp(address(account), wrapped6492Signature);
        assertEq(module.validateUserOp(0, userOp, userOpHash), 1);
    }

    function test_ERC6492_SignatureShorterThanMinLength_ReturnsInvalid() public {
        bytes memory shortWrapped6492Signature = bytes.concat(new bytes(ERC6492_MIN_LENGTH - 33), bytes32(ERC6492_MAGIC_VALUE));
        bytes32 userOpHash = keccak256("erc6492-short-signature");
        bytes32 messageHash = keccak256("erc6492-short-signature-message");

        Mock6551Account account = new Mock6551Account(makeAddr("owner"));
        PackedUserOperation memory userOp = _buildUserOp(address(account), shortWrapped6492Signature);

        assertEq(module.validateUserOp(0, userOp, userOpHash), 1);
        assertEq(
            module.validateSignature(address(account), 0, address(0), messageHash, shortWrapped6492Signature),
            bytes4(0xffffffff)
        );
    }

    function test_ERC6492_InvalidInnerSignatureAfterSuccessfulFactoryDeploy_ReturnsInvalid() public {
        uint256 signerKey = 0xABCD;
        uint256 wrongKey = 0x1234;
        address signer = vm.addr(signerKey);
        bytes32 salt = keccak256("erc6492-invalid-inner-sig");
        bytes32 userOpHash = keccak256("erc6492-invalid-inner-sig-hash");

        Mock1271Factory factory = new Mock1271Factory();
        address predictedOwner = factory.computeAddress(salt, signer);
        Mock6551Account account = new Mock6551Account(predictedOwner);

        bytes32 digest = _hashUserOp(address(account), userOpHash);
        bytes memory wrongInnerSig = _sign(wrongKey, digest);
        bytes memory wrapped6492Signature =
            _wrapERC6492(address(factory), abi.encodeCall(Mock1271Factory.deploy, (salt, signer)), wrongInnerSig);

        PackedUserOperation memory userOp = _buildUserOp(address(account), wrapped6492Signature);
        assertEq(module.validateUserOp(0, userOp, userOpHash), 1);
        assertGt(predictedOwner.code.length, 0);
    }

    function test_ERC6492_FactoryDeploysWrongAddress_ReturnsInvalid() public {
        uint256 signerKey = 0xF00D;
        address signer = vm.addr(signerKey);
        bytes32 salt = keccak256("erc6492-wrong-address");
        bytes32 userOpHash = keccak256("erc6492-wrong-address-hash");

        Mock1271WrongAddressFactory factory = new Mock1271WrongAddressFactory();
        address expectedOwner = makeAddr("expected-owner");
        assertEq(expectedOwner.code.length, 0);
        Mock6551Account account = new Mock6551Account(expectedOwner);

        bytes32 digest = _hashUserOp(address(account), userOpHash);
        bytes memory innerSig = _sign(signerKey, digest);
        bytes memory wrapped6492Signature =
            _wrapERC6492(address(factory), abi.encodeCall(Mock1271WrongAddressFactory.deploy, (salt, signer)), innerSig);

        PackedUserOperation memory userOp = _buildUserOp(address(account), wrapped6492Signature);
        assertEq(module.validateUserOp(0, userOp, userOpHash), 1);
        assertEq(factory.deployCalls(), 1);
        assertEq(expectedOwner.code.length, 0);
        assertGt(factory.lastDeployed().code.length, 0);
    }

    function test_ValidateSignatureView_ERC6492UndeployedOwner_ReturnsInvalid() public {
        uint256 signerKey = 0xDADA;
        address signer = vm.addr(signerKey);
        bytes32 salt = keccak256("erc6492-view-undeployed");
        bytes32 messageHash = keccak256("erc6492-view-undeployed-message");

        Mock1271Factory factory = new Mock1271Factory();
        address predictedOwner = factory.computeAddress(salt, signer);
        Mock6551Account account = new Mock6551Account(predictedOwner);

        bytes32 digest = _hashMessage(address(account), messageHash);
        bytes memory innerSig = _sign(signerKey, digest);
        bytes memory wrapped6492Signature =
            _wrapERC6492(address(factory), abi.encodeCall(Mock1271Factory.deploy, (salt, signer)), innerSig);

        assertEq(
            module.validateSignature(address(account), 0, address(0), messageHash, wrapped6492Signature),
            bytes4(0xffffffff)
        );
    }

    function test_ValidateSignatureView_ERC6492DeployedOwner_ReturnsValid() public {
        uint256 signerKey = 0xBABE;
        address signer = vm.addr(signerKey);
        bytes32 salt = keccak256("erc6492-view-deployed");
        bytes32 messageHash = keccak256("erc6492-view-deployed-message");

        Mock1271Factory factory = new Mock1271Factory();
        address predictedOwner = factory.computeAddress(salt, signer);
        factory.deploy(salt, signer);
        Mock6551Account account = new Mock6551Account(predictedOwner);

        bytes32 digest = _hashMessage(address(account), messageHash);
        bytes memory innerSig = _sign(signerKey, digest);
        bytes memory wrapped6492Signature =
            _wrapERC6492(address(factory), abi.encodeCall(Mock1271Factory.deploy, (salt, signer)), innerSig);

        assertEq(
            module.validateSignature(address(account), 0, address(0), messageHash, wrapped6492Signature),
            ERC1271_MAGICVALUE
        );
    }

    function test_NonERC6492LikeSuffixButTooShort_RemainsInvalid() public {
        bytes memory magicLikeButTooShort = bytes.concat(new bytes(64), bytes32(ERC6492_MAGIC_VALUE));
        bytes32 messageHash = keccak256("erc6492-magic-like-short");
        Mock6551Account account = new Mock6551Account(makeAddr("owner"));

        assertLt(magicLikeButTooShort.length, ERC6492_MIN_LENGTH);
        assertEq(
            module.validateSignature(address(account), 0, address(0), messageHash, magicLikeButTooShort),
            bytes4(0xffffffff)
        );
    }

    function test_ERC6492_FactoryDeploymentGasWithinVerificationBound() public {
        uint256 signerKey = 0x1BADB002;
        address signer = vm.addr(signerKey);
        bytes32 salt = keccak256("erc6492-gas-bound");
        bytes32 userOpHash = keccak256("erc6492-gas-bound-hash");

        Mock1271Factory factory = new Mock1271Factory();
        address predictedOwner = factory.computeAddress(salt, signer);
        Mock6551Account account = new Mock6551Account(predictedOwner);

        bytes32 digest = _hashUserOp(address(account), userOpHash);
        bytes memory innerSig = _sign(signerKey, digest);
        bytes memory wrapped6492Signature =
            _wrapERC6492(address(factory), abi.encodeCall(Mock1271Factory.deploy, (salt, signer)), innerSig);

        PackedUserOperation memory userOp = _buildUserOp(address(account), wrapped6492Signature);

        uint256 gasBefore = gasleft();
        uint256 result = module.validateUserOp(0, userOp, userOpHash);
        uint256 gasUsed = gasBefore - gasleft();

        assertEq(result, 0);
        assertLt(gasUsed, ERC4337_VERIFICATION_GAS_BOUND);
    }

    function testFuzz_ERC6492_ArbitraryFactoryCalldataAndInnerSignatureCombinations(
        uint256 signerKeySeed,
        uint256 otherKeySeed,
        bytes32 userOpHash,
        bytes32 salt,
        uint8 modeSeed,
        bool ownerPredeployed,
        bool useValidInnerSignature,
        bytes memory arbitraryFactoryCalldata
    ) public {
        uint256 signerKey = bound(signerKeySeed, 1, SECP256K1_N - 1);
        uint256 otherKey = bound(otherKeySeed, 1, SECP256K1_N - 1);
        vm.assume(signerKey != otherKey);
        vm.assume(arbitraryFactoryCalldata.length <= 256);

        address signer = vm.addr(signerKey);
        Mock1271Factory goodFactory = new Mock1271Factory();
        address predictedOwner = goodFactory.computeAddress(salt, signer);
        if (ownerPredeployed) {
            goodFactory.deploy(salt, signer);
        }
        Mock6551Account account = new Mock6551Account(predictedOwner);

        bytes32 digest = _hashUserOp(address(account), userOpHash);
        bytes memory innerSig = _sign(useValidInnerSignature ? signerKey : otherKey, digest);

        uint8 mode = uint8(bound(modeSeed, 0, 3));
        address factory;
        bytes memory factoryCalldata;
        if (mode == 0) {
            factory = address(goodFactory);
            factoryCalldata = abi.encodeCall(Mock1271Factory.deploy, (salt, signer));
        } else if (mode == 1) {
            Mock1271RevertingFactory revertingFactory = new Mock1271RevertingFactory();
            factory = address(revertingFactory);
            factoryCalldata = abi.encodeCall(Mock1271RevertingFactory.deploy, (salt, signer));
        } else if (mode == 2) {
            address eoaFactory = address(uint160(uint256(keccak256(abi.encodePacked(salt, arbitraryFactoryCalldata)))));
            vm.assume(eoaFactory.code.length == 0);
            factory = eoaFactory;
            factoryCalldata = arbitraryFactoryCalldata;
        } else {
            Mock1271WrongAddressFactory wrongFactory = new Mock1271WrongAddressFactory();
            factory = address(wrongFactory);
            factoryCalldata = abi.encodeCall(Mock1271WrongAddressFactory.deploy, (salt, signer));
        }

        bytes memory wrapped6492Signature = _wrapERC6492(factory, factoryCalldata, innerSig);
        PackedUserOperation memory userOp = _buildUserOp(address(account), wrapped6492Signature);
        uint256 result = module.validateUserOp(0, userOp, userOpHash);

        bool expectValid;
        if (ownerPredeployed) {
            expectValid = useValidInnerSignature;
        } else if (mode == 0) {
            expectValid = useValidInnerSignature;
        } else {
            expectValid = false;
        }

        assertEq(result == 0, expectValid);
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

    function _wrapERC6492(address factory, bytes memory factoryCalldata, bytes memory innerSig)
        internal
        pure
        returns (bytes memory wrapped6492Signature)
    {
        bytes memory wrapped = abi.encode(factory, factoryCalldata, innerSig);
        wrapped6492Signature = bytes.concat(wrapped, bytes32(ERC6492_MAGIC_VALUE));
    }
}
