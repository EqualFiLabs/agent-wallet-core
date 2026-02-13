// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";

import {ERC8128PolicyRegistry} from "../../src/core/ERC8128PolicyRegistry.sol";
import {SIWAValidationModule} from "../../src/modules/validation/SIWAValidationModule.sol";
import {IERC165} from "../../src/interfaces/IERC165.sol";
import {IERC6900Module} from "../../src/interfaces/IERC6900Module.sol";
import {IERC6900ValidationModule} from "../../src/interfaces/IERC6900ValidationModule.sol";
import {SIWATestHelper} from "../siwa/SIWATestHelper.sol";
import {Mock1271Owner, Mock6551Account} from "../mocks/OwnerValidationMocks.sol";

contract SIWAValidationModuleTest is Test {
    bytes4 internal constant ERC1271_MAGICVALUE = 0x1626ba7e;
    bytes4 internal constant ERC1271_INVALID = 0xffffffff;
    uint256 internal constant SIG_VALIDATION_FAILED = 1;

    ERC8128PolicyRegistry internal registry;
    SIWAValidationModule internal module;

    function setUp() public {
        registry = new ERC8128PolicyRegistry();
        module = new SIWAValidationModule(address(registry));
    }

    function test_ModuleMetadata_ConformsToERC6900Interfaces() public view {
        assertEq(module.moduleId(), "agent.wallet.siwa-validation.1.0.0");
        assertTrue(module.supportsInterface(type(IERC165).interfaceId));
        assertTrue(module.supportsInterface(type(IERC6900Module).interfaceId));
        assertTrue(module.supportsInterface(type(IERC6900ValidationModule).interfaceId));
    }

    function test_Constructor_RevertsWithZeroRegistry() public {
        vm.expectRevert(abi.encodeWithSelector(SIWAValidationModule.InvalidRegistry.selector, address(0)));
        new SIWAValidationModule(address(0));
    }

    function testFuzz_Property3_NonGatewayPathsRejected(uint32 entityId, bytes32 userOpHash) public {
        PackedUserOperation memory userOp;
        assertEq(module.validateUserOp(entityId, userOp, userOpHash), SIG_VALIDATION_FAILED);

        vm.expectRevert(SIWAValidationModule.RuntimeValidationNotSupported.selector);
        module.validateRuntime(address(0xA11CE), entityId, address(0xBEEF), 1, bytes("abc"), bytes("auth"));
    }

    function test_ValidateSignature_AcceptsValidRawSignature() public {
        uint256 ownerKey = 111;
        uint256 signerKey = 222;
        address owner = vm.addr(ownerKey);
        address signer = vm.addr(signerKey);
        uint32 entityId = 7;
        bytes32 requestHash = keccak256("siwa-request");

        Mock6551Account account = new Mock6551Account(owner);
        _setPolicy(owner, address(account), entityId, signer, 0, 0);

        bytes memory signature = SIWATestHelper.signRequestHash(vm, signerKey, requestHash);
        bytes4 result = module.validateSignature(address(account), entityId, address(0), requestHash, signature);
        assertEq(result, ERC1271_MAGICVALUE);
    }

    function test_ValidateSignature_RejectsMalformedSignature() public view {
        bytes4 result = module.validateSignature(address(0xCAFE), 0, address(0), bytes32(0), bytes("not-a-signature"));
        assertEq(result, ERC1271_INVALID);
    }

    function test_ValidateSignature_RejectsWithoutActivePolicy() public {
        uint256 ownerKey = 123;
        uint256 signerKey = 456;
        address owner = vm.addr(ownerKey);
        Mock6551Account account = new Mock6551Account(owner);

        bytes32 requestHash = keccak256("siwa-no-policy");
        bytes memory signature = SIWATestHelper.signRequestHash(vm, signerKey, requestHash);
        assertEq(module.validateSignature(address(account), 1, address(0), requestHash, signature), ERC1271_INVALID);
    }

    function test_ValidateSignature_AcceptsContractOwnerSessionSigner_TBAPath() public {
        uint256 contractOwnerSignerKey = 333;
        address contractOwnerSigner = vm.addr(contractOwnerSignerKey);
        Mock1271Owner contractOwner = new Mock1271Owner(contractOwnerSigner);

        uint32 entityId = 12;
        bytes32 requestHash = keccak256("siwa-contract-owner-session-signer");
        Mock6551Account account = new Mock6551Account(address(contractOwner));

        _setPolicy(address(contractOwner), address(account), entityId, address(contractOwner), 0, 0);

        bytes memory signature = SIWATestHelper.signRequestHash(vm, contractOwnerSignerKey, requestHash);
        bytes4 result = module.validateSignature(address(account), entityId, address(0), requestHash, signature);
        assertEq(result, ERC1271_MAGICVALUE);
    }

    function testFuzz_Property4_FieldTamperingRejection(uint256 signerKeySeed, bytes32 requestHash) public {
        uint256 signerKey = SIWATestHelper.normalizePrivateKey(signerKeySeed);
        address signer = vm.addr(signerKey);
        address owner = makeAddr("prop4-owner");
        uint32 entityId = 19;

        Mock6551Account account = new Mock6551Account(owner);
        _setPolicy(owner, address(account), entityId, signer, 0, 0);

        bytes memory signature = SIWATestHelper.signRequestHash(vm, signerKey, requestHash);
        bytes32 tamperedHash = keccak256(abi.encodePacked("tampered", requestHash));

        bytes4 result = module.validateSignature(address(account), entityId, address(0), tamperedHash, signature);
        assertEq(result, ERC1271_INVALID);
    }

    function testFuzz_Property5_SignatureVerification(uint256 signerKeySeed, uint256 wrongKeySeed, bytes32 requestHash)
        public
    {
        uint256 signerKey = SIWATestHelper.normalizePrivateKey(signerKeySeed);
        uint256 wrongKey = SIWATestHelper.normalizePrivateKey(wrongKeySeed);
        vm.assume(signerKey != wrongKey);

        address owner = makeAddr("prop5-owner");
        address signer = vm.addr(signerKey);
        uint32 entityId = 23;
        Mock6551Account account = new Mock6551Account(owner);
        _setPolicy(owner, address(account), entityId, signer, 0, 0);

        bytes memory badSignature = SIWATestHelper.signRequestHash(vm, wrongKey, requestHash);
        bytes4 result = module.validateSignature(address(account), entityId, address(0), requestHash, badSignature);
        assertEq(result, ERC1271_INVALID);
    }

    function testFuzz_Property8_TimeWindowEnforcement(uint8 timeCaseSeed, uint48 baseTimeSeed) public {
        uint8 timeCase = uint8(bound(timeCaseSeed, 0, 1)); // 0:not yet active, 1:expired policy
        uint48 baseTime = uint48(bound(baseTimeSeed, 500, type(uint48).max - 1000));
        vm.warp(baseTime);

        uint256 ownerKey = 7777;
        uint256 signerKey = 8888;
        address owner = vm.addr(ownerKey);
        address signer = vm.addr(signerKey);
        uint32 entityId = 41;
        bytes32 requestHash = keccak256("siwa-prop8-request");
        Mock6551Account account = new Mock6551Account(owner);

        if (timeCase == 0) {
            _setPolicy(owner, address(account), entityId, signer, baseTime + 100, 0);
        } else {
            _setPolicy(owner, address(account), entityId, signer, 0, baseTime - 1);
        }

        bytes memory signature = SIWATestHelper.signRequestHash(vm, signerKey, requestHash);
        bytes4 result = module.validateSignature(address(account), entityId, address(0), requestHash, signature);
        assertEq(result, ERC1271_INVALID);
    }

    function testFuzz_Property9_PauseStateEnforcement(bool pauseAccountFlow) public {
        uint256 ownerKey = 9999;
        uint256 signerKey = 1010;
        address owner = vm.addr(ownerKey);
        address signer = vm.addr(signerKey);
        uint32 entityId = 53;
        bytes32 requestHash = keccak256("siwa-prop9-request");
        Mock6551Account account = new Mock6551Account(owner);

        _setPolicy(owner, address(account), entityId, signer, 0, 0);

        if (pauseAccountFlow) {
            vm.prank(owner);
            registry.pauseAccount(address(account));
        } else {
            vm.prank(owner);
            registry.pauseEntity(address(account), entityId);
        }

        bytes memory signature = SIWATestHelper.signRequestHash(vm, signerKey, requestHash);
        bytes4 result = module.validateSignature(address(account), entityId, address(0), requestHash, signature);
        assertEq(result, ERC1271_INVALID);
    }

    function _setPolicy(
        address owner,
        address account,
        uint32 entityId,
        address sessionKey,
        uint48 validAfter,
        uint48 validUntil
    ) internal {
        vm.prank(owner);
        registry.setPolicy(account, entityId, sessionKey, validAfter, validUntil, 0, bytes32(0), 0, 0, 0);
    }
}
