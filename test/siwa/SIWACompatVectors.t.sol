// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";

import {ERC8128PolicyRegistry} from "../../src/core/ERC8128PolicyRegistry.sol";
import {SIWAValidationModule} from "../../src/modules/validation/SIWAValidationModule.sol";
import {SIWATestHelper} from "./SIWATestHelper.sol";
import {Mock6551Account} from "../mocks/OwnerValidationMocks.sol";

contract SIWACompatVectorsTest is Test {
    bytes4 internal constant ERC1271_MAGICVALUE = 0x1626ba7e;
    bytes4 internal constant ERC1271_INVALID = 0xffffffff;

    // Canonical deterministic vector inputs for cross-system reproducibility.
    uint256 internal constant OWNER_PRIVATE_KEY = 0xB0B;
    uint256 internal constant SIGNER_PRIVATE_KEY = 0xA11CE;
    uint32 internal constant ENTITY_ID = 7;
    bytes32 internal constant REQUEST_HASH = keccak256("SIWA_COMPAT_VECTOR_REQUEST_V2");

    ERC8128PolicyRegistry internal registry;
    SIWAValidationModule internal module;
    Mock6551Account internal account;
    address internal owner;
    address internal signer;

    function setUp() public {
        registry = new ERC8128PolicyRegistry();
        module = new SIWAValidationModule(address(registry));

        owner = vm.addr(OWNER_PRIVATE_KEY);
        signer = vm.addr(SIGNER_PRIVATE_KEY);
        account = new Mock6551Account(owner);

        _setPolicy(address(account), ENTITY_ID, signer);
    }

    // Positive vector: known key + known fields + deterministic accept.
    function test_Vector_Positive_AcceptsKnownFixture() public {
        bytes memory signature = SIWATestHelper.signRequestHash(vm, SIGNER_PRIVATE_KEY, REQUEST_HASH);
        bytes4 result = module.validateSignature(address(account), ENTITY_ID, address(0), REQUEST_HASH, signature);
        assertEq(result, ERC1271_MAGICVALUE);
    }

    // Negative vectors: tamper one field at a time.
    function test_Vector_Negative_TamperedRequestHash() public {
        bytes memory signature = SIWATestHelper.signRequestHash(vm, SIGNER_PRIVATE_KEY, REQUEST_HASH);
        bytes32 tamperedHash = keccak256("SIWA_COMPAT_VECTOR_REQUEST_V2_TAMPERED");

        bytes4 result = module.validateSignature(address(account), ENTITY_ID, address(0), tamperedHash, signature);
        assertEq(result, ERC1271_INVALID);
    }

    function test_Vector_Negative_TamperedSignature() public {
        bytes memory signature = SIWATestHelper.signRequestHash(vm, OWNER_PRIVATE_KEY, REQUEST_HASH);
        bytes4 result = module.validateSignature(address(account), ENTITY_ID, address(0), REQUEST_HASH, signature);
        assertEq(result, ERC1271_INVALID);
    }

    function test_Vector_Negative_MalformedSignature() public view {
        bytes4 result =
            module.validateSignature(address(0x1234), ENTITY_ID, address(0), REQUEST_HASH, bytes("not-a-signature"));
        assertEq(result, ERC1271_INVALID);
    }

    // Pause vectors.
    function test_Vector_PauseEntity_Rejects() public {
        bytes memory signature = SIWATestHelper.signRequestHash(vm, SIGNER_PRIVATE_KEY, REQUEST_HASH);

        vm.prank(owner);
        registry.pauseEntity(address(account), ENTITY_ID);

        bytes4 result = module.validateSignature(address(account), ENTITY_ID, address(0), REQUEST_HASH, signature);
        assertEq(result, ERC1271_INVALID);
    }

    function test_Vector_PauseAccount_Rejects() public {
        bytes memory signature = SIWATestHelper.signRequestHash(vm, SIGNER_PRIVATE_KEY, REQUEST_HASH);

        vm.prank(owner);
        registry.pauseAccount(address(account));

        bytes4 result = module.validateSignature(address(account), ENTITY_ID, address(0), REQUEST_HASH, signature);
        assertEq(result, ERC1271_INVALID);
    }

    function _setPolicy(address account_, uint32 entityId, address sessionKey) internal {
        vm.prank(owner);
        registry.setPolicy(account_, entityId, sessionKey, 0, 0, 0, bytes32(0), 0, 0, 0);
    }
}
