// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";

import {ERC8128PolicyRegistry} from "../../src/core/ERC8128PolicyRegistry.sol";
import {SIWAValidationModule} from "../../src/modules/validation/SIWAValidationModule.sol";
import {SIWAAuthV1} from "../../src/libraries/SIWATypes.sol";
import {GatewayClaimsV2} from "../../src/libraries/ERC8128Types.sol";
import {SIWATestHelper} from "./SIWATestHelper.sol";
import {Mock6551Account} from "../mocks/OwnerValidationMocks.sol";

contract SIWACompatVectorsTest is Test {
    bytes4 internal constant ERC1271_MAGICVALUE = 0x1626ba7e;
    bytes4 internal constant ERC1271_INVALID = 0xffffffff;

    // Canonical deterministic vector inputs for cross-system reproducibility.
    uint256 internal constant OWNER_PRIVATE_KEY = 0xB0B;
    uint256 internal constant SIGNER_PRIVATE_KEY = 0xA11CE;
    uint32 internal constant ENTITY_ID = 7;
    uint48 internal constant CREATED = 1_700_000_000;
    uint48 internal constant EXPIRES = 1_700_000_900;
    bytes32 internal constant REQUEST_HASH = keccak256("SIWA_COMPAT_VECTOR_REQUEST_V2");

    ERC8128PolicyRegistry internal registry;
    SIWAValidationModule internal module;
    Mock6551Account internal account;
    address internal owner;
    address internal signer;

    struct CompatVector {
        GatewayClaimsV2 claims;
        SIWAAuthV1 auth;
    }

    function setUp() public {
        registry = new ERC8128PolicyRegistry();
        module = new SIWAValidationModule(address(registry));

        owner = vm.addr(OWNER_PRIVATE_KEY);
        signer = vm.addr(SIGNER_PRIVATE_KEY);
        account = new Mock6551Account(owner);

        GatewayClaimsV2 memory claims = SIWATestHelper.buildGatewayClaims(REQUEST_HASH);
        _setPolicy(address(account), ENTITY_ID, signer, claims.scopeLeaf);

        vm.warp(CREATED + 1);
    }

    // Positive vector: known key + known fields + deterministic accept.
    function test_Vector_Positive_AcceptsKnownFixture() public {
        CompatVector memory vector = _baseVector();

        // Deterministic values that TS SDK should reproduce.
        assertEq(vector.auth.requestHash, REQUEST_HASH);
        assertEq(vector.auth.claimsHash, keccak256(abi.encode(vector.claims)));
        assertEq(vector.auth.created, CREATED);
        assertEq(vector.auth.expires, EXPIRES);
        assertEq(vector.auth.signer, signer);

        bytes4 result = module.validateSignature(address(account), ENTITY_ID, address(0), REQUEST_HASH, abi.encode(vector.auth));
        assertEq(result, ERC1271_MAGICVALUE);
    }

    // Negative vectors: tamper one field at a time.
    function test_Vector_Negative_TamperedRequestHash() public {
        CompatVector memory vector = _baseVector();
        vector.auth.requestHash = keccak256("SIWA_COMPAT_VECTOR_REQUEST_V2_TAMPERED");

        bytes4 result = module.validateSignature(address(account), ENTITY_ID, address(0), REQUEST_HASH, abi.encode(vector.auth));
        assertEq(result, ERC1271_INVALID);
    }

    function test_Vector_Negative_TamperedClaimsHash() public {
        CompatVector memory vector = _baseVector();
        vector.auth.claimsHash = keccak256("SIWA_COMPAT_VECTOR_CLAIMS_HASH_TAMPERED");

        bytes4 result = module.validateSignature(address(account), ENTITY_ID, address(0), REQUEST_HASH, abi.encode(vector.auth));
        assertEq(result, ERC1271_INVALID);
    }

    function test_Vector_Negative_TamperedSigner() public {
        CompatVector memory vector = _baseVector();
        vector.auth.signer = makeAddr("siwa-vector-wrong-signer");

        bytes4 result = module.validateSignature(address(account), ENTITY_ID, address(0), REQUEST_HASH, abi.encode(vector.auth));
        assertEq(result, ERC1271_INVALID);
    }

    function test_Vector_Negative_TamperedCreated() public {
        CompatVector memory vector = _baseVector();
        vector.auth.created = EXPIRES;

        bytes4 result = module.validateSignature(address(account), ENTITY_ID, address(0), REQUEST_HASH, abi.encode(vector.auth));
        assertEq(result, ERC1271_INVALID);
    }

    function test_Vector_Negative_TamperedExpires() public {
        CompatVector memory vector = _baseVector();
        vector.auth.expires = CREATED - 1;

        bytes4 result = module.validateSignature(address(account), ENTITY_ID, address(0), REQUEST_HASH, abi.encode(vector.auth));
        assertEq(result, ERC1271_INVALID);
    }

    // Pause vectors.
    function test_Vector_PauseEntity_Rejects() public {
        CompatVector memory vector = _baseVector();

        vm.prank(owner);
        registry.pauseEntity(address(account), ENTITY_ID);

        bytes4 result = module.validateSignature(address(account), ENTITY_ID, address(0), REQUEST_HASH, abi.encode(vector.auth));
        assertEq(result, ERC1271_INVALID);
    }

    function test_Vector_PauseAccount_Rejects() public {
        CompatVector memory vector = _baseVector();

        vm.prank(owner);
        registry.pauseAccount(address(account));

        bytes4 result = module.validateSignature(address(account), ENTITY_ID, address(0), REQUEST_HASH, abi.encode(vector.auth));
        assertEq(result, ERC1271_INVALID);
    }

    function _baseVector() internal returns (CompatVector memory vector) {
        GatewayClaimsV2 memory claims = SIWATestHelper.buildGatewayClaims(REQUEST_HASH);
        SIWAAuthV1 memory auth = SIWATestHelper.buildGatewayAuth(
            vm,
            SIGNER_PRIVATE_KEY,
            signer,
            CREATED,
            EXPIRES,
            REQUEST_HASH,
            claims
        );
        vector = CompatVector({claims: claims, auth: auth});
    }

    function _setPolicy(address account_, uint32 entityId, address sessionKey, bytes32 scopeRoot) internal {
        vm.prank(owner);
        registry.setPolicy(account_, entityId, sessionKey, 0, 0, 1200, scopeRoot, 0, 0, 0);
    }
}
