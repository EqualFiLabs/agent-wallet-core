// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";

import {ERC8128PolicyRegistry} from "../../src/core/ERC8128PolicyRegistry.sol";
import {SIWAValidationModule} from "../../src/modules/validation/SIWAValidationModule.sol";
import {SIWAAuthV1} from "../../src/libraries/SIWATypes.sol";
import {GatewayClaimsV2} from "../../src/libraries/ERC8128Types.sol";
import {IERC165} from "../../src/interfaces/IERC165.sol";
import {IERC6900Module} from "../../src/interfaces/IERC6900Module.sol";
import {IERC6900ValidationModule} from "../../src/interfaces/IERC6900ValidationModule.sol";
import {SIWATestHelper} from "../siwa/SIWATestHelper.sol";
import {Mock6551Account, Mock1271Owner} from "../mocks/OwnerValidationMocks.sol";

contract MockReverting1271 {
    function isValidSignature(bytes32, bytes memory) external pure returns (bytes4) {
        revert("reverting-1271");
    }
}

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

    // **Feature: siwa-compat-layer, Property 3: Non-Gateway Paths Rejected**
    function testFuzz_Property3_NonGatewayPathsRejected(uint32 entityId, bytes32 userOpHash) public {
        PackedUserOperation memory userOp;
        assertEq(module.validateUserOp(entityId, userOp, userOpHash), SIG_VALIDATION_FAILED);

        vm.expectRevert(SIWAValidationModule.RuntimeValidationNotSupported.selector);
        module.validateRuntime(address(0xA11CE), entityId, address(0xBEEF), 1, bytes("abc"), bytes("auth"));
    }

    function test_ValidateSignature_AcceptsValidEnvelope() public {
        uint256 ownerKey = 111;
        uint256 signerKey = 222;
        address owner = vm.addr(ownerKey);
        address signer = vm.addr(signerKey);
        uint32 entityId = 7;
        bytes32 requestHash = keccak256("siwa-request");

        Mock6551Account account = new Mock6551Account(owner);
        GatewayClaimsV2 memory claims = SIWATestHelper.buildGatewayClaims(requestHash);

        _setPolicy(owner, address(account), entityId, signer, claims.scopeLeaf);

        SIWAAuthV1 memory auth = SIWATestHelper.buildGatewayAuth(
            vm,
            signerKey,
            signer,
            uint48(block.timestamp - 1),
            uint48(block.timestamp + 300),
            requestHash,
            claims
        );

        bytes4 result = module.validateSignature(address(account), entityId, address(0), requestHash, abi.encode(auth));
        assertEq(result, ERC1271_MAGICVALUE);
    }

    function test_ValidateSignature_RejectsMalformedEnvelope() public view {
        bytes4 result = module.validateSignature(address(0xCAFE), 0, address(0), bytes32(0), bytes("not-abi-encoded"));
        assertEq(result, ERC1271_INVALID);
    }

    function test_ValidateSignature_RejectsWithoutActivePolicy() public {
        uint256 ownerKey = 123;
        uint256 signerKey = 456;
        address owner = vm.addr(ownerKey);
        address signer = vm.addr(signerKey);
        Mock6551Account account = new Mock6551Account(owner);

        bytes32 requestHash = keccak256("siwa-no-policy");
        GatewayClaimsV2 memory claims = SIWATestHelper.buildGatewayClaims(requestHash);

        SIWAAuthV1 memory auth = SIWATestHelper.buildGatewayAuth(
            vm,
            signerKey,
            signer,
            uint48(block.timestamp - 1),
            uint48(block.timestamp + 300),
            requestHash,
            claims
        );

        assertEq(module.validateSignature(address(account), 1, address(0), requestHash, abi.encode(auth)), ERC1271_INVALID);
    }

    // **Feature: siwa-compat-layer, Property 4: Field Tampering Rejection**
    function testFuzz_Property4_FieldTamperingRejection(uint8 tamperCaseSeed) public {
        uint8 tamperCase = uint8(bound(tamperCaseSeed, 0, 1)); // 0=requestHash, 1=claimsHash

        uint256 ownerKey = 1111;
        uint256 signerKey = 2222;
        address owner = vm.addr(ownerKey);
        address signer = vm.addr(signerKey);
        uint32 entityId = 19;
        bytes32 requestHash = keccak256("siwa-prop4-request");

        Mock6551Account account = new Mock6551Account(owner);

        GatewayClaimsV2 memory claims = SIWATestHelper.buildGatewayClaims(requestHash);
        _setPolicy(owner, address(account), entityId, signer, claims.scopeLeaf);

        SIWAAuthV1 memory auth = SIWATestHelper.buildGatewayAuth(
            vm,
            signerKey,
            signer,
            uint48(block.timestamp - 1),
            uint48(block.timestamp + 300),
            requestHash,
            claims
        );

        if (tamperCase == 0) {
            auth.requestHash = keccak256("tampered-request-hash");
        } else {
            auth.claimsHash = keccak256("tampered-claims-hash");
        }

        bytes4 result = module.validateSignature(address(account), entityId, address(0), requestHash, abi.encode(auth));
        assertEq(result, ERC1271_INVALID);
    }

    // **Feature: siwa-compat-layer, Property 5: Signature Verification**
    function testFuzz_Property5_SignatureVerification(uint256 signerKeySeed, uint256 wrongKeySeed, bool useScaSigner)
        public
    {
        uint256 signerKey = SIWATestHelper.normalizePrivateKey(signerKeySeed);
        uint256 wrongKey = SIWATestHelper.normalizePrivateKey(wrongKeySeed);
        vm.assume(signerKey != wrongKey);

        address owner = makeAddr("prop5-owner");
        address signerEOA = vm.addr(signerKey);
        address signerAddress = signerEOA;

        if (useScaSigner) {
            signerAddress = address(new Mock1271Owner(signerEOA));
        }

        Mock6551Account account = new Mock6551Account(owner);
        uint32 entityId = 23;
        bytes32 requestHash = keccak256("siwa-prop5-request");

        GatewayClaimsV2 memory claims = SIWATestHelper.buildGatewayClaims(requestHash);
        _setPolicy(owner, address(account), entityId, signerAddress, claims.scopeLeaf);

        SIWAAuthV1 memory auth = SIWATestHelper.buildGatewayAuth(
            vm,
            wrongKey,
            signerAddress,
            uint48(block.timestamp - 1),
            uint48(block.timestamp + 300),
            requestHash,
            claims
        );

        bytes4 result = module.validateSignature(address(account), entityId, address(0), requestHash, abi.encode(auth));
        assertEq(result, ERC1271_INVALID);
    }

    // **Feature: siwa-compat-layer, Property 8: Time Window Enforcement**
    function testFuzz_Property8_TimeWindowEnforcement(uint8 timeCaseSeed, uint48 baseTimeSeed) public {
        uint8 timeCase = uint8(bound(timeCaseSeed, 0, 2));
        uint48 baseTime = uint48(bound(baseTimeSeed, 500, type(uint48).max - 1000));
        vm.warp(baseTime);

        uint48 created;
        uint48 expires;
        if (timeCase == 0) {
            created = baseTime + 10;
            expires = baseTime + 10; // created >= expires
        } else if (timeCase == 1) {
            created = baseTime + 50; // not yet valid
            expires = baseTime + 100;
        } else {
            created = baseTime - 200; // expired
            expires = baseTime - 100;
        }

        uint256 ownerKey = 7777;
        uint256 signerKey = 8888;
        address owner = vm.addr(ownerKey);
        address signer = vm.addr(signerKey);
        uint32 entityId = 41;
        bytes32 requestHash = keccak256("siwa-prop8-request");

        Mock6551Account account = new Mock6551Account(owner);

        GatewayClaimsV2 memory claims = SIWATestHelper.buildGatewayClaims(requestHash);
        _setPolicy(owner, address(account), entityId, signer, claims.scopeLeaf);

        SIWAAuthV1 memory auth = SIWATestHelper.buildGatewayAuth(vm, signerKey, signer, created, expires, requestHash, claims);
        bytes4 result = module.validateSignature(address(account), entityId, address(0), requestHash, abi.encode(auth));
        assertEq(result, ERC1271_INVALID);
    }

    // **Feature: siwa-compat-layer, Property 9: Pause State Enforcement**
    function testFuzz_Property9_PauseStateEnforcement(bool pauseAccountFlow) public {
        uint256 ownerKey = 9999;
        uint256 signerKey = 1010;
        address owner = vm.addr(ownerKey);
        address signer = vm.addr(signerKey);
        uint32 entityId = 53;
        bytes32 requestHash = keccak256("siwa-prop9-request");

        Mock6551Account account = new Mock6551Account(owner);

        GatewayClaimsV2 memory claims = SIWATestHelper.buildGatewayClaims(requestHash);
        _setPolicy(owner, address(account), entityId, signer, claims.scopeLeaf);

        if (pauseAccountFlow) {
            vm.prank(owner);
            registry.pauseAccount(address(account));
        } else {
            vm.prank(owner);
            registry.pauseEntity(address(account), entityId);
        }

        SIWAAuthV1 memory auth = SIWATestHelper.buildGatewayAuth(
            vm,
            signerKey,
            signer,
            uint48(block.timestamp - 1),
            uint48(block.timestamp + 300),
            requestHash,
            claims
        );
        bytes4 result = module.validateSignature(address(account), entityId, address(0), requestHash, abi.encode(auth));
        assertEq(result, ERC1271_INVALID);
    }

    // **Feature: siwa-compat-layer, Property 11: NR rule tests for recursive signer prevention**
    function test_ValidateSignature_RejectsSignerEqualToAccountContract_NR1() public {
        uint256 signerKey = 888;
        address signer = vm.addr(signerKey);
        address owner = makeAddr("nr1-owner");
        Mock6551Account account = new Mock6551Account(owner);

        uint32 entityId = 5;
        bytes32 requestHash = keccak256("siwa-nr1");

        GatewayClaimsV2 memory claims = SIWATestHelper.buildGatewayClaims(requestHash);
        _setPolicy(owner, address(account), entityId, address(account), claims.scopeLeaf);

        SIWAAuthV1 memory auth = SIWATestHelper.buildGatewayAuth(
            vm,
            signerKey,
            address(account),
            uint48(block.timestamp - 1),
            uint48(block.timestamp + 300),
            requestHash,
            claims
        );

        bytes4 result = module.validateSignature(address(account), entityId, address(0), requestHash, abi.encode(auth));
        assertEq(result, ERC1271_INVALID);
    }

    function testFuzz_Property11_NR2_ContractSignerSingleHopNoAccountRecursion(uint256 signerKeySeed) public {
        uint256 signerKey = SIWATestHelper.normalizePrivateKey(signerKeySeed);
        address signerEOA = vm.addr(signerKey);

        MockReverting1271 account = new MockReverting1271();
        Mock1271Owner signerContract = new Mock1271Owner(signerEOA);

        uint32 entityId = 61;
        bytes32 requestHash = keccak256("siwa-nr2-request");

        GatewayClaimsV2 memory claims = SIWATestHelper.buildGatewayClaims(requestHash);

        SIWAAuthV1 memory auth = SIWATestHelper.buildGatewayAuth(
            vm,
            signerKey,
            address(signerContract),
            uint48(block.timestamp - 1),
            uint48(block.timestamp + 300),
            requestHash,
            claims
        );

        // No policy for this account means invalid, but call must not recurse into account ERC-1271.
        bytes4 result = module.validateSignature(address(account), entityId, address(0), requestHash, abi.encode(auth));
        assertEq(result, ERC1271_INVALID);
    }

    function _setPolicy(address owner, address account, uint32 entityId, address sessionKey, bytes32 scopeRoot) internal {
        vm.prank(owner);
        registry.setPolicy(account, entityId, sessionKey, 0, 0, 600, scopeRoot, 0, 0, 0);
    }
}
