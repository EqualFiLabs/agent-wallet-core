// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";

import {ERC8128PolicyRegistry} from "../../src/core/ERC8128PolicyRegistry.sol";
import {ERC8128GatewayValidationModuleV2} from "../../src/modules/validation/ERC8128GatewayValidationModuleV2.sol";
import {SessionAuthV2, GatewayClaimsV2} from "../../src/libraries/ERC8128Types.sol";
import {IERC165} from "../../src/interfaces/IERC165.sol";
import {IERC6900Module} from "../../src/interfaces/IERC6900Module.sol";
import {IERC6900ValidationModule} from "../../src/interfaces/IERC6900ValidationModule.sol";
import {Mock6551Account} from "../mocks/OwnerValidationMocks.sol";

contract ERC8128GatewayValidationModuleV2Test is Test {
    uint256 internal constant SECP256K1_N =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    bytes4 internal constant ERC1271_MAGICVALUE = 0x1626ba7e;
    bytes4 internal constant ERC1271_INVALID = 0xffffffff;
    uint256 internal constant SIG_VALIDATION_FAILED = 1;

    bytes32 internal constant EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 internal constant DOMAIN_NAME_HASH = keccak256(bytes("AgentWalletERC8128"));
    bytes32 internal constant DOMAIN_VERSION_HASH = keccak256(bytes("2"));
    bytes32 internal constant SESSION_AUTHORIZATION_V2_TYPEHASH = keccak256(
        "SessionAuthorizationV2(uint8 mode,address account,uint32 entityId,address sessionKey,uint64 epoch,uint64 policyNonce,uint48 created,uint48 expires,bytes32 requestHash,bytes32 claimsHash)"
    );

    ERC8128PolicyRegistry internal registry;
    ERC8128GatewayValidationModuleV2 internal module;

    function setUp() public {
        registry = new ERC8128PolicyRegistry();
        module = new ERC8128GatewayValidationModuleV2(address(registry));
    }

    function test_ModuleMetadata_ConformsToERC6900Interfaces() public view {
        assertEq(module.moduleId(), "agent.wallet.erc8128-gateway-validation.2.0.0");
        assertTrue(module.supportsInterface(type(IERC165).interfaceId));
        assertTrue(module.supportsInterface(type(IERC6900Module).interfaceId));
        assertTrue(module.supportsInterface(type(IERC6900ValidationModule).interfaceId));
    }

    function test_ValidateUserOp_ReturnsSigValidationFailed() public view {
        PackedUserOperation memory op;
        assertEq(module.validateUserOp(0, op, bytes32(0)), SIG_VALIDATION_FAILED);
    }

    function test_ValidateRuntime_RevertsAsUnsupported() public {
        vm.expectRevert(ERC8128GatewayValidationModuleV2.RuntimeValidationNotSupported.selector);
        module.validateRuntime(address(0), 0, address(0), 0, bytes(""), bytes(""));
    }

    // **Feature: erc8128-v2-unified-policy, Property 12: Valid gateway session signature acceptance**
    function testFuzz_Property12_ValidGatewaySessionSignatureAcceptance(
        uint256 ownerKeySeed,
        uint256 sessionKeySeed,
        uint32 entityId,
        bytes32 requestHash,
        uint48 createdSeed,
        uint32 maxTtlSecondsSeed
    ) public {
        uint256 ownerKey = bound(ownerKeySeed, 1, SECP256K1_N - 1);
        uint256 sessionKey = bound(sessionKeySeed, 1, SECP256K1_N - 1);
        vm.assume(ownerKey != sessionKey);

        address owner = vm.addr(ownerKey);
        address sessionSigner = vm.addr(sessionKey);
        Mock6551Account account = new Mock6551Account(owner);

        uint48 created = uint48(bound(createdSeed, 1, type(uint48).max - 500));
        uint48 expires = created + 300;
        uint32 maxTtlSeconds = uint32(bound(maxTtlSecondsSeed, 300, type(uint32).max));
        vm.warp(created + 1);

        GatewayClaimsV2 memory claims = _baseGatewayClaims(requestHash);

        vm.prank(owner);
        registry.setPolicy(address(account), entityId, sessionSigner, 0, 0, maxTtlSeconds, claims.scopeLeaf, 0, 0, 0);

        (, uint64 epoch, uint64 policyNonce) = registry.getPolicy(address(account), entityId, sessionSigner);

        SessionAuthV2 memory auth = SessionAuthV2({
            mode: 0,
            sessionKey: sessionSigner,
            epoch: epoch,
            policyNonce: policyNonce,
            created: created,
            expires: expires,
            requestHash: requestHash,
            claimsHash: keccak256(abi.encode(claims)),
            sessionSignature: "",
            claims: abi.encode(claims)
        });

        auth.sessionSignature = _sign(sessionKey, _sessionDigest(auth, address(account), entityId));

        bytes4 result = module.validateSignature(address(account), entityId, address(0), requestHash, abi.encode(auth));
        assertEq(result, ERC1271_MAGICVALUE);
    }

    function test_ValidateSignature_RejectsOutsideCreatedExpiresWindow() public {
        uint256 ownerKey = 0xA11CE;
        uint256 sessionKey = 0xB0B;
        address owner = vm.addr(ownerKey);
        address sessionSigner = vm.addr(sessionKey);
        uint32 entityId = 7;
        bytes32 requestHash = keccak256("gateway-window-check");

        Mock6551Account account = new Mock6551Account(owner);
        GatewayClaimsV2 memory claims = _baseGatewayClaims(requestHash);

        vm.prank(owner);
        registry.setPolicy(address(account), entityId, sessionSigner, 0, 0, 900, claims.scopeLeaf, 0, 0, 0);

        (, uint64 epoch, uint64 policyNonce) = registry.getPolicy(address(account), entityId, sessionSigner);

        SessionAuthV2 memory auth = SessionAuthV2({
            mode: 0,
            sessionKey: sessionSigner,
            epoch: epoch,
            policyNonce: policyNonce,
            created: 100,
            expires: 300,
            requestHash: requestHash,
            claimsHash: keccak256(abi.encode(claims)),
            sessionSignature: "",
            claims: abi.encode(claims)
        });
        auth.sessionSignature = _sign(sessionKey, _sessionDigest(auth, address(account), entityId));

        vm.warp(99);
        assertEq(
            module.validateSignature(address(account), entityId, address(0), requestHash, abi.encode(auth)),
            ERC1271_INVALID
        );

        vm.warp(301);
        assertEq(
            module.validateSignature(address(account), entityId, address(0), requestHash, abi.encode(auth)),
            ERC1271_INVALID
        );
    }

    // **Feature: erc8128-v2-unified-policy, Property 13: Gateway validation rejection on tampered fields**
    function testFuzz_Property13_GatewayValidationRejectionOnTamperedFields(
        uint256 ownerKeySeed,
        uint256 sessionKeySeed,
        uint256 otherKeySeed,
        uint8 tamperCaseSeed,
        uint32 entityId,
        bytes32 requestHash
    ) public {
        uint256 ownerKey = bound(ownerKeySeed, 1, SECP256K1_N - 1);
        uint256 sessionKey = bound(sessionKeySeed, 1, SECP256K1_N - 1);
        uint256 otherKey = bound(otherKeySeed, 1, SECP256K1_N - 1);
        vm.assume(ownerKey != sessionKey && ownerKey != otherKey && sessionKey != otherKey);

        address owner = vm.addr(ownerKey);
        address sessionSigner = vm.addr(sessionKey);
        Mock6551Account account = new Mock6551Account(owner);

        GatewayClaimsV2 memory claims = _baseGatewayClaims(requestHash);

        vm.prank(owner);
        registry.setPolicy(address(account), entityId, sessionSigner, 0, 0, 900, claims.scopeLeaf, 0, 0, 0);

        (, uint64 epoch, uint64 policyNonce) = registry.getPolicy(address(account), entityId, sessionSigner);

        SessionAuthV2 memory auth = SessionAuthV2({
            mode: 0,
            sessionKey: sessionSigner,
            epoch: epoch,
            policyNonce: policyNonce,
            created: 100,
            expires: 300,
            requestHash: requestHash,
            claimsHash: keccak256(abi.encode(claims)),
            sessionSignature: "",
            claims: abi.encode(claims)
        });

        auth.sessionSignature = _sign(sessionKey, _sessionDigest(auth, address(account), entityId));

        uint8 tamperCase = uint8(bound(tamperCaseSeed, 0, 8));
        bytes32 callHash = requestHash;

        if (tamperCase == 0) {
            auth.mode = 1;
            auth.sessionSignature = _sign(sessionKey, _sessionDigest(auth, address(account), entityId));
        } else if (tamperCase == 1) {
            auth.requestHash = bytes32(uint256(requestHash) + 1);
            auth.sessionSignature = _sign(sessionKey, _sessionDigest(auth, address(account), entityId));
        } else if (tamperCase == 2) {
            auth.epoch = auth.epoch + 1;
            auth.sessionSignature = _sign(sessionKey, _sessionDigest(auth, address(account), entityId));
        } else if (tamperCase == 3) {
            auth.policyNonce = auth.policyNonce + 1;
            auth.sessionSignature = _sign(sessionKey, _sessionDigest(auth, address(account), entityId));
        } else if (tamperCase == 4) {
            claims.nonceHash = bytes32(0);
            _rehashAndResign(auth, claims, sessionKey, address(account), entityId);
        } else if (tamperCase == 5) {
            claims.isReplayable = true;
            claims.allowReplayable = false;
            _rehashAndResign(auth, claims, sessionKey, address(account), entityId);
        } else if (tamperCase == 6) {
            claims.scopeProof = new bytes32[](1);
            claims.scopeProof[0] = keccak256("invalid-proof");
            _rehashAndResign(auth, claims, sessionKey, address(account), entityId);
        } else if (tamperCase == 7) {
            auth.sessionSignature = _sign(otherKey, _sessionDigest(auth, address(account), entityId));
        } else {
            callHash = bytes32(uint256(requestHash) + 2);
        }

        bytes4 result = module.validateSignature(address(account), entityId, address(0), callHash, abi.encode(auth));
        assertEq(result, ERC1271_INVALID);
    }

    function _baseGatewayClaims(bytes32 requestHash) internal pure returns (GatewayClaimsV2 memory claims) {
        claims.methodBit = 1;
        claims.authorityHash = keccak256("api.example.com");
        claims.pathPrefixHash = keccak256("/v1");
        claims.isReadOnly = true;
        claims.allowReplayable = true;
        claims.allowClassBound = true;
        claims.maxBodyBytes = 4096;
        claims.isReplayable = false;
        claims.isClassBound = false;
        claims.nonceHash = keccak256(abi.encodePacked("nonce", requestHash));
        claims.scopeLeaf = keccak256(
            abi.encode(
                "AW_ERC8128_SCOPE_LEAF_V2",
                claims.methodBit,
                claims.authorityHash,
                claims.pathPrefixHash,
                claims.isReadOnly,
                claims.allowReplayable,
                claims.allowClassBound,
                claims.maxBodyBytes
            )
        );
        claims.scopeProof = new bytes32[](0);
    }

    function _rehashAndResign(
        SessionAuthV2 memory auth,
        GatewayClaimsV2 memory claims,
        uint256 sessionKey,
        address account,
        uint32 entityId
    ) internal view {
        auth.claims = abi.encode(claims);
        auth.claimsHash = keccak256(abi.encode(claims));
        auth.sessionSignature = _sign(sessionKey, _sessionDigest(auth, account, entityId));
    }

    function _sessionDigest(SessionAuthV2 memory auth, address account, uint32 entityId) internal view returns (bytes32) {
        bytes32 domainSeparator =
            keccak256(abi.encode(EIP712_DOMAIN_TYPEHASH, DOMAIN_NAME_HASH, DOMAIN_VERSION_HASH, block.chainid, address(module)));

        bytes32 structHash = keccak256(
            abi.encode(
                SESSION_AUTHORIZATION_V2_TYPEHASH,
                auth.mode,
                account,
                entityId,
                auth.sessionKey,
                auth.epoch,
                auth.policyNonce,
                auth.created,
                auth.expires,
                auth.requestHash,
                auth.claimsHash
            )
        );

        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    }

    function _sign(uint256 privateKey, bytes32 digest) internal pure returns (bytes memory signature) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        signature = abi.encodePacked(r, s, v);
    }
}
