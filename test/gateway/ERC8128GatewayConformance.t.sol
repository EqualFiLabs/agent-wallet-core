// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";

import {SessionAuthV2, GatewayClaimsV2} from "../../src/libraries/ERC8128Types.sol";

contract GatewayConformanceHarness {
    bytes4 internal constant ERC1271_MAGICVALUE = 0x1626ba7e;

    function computeNonceHash(bytes calldata nonce) external pure returns (bytes32) {
        return keccak256(nonce);
    }

    function verifyConformanceAndCall(
        uint48 parsedCreated,
        uint48 parsedExpires,
        bytes32 parsedNonceHash,
        uint256 parsedBodyBytes,
        bool nonReplayableRequest,
        address signerAccount,
        bytes32 requestHash,
        bytes calldata signature,
        SessionAuthV2 calldata auth
    ) external view returns (bool) {
        GatewayClaimsV2 memory claims = abi.decode(auth.claims, (GatewayClaimsV2));

        if (parsedCreated != auth.created) {
            return false;
        }
        if (parsedExpires != auth.expires) {
            return false;
        }
        if (requestHash != auth.requestHash) {
            return false;
        }
        if (nonReplayableRequest && parsedNonceHash != claims.nonceHash) {
            return false;
        }
        if (parsedBodyBytes > claims.maxBodyBytes) {
            return false;
        }

        return IERC1271(signerAccount).isValidSignature(requestHash, signature) == ERC1271_MAGICVALUE;
    }
}

contract Mock1271Accepting is IERC1271 {
    function isValidSignature(bytes32, bytes memory) external pure returns (bytes4) {
        return IERC1271.isValidSignature.selector;
    }
}

contract Mock1271Reverting is IERC1271 {
    function isValidSignature(bytes32, bytes memory) external pure returns (bytes4) {
        revert("gateway-should-not-call");
    }
}

contract ERC8128GatewayConformanceTest is Test {
    GatewayConformanceHarness internal harness;
    Mock1271Accepting internal accepting1271;
    Mock1271Reverting internal reverting1271;

    function setUp() public {
        harness = new GatewayConformanceHarness();
        accepting1271 = new Mock1271Accepting();
        reverting1271 = new Mock1271Reverting();
    }

    // Gateway vector/spec case (Req 12.1, 12.4):
    // Reject when Signature-Input.created != SessionAuth.created
    function test_GatewayVector_RejectsCreatedMismatch() public view {
        SessionAuthV2 memory auth = _baseAuth();
        GatewayClaimsV2 memory claims = abi.decode(auth.claims, (GatewayClaimsV2));
        bool ok = harness.verifyConformanceAndCall(
            auth.created + 1, // mismatch
            auth.expires,
            claims.nonceHash,
            claims.maxBodyBytes,
            true,
            address(reverting1271),
            auth.requestHash,
            bytes("sig"),
            auth
        );
        assertFalse(ok);
    }

    // Gateway vector/spec case (Req 12.2, 12.4):
    // Reject when Signature-Input.expires != SessionAuth.expires
    function test_GatewayVector_RejectsExpiresMismatch() public view {
        SessionAuthV2 memory auth = _baseAuth();
        GatewayClaimsV2 memory claims = abi.decode(auth.claims, (GatewayClaimsV2));
        bool ok = harness.verifyConformanceAndCall(
            auth.created,
            auth.expires + 1, // mismatch
            claims.nonceHash,
            claims.maxBodyBytes,
            true,
            address(reverting1271),
            auth.requestHash,
            bytes("sig"),
            auth
        );
        assertFalse(ok);
    }

    // Gateway vector/spec case (Req 12.3, 12.4):
    // Reject non-replayable request when parsed nonce hash != SessionAuth.nonceHash
    function test_GatewayVector_RejectsNonceHashMismatchForNonReplayable() public view {
        SessionAuthV2 memory auth = _baseAuth();
        GatewayClaimsV2 memory claims = abi.decode(auth.claims, (GatewayClaimsV2));
        bool ok = harness.verifyConformanceAndCall(
            auth.created,
            auth.expires,
            bytes32(uint256(claims.nonceHash) ^ uint256(1)), // mismatch
            claims.maxBodyBytes,
            true,
            address(reverting1271),
            auth.requestHash,
            bytes("sig"),
            auth
        );
        assertFalse(ok);
    }

    // Gateway vector/spec case (Req 13.1, 13.2):
    // Reject when request body length exceeds proved leaf maxBodyBytes
    function test_GatewayVector_RejectsBodyBytesExceeded() public view {
        SessionAuthV2 memory auth = _baseAuth();
        GatewayClaimsV2 memory claims = abi.decode(auth.claims, (GatewayClaimsV2));
        bool ok = harness.verifyConformanceAndCall(
            auth.created,
            auth.expires,
            claims.nonceHash,
            uint256(claims.maxBodyBytes) + 1, // exceed limit
            true,
            address(reverting1271),
            auth.requestHash,
            bytes("sig"),
            auth
        );
        assertFalse(ok);
    }

    // Gateway vector/spec case:
    // Reject when SessionAuth.requestHash does not match parsed outer request hash.
    function test_GatewayVector_RejectsRequestHashMismatch() public view {
        SessionAuthV2 memory auth = _baseAuth();
        GatewayClaimsV2 memory claims = abi.decode(auth.claims, (GatewayClaimsV2));
        bool ok = harness.verifyConformanceAndCall(
            auth.created,
            auth.expires,
            claims.nonceHash,
            claims.maxBodyBytes,
            true,
            address(reverting1271),
            keccak256("other-request"), // mismatch
            bytes("sig"),
            auth
        );
        assertFalse(ok);
    }

    // Positive control for vector harness:
    // matching fields + within body limit should reach isValidSignature path and succeed.
    function test_GatewayVector_AcceptsMatchingInputs() public view {
        SessionAuthV2 memory auth = _baseAuth();
        GatewayClaimsV2 memory claims = abi.decode(auth.claims, (GatewayClaimsV2));
        bool ok = harness.verifyConformanceAndCall(
            auth.created,
            auth.expires,
            claims.nonceHash,
            claims.maxBodyBytes,
            true,
            address(accepting1271),
            auth.requestHash,
            bytes("sig"),
            auth
        );
        assertTrue(ok);
    }

    function test_GatewayVector_NonceHashHelper() public view {
        bytes memory nonce = bytes("base64url_nonce_example");
        assertEq(harness.computeNonceHash(nonce), keccak256(nonce));
    }

    function _baseAuth() internal pure returns (SessionAuthV2 memory auth) {
        GatewayClaimsV2 memory claims;
        claims.methodBit = 1;
        claims.authorityHash = keccak256("api.example.com");
        claims.pathPrefixHash = keccak256("/v1/resource");
        claims.isReadOnly = true;
        claims.allowReplayable = true;
        claims.allowClassBound = true;
        claims.maxBodyBytes = 1024;
        claims.isReplayable = false;
        claims.isClassBound = false;
        claims.nonceHash = keccak256("nonce");
        claims.scopeLeaf = keccak256("scopeLeaf");
        claims.scopeProof = new bytes32[](0);

        auth.mode = 0;
        auth.sessionKey = address(0xBEEF);
        auth.epoch = 1;
        auth.policyNonce = 1;
        auth.created = 1000;
        auth.expires = 1300;
        auth.requestHash = keccak256("request");
        auth.claimsHash = keccak256(abi.encode(claims));
        auth.sessionSignature = bytes("sig");
        auth.claims = abi.encode(claims);
    }
}
