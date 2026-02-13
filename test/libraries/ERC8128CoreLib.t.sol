// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";

import {ERC8128CoreLib} from "../../src/libraries/ERC8128CoreLib.sol";
import {
    AAClaimsV2,
    AACallClaimV2,
    GatewayClaimsV2
} from "../../src/libraries/ERC8128Types.sol";
import {EIP712DomainLib} from "../../src/libraries/EIP712DomainLib.sol";
import {Mock1271Owner} from "../mocks/OwnerValidationMocks.sol";

contract ERC8128CoreLibHarness {
    function domainSeparator(address verifyingContract) external view returns (bytes32) {
        return ERC8128CoreLib.domainSeparator(verifyingContract);
    }

    function domainSeparatorForChain(uint256 chainId, address verifyingContract) external pure returns (bytes32) {
        return ERC8128CoreLib.domainSeparatorForChain(chainId, verifyingContract);
    }

    function sessionAuthorizationHash(
        uint8 mode,
        address account,
        uint32 entityId,
        address sessionKey,
        uint64 epoch,
        uint64 policyNonce,
        uint48 created,
        uint48 expires,
        bytes32 requestHash,
        bytes32 claimsHash
    ) external pure returns (bytes32) {
        return ERC8128CoreLib.sessionAuthorizationHash(
            mode,
            account,
            entityId,
            sessionKey,
            epoch,
            policyNonce,
            created,
            expires,
            requestHash,
            claimsHash
        );
    }

    function computeDigest(bytes32 domainSep, bytes32 structHash) external pure returns (bytes32) {
        return ERC8128CoreLib.computeDigest(domainSep, structHash);
    }

    function basePolicyKey(address account, uint32 entityId, address sessionKey, uint64 epoch)
        external
        pure
        returns (bytes32)
    {
        return ERC8128CoreLib.basePolicyKey(account, entityId, sessionKey, epoch);
    }

    function resolvedPolicyKey(bytes32 baseKey, uint64 policyNonce) external pure returns (bytes32) {
        return ERC8128CoreLib.resolvedPolicyKey(baseKey, policyNonce);
    }

    function computeGatewayScopeLeaf(
        uint16 methodBit,
        bytes32 authorityHash,
        bytes32 pathPrefixHash,
        bool isReadOnly,
        bool allowReplayable,
        bool allowClassBound,
        uint32 maxBodyBytes
    ) external pure returns (bytes32) {
        return ERC8128CoreLib.computeGatewayScopeLeaf(
            methodBit,
            authorityHash,
            pathPrefixHash,
            isReadOnly,
            allowReplayable,
            allowClassBound,
            maxBodyBytes
        );
    }

    function computeAAScopeLeaf(address target, bytes4 selector, uint256 valueLimit, bool allowDelegateCall)
        external
        pure
        returns (bytes32)
    {
        return ERC8128CoreLib.computeAAScopeLeaf(target, selector, valueLimit, allowDelegateCall);
    }

    function computeGatewayClaimsHash(GatewayClaimsV2 calldata claims) external pure returns (bytes32) {
        return ERC8128CoreLib.computeGatewayClaimsHash(claims);
    }

    function computeAAClaimsHash(AAClaimsV2 calldata claims) external pure returns (bytes32) {
        return ERC8128CoreLib.computeAAClaimsHash(claims);
    }

    function isValidSessionSigner(address sessionKey, bytes32 digest, bytes calldata sessionSignature)
        external
        view
        returns (bool)
    {
        return ERC8128CoreLib.isValidSessionSigner(sessionKey, digest, sessionSignature);
    }

    function packValidationData(address aggregator, uint48 validUntil, uint48 validAfter)
        external
        pure
        returns (uint256)
    {
        return ERC8128CoreLib.packValidationData(aggregator, validUntil, validAfter);
    }

    function serializeDomain(address verifyingContract) external view returns (string memory) {
        return ERC8128CoreLib.serializeDomain(verifyingContract);
    }

    function serializeDomainForChain(uint256 chainId, address verifyingContract) external pure returns (string memory) {
        return ERC8128CoreLib.serializeDomainForChain(chainId, verifyingContract);
    }

    function parseDomain(string calldata encoded) external pure returns (uint256 chainId, address verifyingContract) {
        return ERC8128CoreLib.parseDomain(encoded);
    }
}

contract ERC8128CoreLibTest is Test {
    uint256 internal constant SECP256K1_N =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    bytes32 internal constant EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 internal constant DOMAIN_NAME_HASH = keccak256(bytes("AgentWalletERC8128"));
    bytes32 internal constant DOMAIN_VERSION_HASH = keccak256(bytes("2"));
    bytes32 internal constant SESSION_AUTHORIZATION_V2_TYPEHASH = keccak256(
        "SessionAuthorizationV2(uint8 mode,address account,uint32 entityId,address sessionKey,uint64 epoch,uint64 policyNonce,uint48 created,uint48 expires,bytes32 requestHash,bytes32 claimsHash)"
    );

    ERC8128CoreLibHarness private _harness;

    function setUp() public {
        _harness = new ERC8128CoreLibHarness();
    }

    // **Feature: erc8128-v2-unified-policy, Property 9: EIP-712 digest computation determinism**
    function testFuzz_Property9_EIP712DigestComputationDeterminism(
        uint8 mode,
        address account,
        uint32 entityId,
        address sessionKey,
        uint64 epoch,
        uint64 policyNonce,
        uint48 created,
        uint48 expires,
        bytes32 requestHash,
        bytes32 claimsHash,
        address verifyingContract,
        uint256 chainId
    ) public view {
        bytes32 expectedDomainSep = keccak256(
            abi.encode(EIP712_DOMAIN_TYPEHASH, DOMAIN_NAME_HASH, DOMAIN_VERSION_HASH, block.chainid, verifyingContract)
        );
        bytes32 actualDomainSep = _harness.domainSeparator(verifyingContract);
        assertEq(actualDomainSep, expectedDomainSep);

        bytes32 expectedDomainSepForChain =
            keccak256(abi.encode(EIP712_DOMAIN_TYPEHASH, DOMAIN_NAME_HASH, DOMAIN_VERSION_HASH, chainId, verifyingContract));
        bytes32 actualDomainSepForChain = _harness.domainSeparatorForChain(chainId, verifyingContract);
        assertEq(actualDomainSepForChain, expectedDomainSepForChain);

        bytes32 expectedStructHash = keccak256(
            abi.encode(
                SESSION_AUTHORIZATION_V2_TYPEHASH,
                mode,
                account,
                entityId,
                sessionKey,
                epoch,
                policyNonce,
                created,
                expires,
                requestHash,
                claimsHash
            )
        );
        bytes32 actualStructHash = _harness.sessionAuthorizationHash(
            mode,
            account,
            entityId,
            sessionKey,
            epoch,
            policyNonce,
            created,
            expires,
            requestHash,
            claimsHash
        );
        assertEq(actualStructHash, expectedStructHash);

        bytes32 expectedDigest = keccak256(abi.encodePacked("\x19\x01", expectedDomainSepForChain, expectedStructHash));
        bytes32 actualDigest = _harness.computeDigest(actualDomainSepForChain, actualStructHash);
        assertEq(actualDigest, expectedDigest);
    }

    // **Feature: erc8128-v2-unified-policy, Property 10: EIP-712 domain serialization round-trip**
    function testFuzz_Property10_EIP712DomainSerializationRoundTrip(uint256 chainId, address verifyingContract)
        public
        view
    {
        string memory encoded = _harness.serializeDomainForChain(chainId, verifyingContract);
        (uint256 parsedChainId, address parsedVerifyingContract) = _harness.parseDomain(encoded);

        assertEq(parsedChainId, chainId);
        assertEq(parsedVerifyingContract, verifyingContract);

        string memory reEncoded = _harness.serializeDomainForChain(parsedChainId, parsedVerifyingContract);
        assertEq(reEncoded, encoded);
    }

    // **Feature: erc8128-v2-unified-policy, Property 11: Scope leaf and claims hash computation determinism**
    function testFuzz_Property11_ScopeLeafAndClaimsHashComputationDeterminism(
        address account,
        uint32 entityId,
        uint64 epoch,
        uint64 policyNonce,
        uint16 methodBit,
        bytes32 authorityHash,
        bytes32 pathPrefixHash,
        bool isReadOnly,
        bool allowReplayable,
        bool allowClassBound,
        uint32 maxBodyBytes,
        address target,
        bytes4 selector,
        uint256 valueLimit,
        bool allowDelegateCall,
        bytes32 leafOrderHash,
        bytes32 digestSeed,
        uint256 sessionKeySeed,
        uint256 otherKeySeed,
        address aggregator,
        uint48 validUntil,
        uint48 validAfter
    ) public view {
        bytes32 expectedGatewayLeaf = keccak256(
            abi.encode(
                "AW_ERC8128_SCOPE_LEAF_V2",
                methodBit,
                authorityHash,
                pathPrefixHash,
                isReadOnly,
                allowReplayable,
                allowClassBound,
                maxBodyBytes
            )
        );
        bytes32 actualGatewayLeaf = _harness.computeGatewayScopeLeaf(
            methodBit,
            authorityHash,
            pathPrefixHash,
            isReadOnly,
            allowReplayable,
            allowClassBound,
            maxBodyBytes
        );
        assertEq(actualGatewayLeaf, expectedGatewayLeaf);

        bytes32 expectedAALeaf = keccak256(abi.encode("AW_ERC8128_AA_SCOPE_LEAF_V2", target, selector, valueLimit, allowDelegateCall));
        bytes32 actualAALeaf = _harness.computeAAScopeLeaf(target, selector, valueLimit, allowDelegateCall);
        assertEq(actualAALeaf, expectedAALeaf);

        bytes32[] memory gatewayProof = new bytes32[](2);
        gatewayProof[0] = keccak256(abi.encodePacked("gateway-proof-0", authorityHash));
        gatewayProof[1] = keccak256(abi.encodePacked("gateway-proof-1", pathPrefixHash));
        GatewayClaimsV2 memory gatewayClaims = GatewayClaimsV2({
            methodBit: methodBit,
            authorityHash: authorityHash,
            pathPrefixHash: pathPrefixHash,
            isReadOnly: isReadOnly,
            allowReplayable: allowReplayable,
            allowClassBound: allowClassBound,
            maxBodyBytes: maxBodyBytes,
            isReplayable: false,
            isClassBound: false,
            nonceHash: keccak256(abi.encodePacked("nonce", digestSeed)),
            scopeLeaf: actualGatewayLeaf,
            scopeProof: gatewayProof
        });

        bytes32 expectedGatewayClaimsHash = keccak256(abi.encode(gatewayClaims));
        bytes32 actualGatewayClaimsHash = _harness.computeGatewayClaimsHash(gatewayClaims);
        assertEq(actualGatewayClaimsHash, expectedGatewayClaimsHash);

        AACallClaimV2[] memory callClaims = new AACallClaimV2[](2);

        bytes32[] memory scopeProofA = new bytes32[](1);
        scopeProofA[0] = keccak256(abi.encodePacked("aa-proof-a", target));
        callClaims[0] = AACallClaimV2({
            target: target,
            selector: selector,
            valueLimit: valueLimit,
            allowDelegateCall: allowDelegateCall,
            scopeLeaf: actualAALeaf,
            scopeProof: scopeProofA
        });

        bytes32[] memory scopeProofB = new bytes32[](1);
        scopeProofB[0] = keccak256(abi.encodePacked("aa-proof-b", account));
        callClaims[1] = AACallClaimV2({
            target: account,
            selector: bytes4(keccak256("execute(address,uint256,bytes)")),
            valueLimit: uint256(methodBit) + 1,
            allowDelegateCall: false,
            scopeLeaf: keccak256(abi.encodePacked("aa-leaf-b", target, selector, valueLimit)),
            scopeProof: scopeProofB
        });

        bytes32[] memory multiproof = new bytes32[](2);
        multiproof[0] = keccak256(abi.encodePacked("multi-proof-0", leafOrderHash));
        multiproof[1] = keccak256(abi.encodePacked("multi-proof-1", digestSeed));

        bool[] memory proofFlags = new bool[](2);
        proofFlags[0] = true;
        proofFlags[1] = false;

        AAClaimsV2 memory aaClaims =
            AAClaimsV2({callClaims: callClaims, multiproof: multiproof, proofFlags: proofFlags, leafOrderHash: leafOrderHash});

        bytes32 expectedAAClaimsHash = keccak256(abi.encode(aaClaims));
        bytes32 actualAAClaimsHash = _harness.computeAAClaimsHash(aaClaims);
        assertEq(actualAAClaimsHash, expectedAAClaimsHash);

        bytes32 expectedBaseKey = keccak256(abi.encode(account, entityId, account, epoch));
        bytes32 actualBaseKey = _harness.basePolicyKey(account, entityId, account, epoch);
        assertEq(actualBaseKey, expectedBaseKey);

        bytes32 expectedResolvedKey = keccak256(abi.encode(expectedBaseKey, policyNonce));
        bytes32 actualResolvedKey = _harness.resolvedPolicyKey(actualBaseKey, policyNonce);
        assertEq(actualResolvedKey, expectedResolvedKey);

        uint256 sessionKey = bound(sessionKeySeed, 1, SECP256K1_N - 1);
        uint256 otherKey = bound(otherKeySeed, 1, SECP256K1_N - 1);
        vm.assume(sessionKey != otherKey);

        address signer = vm.addr(sessionKey);
        bytes32 digest = keccak256(abi.encodePacked("session-digest", digestSeed));

        bytes memory validSignature = _sign(sessionKey, digest);
        assertTrue(_harness.isValidSessionSigner(signer, digest, validSignature));

        bytes memory invalidSignature = _sign(otherKey, digest);
        assertFalse(_harness.isValidSessionSigner(signer, digest, invalidSignature));

        uint256 expectedPacked = uint256(uint160(aggregator)) | (uint256(validUntil) << 160) | (uint256(validAfter) << 208);
        uint256 actualPacked = _harness.packValidationData(aggregator, validUntil, validAfter);
        assertEq(actualPacked, expectedPacked);
    }

    function test_IsValidSessionSigner_AcceptsScaSigner() public {
        uint256 signerKey = 123456;
        address signer = vm.addr(signerKey);
        Mock1271Owner scaSigner = new Mock1271Owner(signer);

        bytes32 digest = keccak256("sca-digest");
        bytes memory signature = _sign(signerKey, digest);

        assertTrue(_harness.isValidSessionSigner(address(scaSigner), digest, signature));
    }

    function test_IsValidSessionSigner_RejectsScaSignerWithBadSignature() public {
        uint256 signerKey = 999;
        uint256 otherKey = 1000;
        address signer = vm.addr(signerKey);
        Mock1271Owner scaSigner = new Mock1271Owner(signer);

        bytes32 digest = keccak256("sca-digest-bad");
        bytes memory signature = _sign(otherKey, digest);

        assertFalse(_harness.isValidSessionSigner(address(scaSigner), digest, signature));
    }

    function test_ParseDomain_RevertsForWrongNameOrVersion() public {
        string memory encoded = EIP712DomainLib.serialize("WrongName", "2", block.chainid, address(_harness));
        vm.expectRevert(ERC8128CoreLib.InvalidDomainNameOrVersion.selector);
        _harness.parseDomain(encoded);
    }

    function _sign(uint256 key, bytes32 digest) internal pure returns (bytes memory signature) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest);
        signature = abi.encodePacked(r, s, v);
    }
}
