// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";

import {AAClaimsV2, GatewayClaimsV2} from "./ERC8128Types.sol";
import {EIP712DomainLib} from "./EIP712DomainLib.sol";

/// @title ERC8128CoreLib
/// @notice Shared v2 helpers for ERC-8128 gateway and AA validation modules.
library ERC8128CoreLib {
    bytes4 internal constant ERC1271_MAGICVALUE = IERC1271.isValidSignature.selector;

    string internal constant DOMAIN_NAME = "AgentWalletERC8128";
    string internal constant DOMAIN_VERSION = "2";
    string internal constant GATEWAY_SCOPE_LEAF_TAG = "AW_ERC8128_SCOPE_LEAF_V2";
    string internal constant AA_SCOPE_LEAF_TAG = "AW_ERC8128_AA_SCOPE_LEAF_V2";

    bytes32 internal constant DOMAIN_NAME_HASH = keccak256(bytes(DOMAIN_NAME));
    bytes32 internal constant DOMAIN_VERSION_HASH = keccak256(bytes(DOMAIN_VERSION));
    bytes32 internal constant EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 internal constant SESSION_AUTHORIZATION_V2_TYPEHASH = keccak256(
        "SessionAuthorizationV2(uint8 mode,address account,uint32 entityId,address sessionKey,uint64 epoch,uint64 policyNonce,uint48 created,uint48 expires,bytes32 requestHash,bytes32 claimsHash)"
    );

    error InvalidDomainNameOrVersion();

    function domainSeparator(address verifyingContract) internal view returns (bytes32) {
        return domainSeparatorForChain(block.chainid, verifyingContract);
    }

    function domainSeparatorForChain(uint256 chainId, address verifyingContract) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                DOMAIN_NAME_HASH,
                DOMAIN_VERSION_HASH,
                chainId,
                verifyingContract
            )
        );
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
    ) internal pure returns (bytes32) {
        return keccak256(
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
    }

    function computeDigest(bytes32 domainSep, bytes32 structHash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", domainSep, structHash));
    }

    function basePolicyKey(address account, uint32 entityId, address sessionKey, uint64 epoch)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(account, entityId, sessionKey, epoch));
    }

    function resolvedPolicyKey(bytes32 baseKey, uint64 policyNonce) internal pure returns (bytes32) {
        return keccak256(abi.encode(baseKey, policyNonce));
    }

    function computeGatewayScopeLeaf(
        uint16 methodBit,
        bytes32 authorityHash,
        bytes32 pathPrefixHash,
        bool isReadOnly,
        bool allowReplayable,
        bool allowClassBound,
        uint32 maxBodyBytes
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                GATEWAY_SCOPE_LEAF_TAG,
                methodBit,
                authorityHash,
                pathPrefixHash,
                isReadOnly,
                allowReplayable,
                allowClassBound,
                maxBodyBytes
            )
        );
    }

    function computeAAScopeLeaf(address target, bytes4 selector, uint256 valueLimit, bool allowDelegateCall)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(AA_SCOPE_LEAF_TAG, target, selector, valueLimit, allowDelegateCall));
    }

    function computeGatewayClaimsHash(GatewayClaimsV2 memory gatewayClaims) internal pure returns (bytes32) {
        return keccak256(abi.encode(gatewayClaims));
    }

    function computeAAClaimsHash(AAClaimsV2 memory aaClaims) internal pure returns (bytes32) {
        return keccak256(abi.encode(aaClaims));
    }

    function isValidSessionSigner(address sessionKey, bytes32 digest, bytes memory sessionSignature)
        internal
        view
        returns (bool)
    {
        if (sessionKey.code.length == 0) {
            (address recovered, ECDSA.RecoverError err, ) = ECDSA.tryRecover(digest, sessionSignature);
            return err == ECDSA.RecoverError.NoError && recovered == sessionKey;
        }

        (bool ok, bytes memory data) =
            sessionKey.staticcall(abi.encodeWithSelector(IERC1271.isValidSignature.selector, digest, sessionSignature));
        return ok && data.length == 32 && bytes4(data) == ERC1271_MAGICVALUE;
    }

    function packValidationData(address aggregator, uint48 validUntil, uint48 validAfter)
        internal
        pure
        returns (uint256)
    {
        return uint256(uint160(aggregator)) | (uint256(validUntil) << 160) | (uint256(validAfter) << 208);
    }

    function serializeDomain(address verifyingContract) internal view returns (string memory) {
        return serializeDomainForChain(block.chainid, verifyingContract);
    }

    function serializeDomainForChain(uint256 chainId, address verifyingContract) internal pure returns (string memory) {
        return EIP712DomainLib.serialize(DOMAIN_NAME, DOMAIN_VERSION, chainId, verifyingContract);
    }

    function parseDomain(string memory encoded) internal pure returns (uint256 chainId, address verifyingContract) {
        string memory parsedName;
        string memory parsedVersion;

        (parsedName, parsedVersion, chainId, verifyingContract) = EIP712DomainLib.parse(encoded);
        if (keccak256(bytes(parsedName)) != DOMAIN_NAME_HASH || keccak256(bytes(parsedVersion)) != DOMAIN_VERSION_HASH) {
            revert InvalidDomainNameOrVersion();
        }
    }
}
