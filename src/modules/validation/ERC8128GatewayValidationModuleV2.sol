// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";

import {IERC165} from "../../interfaces/IERC165.sol";
import {IERC6900Module} from "../../interfaces/IERC6900Module.sol";
import {IERC6900ValidationModule} from "../../interfaces/IERC6900ValidationModule.sol";
import {ERC8128PolicyRegistry} from "../../core/ERC8128PolicyRegistry.sol";
import {ERC8128CoreLib} from "../../libraries/ERC8128CoreLib.sol";
import {SessionAuthV2, SessionPolicyV2, GatewayClaimsV2} from "../../libraries/ERC8128Types.sol";

/// @title ERC8128GatewayValidationModuleV2
/// @notice ERC-6900 gateway validation module for the ERC-1271 validation path.
contract ERC8128GatewayValidationModuleV2 is IERC6900ValidationModule {
    bytes4 internal constant ERC1271_MAGICVALUE = 0x1626ba7e;
    bytes4 internal constant ERC1271_INVALID = 0xffffffff;
    uint256 internal constant SIG_VALIDATION_FAILED = 1;

    uint8 internal constant MODE_GATEWAY = 0;

    ERC8128PolicyRegistry public immutable registry;

    error RuntimeValidationNotSupported();
    error InvalidRegistry(address registryAddress);

    constructor(address registryAddress) {
        if (registryAddress == address(0)) {
            revert InvalidRegistry(registryAddress);
        }
        registry = ERC8128PolicyRegistry(registryAddress);
    }

    function onInstall(bytes calldata) external pure override {}

    function onUninstall(bytes calldata) external pure override {}

    function moduleId() external pure override returns (string memory) {
        return "agent.wallet.erc8128-gateway-validation.2.0.0";
    }

    function supportsInterface(bytes4 interfaceId) external pure override returns (bool) {
        return interfaceId == type(IERC165).interfaceId || interfaceId == type(IERC6900Module).interfaceId
            || interfaceId == type(IERC6900ValidationModule).interfaceId;
    }

    function validateUserOp(uint32, PackedUserOperation calldata, bytes32) external pure override returns (uint256) {
        return SIG_VALIDATION_FAILED;
    }

    function validateRuntime(address, uint32, address, uint256, bytes calldata, bytes calldata) external pure override {
        revert RuntimeValidationNotSupported();
    }

    function validateSignature(address account, uint32 entityId, address, bytes32 hash, bytes calldata signature)
        external
        view
        override
        returns (bytes4)
    {
        SessionAuthV2 memory auth;
        try this.decodeSessionAuth(signature) returns (SessionAuthV2 memory decodedAuth) {
            auth = decodedAuth;
        } catch {
            return ERC1271_INVALID;
        }

        if (auth.mode != MODE_GATEWAY) {
            return ERC1271_INVALID;
        }
        if (auth.requestHash != hash) {
            return ERC1271_INVALID;
        }
        if (auth.sessionKey == address(0)) {
            return ERC1271_INVALID;
        }

        GatewayClaimsV2 memory claims;
        try this.decodeGatewayClaims(auth.claims) returns (GatewayClaimsV2 memory decodedClaims) {
            claims = decodedClaims;
        } catch {
            return ERC1271_INVALID;
        }

        if (auth.claimsHash != ERC8128CoreLib.computeGatewayClaimsHash(claims)) {
            return ERC1271_INVALID;
        }

        (SessionPolicyV2 memory policy, uint64 epoch, uint64 policyNonce) = registry.getPolicy(account, entityId, auth.sessionKey);

        if (!registry.isPolicyActive(account, entityId, auth.sessionKey)) {
            return ERC1271_INVALID;
        }
        if (auth.epoch != epoch || auth.policyNonce != policyNonce) {
            return ERC1271_INVALID;
        }

        if (block.timestamp < policy.validAfter) {
            return ERC1271_INVALID;
        }
        if (policy.validUntil != 0 && block.timestamp > policy.validUntil) {
            return ERC1271_INVALID;
        }

        if (auth.created >= auth.expires) {
            return ERC1271_INVALID;
        }
        if (block.timestamp < auth.created || block.timestamp > auth.expires) {
            return ERC1271_INVALID;
        }
        if (policy.maxTtlSeconds != 0 && uint256(auth.expires) - uint256(auth.created) > policy.maxTtlSeconds) {
            return ERC1271_INVALID;
        }

        if (!claims.isReplayable && claims.nonceHash == bytes32(0)) {
            return ERC1271_INVALID;
        }
        if (claims.isReplayable && !claims.allowReplayable) {
            return ERC1271_INVALID;
        }
        if (claims.isClassBound && !claims.allowClassBound) {
            return ERC1271_INVALID;
        }
        if ((claims.isReplayable || claims.isClassBound) && !claims.isReadOnly) {
            return ERC1271_INVALID;
        }

        bytes32 recomputedScopeLeaf = ERC8128CoreLib.computeGatewayScopeLeaf(
            claims.methodBit,
            claims.authorityHash,
            claims.pathPrefixHash,
            claims.isReadOnly,
            claims.allowReplayable,
            claims.allowClassBound,
            claims.maxBodyBytes
        );

        if (recomputedScopeLeaf != claims.scopeLeaf) {
            return ERC1271_INVALID;
        }
        if (!MerkleProof.verify(claims.scopeProof, policy.scopeRoot, claims.scopeLeaf)) {
            return ERC1271_INVALID;
        }

        bytes32 domainSep = ERC8128CoreLib.domainSeparator(address(this));
        bytes32 structHash = ERC8128CoreLib.sessionAuthorizationHash(
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
        );
        bytes32 digest = ERC8128CoreLib.computeDigest(domainSep, structHash);

        if (ERC8128CoreLib.isValidSessionSigner(auth.sessionKey, digest, auth.sessionSignature)) {
            return ERC1271_MAGICVALUE;
        }

        return ERC1271_INVALID;
    }

    function decodeSessionAuth(bytes calldata signature) external pure returns (SessionAuthV2 memory) {
        return abi.decode(signature, (SessionAuthV2));
    }

    function decodeGatewayClaims(bytes memory claims) external pure returns (GatewayClaimsV2 memory) {
        return abi.decode(claims, (GatewayClaimsV2));
    }
}
