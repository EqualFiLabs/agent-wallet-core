// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";

import {IERC165} from "../../interfaces/IERC165.sol";
import {IERC6900Module} from "../../interfaces/IERC6900Module.sol";
import {IERC6900ValidationModule} from "../../interfaces/IERC6900ValidationModule.sol";
import {ERC8128PolicyRegistry} from "../../core/ERC8128PolicyRegistry.sol";
import {ERC8128CoreLib} from "../../libraries/ERC8128CoreLib.sol";
import {Call} from "../../libraries/ModuleTypes.sol";
import {SessionAuthV2, SessionPolicyV2, AAClaimsV2, AACallClaimV2, ParsedCall} from "../../libraries/ERC8128Types.sol";

/// @title ERC8128AAValidationModuleV2
/// @notice ERC-6900 validation module for the ERC-4337 path.
contract ERC8128AAValidationModuleV2 is IERC6900ValidationModule {
    bytes4 internal constant ERC1271_INVALID = 0xffffffff;
    uint256 internal constant SIG_VALIDATION_FAILED = 1;

    uint8 internal constant MODE_AA = 1;

    bytes4 internal constant EXECUTE_SELECTOR = bytes4(keccak256("execute(address,uint256,bytes)"));
    bytes4 internal constant EXECUTE_BATCH_SELECTOR = bytes4(keccak256("executeBatch((address,uint256,bytes)[])"));
    bytes4 internal constant EXECUTE_OPERATION_SELECTOR = bytes4(keccak256("execute(address,uint256,bytes,uint8)"));

    struct InstallPresetConfig {
        address account;
        uint32 entityId;
        bytes4[] allowedSelectors;
        bool defaultAllowDelegateCall;
        uint32 minTtlSeconds;
        uint32 maxTtlSeconds;
    }

    struct UninstallPresetConfig {
        address account;
        uint32 entityId;
    }

    struct InstallPreset {
        bytes4[] allowedSelectors;
        bool defaultAllowDelegateCall;
        uint32 minTtlSeconds;
        uint32 maxTtlSeconds;
        bool initialized;
    }

    ERC8128PolicyRegistry public immutable registry;

    mapping(address => mapping(uint32 => InstallPreset)) private _presets;

    error RuntimeValidationNotSupported();
    error InvalidRegistry(address registryAddress);
    error InvalidInstallScope(address expectedAccount, address caller);
    error InvalidInstallTtlWindow(uint32 minTtlSeconds, uint32 maxTtlSeconds);

    constructor(address registryAddress) {
        if (registryAddress == address(0)) {
            revert InvalidRegistry(registryAddress);
        }
        registry = ERC8128PolicyRegistry(registryAddress);
    }

    function onInstall(bytes calldata data) external override {
        InstallPresetConfig memory config = abi.decode(data, (InstallPresetConfig));
        if (config.account != msg.sender) {
            revert InvalidInstallScope(config.account, msg.sender);
        }
        if (config.maxTtlSeconds != 0 && config.maxTtlSeconds < config.minTtlSeconds) {
            revert InvalidInstallTtlWindow(config.minTtlSeconds, config.maxTtlSeconds);
        }

        InstallPreset storage preset = _presets[config.account][config.entityId];
        delete preset.allowedSelectors;
        for (uint256 i = 0; i < config.allowedSelectors.length; i++) {
            preset.allowedSelectors.push(config.allowedSelectors[i]);
        }

        preset.defaultAllowDelegateCall = config.defaultAllowDelegateCall;
        preset.minTtlSeconds = config.minTtlSeconds;
        preset.maxTtlSeconds = config.maxTtlSeconds;
        preset.initialized = true;
    }

    function onUninstall(bytes calldata data) external override {
        UninstallPresetConfig memory config = abi.decode(data, (UninstallPresetConfig));
        if (config.account != msg.sender) {
            revert InvalidInstallScope(config.account, msg.sender);
        }
        delete _presets[config.account][config.entityId];
    }

    function moduleId() external pure override returns (string memory) {
        return "agent.wallet.erc8128-aa-validation.2.0.0";
    }

    function supportsInterface(bytes4 interfaceId) external pure override returns (bool) {
        return interfaceId == type(IERC165).interfaceId || interfaceId == type(IERC6900Module).interfaceId
            || interfaceId == type(IERC6900ValidationModule).interfaceId;
    }

    function validateSignature(address, uint32, address, bytes32, bytes calldata)
        external
        pure
        override
        returns (bytes4)
    {
        return ERC1271_INVALID;
    }

    function validateRuntime(address, uint32, address, uint256, bytes calldata, bytes calldata) external pure override {
        revert RuntimeValidationNotSupported();
    }

    function validateUserOp(uint32 entityId, PackedUserOperation calldata userOp, bytes32 userOpHash)
        external
        view
        override
        returns (uint256)
    {
        SessionAuthV2 memory auth;
        try this.decodeSessionAuth(userOp.signature) returns (SessionAuthV2 memory decodedAuth) {
            auth = decodedAuth;
        } catch {
            return SIG_VALIDATION_FAILED;
        }

        if (auth.mode != MODE_AA) {
            return SIG_VALIDATION_FAILED;
        }
        if (auth.requestHash != userOpHash) {
            return SIG_VALIDATION_FAILED;
        }
        if (auth.sessionKey == address(0)) {
            return SIG_VALIDATION_FAILED;
        }

        InstallPreset storage preset = _presets[userOp.sender][entityId];
        bytes4 topLevelSelector = _extractSelectorFromCalldata(userOp.callData);
        if (!preset.initialized || !_isSelectorAllowed(preset, topLevelSelector)) {
            return SIG_VALIDATION_FAILED;
        }

        ParsedCall[] memory parsedCalls;
        bool supported;
        try this.parseCalls(userOp.callData) returns (ParsedCall[] memory decodedCalls, bool isSupported) {
            parsedCalls = decodedCalls;
            supported = isSupported;
        } catch {
            return SIG_VALIDATION_FAILED;
        }

        if (!supported || parsedCalls.length == 0) {
            return SIG_VALIDATION_FAILED;
        }

        AAClaimsV2 memory aaClaims;
        try this.decodeAAClaims(auth.claims) returns (AAClaimsV2 memory decodedClaims) {
            aaClaims = decodedClaims;
        } catch {
            return SIG_VALIDATION_FAILED;
        }

        if (auth.claimsHash != ERC8128CoreLib.computeAAClaimsHash(aaClaims)) {
            return SIG_VALIDATION_FAILED;
        }

        if (aaClaims.callClaims.length != parsedCalls.length) {
            return SIG_VALIDATION_FAILED;
        }

        (SessionPolicyV2 memory policy, uint64 epoch, uint64 policyNonce) =
            registry.getPolicy(userOp.sender, entityId, auth.sessionKey);

        if (!registry.isPolicyActive(userOp.sender, entityId, auth.sessionKey)) {
            return SIG_VALIDATION_FAILED;
        }
        if (auth.epoch != epoch || auth.policyNonce != policyNonce) {
            return SIG_VALIDATION_FAILED;
        }

        if (block.timestamp < policy.validAfter) {
            return SIG_VALIDATION_FAILED;
        }
        if (policy.validUntil != 0 && block.timestamp > policy.validUntil) {
            return SIG_VALIDATION_FAILED;
        }

        if (auth.created >= auth.expires) {
            return SIG_VALIDATION_FAILED;
        }
        if (block.timestamp < auth.created || block.timestamp > auth.expires) {
            return SIG_VALIDATION_FAILED;
        }

        uint256 ttl = uint256(auth.expires) - uint256(auth.created);
        if (policy.maxTtlSeconds != 0 && ttl > policy.maxTtlSeconds) {
            return SIG_VALIDATION_FAILED;
        }
        if (preset.minTtlSeconds != 0 && ttl < preset.minTtlSeconds) {
            return SIG_VALIDATION_FAILED;
        }
        if (preset.maxTtlSeconds != 0 && ttl > preset.maxTtlSeconds) {
            return SIG_VALIDATION_FAILED;
        }

        bytes32[] memory scopeLeaves = new bytes32[](aaClaims.callClaims.length);
        for (uint256 i = 0; i < aaClaims.callClaims.length; i++) {
            ParsedCall memory parsedCall = parsedCalls[i];
            AACallClaimV2 memory claim = aaClaims.callClaims[i];

            if (parsedCall.target != claim.target || parsedCall.selector != claim.selector) {
                return SIG_VALIDATION_FAILED;
            }
            if (parsedCall.value > claim.valueLimit) {
                return SIG_VALIDATION_FAILED;
            }

            bool delegateAllowed = claim.allowDelegateCall || preset.defaultAllowDelegateCall;
            if (parsedCall.isDelegateCall && !delegateAllowed) {
                return SIG_VALIDATION_FAILED;
            }

            bytes32 recomputedLeaf =
                ERC8128CoreLib.computeAAScopeLeaf(claim.target, claim.selector, claim.valueLimit, claim.allowDelegateCall);
            if (recomputedLeaf != claim.scopeLeaf) {
                return SIG_VALIDATION_FAILED;
            }

            scopeLeaves[i] = claim.scopeLeaf;

            if (topLevelSelector != EXECUTE_BATCH_SELECTOR) {
                if (!MerkleProof.verify(claim.scopeProof, policy.scopeRoot, claim.scopeLeaf)) {
                    return SIG_VALIDATION_FAILED;
                }
            }
        }

        if (aaClaims.leafOrderHash != bytes32(0) && aaClaims.leafOrderHash != keccak256(abi.encode(scopeLeaves))) {
            return SIG_VALIDATION_FAILED;
        }

        if (topLevelSelector == EXECUTE_BATCH_SELECTOR) {
            if (!MerkleProof.multiProofVerify(aaClaims.multiproof, aaClaims.proofFlags, policy.scopeRoot, scopeLeaves)) {
                return SIG_VALIDATION_FAILED;
            }
        }

        bytes32 domainSeparator = ERC8128CoreLib.domainSeparator(address(this));
        bytes32 structHash = ERC8128CoreLib.sessionAuthorizationHash(
            auth.mode,
            userOp.sender,
            entityId,
            auth.sessionKey,
            auth.epoch,
            auth.policyNonce,
            auth.created,
            auth.expires,
            auth.requestHash,
            auth.claimsHash
        );
        bytes32 digest = ERC8128CoreLib.computeDigest(domainSeparator, structHash);

        if (!ERC8128CoreLib.isValidSessionSigner(auth.sessionKey, digest, auth.sessionSignature)) {
            return SIG_VALIDATION_FAILED;
        }

        uint48 validAfter = auth.created > policy.validAfter ? auth.created : policy.validAfter;
        uint48 validUntil = policy.validUntil;
        if (validUntil == 0 || auth.expires < validUntil) {
            validUntil = auth.expires;
        }

        return ERC8128CoreLib.packValidationData(address(0), validUntil, validAfter);
    }

    function parseCalls(bytes calldata callData) external pure returns (ParsedCall[] memory parsedCalls, bool supported) {
        bytes4 selector = _extractSelectorFromCalldata(callData);

        if (selector == EXECUTE_SELECTOR) {
            (address target, uint256 value, bytes memory data) = abi.decode(callData[4:], (address, uint256, bytes));
            parsedCalls = new ParsedCall[](1);
            parsedCalls[0] = ParsedCall({
                target: target,
                value: value,
                data: data,
                selector: _extractSelectorFromBytes(data),
                isDelegateCall: false
            });
            return (parsedCalls, true);
        }

        if (selector == EXECUTE_OPERATION_SELECTOR) {
            (address target, uint256 value, bytes memory data, uint8 operation) =
                abi.decode(callData[4:], (address, uint256, bytes, uint8));
            if (operation > 1) {
                return (new ParsedCall[](0), false);
            }

            bool isDelegateCall = operation == 1;
            if (isDelegateCall && value != 0) {
                return (new ParsedCall[](0), false);
            }

            parsedCalls = new ParsedCall[](1);
            parsedCalls[0] = ParsedCall({
                target: target,
                value: value,
                data: data,
                selector: _extractSelectorFromBytes(data),
                isDelegateCall: isDelegateCall
            });
            return (parsedCalls, true);
        }

        if (selector == EXECUTE_BATCH_SELECTOR) {
            Call[] memory calls = abi.decode(callData[4:], (Call[]));
            parsedCalls = new ParsedCall[](calls.length);

            for (uint256 i = 0; i < calls.length; i++) {
                parsedCalls[i] = ParsedCall({
                    target: calls[i].target,
                    value: calls[i].value,
                    data: calls[i].data,
                    selector: _extractSelectorFromBytes(calls[i].data),
                    isDelegateCall: false
                });
            }

            return (parsedCalls, true);
        }

        return (new ParsedCall[](0), false);
    }

    function decodeSessionAuth(bytes calldata signature) external pure returns (SessionAuthV2 memory) {
        return abi.decode(signature, (SessionAuthV2));
    }

    function decodeAAClaims(bytes memory claims) external pure returns (AAClaimsV2 memory) {
        return abi.decode(claims, (AAClaimsV2));
    }

    function computeAAScopeLeaf(address target, bytes4 selector, uint256 valueLimit, bool allowDelegateCall)
        external
        pure
        returns (bytes32)
    {
        return ERC8128CoreLib.computeAAScopeLeaf(target, selector, valueLimit, allowDelegateCall);
    }

    function computeAAClaimsHash(AAClaimsV2 memory claims) external pure returns (bytes32) {
        return ERC8128CoreLib.computeAAClaimsHash(claims);
    }

    function getInstallPreset(address account, uint32 entityId)
        external
        view
        returns (
            bytes4[] memory allowedSelectors,
            bool defaultAllowDelegateCall,
            uint32 minTtlSeconds,
            uint32 maxTtlSeconds,
            bool initialized
        )
    {
        InstallPreset storage preset = _presets[account][entityId];
        return (
            preset.allowedSelectors,
            preset.defaultAllowDelegateCall,
            preset.minTtlSeconds,
            preset.maxTtlSeconds,
            preset.initialized
        );
    }

    function _extractSelectorFromBytes(bytes memory data) private pure returns (bytes4 selector) {
        if (data.length < 4) {
            return bytes4(0);
        }

        assembly {
            selector := mload(add(data, 32))
        }
    }

    function _extractSelectorFromCalldata(bytes calldata data) private pure returns (bytes4 selector) {
        if (data.length < 4) {
            return bytes4(0);
        }

        assembly {
            selector := calldataload(data.offset)
        }
    }

    function _isSelectorAllowed(InstallPreset storage preset, bytes4 selector) private view returns (bool) {
        for (uint256 i = 0; i < preset.allowedSelectors.length; i++) {
            if (preset.allowedSelectors[i] == selector) {
                return true;
            }
        }
        return false;
    }
}
