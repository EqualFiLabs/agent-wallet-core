// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import {IERC165} from "../../interfaces/IERC165.sol";
import {IERC6551Account} from "../../interfaces/IERC6551Account.sol";
import {IERC6900Module} from "../../interfaces/IERC6900Module.sol";
import {IERC6900ValidationModule} from "../../interfaces/IERC6900ValidationModule.sol";
import {ERC8128PolicyRegistry} from "../../core/ERC8128PolicyRegistry.sol";
import {SessionPolicyV2} from "../../libraries/ERC8128Types.sol";
import {SIWACoreLib} from "../../libraries/SIWACoreLib.sol";

/// @title SIWAValidationModule
/// @notice ERC-6900 validation module for strict SIWA-compatible ERC-1271 authentication.
/// @dev Expects standard ERC-1271 `(hash, signature)` inputs where `signature` is the raw SIWA/ERC-8128 signature.
contract SIWAValidationModule is IERC6900ValidationModule {
    bytes4 internal constant ERC1271_MAGICVALUE = 0x1626ba7e;
    bytes4 internal constant ERC1271_INVALID = 0xffffffff;
    uint256 internal constant SIG_VALIDATION_FAILED = 1;

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
        return "agent.wallet.siwa-validation.1.0.0";
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
        address recoveredSigner = address(0);
        (address signer, ECDSA.RecoverError err,) = ECDSA.tryRecover(hash, signature);
        if (err == ECDSA.RecoverError.NoError && signer != address(0)) {
            recoveredSigner = signer;
            if (_validateSignerPolicy(account, entityId, signer, hash, signature)) {
                return ERC1271_MAGICVALUE;
            }
        }

        // Support contract-owned/TBA flows where the effective session signer is the account owner
        // and signature validation must go through ERC-1271.
        if (account.code.length != 0) {
            try IERC6551Account(account).owner() returns (address ownerSigner) {
                if (ownerSigner != address(0) && ownerSigner != recoveredSigner) {
                    if (_validateSignerPolicy(account, entityId, ownerSigner, hash, signature)) {
                        return ERC1271_MAGICVALUE;
                    }
                }
            } catch {}
        }

        return ERC1271_INVALID;
    }

    function _validateSignerPolicy(
        address account,
        uint32 entityId,
        address signer,
        bytes32 hash,
        bytes calldata signature
    ) internal view returns (bool) {
        if (!registry.isPolicyActive(account, entityId, signer)) {
            return false;
        }

        (SessionPolicyV2 memory policy,,) = registry.getPolicy(account, entityId, signer);
        if (block.timestamp < policy.validAfter) {
            return false;
        }
        if (policy.validUntil != 0 && block.timestamp > policy.validUntil) {
            return false;
        }

        return SIWACoreLib.isValidSIWASigner(account, signer, hash, signature);
    }
}
