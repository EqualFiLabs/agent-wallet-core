// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IERC6551Account} from "../interfaces/IERC6551Account.sol";
import {ERC8128CoreLib} from "../libraries/ERC8128CoreLib.sol";
import {SessionPolicyV2} from "../libraries/ERC8128Types.sol";

/// @title ERC8128PolicyRegistry
/// @notice Unified onchain policy registry shared by ERC-8128 gateway and AA validation modules.
contract ERC8128PolicyRegistry {
    mapping(bytes32 => uint64) private _policyNonce;
    mapping(bytes32 => SessionPolicyV2) private _policies;
    mapping(address => mapping(uint32 => uint64)) private _accountEntityEpoch;
    mapping(address => mapping(uint32 => mapping(address => bool))) private _guardians;
    mapping(address => mapping(uint32 => bool)) private _entityPaused;
    mapping(address => bool) private _accountPaused;

    error NotAccountOwner(address account, address caller, address owner);
    error InvalidSessionKey(address sessionKey);
    error InvalidPolicyWindow(uint48 validAfter, uint48 validUntil);
    error PolicyNotActive(address account, uint32 entityId, address sessionKey);
    error Unauthorized(address caller);

    event PolicySetV2(
        address indexed account,
        uint32 indexed entityId,
        address indexed sessionKey,
        uint64 policyNonce,
        uint48 validAfter,
        uint48 validUntil,
        uint32 maxTtlSeconds,
        bytes32 scopeRoot,
        uint64 maxCallsPerPeriod,
        uint128 maxValuePerPeriod,
        uint48 periodSeconds
    );
    event PolicyRevokedV2(address indexed account, uint32 indexed entityId, address indexed sessionKey, uint64 policyNonce);
    event EpochRevokedV2(address indexed account, uint32 indexed entityId, uint64 epoch);
    event ScopeRootRotatedV2(
        address indexed account, uint32 indexed entityId, address indexed sessionKey, uint64 policyNonce, bytes32 scopeRoot
    );
    event GuardianPauseSetV2(address indexed account, uint32 indexed entityId, address indexed sessionKey, bool paused);

    function setPolicy(
        address account,
        uint32 entityId,
        address sessionKey,
        uint48 validAfter,
        uint48 validUntil,
        uint32 maxTtlSeconds,
        bytes32 scopeRoot,
        uint64 maxCallsPerPeriod,
        uint128 maxValuePerPeriod,
        uint48 periodSeconds
    ) external {
        _requireAccountOwner(account);
        if (sessionKey == address(0)) {
            revert InvalidSessionKey(sessionKey);
        }
        if (validUntil != 0 && validUntil <= validAfter) {
            revert InvalidPolicyWindow(validAfter, validUntil);
        }

        bytes32 baseKey = _basePolicyKey(account, entityId, sessionKey);
        uint64 nextPolicyNonce = _policyNonce[baseKey] + 1;
        _policyNonce[baseKey] = nextPolicyNonce;

        bytes32 policyKey = _resolvedPolicyKey(baseKey, nextPolicyNonce);
        _policies[policyKey] = SessionPolicyV2({
            active: true,
            validAfter: validAfter,
            validUntil: validUntil,
            maxTtlSeconds: maxTtlSeconds,
            scopeRoot: scopeRoot,
            maxCallsPerPeriod: maxCallsPerPeriod,
            maxValuePerPeriod: maxValuePerPeriod,
            periodSeconds: periodSeconds,
            paused: false
        });

        emit PolicySetV2(
            account,
            entityId,
            sessionKey,
            nextPolicyNonce,
            validAfter,
            validUntil,
            maxTtlSeconds,
            scopeRoot,
            maxCallsPerPeriod,
            maxValuePerPeriod,
            periodSeconds
        );
    }

    function revokeSessionKey(address account, uint32 entityId, address sessionKey) external {
        _requireAccountOwner(account);
        if (sessionKey == address(0)) {
            revert InvalidSessionKey(sessionKey);
        }

        bytes32 baseKey = _basePolicyKey(account, entityId, sessionKey);
        uint64 nextPolicyNonce = _policyNonce[baseKey] + 1;
        _policyNonce[baseKey] = nextPolicyNonce;

        emit PolicyRevokedV2(account, entityId, sessionKey, nextPolicyNonce);
    }

    function revokeAllSessionKeys(address account, uint32 entityId) external {
        _requireAccountOwner(account);

        uint64 nextEpoch = _accountEntityEpoch[account][entityId] + 1;
        _accountEntityEpoch[account][entityId] = nextEpoch;

        emit EpochRevokedV2(account, entityId, nextEpoch);
    }

    function rotateScopeRoot(address account, uint32 entityId, address sessionKey, bytes32 newScopeRoot) external {
        _requireAccountOwner(account);
        if (sessionKey == address(0)) {
            revert InvalidSessionKey(sessionKey);
        }

        bytes32 baseKey = _basePolicyKey(account, entityId, sessionKey);
        uint64 policyNonce = _policyNonce[baseKey];
        bytes32 policyKey = _resolvedPolicyKey(baseKey, policyNonce);

        if (!_policies[policyKey].active) {
            revert PolicyNotActive(account, entityId, sessionKey);
        }

        _policies[policyKey].scopeRoot = newScopeRoot;

        emit ScopeRootRotatedV2(account, entityId, sessionKey, policyNonce, newScopeRoot);
    }

    function setGuardian(address account, uint32 entityId, address guardian, bool enabled) external {
        _requireAccountOwner(account);
        _guardians[account][entityId][guardian] = enabled;
    }

    function pausePolicy(address account, uint32 entityId, address sessionKey) external {
        _requireGuardianOrOwner(account, entityId);
        if (sessionKey == address(0)) {
            revert InvalidSessionKey(sessionKey);
        }

        bytes32 baseKey = _basePolicyKey(account, entityId, sessionKey);
        uint64 policyNonce = _policyNonce[baseKey];
        bytes32 policyKey = _resolvedPolicyKey(baseKey, policyNonce);
        SessionPolicyV2 storage policy = _policies[policyKey];

        if (!policy.active) {
            revert PolicyNotActive(account, entityId, sessionKey);
        }

        policy.paused = true;
        emit GuardianPauseSetV2(account, entityId, sessionKey, true);
    }

    function pauseEntity(address account, uint32 entityId) external {
        _requireGuardianOrOwner(account, entityId);
        _entityPaused[account][entityId] = true;
        emit GuardianPauseSetV2(account, entityId, address(0), true);
    }

    function pauseAccount(address account) external {
        _requireGuardianOrOwner(account, 0);
        _accountPaused[account] = true;
        emit GuardianPauseSetV2(account, 0, address(0), true);
    }

    function getPolicy(address account, uint32 entityId, address sessionKey)
        external
        view
        returns (SessionPolicyV2 memory policy, uint64 epoch, uint64 policyNonce)
    {
        epoch = _accountEntityEpoch[account][entityId];
        bytes32 baseKey = ERC8128CoreLib.basePolicyKey(account, entityId, sessionKey, epoch);
        policyNonce = _policyNonce[baseKey];
        bytes32 policyKey = ERC8128CoreLib.resolvedPolicyKey(baseKey, policyNonce);
        policy = _policies[policyKey];
    }

    function getEpoch(address account, uint32 entityId) external view returns (uint64) {
        return _accountEntityEpoch[account][entityId];
    }

    function isGuardian(address account, uint32 entityId, address guardian) external view returns (bool) {
        return _guardians[account][entityId][guardian];
    }

    function isPolicyActive(address account, uint32 entityId, address sessionKey) external view returns (bool) {
        bytes32 baseKey = _basePolicyKey(account, entityId, sessionKey);
        uint64 policyNonce = _policyNonce[baseKey];
        bytes32 policyKey = _resolvedPolicyKey(baseKey, policyNonce);

        SessionPolicyV2 memory policy = _policies[policyKey];
        if (!policy.active || policy.paused) {
            return false;
        }
        if (_entityPaused[account][entityId] || _accountPaused[account]) {
            return false;
        }

        return true;
    }

    function _basePolicyKey(address account, uint32 entityId, address sessionKey) internal view returns (bytes32) {
        return ERC8128CoreLib.basePolicyKey(account, entityId, sessionKey, _accountEntityEpoch[account][entityId]);
    }

    function _resolvedPolicyKey(bytes32 baseKey, uint64 policyNonce) internal pure returns (bytes32) {
        return ERC8128CoreLib.resolvedPolicyKey(baseKey, policyNonce);
    }

    function _requireAccountOwner(address account) internal view {
        address accountOwner = IERC6551Account(account).owner();
        if (msg.sender != accountOwner) {
            revert NotAccountOwner(account, msg.sender, accountOwner);
        }
    }

    function _requireGuardianOrOwner(address account, uint32 entityId) internal view {
        address accountOwner = IERC6551Account(account).owner();
        if (msg.sender == accountOwner) {
            return;
        }

        bool authorized = _guardians[account][entityId][msg.sender] || _guardians[account][0][msg.sender];
        if (!authorized) {
            revert Unauthorized(msg.sender);
        }
    }
}
