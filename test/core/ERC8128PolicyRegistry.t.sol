// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";

import {ERC8128PolicyRegistry} from "../../src/core/ERC8128PolicyRegistry.sol";
import {SessionPolicyV2} from "../../src/libraries/ERC8128Types.sol";
import {Mock6551Account} from "../mocks/OwnerValidationMocks.sol";

contract ERC8128PolicyRegistryTest is Test {
    uint256 internal constant SECP256K1_N =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    ERC8128PolicyRegistry internal registry;

    function setUp() public {
        registry = new ERC8128PolicyRegistry();
    }

    // **Feature: erc8128-v2-unified-policy, Property 1: Policy storage round-trip**
    function testFuzz_Property1_PolicyStorageRoundTrip(
        uint256 ownerKeySeed,
        uint256 sessionKeySeed,
        uint32 entityId,
        uint48 validAfterSeed,
        bool finiteWindow,
        uint48 validUntilDeltaSeed,
        uint32 maxTtlSeconds,
        bytes32 scopeRoot,
        uint64 maxCallsPerPeriod,
        uint128 maxValuePerPeriod,
        uint48 periodSeconds
    ) public {
        uint256 ownerKey = bound(ownerKeySeed, 1, SECP256K1_N - 1);
        uint256 sessionKey = bound(sessionKeySeed, 1, SECP256K1_N - 1);
        vm.assume(ownerKey != sessionKey);

        address owner = vm.addr(ownerKey);
        address sessionSigner = vm.addr(sessionKey);
        Mock6551Account account = new Mock6551Account(owner);

        uint48 validAfter = uint48(bound(validAfterSeed, 0, type(uint48).max - 2));
        uint48 validUntil = 0;
        if (finiteWindow) {
            uint48 delta = uint48(bound(validUntilDeltaSeed, 1, type(uint48).max - validAfter));
            validUntil = validAfter + delta;
        }

        vm.prank(owner);
        registry.setPolicy(
            address(account),
            entityId,
            sessionSigner,
            validAfter,
            validUntil,
            maxTtlSeconds,
            scopeRoot,
            maxCallsPerPeriod,
            maxValuePerPeriod,
            periodSeconds
        );

        (SessionPolicyV2 memory policy, uint64 epoch, uint64 policyNonce) =
            registry.getPolicy(address(account), entityId, sessionSigner);

        assertTrue(policy.active);
        assertEq(policy.validAfter, validAfter);
        assertEq(policy.validUntil, validUntil);
        assertEq(policy.maxTtlSeconds, maxTtlSeconds);
        assertEq(policy.scopeRoot, scopeRoot);
        assertEq(policy.maxCallsPerPeriod, maxCallsPerPeriod);
        assertEq(policy.maxValuePerPeriod, maxValuePerPeriod);
        assertEq(policy.periodSeconds, periodSeconds);
        assertFalse(policy.paused);

        assertEq(epoch, 0);
        assertEq(policyNonce, 1);
        assertEq(registry.getEpoch(address(account), entityId), 0);
        assertTrue(registry.isPolicyActive(address(account), entityId, sessionSigner));
    }

    // **Feature: erc8128-v2-unified-policy, Property 2: Non-owner authorization rejection**
    function testFuzz_Property2_NonOwnerAuthorizationRejection(
        uint256 ownerKeySeed,
        uint256 callerKeySeed,
        uint256 sessionKeySeed,
        uint32 entityId,
        uint48 validAfterSeed,
        uint48 validUntilDeltaSeed,
        uint32 maxTtlSeconds,
        bytes32 scopeRoot,
        uint64 maxCallsPerPeriod,
        uint128 maxValuePerPeriod,
        uint48 periodSeconds,
        bytes32 rotatedScopeRoot,
        address guardian
    ) public {
        uint256 ownerKey = bound(ownerKeySeed, 1, SECP256K1_N - 1);
        uint256 callerKey = bound(callerKeySeed, 1, SECP256K1_N - 1);
        uint256 sessionKey = bound(sessionKeySeed, 1, SECP256K1_N - 1);
        vm.assume(ownerKey != callerKey);

        address owner = vm.addr(ownerKey);
        address caller = vm.addr(callerKey);
        address sessionSigner = vm.addr(sessionKey);
        Mock6551Account account = new Mock6551Account(owner);

        uint48 validAfter = uint48(bound(validAfterSeed, 0, type(uint48).max - 2));
        uint48 delta = uint48(bound(validUntilDeltaSeed, 1, type(uint48).max - validAfter));
        uint48 validUntil = validAfter + delta;

        vm.expectRevert(
            abi.encodeWithSelector(ERC8128PolicyRegistry.NotAccountOwner.selector, address(account), caller, owner)
        );
        vm.prank(caller);
        registry.setPolicy(
            address(account),
            entityId,
            sessionSigner,
            validAfter,
            validUntil,
            maxTtlSeconds,
            scopeRoot,
            maxCallsPerPeriod,
            maxValuePerPeriod,
            periodSeconds
        );

        vm.prank(owner);
        registry.setPolicy(
            address(account),
            entityId,
            sessionSigner,
            validAfter,
            validUntil,
            maxTtlSeconds,
            scopeRoot,
            maxCallsPerPeriod,
            maxValuePerPeriod,
            periodSeconds
        );

        vm.expectRevert(
            abi.encodeWithSelector(ERC8128PolicyRegistry.NotAccountOwner.selector, address(account), caller, owner)
        );
        vm.prank(caller);
        registry.revokeSessionKey(address(account), entityId, sessionSigner);

        vm.expectRevert(
            abi.encodeWithSelector(ERC8128PolicyRegistry.NotAccountOwner.selector, address(account), caller, owner)
        );
        vm.prank(caller);
        registry.revokeAllSessionKeys(address(account), entityId);

        vm.expectRevert(
            abi.encodeWithSelector(ERC8128PolicyRegistry.NotAccountOwner.selector, address(account), caller, owner)
        );
        vm.prank(caller);
        registry.rotateScopeRoot(address(account), entityId, sessionSigner, rotatedScopeRoot);

        vm.expectRevert(
            abi.encodeWithSelector(ERC8128PolicyRegistry.NotAccountOwner.selector, address(account), caller, owner)
        );
        vm.prank(caller);
        registry.setGuardian(address(account), entityId, guardian, true);
    }

    // **Feature: erc8128-v2-unified-policy, Property 3: Invalid time window rejection**
    function testFuzz_Property3_InvalidTimeWindowRejection(
        uint256 ownerKeySeed,
        uint256 sessionKeySeed,
        uint32 entityId,
        uint48 validAfterSeed,
        uint48 validUntilSeed,
        uint32 maxTtlSeconds,
        bytes32 scopeRoot,
        uint64 maxCallsPerPeriod,
        uint128 maxValuePerPeriod,
        uint48 periodSeconds
    ) public {
        uint256 ownerKey = bound(ownerKeySeed, 1, SECP256K1_N - 1);
        uint256 sessionKey = bound(sessionKeySeed, 1, SECP256K1_N - 1);
        vm.assume(ownerKey != sessionKey);

        address owner = vm.addr(ownerKey);
        address sessionSigner = vm.addr(sessionKey);
        Mock6551Account account = new Mock6551Account(owner);

        uint48 validAfter = uint48(bound(validAfterSeed, 1, type(uint48).max));
        uint48 validUntil = uint48(bound(validUntilSeed, 1, validAfter));

        vm.expectRevert(abi.encodeWithSelector(ERC8128PolicyRegistry.InvalidPolicyWindow.selector, validAfter, validUntil));
        vm.prank(owner);
        registry.setPolicy(
            address(account),
            entityId,
            sessionSigner,
            validAfter,
            validUntil,
            maxTtlSeconds,
            scopeRoot,
            maxCallsPerPeriod,
            maxValuePerPeriod,
            periodSeconds
        );
    }

    // **Feature: erc8128-v2-unified-policy, Property 7: Guardian pause enforcement**
    function testFuzz_Property7_GuardianPauseEnforcement(
        uint256 ownerKeySeed,
        uint256 guardianKeySeed,
        uint256 outsiderKeySeed,
        uint256 sessionASeed,
        uint256 sessionBSeed,
        uint256 sessionCSeed,
        bytes32 scopeRootA,
        bytes32 scopeRootB,
        bytes32 scopeRootC
    ) public {
        uint256 ownerKey = bound(ownerKeySeed, 1, SECP256K1_N - 1);
        uint256 guardianKey = bound(guardianKeySeed, 1, SECP256K1_N - 1);
        uint256 outsiderKey = bound(outsiderKeySeed, 1, SECP256K1_N - 1);
        uint256 sessionAKey = bound(sessionASeed, 1, SECP256K1_N - 1);
        uint256 sessionBKey = bound(sessionBSeed, 1, SECP256K1_N - 1);
        uint256 sessionCKey = bound(sessionCSeed, 1, SECP256K1_N - 1);

        vm.assume(ownerKey != guardianKey && ownerKey != outsiderKey && guardianKey != outsiderKey);

        address owner = vm.addr(ownerKey);
        address guardian = vm.addr(guardianKey);
        address outsider = vm.addr(outsiderKey);
        address sessionA = vm.addr(sessionAKey);
        address sessionB = vm.addr(sessionBKey);
        address sessionC = vm.addr(sessionCKey);

        Mock6551Account account = new Mock6551Account(owner);

        uint32 entityA = 100;
        uint32 entityB = 101;
        uint32 entityC = 102;

        _setPolicy(owner, address(account), entityA, sessionA, scopeRootA);
        _setPolicy(owner, address(account), entityB, sessionB, scopeRootB);
        _setPolicy(owner, address(account), entityC, sessionC, scopeRootC);

        vm.expectRevert(abi.encodeWithSelector(ERC8128PolicyRegistry.Unauthorized.selector, outsider));
        vm.prank(outsider);
        registry.pausePolicy(address(account), entityA, sessionA);

        vm.prank(owner);
        registry.setGuardian(address(account), entityA, guardian, true);
        vm.prank(owner);
        registry.setGuardian(address(account), entityB, guardian, true);
        vm.prank(owner);
        registry.setGuardian(address(account), 0, guardian, true);

        vm.prank(guardian);
        registry.pausePolicy(address(account), entityA, sessionA);
        assertFalse(registry.isPolicyActive(address(account), entityA, sessionA));

        vm.prank(guardian);
        registry.pauseEntity(address(account), entityB);
        assertFalse(registry.isPolicyActive(address(account), entityB, sessionB));

        assertTrue(registry.isPolicyActive(address(account), entityC, sessionC));
        vm.prank(guardian);
        registry.pauseAccount(address(account));
        assertFalse(registry.isPolicyActive(address(account), entityC, sessionC));
    }

    // **Feature: erc8128-v2-unified-policy, Property 8: Guardian role management round-trip**
    function testFuzz_Property8_GuardianRoleManagementRoundTrip(
        uint256 ownerKeySeed,
        uint256 guardianKeySeed,
        uint256 sessionOneSeed,
        uint256 sessionTwoSeed,
        bytes32 scopeRootOne,
        bytes32 scopeRootTwo
    ) public {
        uint256 ownerKey = bound(ownerKeySeed, 1, SECP256K1_N - 1);
        uint256 guardianKey = bound(guardianKeySeed, 1, SECP256K1_N - 1);
        uint256 sessionOneKey = bound(sessionOneSeed, 1, SECP256K1_N - 1);
        uint256 sessionTwoKey = bound(sessionTwoSeed, 1, SECP256K1_N - 1);

        vm.assume(ownerKey != guardianKey);

        address owner = vm.addr(ownerKey);
        address guardian = vm.addr(guardianKey);
        address sessionOne = vm.addr(sessionOneKey);
        address sessionTwo = vm.addr(sessionTwoKey);

        Mock6551Account account = new Mock6551Account(owner);
        uint32 entityId = 250;

        _setPolicy(owner, address(account), entityId, sessionOne, scopeRootOne);

        vm.prank(owner);
        registry.setGuardian(address(account), entityId, guardian, true);
        assertTrue(registry.isGuardian(address(account), entityId, guardian));

        vm.prank(guardian);
        registry.pausePolicy(address(account), entityId, sessionOne);
        assertFalse(registry.isPolicyActive(address(account), entityId, sessionOne));

        vm.prank(owner);
        registry.setGuardian(address(account), entityId, guardian, false);
        assertFalse(registry.isGuardian(address(account), entityId, guardian));

        _setPolicy(owner, address(account), entityId, sessionTwo, scopeRootTwo);

        vm.expectRevert(abi.encodeWithSelector(ERC8128PolicyRegistry.Unauthorized.selector, guardian));
        vm.prank(guardian);
        registry.pausePolicy(address(account), entityId, sessionTwo);
    }

    function _setPolicy(address owner, address account, uint32 entityId, address sessionKey, bytes32 scopeRoot) internal {
        vm.prank(owner);
        registry.setPolicy(account, entityId, sessionKey, 0, 0, 600, scopeRoot, 0, 0, 0);
    }
}
