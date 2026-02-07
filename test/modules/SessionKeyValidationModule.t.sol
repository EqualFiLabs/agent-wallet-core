// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";

import {SessionKeyValidationModule} from "../../src/modules/validation/SessionKeyValidationModule.sol";
import {Mock6551Account} from "../mocks/OwnerValidationMocks.sol";

contract SessionKeyValidationModuleTest is Test {
    bytes4 internal constant EXECUTE_SELECTOR = bytes4(keccak256("execute(address,uint256,bytes)"));
    bytes32 internal constant USER_OP_TAG = keccak256("AGENT_WALLET_SESSION_USEROP_V1");
    bytes32 internal constant RUNTIME_TAG = keccak256("AGENT_WALLET_SESSION_RUNTIME_V1");

    uint32 internal constant ENTITY_ID = 7;
    uint256 internal constant SECP256K1_N =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    bytes4 internal constant INNER_ALLOWED_SELECTOR = bytes4(keccak256("allowedInner()"));
    bytes4 internal constant INNER_BLOCKED_SELECTOR = bytes4(keccak256("blockedInner()"));

    SessionKeyValidationModule internal module;

    event SessionBudgetConsumed(
        address indexed account,
        uint32 indexed entityId,
        address indexed sessionKey,
        uint64 policyNonce,
        uint256 amount,
        uint256 cumulativeValueUsed
    );

    function setUp() public {
        module = new SessionKeyValidationModule();
    }

    // **Feature: standalone-nft-agent-wallet, Property 11: Session key empty selector policy rejection**
    function testFuzz_Property11_SessionKeyEmptySelectorPolicyRejection(uint256 ownerKeySeed, uint256 sessionKeySeed)
        public
    {
        uint256 ownerKey = bound(ownerKeySeed, 1, SECP256K1_N - 1);
        uint256 sessionKey = bound(sessionKeySeed, 1, SECP256K1_N - 1);
        vm.assume(ownerKey != sessionKey);

        address owner = vm.addr(ownerKey);
        address sessionSigner = vm.addr(sessionKey);
        Mock6551Account account = new Mock6551Account(owner);

        vm.prank(owner);
        vm.expectRevert(SessionKeyValidationModule.EmptySelectorPolicy.selector);
        module.setSessionKeyPolicy(
            address(account),
            ENTITY_ID,
            sessionSigner,
            0,
            0,
            0,
            0,
            new address[](0),
            new bytes4[](0),
            _emptyTargetRules()
        );
    }

    // **Feature: standalone-nft-agent-wallet, Property 12: Session key execution selector target requirement**
    function testFuzz_Property12_SessionKeyExecutionSelectorTargetRequirement(
        uint256 ownerKeySeed,
        uint256 sessionKeySeed
    ) public {
        uint256 ownerKey = bound(ownerKeySeed, 1, SECP256K1_N - 1);
        uint256 sessionKey = bound(sessionKeySeed, 1, SECP256K1_N - 1);
        vm.assume(ownerKey != sessionKey);

        address owner = vm.addr(ownerKey);
        address sessionSigner = vm.addr(sessionKey);
        Mock6551Account account = new Mock6551Account(owner);

        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = EXECUTE_SELECTOR;

        vm.prank(owner);
        vm.expectRevert(SessionKeyValidationModule.MissingTargetAllowlistForExecutionSelectors.selector);
        module.setSessionKeyPolicy(
            address(account), ENTITY_ID, sessionSigner, 0, 0, 1 ether, 0, new address[](0), selectors, _emptyTargetRules()
        );
    }

    // **Feature: standalone-nft-agent-wallet, Property 13: Session key call permission enforcement**
    function testFuzz_Property13_SessionKeyCallPermissionEnforcement(
        uint256 ownerKeySeed,
        uint256 sessionKeySeed,
        address allowedTarget,
        address disallowedTarget
    ) public {
        uint256 ownerKey = bound(ownerKeySeed, 1, SECP256K1_N - 1);
        uint256 sessionKey = bound(sessionKeySeed, 1, SECP256K1_N - 1);
        vm.assume(ownerKey != sessionKey);
        vm.assume(allowedTarget != address(0));
        vm.assume(disallowedTarget != address(0) && disallowedTarget != allowedTarget);

        address owner = vm.addr(ownerKey);
        address sessionSigner = vm.addr(sessionKey);
        Mock6551Account account = new Mock6551Account(owner);

        address[] memory targets = new address[](1);
        targets[0] = allowedTarget;
        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = EXECUTE_SELECTOR;

        SessionKeyValidationModule.TargetSelectorRule[] memory rules =
            new SessionKeyValidationModule.TargetSelectorRule[](1);
        bytes4[] memory innerSelectors = new bytes4[](1);
        innerSelectors[0] = INNER_ALLOWED_SELECTOR;
        rules[0] = SessionKeyValidationModule.TargetSelectorRule({target: allowedTarget, selectors: innerSelectors});

        vm.prank(owner);
        module.setSessionKeyPolicy(address(account), ENTITY_ID, sessionSigner, 0, 0, 1 ether, 0, targets, selectors, rules);

        bytes32 disallowedSelectorHash = keccak256("disallowed-selector");
        bytes memory disallowedSelectorCall = abi.encodeWithSelector(bytes4(keccak256("forbidden()")));
        bytes memory disallowedSelectorSig =
            _asModuleSig(sessionSigner, _sign(sessionKey, _userOpDigest(address(account), disallowedSelectorHash)));
        PackedUserOperation memory disallowedSelectorOp =
            _buildUserOp(address(account), disallowedSelectorCall, disallowedSelectorSig);
        assertEq(module.validateUserOp(ENTITY_ID, disallowedSelectorOp, disallowedSelectorHash), 1);

        bytes32 disallowedTargetHash = keccak256("disallowed-target");
        bytes memory disallowedTargetCall =
            abi.encodeWithSelector(EXECUTE_SELECTOR, disallowedTarget, 0.1 ether, bytes(""));
        bytes memory disallowedTargetSig =
            _asModuleSig(sessionSigner, _sign(sessionKey, _userOpDigest(address(account), disallowedTargetHash)));
        PackedUserOperation memory disallowedTargetOp =
            _buildUserOp(address(account), disallowedTargetCall, disallowedTargetSig);
        assertEq(module.validateUserOp(ENTITY_ID, disallowedTargetOp, disallowedTargetHash), 1);

        bytes32 blockedInnerHash = keccak256("blocked-inner");
        bytes memory blockedInnerCall =
            abi.encodeWithSelector(EXECUTE_SELECTOR, allowedTarget, 0.1 ether, abi.encodeWithSelector(INNER_BLOCKED_SELECTOR));
        bytes memory blockedInnerSig =
            _asModuleSig(sessionSigner, _sign(sessionKey, _userOpDigest(address(account), blockedInnerHash)));
        PackedUserOperation memory blockedInnerOp = _buildUserOp(address(account), blockedInnerCall, blockedInnerSig);
        assertEq(module.validateUserOp(ENTITY_ID, blockedInnerOp, blockedInnerHash), 1);

        bytes32 allowedHash = keccak256("allowed-call");
        bytes memory allowedCall =
            abi.encodeWithSelector(EXECUTE_SELECTOR, allowedTarget, 0.1 ether, abi.encodeWithSelector(INNER_ALLOWED_SELECTOR));
        bytes memory allowedSig =
            _asModuleSig(sessionSigner, _sign(sessionKey, _userOpDigest(address(account), allowedHash)));
        PackedUserOperation memory allowedOp = _buildUserOp(address(account), allowedCall, allowedSig);
        assertEq(module.validateUserOp(ENTITY_ID, allowedOp, allowedHash), 0);
    }

    // **Feature: standalone-nft-agent-wallet, Property 14: Session key time window enforcement**
    function testFuzz_Property14_SessionKeyTimeWindowEnforcement(
        uint256 ownerKeySeed,
        uint256 sessionKeySeed,
        address allowedTarget
    ) public {
        uint256 ownerKey = bound(ownerKeySeed, 1, SECP256K1_N - 1);
        uint256 sessionKey = bound(sessionKeySeed, 1, SECP256K1_N - 1);
        vm.assume(ownerKey != sessionKey);
        vm.assume(allowedTarget != address(0));

        address owner = vm.addr(ownerKey);
        address sessionSigner = vm.addr(sessionKey);
        Mock6551Account account = new Mock6551Account(owner);

        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = EXECUTE_SELECTOR;
        address[] memory targets = new address[](1);
        targets[0] = allowedTarget;

        uint48 validAfter = uint48(block.timestamp + 10);
        uint48 validUntil = uint48(block.timestamp + 100);

        vm.prank(owner);
        module.setSessionKeyPolicy(
            address(account), ENTITY_ID, sessionSigner, validAfter, validUntil, 1 ether, 0, targets, selectors, _emptyTargetRules()
        );

        bytes memory callData = abi.encodeWithSelector(EXECUTE_SELECTOR, allowedTarget, 0.1 ether, bytes(""));
        bytes32 hashBefore = keccak256("before-window");
        bytes memory sigBefore =
            _asModuleSig(sessionSigner, _sign(sessionKey, _userOpDigest(address(account), hashBefore)));
        PackedUserOperation memory opBefore = _buildUserOp(address(account), callData, sigBefore);
        assertEq(module.validateUserOp(ENTITY_ID, opBefore, hashBefore), 1);

        vm.warp(validAfter + 1);
        bytes32 hashWithin = keccak256("within-window");
        bytes memory sigWithin =
            _asModuleSig(sessionSigner, _sign(sessionKey, _userOpDigest(address(account), hashWithin)));
        PackedUserOperation memory opWithin = _buildUserOp(address(account), callData, sigWithin);
        uint256 validationData = module.validateUserOp(ENTITY_ID, opWithin, hashWithin);
        (, uint48 packedValidUntil, uint48 packedValidAfter) = _parseValidationData(validationData);
        assertEq(packedValidAfter, validAfter);
        assertEq(packedValidUntil, validUntil);

        vm.warp(validUntil + 1);
        bytes32 hashAfter = keccak256("after-window");
        bytes memory sigAfter =
            _asModuleSig(sessionSigner, _sign(sessionKey, _userOpDigest(address(account), hashAfter)));
        PackedUserOperation memory opAfter = _buildUserOp(address(account), callData, sigAfter);
        assertEq(module.validateUserOp(ENTITY_ID, opAfter, hashAfter), 1);
    }

    // **Feature: standalone-nft-agent-wallet, Property 15: Session key revocation invalidation**
    function testFuzz_Property15_SessionKeyRevocationInvalidation(
        uint256 ownerKeySeed,
        uint256 sessionKeySeed,
        address allowedTarget
    ) public {
        uint256 ownerKey = bound(ownerKeySeed, 1, SECP256K1_N - 1);
        uint256 sessionKey = bound(sessionKeySeed, 1, SECP256K1_N - 1);
        vm.assume(ownerKey != sessionKey);
        vm.assume(allowedTarget != address(0));

        address owner = vm.addr(ownerKey);
        address sessionSigner = vm.addr(sessionKey);
        Mock6551Account account = new Mock6551Account(owner);

        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = EXECUTE_SELECTOR;
        address[] memory targets = new address[](1);
        targets[0] = allowedTarget;

        vm.prank(owner);
        module.setSessionKeyPolicy(
            address(account), ENTITY_ID, sessionSigner, 0, 0, 1 ether, 0, targets, selectors, _emptyTargetRules()
        );

        bytes memory callData = abi.encodeWithSelector(EXECUTE_SELECTOR, allowedTarget, 0.1 ether, bytes(""));
        bytes32 hashBeforeRevoke = keccak256("before-revoke");
        bytes memory sigBeforeRevoke =
            _asModuleSig(sessionSigner, _sign(sessionKey, _userOpDigest(address(account), hashBeforeRevoke)));
        PackedUserOperation memory opBeforeRevoke = _buildUserOp(address(account), callData, sigBeforeRevoke);
        assertEq(module.validateUserOp(ENTITY_ID, opBeforeRevoke, hashBeforeRevoke), 0);

        vm.prank(owner);
        module.revokeSessionKey(address(account), ENTITY_ID, sessionSigner);

        bytes32 hashAfterRevoke = keccak256("after-revoke");
        bytes memory sigAfterRevoke =
            _asModuleSig(sessionSigner, _sign(sessionKey, _userOpDigest(address(account), hashAfterRevoke)));
        PackedUserOperation memory opAfterRevoke = _buildUserOp(address(account), callData, sigAfterRevoke);
        assertEq(module.validateUserOp(ENTITY_ID, opAfterRevoke, hashAfterRevoke), 1);

        vm.prank(owner);
        module.setSessionKeyPolicy(
            address(account), ENTITY_ID, sessionSigner, 0, 0, 1 ether, 0, targets, selectors, _emptyTargetRules()
        );

        bytes32 hashBeforeRevokeAll = keccak256("before-revoke-all");
        bytes memory sigBeforeRevokeAll =
            _asModuleSig(sessionSigner, _sign(sessionKey, _userOpDigest(address(account), hashBeforeRevokeAll)));
        PackedUserOperation memory opBeforeRevokeAll = _buildUserOp(address(account), callData, sigBeforeRevokeAll);
        assertEq(module.validateUserOp(ENTITY_ID, opBeforeRevokeAll, hashBeforeRevokeAll), 0);

        vm.prank(owner);
        module.revokeAllSessionKeys(address(account), ENTITY_ID);

        bytes32 hashAfterRevokeAll = keccak256("after-revoke-all");
        bytes memory sigAfterRevokeAll =
            _asModuleSig(sessionSigner, _sign(sessionKey, _userOpDigest(address(account), hashAfterRevokeAll)));
        PackedUserOperation memory opAfterRevokeAll = _buildUserOp(address(account), callData, sigAfterRevokeAll);
        assertEq(module.validateUserOp(ENTITY_ID, opAfterRevokeAll, hashAfterRevokeAll), 1);
    }

    // **Feature: standalone-nft-agent-wallet, Property 16: Session key budget enforcement**
    function testFuzz_Property16_SessionKeyBudgetEnforcement(
        uint256 ownerKeySeed,
        uint256 sessionKeySeed,
        address allowedTarget
    ) public {
        uint256 ownerKey = bound(ownerKeySeed, 1, SECP256K1_N - 1);
        uint256 sessionKey = bound(sessionKeySeed, 1, SECP256K1_N - 1);
        vm.assume(ownerKey != sessionKey);
        vm.assume(allowedTarget != address(0));

        address owner = vm.addr(ownerKey);
        address sessionSigner = vm.addr(sessionKey);
        Mock6551Account account = new Mock6551Account(owner);

        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = EXECUTE_SELECTOR;
        address[] memory targets = new address[](1);
        targets[0] = allowedTarget;

        vm.prank(owner);
        module.setSessionKeyPolicy(
            address(account), ENTITY_ID, sessionSigner, 0, 0, 1 ether, 1 ether, targets, selectors, _emptyTargetRules()
        );

        bytes memory spendCall = abi.encodeWithSelector(EXECUTE_SELECTOR, allowedTarget, 0.6 ether, bytes(""));
        bytes32 hash1 = keccak256("budget-spend-1");
        bytes memory sig1 = _asModuleSig(sessionSigner, _sign(sessionKey, _userOpDigest(address(account), hash1)));
        PackedUserOperation memory op1 = _buildUserOp(address(account), spendCall, sig1);

        vm.expectEmit(true, true, true, true);
        emit SessionBudgetConsumed(address(account), ENTITY_ID, sessionSigner, 1, 0.6 ether, 0.6 ether);
        assertEq(module.validateUserOp(ENTITY_ID, op1, hash1), 0);

        bytes32 hash2 = keccak256("budget-spend-2");
        bytes memory sig2 = _asModuleSig(sessionSigner, _sign(sessionKey, _userOpDigest(address(account), hash2)));
        PackedUserOperation memory op2 = _buildUserOp(address(account), spendCall, sig2);
        assertEq(module.validateUserOp(ENTITY_ID, op2, hash2), 1);

        bytes memory overPerCall = abi.encodeWithSelector(EXECUTE_SELECTOR, allowedTarget, 1.1 ether, bytes(""));
        bytes32 hash3 = keccak256("budget-over-per-call");
        bytes memory sig3 = _asModuleSig(sessionSigner, _sign(sessionKey, _userOpDigest(address(account), hash3)));
        PackedUserOperation memory op3 = _buildUserOp(address(account), overPerCall, sig3);
        assertEq(module.validateUserOp(ENTITY_ID, op3, hash3), 1);
    }

    // **Feature: standalone-nft-agent-wallet, Property 22: Runtime authorization replay prevention**
    function testFuzz_Property22_RuntimeAuthorizationReplayPrevention(
        uint256 ownerKeySeed,
        uint256 sessionKeySeed,
        address allowedTarget
    ) public {
        uint256 ownerKey = bound(ownerKeySeed, 1, SECP256K1_N - 1);
        uint256 sessionKey = bound(sessionKeySeed, 1, SECP256K1_N - 1);
        vm.assume(ownerKey != sessionKey);
        vm.assume(allowedTarget != address(0));

        address owner = vm.addr(ownerKey);
        address sessionSigner = vm.addr(sessionKey);
        Mock6551Account account = new Mock6551Account(owner);

        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = EXECUTE_SELECTOR;
        address[] memory targets = new address[](1);
        targets[0] = allowedTarget;

        vm.prank(owner);
        module.setSessionKeyPolicy(
            address(account), ENTITY_ID, sessionSigner, 0, 0, 1 ether, 0, targets, selectors, _emptyTargetRules()
        );

        bytes memory data = abi.encodeWithSelector(EXECUTE_SELECTOR, allowedTarget, 0.1 ether, bytes(""));
        address runtimeSender = makeAddr("runtimeSender");
        uint256 runtimeValue = 0;
        bytes32 replayProtection = keccak256("runtime-replay-key");

        bytes32 digest = _runtimeDigest(address(account), runtimeSender, runtimeValue, data, replayProtection);
        bytes memory auth = abi.encode(sessionSigner, replayProtection, _sign(sessionKey, digest));

        module.validateRuntime(address(account), ENTITY_ID, runtimeSender, runtimeValue, data, auth);

        vm.expectRevert(abi.encodeWithSelector(SessionKeyValidationModule.ReplayProtectionAlreadyUsed.selector, replayProtection));
        module.validateRuntime(address(account), ENTITY_ID, runtimeSender, runtimeValue, data, auth);

        bytes32 replayProtection2 = keccak256("runtime-replay-key-2");
        bytes32 digest2 = _runtimeDigest(address(account), runtimeSender, runtimeValue, data, replayProtection2);
        bytes memory auth2 = abi.encode(sessionSigner, replayProtection2, _sign(sessionKey, digest2));
        module.validateRuntime(address(account), ENTITY_ID, runtimeSender, runtimeValue, data, auth2);
    }

    function _emptyTargetRules() internal pure returns (SessionKeyValidationModule.TargetSelectorRule[] memory rules) {
        rules = new SessionKeyValidationModule.TargetSelectorRule[](0);
    }

    function _buildUserOp(address sender, bytes memory callData, bytes memory signature)
        internal
        pure
        returns (PackedUserOperation memory userOp)
    {
        userOp.sender = sender;
        userOp.nonce = 0;
        userOp.initCode = bytes("");
        userOp.callData = callData;
        userOp.accountGasLimits = bytes32(0);
        userOp.preVerificationGas = 0;
        userOp.gasFees = bytes32(0);
        userOp.paymasterAndData = bytes("");
        userOp.signature = signature;
    }

    function _userOpDigest(address account, bytes32 userOpHash) internal view returns (bytes32) {
        bytes32 payloadHash = keccak256(abi.encode(USER_OP_TAG, block.chainid, address(module), account, ENTITY_ID, userOpHash));
        return MessageHashUtils.toEthSignedMessageHash(payloadHash);
    }

    function _runtimeDigest(
        address account,
        address sender,
        uint256 value,
        bytes memory data,
        bytes32 replayProtection
    ) internal view returns (bytes32) {
        bytes32 payloadHash = keccak256(
            abi.encode(
                RUNTIME_TAG,
                block.chainid,
                address(module),
                account,
                ENTITY_ID,
                sender,
                value,
                keccak256(data),
                replayProtection
            )
        );
        return MessageHashUtils.toEthSignedMessageHash(payloadHash);
    }

    function _asModuleSig(address sessionKey, bytes memory sig) internal pure returns (bytes memory) {
        return abi.encode(sessionKey, sig);
    }

    function _sign(uint256 key, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest);
        return abi.encodePacked(r, s, v);
    }

    function _parseValidationData(uint256 data) internal pure returns (address authorizer, uint48 validUntil, uint48 validAfter) {
        authorizer = address(uint160(data));
        validUntil = uint48(data >> 160);
        validAfter = uint48(data >> 208);
    }
}
