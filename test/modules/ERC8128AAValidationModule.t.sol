// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";

import {ERC8128PolicyRegistry} from "../../src/core/ERC8128PolicyRegistry.sol";
import {ERC8128AAValidationModule} from "../../src/modules/validation/ERC8128AAValidationModule.sol";
import {SessionAuthV2, AAClaimsV2, AACallClaimV2, ParsedCall} from "../../src/libraries/ERC8128Types.sol";
import {Call} from "../../src/libraries/ModuleTypes.sol";
import {IERC165} from "../../src/interfaces/IERC165.sol";
import {IERC6900Module} from "../../src/interfaces/IERC6900Module.sol";
import {IERC6900ValidationModule} from "../../src/interfaces/IERC6900ValidationModule.sol";
import {Mock6551Account} from "../mocks/OwnerValidationMocks.sol";

contract ERC8128AAValidationModuleTest is Test {
    uint256 internal constant SECP256K1_N =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    bytes4 internal constant ERC1271_INVALID = 0xffffffff;
    uint256 internal constant SIG_VALIDATION_FAILED = 1;

    bytes4 internal constant EXECUTE_SELECTOR = bytes4(keccak256("execute(address,uint256,bytes)"));
    bytes4 internal constant EXECUTE_BATCH_SELECTOR = bytes4(keccak256("executeBatch((address,uint256,bytes)[])"));
    bytes4 internal constant EXECUTE_OPERATION_SELECTOR = bytes4(keccak256("execute(address,uint256,bytes,uint8)"));

    bytes32 internal constant EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 internal constant DOMAIN_NAME_HASH = keccak256(bytes("AgentWalletERC8128"));
    bytes32 internal constant DOMAIN_VERSION_HASH = keccak256(bytes("2"));
    bytes32 internal constant SESSION_AUTHORIZATION_V2_TYPEHASH = keccak256(
        "SessionAuthorizationV2(uint8 mode,address account,uint32 entityId,address sessionKey,uint64 epoch,uint64 policyNonce,uint48 created,uint48 expires,bytes32 requestHash,bytes32 claimsHash)"
    );

    ERC8128PolicyRegistry internal registry;
    ERC8128AAValidationModule internal module;

    function setUp() public {
        registry = new ERC8128PolicyRegistry();
        module = new ERC8128AAValidationModule(address(registry));
    }

    function test_ModuleMetadata_ConformsToERC6900Interfaces() public view {
        assertEq(module.moduleId(), "agent.wallet.erc8128-aa-validation.1.0.0");
        assertTrue(module.supportsInterface(type(IERC165).interfaceId));
        assertTrue(module.supportsInterface(type(IERC6900Module).interfaceId));
        assertTrue(module.supportsInterface(type(IERC6900ValidationModule).interfaceId));
    }

    function test_ValidateSignature_ReturnsInvalid() public view {
        assertEq(module.validateSignature(address(0), 0, address(0), bytes32(0), bytes("")), ERC1271_INVALID);
    }

    function test_ValidateRuntime_RevertsAsUnsupported() public {
        vm.expectRevert(ERC8128AAValidationModule.RuntimeValidationNotSupported.selector);
        module.validateRuntime(address(0), 0, address(0), 0, bytes(""), bytes(""));
    }

    // **Feature: erc8128-v2-unified-policy, Property 14: Valid AA session signature acceptance**
    function testFuzz_Property14_ValidAASessionSignatureAcceptance(
        uint256 ownerKeySeed,
        uint256 sessionKeySeed,
        uint32 entityId,
        bytes32 userOpHash,
        uint96 valueSeed
    ) public {
        uint256 ownerKey = bound(ownerKeySeed, 1, SECP256K1_N - 1);
        uint256 sessionKey = bound(sessionKeySeed, 1, SECP256K1_N - 1);
        vm.assume(ownerKey != sessionKey);

        address owner = vm.addr(ownerKey);
        address sessionSigner = vm.addr(sessionKey);
        Mock6551Account account = new Mock6551Account(owner);

        bytes4[] memory allowedSelectors = new bytes4[](1);
        allowedSelectors[0] = EXECUTE_SELECTOR;
        _installPreset(address(account), entityId, allowedSelectors, false, 30, 1000);

        address target = makeAddr("aa-valid-target");
        bytes4 innerSelector = bytes4(keccak256("runJob()"));
        uint256 callValue = bound(valueSeed, 0, 1 ether);
        uint256 valueLimit = callValue + 1;

        bytes memory callData = abi.encodeWithSelector(EXECUTE_SELECTOR, target, callValue, abi.encodeWithSelector(innerSelector));

        bytes32 scopeLeaf = module.computeAAScopeLeaf(target, innerSelector, valueLimit, false);

        _setPolicy(owner, address(account), entityId, sessionSigner, scopeLeaf, 900);

        (, uint64 epoch, uint64 policyNonce) = registry.getPolicy(address(account), entityId, sessionSigner);

        AACallClaimV2[] memory callClaims = new AACallClaimV2[](1);
        callClaims[0] = _claim(target, innerSelector, valueLimit, false, scopeLeaf, new bytes32[](0));

        AAClaimsV2 memory aaClaims =
            AAClaimsV2({callClaims: callClaims, multiproof: new bytes32[](0), proofFlags: new bool[](0), leafOrderHash: bytes32(0)});

        uint48 created = uint48(block.timestamp - 1);
        uint48 expires = created + 300;

        SessionAuthV2 memory auth = SessionAuthV2({
            mode: 1,
            sessionKey: sessionSigner,
            epoch: epoch,
            policyNonce: policyNonce,
            created: created,
            expires: expires,
            requestHash: userOpHash,
            claimsHash: module.computeAAClaimsHash(aaClaims),
            sessionSignature: "",
            claims: abi.encode(aaClaims)
        });
        auth.sessionSignature = _sign(sessionKey, _sessionDigest(auth, address(account), entityId));

        PackedUserOperation memory userOp = _buildUserOp(address(account), callData, abi.encode(auth));

        uint256 validationData = module.validateUserOp(entityId, userOp, userOpHash);
        assertNotEq(validationData, SIG_VALIDATION_FAILED);

        (address authorizer, uint48 validUntil, uint48 validAfter) = _parseValidationData(validationData);
        assertEq(authorizer, address(0));
        assertEq(validAfter, created);
        assertEq(validUntil, expires);
    }

    // **Feature: erc8128-v2-unified-policy, Property 15: AA claim constraint enforcement**
    function testFuzz_Property15_AAClaimConstraintEnforcement(
        uint256 ownerKeySeed,
        uint256 sessionKeySeed,
        uint8 tamperCaseSeed,
        uint32 entityId,
        bytes32 userOpHash
    ) public {
        uint256 ownerKey = bound(ownerKeySeed, 1, SECP256K1_N - 1);
        uint256 sessionKey = bound(sessionKeySeed, 1, SECP256K1_N - 1);
        vm.assume(ownerKey != sessionKey);

        address owner = vm.addr(ownerKey);
        address sessionSigner = vm.addr(sessionKey);
        Mock6551Account account = new Mock6551Account(owner);

        bytes4[] memory allowedSelectors = new bytes4[](2);
        allowedSelectors[0] = EXECUTE_SELECTOR;
        allowedSelectors[1] = EXECUTE_OPERATION_SELECTOR;
        _installPreset(address(account), entityId, allowedSelectors, false, 10, 1200);

        uint8 tamperCase = uint8(bound(tamperCaseSeed, 0, 3));

        address target = makeAddr("aa-constraint-target");
        address otherTarget = makeAddr("aa-constraint-other-target");
        bytes4 innerSelector = bytes4(keccak256("doThing()"));

        bytes memory callData;
        uint256 parsedValue;
        if (tamperCase == 2) {
            parsedValue = 0;
            callData = abi.encodeWithSelector(
                EXECUTE_OPERATION_SELECTOR, target, parsedValue, abi.encodeWithSelector(innerSelector), uint8(1)
            );
        } else {
            parsedValue = 1 ether;
            callData = abi.encodeWithSelector(EXECUTE_SELECTOR, target, parsedValue, abi.encodeWithSelector(innerSelector));
        }

        AACallClaimV2[] memory callClaims;
        bytes32 scopeRoot;

        if (tamperCase == 0) {
            callClaims = new AACallClaimV2[](0);
            scopeRoot = keccak256("unused-scope-root");
        } else if (tamperCase == 1) {
            callClaims = new AACallClaimV2[](1);
            uint256 valueLimit = parsedValue - 1;
            bytes32 leaf = module.computeAAScopeLeaf(target, innerSelector, valueLimit, false);
            callClaims[0] = _claim(target, innerSelector, valueLimit, false, leaf, new bytes32[](0));
            scopeRoot = leaf;
        } else if (tamperCase == 2) {
            callClaims = new AACallClaimV2[](1);
            uint256 valueLimit = 1 ether;
            bytes32 leaf = module.computeAAScopeLeaf(target, innerSelector, valueLimit, false);
            callClaims[0] = _claim(target, innerSelector, valueLimit, false, leaf, new bytes32[](0));
            scopeRoot = leaf;
        } else {
            callClaims = new AACallClaimV2[](1);
            uint256 valueLimit = 1 ether;
            bytes32 leaf = module.computeAAScopeLeaf(otherTarget, innerSelector, valueLimit, false);
            callClaims[0] = _claim(otherTarget, innerSelector, valueLimit, false, leaf, new bytes32[](0));
            scopeRoot = leaf;
        }

        _setPolicy(owner, address(account), entityId, sessionSigner, scopeRoot, 900);

        (, uint64 epoch, uint64 policyNonce) = registry.getPolicy(address(account), entityId, sessionSigner);

        AAClaimsV2 memory aaClaims =
            AAClaimsV2({callClaims: callClaims, multiproof: new bytes32[](0), proofFlags: new bool[](0), leafOrderHash: bytes32(0)});

        uint48 created = uint48(block.timestamp - 1);
        uint48 expires = created + 300;

        SessionAuthV2 memory auth = SessionAuthV2({
            mode: 1,
            sessionKey: sessionSigner,
            epoch: epoch,
            policyNonce: policyNonce,
            created: created,
            expires: expires,
            requestHash: userOpHash,
            claimsHash: module.computeAAClaimsHash(aaClaims),
            sessionSignature: "",
            claims: abi.encode(aaClaims)
        });
        auth.sessionSignature = _sign(sessionKey, _sessionDigest(auth, address(account), entityId));

        PackedUserOperation memory userOp = _buildUserOp(address(account), callData, abi.encode(auth));

        uint256 validationData = module.validateUserOp(entityId, userOp, userOpHash);
        assertEq(validationData, SIG_VALIDATION_FAILED);
    }

    // **Feature: erc8128-v2-unified-policy, Property 16: AA multiproof verification**
    function testFuzz_Property16_AAMultiproofVerification(
        uint256 ownerKeySeed,
        uint256 sessionKeySeed,
        uint32 entityId,
        bytes32 userOpHash
    ) public {
        uint256 ownerKey = bound(ownerKeySeed, 1, SECP256K1_N - 1);
        uint256 sessionKey = bound(sessionKeySeed, 1, SECP256K1_N - 1);
        vm.assume(ownerKey != sessionKey);

        address owner = vm.addr(ownerKey);
        address sessionSigner = vm.addr(sessionKey);
        Mock6551Account account = new Mock6551Account(owner);

        bytes4[] memory allowedSelectors = new bytes4[](1);
        allowedSelectors[0] = EXECUTE_BATCH_SELECTOR;
        _installPreset(address(account), entityId, allowedSelectors, false, 10, 1200);

        address targetA = makeAddr("aa-batch-target-a");
        address targetB = makeAddr("aa-batch-target-b");
        bytes4 selectorA = bytes4(keccak256("jobA()"));
        bytes4 selectorB = bytes4(keccak256("jobB()"));

        uint256 valueLimitA = 1 ether;
        uint256 valueLimitB = 2 ether;

        bytes32 leafA = module.computeAAScopeLeaf(targetA, selectorA, valueLimitA, false);
        bytes32 leafB = module.computeAAScopeLeaf(targetB, selectorB, valueLimitB, false);
        bytes32 scopeRoot = _hashPair(leafA, leafB);

        _setPolicy(owner, address(account), entityId, sessionSigner, scopeRoot, 900);

        (, uint64 epoch, uint64 policyNonce) = registry.getPolicy(address(account), entityId, sessionSigner);

        AACallClaimV2[] memory callClaims = new AACallClaimV2[](2);
        callClaims[0] = _claim(targetA, selectorA, valueLimitA, false, leafA, new bytes32[](0));
        callClaims[1] = _claim(targetB, selectorB, valueLimitB, false, leafB, new bytes32[](0));

        bytes32[] memory multiproof = new bytes32[](0);
        bool[] memory proofFlags = new bool[](1);
        proofFlags[0] = true;

        bytes32[] memory leafOrder = new bytes32[](2);
        leafOrder[0] = leafA;
        leafOrder[1] = leafB;

        AAClaimsV2 memory aaClaims = AAClaimsV2({
            callClaims: callClaims,
            multiproof: multiproof,
            proofFlags: proofFlags,
            leafOrderHash: keccak256(abi.encode(leafOrder))
        });

        uint48 created = uint48(block.timestamp - 1);
        uint48 expires = created + 300;

        SessionAuthV2 memory auth = SessionAuthV2({
            mode: 1,
            sessionKey: sessionSigner,
            epoch: epoch,
            policyNonce: policyNonce,
            created: created,
            expires: expires,
            requestHash: userOpHash,
            claimsHash: module.computeAAClaimsHash(aaClaims),
            sessionSignature: "",
            claims: abi.encode(aaClaims)
        });
        auth.sessionSignature = _sign(sessionKey, _sessionDigest(auth, address(account), entityId));

        Call[] memory calls = new Call[](2);
        calls[0] = Call({target: targetA, value: 0.5 ether, data: abi.encodeWithSelector(selectorA)});
        calls[1] = Call({target: targetB, value: 0.7 ether, data: abi.encodeWithSelector(selectorB)});

        bytes memory callData = abi.encodeWithSelector(EXECUTE_BATCH_SELECTOR, calls);

        PackedUserOperation memory userOp = _buildUserOp(address(account), callData, abi.encode(auth));
        uint256 okValidationData = module.validateUserOp(entityId, userOp, userOpHash);
        assertNotEq(okValidationData, SIG_VALIDATION_FAILED);

        bytes32[] memory badMultiproof = new bytes32[](1);
        badMultiproof[0] = keccak256("bad-multiproof");
        bool[] memory badFlags = new bool[](2);
        badFlags[0] = false;
        badFlags[1] = true;

        AAClaimsV2 memory badClaims = AAClaimsV2({
            callClaims: callClaims,
            multiproof: badMultiproof,
            proofFlags: badFlags,
            leafOrderHash: keccak256(abi.encode(leafOrder))
        });

        SessionAuthV2 memory badAuth = auth;
        badAuth.claimsHash = module.computeAAClaimsHash(badClaims);
        badAuth.claims = abi.encode(badClaims);
        badAuth.sessionSignature = _sign(sessionKey, _sessionDigest(badAuth, address(account), entityId));

        PackedUserOperation memory badUserOp = _buildUserOp(address(account), callData, abi.encode(badAuth));
        uint256 badValidationData = module.validateUserOp(entityId, badUserOp, userOpHash);
        assertEq(badValidationData, SIG_VALIDATION_FAILED);
    }

    // **Feature: erc8128-v2-unified-policy, Property 17: Call parsing correctness**
    function testFuzz_Property17_CallParsingCorrectness(address targetA, address targetB, uint96 valueA, uint96 valueB)
        public
        view
    {
        bytes4 innerSelectorA = bytes4(keccak256("selectorA()"));
        bytes4 innerSelectorB = bytes4(keccak256("selectorB()"));

        bytes memory executeData =
            abi.encodeWithSelector(EXECUTE_SELECTOR, targetA, uint256(valueA), abi.encodeWithSelector(innerSelectorA));
        (ParsedCall[] memory parsedExecute, bool supportedExecute) = module.parseCalls(executeData);
        assertTrue(supportedExecute);
        assertEq(parsedExecute.length, 1);
        assertEq(parsedExecute[0].target, targetA);
        assertEq(parsedExecute[0].value, uint256(valueA));
        assertEq(parsedExecute[0].selector, innerSelectorA);
        assertFalse(parsedExecute[0].isDelegateCall);

        bytes memory executeOpCall = abi.encodeWithSelector(
            EXECUTE_OPERATION_SELECTOR, targetA, uint256(valueA), abi.encodeWithSelector(innerSelectorA), uint8(0)
        );
        (ParsedCall[] memory parsedExecuteOpCall, bool supportedExecuteOpCall) = module.parseCalls(executeOpCall);
        assertTrue(supportedExecuteOpCall);
        assertEq(parsedExecuteOpCall.length, 1);
        assertEq(parsedExecuteOpCall[0].selector, innerSelectorA);
        assertFalse(parsedExecuteOpCall[0].isDelegateCall);

        bytes memory executeOpDelegate =
            abi.encodeWithSelector(EXECUTE_OPERATION_SELECTOR, targetA, uint256(0), abi.encodeWithSelector(innerSelectorA), uint8(1));
        (ParsedCall[] memory parsedExecuteOpDelegate, bool supportedExecuteOpDelegate) = module.parseCalls(executeOpDelegate);
        assertTrue(supportedExecuteOpDelegate);
        assertEq(parsedExecuteOpDelegate.length, 1);
        assertEq(parsedExecuteOpDelegate[0].selector, innerSelectorA);
        assertTrue(parsedExecuteOpDelegate[0].isDelegateCall);

        bytes memory invalidDelegate = abi.encodeWithSelector(
            EXECUTE_OPERATION_SELECTOR, targetA, uint256(valueA == 0 ? 1 : valueA), abi.encodeWithSelector(innerSelectorA), uint8(1)
        );
        (ParsedCall[] memory parsedInvalidDelegate, bool supportedInvalidDelegate) = module.parseCalls(invalidDelegate);
        assertFalse(supportedInvalidDelegate);
        assertEq(parsedInvalidDelegate.length, 0);

        Call[] memory calls = new Call[](2);
        calls[0] = Call({target: targetA, value: uint256(valueA), data: abi.encodeWithSelector(innerSelectorA)});
        calls[1] = Call({target: targetB, value: uint256(valueB), data: abi.encodeWithSelector(innerSelectorB)});
        bytes memory batchData = abi.encodeWithSelector(EXECUTE_BATCH_SELECTOR, calls);

        (ParsedCall[] memory parsedBatch, bool supportedBatch) = module.parseCalls(batchData);
        assertTrue(supportedBatch);
        assertEq(parsedBatch.length, 2);
        assertEq(parsedBatch[0].selector, innerSelectorA);
        assertEq(parsedBatch[1].selector, innerSelectorB);
        assertFalse(parsedBatch[0].isDelegateCall);
        assertFalse(parsedBatch[1].isDelegateCall);

        bytes memory unsupportedData = abi.encodeWithSelector(bytes4(keccak256("unknown(bytes)")), bytes("payload"));
        (ParsedCall[] memory unsupportedParsed, bool unsupported) = module.parseCalls(unsupportedData);
        assertFalse(unsupported);
        assertEq(unsupportedParsed.length, 0);
    }

    // **Feature: erc8128-v2-unified-policy, Property 19: Install preset enforcement**
    function testFuzz_Property19_InstallPresetEnforcement(
        uint256 ownerKeySeed,
        uint256 sessionKeySeed,
        uint32 entityId,
        bytes32 userOpHash
    ) public {
        uint256 ownerKey = bound(ownerKeySeed, 1, SECP256K1_N - 1);
        uint256 sessionKey = bound(sessionKeySeed, 1, SECP256K1_N - 1);
        vm.assume(ownerKey != sessionKey);

        address owner = vm.addr(ownerKey);
        address sessionSigner = vm.addr(sessionKey);
        Mock6551Account account = new Mock6551Account(owner);

        address target = makeAddr("aa-preset-target");
        bytes4 innerSelector = bytes4(keccak256("presetWork()"));
        uint256 callValue = 0.25 ether;
        uint256 valueLimit = 1 ether;

        bytes memory callData = abi.encodeWithSelector(EXECUTE_SELECTOR, target, callValue, abi.encodeWithSelector(innerSelector));

        bytes32 scopeLeaf = module.computeAAScopeLeaf(target, innerSelector, valueLimit, false);
        _setPolicy(owner, address(account), entityId, sessionSigner, scopeLeaf, 900);

        (, uint64 epoch, uint64 policyNonce) = registry.getPolicy(address(account), entityId, sessionSigner);

        AACallClaimV2[] memory callClaims = new AACallClaimV2[](1);
        callClaims[0] = _claim(target, innerSelector, valueLimit, false, scopeLeaf, new bytes32[](0));
        AAClaimsV2 memory aaClaims =
            AAClaimsV2({callClaims: callClaims, multiproof: new bytes32[](0), proofFlags: new bool[](0), leafOrderHash: bytes32(0)});

        SessionAuthV2 memory auth = SessionAuthV2({
            mode: 1,
            sessionKey: sessionSigner,
            epoch: epoch,
            policyNonce: policyNonce,
            created: uint48(block.timestamp - 1),
            expires: uint48(block.timestamp + 300),
            requestHash: userOpHash,
            claimsHash: module.computeAAClaimsHash(aaClaims),
            sessionSignature: "",
            claims: abi.encode(aaClaims)
        });
        auth.sessionSignature = _sign(sessionKey, _sessionDigest(auth, address(account), entityId));

        PackedUserOperation memory userOp = _buildUserOp(address(account), callData, abi.encode(auth));

        uint256 withoutPreset = module.validateUserOp(entityId, userOp, userOpHash);
        assertEq(withoutPreset, SIG_VALIDATION_FAILED);

        bytes4[] memory wrongSelectors = new bytes4[](1);
        wrongSelectors[0] = EXECUTE_BATCH_SELECTOR;
        _installPreset(address(account), entityId, wrongSelectors, false, 10, 1200);

        uint256 wrongPreset = module.validateUserOp(entityId, userOp, userOpHash);
        assertEq(wrongPreset, SIG_VALIDATION_FAILED);

        bytes4[] memory correctSelectors = new bytes4[](1);
        correctSelectors[0] = EXECUTE_SELECTOR;
        _installPreset(address(account), entityId, correctSelectors, false, 10, 1200);

        uint256 correctPreset = module.validateUserOp(entityId, userOp, userOpHash);
        assertNotEq(correctPreset, SIG_VALIDATION_FAILED);

        ERC8128AAValidationModule.UninstallPresetConfig memory uninstallConfig =
            ERC8128AAValidationModule.UninstallPresetConfig({account: address(account), entityId: entityId});
        vm.prank(address(account));
        module.onUninstall(abi.encode(uninstallConfig));

        uint256 afterUninstall = module.validateUserOp(entityId, userOp, userOpHash);
        assertEq(afterUninstall, SIG_VALIDATION_FAILED);
    }

    function _installPreset(
        address account,
        uint32 entityId,
        bytes4[] memory allowedSelectors,
        bool defaultAllowDelegateCall,
        uint32 minTtlSeconds,
        uint32 maxTtlSeconds
    ) internal {
        ERC8128AAValidationModule.InstallPresetConfig memory config = ERC8128AAValidationModule.InstallPresetConfig({
            account: account,
            entityId: entityId,
            allowedSelectors: allowedSelectors,
            defaultAllowDelegateCall: defaultAllowDelegateCall,
            minTtlSeconds: minTtlSeconds,
            maxTtlSeconds: maxTtlSeconds
        });

        vm.prank(account);
        module.onInstall(abi.encode(config));
    }

    function _setPolicy(
        address owner,
        address account,
        uint32 entityId,
        address sessionKey,
        bytes32 scopeRoot,
        uint32 maxTtlSeconds
    ) internal {
        vm.prank(owner);
        registry.setPolicy(account, entityId, sessionKey, 0, 0, maxTtlSeconds, scopeRoot, 0, 0, 0);
    }

    function _claim(
        address target,
        bytes4 selector,
        uint256 valueLimit,
        bool allowDelegateCall,
        bytes32 scopeLeaf,
        bytes32[] memory scopeProof
    ) internal pure returns (AACallClaimV2 memory) {
        return AACallClaimV2({
            target: target,
            selector: selector,
            valueLimit: valueLimit,
            allowDelegateCall: allowDelegateCall,
            scopeLeaf: scopeLeaf,
            scopeProof: scopeProof
        });
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

    function _buildUserOp(address sender, bytes memory callData, bytes memory signature)
        internal
        pure
        returns (PackedUserOperation memory userOp)
    {
        userOp.sender = sender;
        userOp.callData = callData;
        userOp.signature = signature;
    }

    function _parseValidationData(uint256 validationData)
        internal
        pure
        returns (address authorizer, uint48 validUntil, uint48 validAfter)
    {
        authorizer = address(uint160(validationData));
        validUntil = uint48(validationData >> 160);
        validAfter = uint48(validationData >> 208);
    }

    function _sign(uint256 privateKey, bytes32 digest) internal pure returns (bytes memory signature) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        signature = abi.encodePacked(r, s, v);
    }

    function _hashPair(bytes32 a, bytes32 b) internal pure returns (bytes32) {
        return a < b ? keccak256(abi.encodePacked(a, b)) : keccak256(abi.encodePacked(b, a));
    }
}
