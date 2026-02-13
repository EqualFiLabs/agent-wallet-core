// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";

import {IERC165} from "../../src/interfaces/IERC165.sol";
import {IERC6900Module} from "../../src/interfaces/IERC6900Module.sol";
import {IERC6900ValidationModule} from "../../src/interfaces/IERC6900ValidationModule.sol";
import {ERC8128PolicyRegistry} from "../../src/core/ERC8128PolicyRegistry.sol";
import {ERC8128GatewayValidationModuleV2} from "../../src/modules/validation/ERC8128GatewayValidationModuleV2.sol";
import {ERC8128AAValidationModuleV2} from "../../src/modules/validation/ERC8128AAValidationModuleV2.sol";
import {SessionAuthV2, GatewayClaimsV2, AAClaimsV2, AACallClaimV2} from "../../src/libraries/ERC8128Types.sol";
import {Mock6551Account} from "../mocks/OwnerValidationMocks.sol";

contract ERC8128V2UnitConformanceTest is Test {
    uint256 internal constant SECP256K1_N =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    uint256 internal constant OWNER_KEY = 0xA11CE;
    uint256 internal constant SESSION_KEY = 0xB0B;

    bytes4 internal constant ERC1271_MAGICVALUE = 0x1626ba7e;
    bytes4 internal constant ERC1271_INVALID = 0xffffffff;
    uint256 internal constant SIG_VALIDATION_FAILED = 1;

    bytes4 internal constant EXECUTE_SELECTOR = bytes4(keccak256("execute(address,uint256,bytes)"));

    bytes32 internal constant EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 internal constant DOMAIN_NAME_HASH = keccak256(bytes("AgentWalletERC8128"));
    bytes32 internal constant DOMAIN_VERSION_HASH = keccak256(bytes("2"));
    bytes32 internal constant SESSION_AUTHORIZATION_V2_TYPEHASH = keccak256(
        "SessionAuthorizationV2(uint8 mode,address account,uint32 entityId,address sessionKey,uint64 epoch,uint64 policyNonce,uint48 created,uint48 expires,bytes32 requestHash,bytes32 claimsHash)"
    );

    ERC8128PolicyRegistry internal registry;
    ERC8128GatewayValidationModuleV2 internal gatewayModule;
    ERC8128AAValidationModuleV2 internal aaModule;

    address internal owner;
    address internal sessionSigner;
    address internal aaTarget;
    Mock6551Account internal account;

    function setUp() public {
        registry = new ERC8128PolicyRegistry();
        gatewayModule = new ERC8128GatewayValidationModuleV2(address(registry));
        aaModule = new ERC8128AAValidationModuleV2(address(registry));

        owner = vm.addr(OWNER_KEY);
        sessionSigner = vm.addr(SESSION_KEY);
        aaTarget = makeAddr("aa-target");
        account = new Mock6551Account(owner);
    }

    function test_InterfaceConformance_BothModules() public view {
        assertEq(gatewayModule.moduleId(), "agent.wallet.erc8128-gateway-validation.2.0.0");
        assertEq(aaModule.moduleId(), "agent.wallet.erc8128-aa-validation.2.0.0");

        assertTrue(gatewayModule.supportsInterface(type(IERC165).interfaceId));
        assertTrue(gatewayModule.supportsInterface(type(IERC6900Module).interfaceId));
        assertTrue(gatewayModule.supportsInterface(type(IERC6900ValidationModule).interfaceId));

        assertTrue(aaModule.supportsInterface(type(IERC165).interfaceId));
        assertTrue(aaModule.supportsInterface(type(IERC6900Module).interfaceId));
        assertTrue(aaModule.supportsInterface(type(IERC6900ValidationModule).interfaceId));
    }

    function test_OnInstallOnUninstall_CallableOnBothModules() public {
        gatewayModule.onInstall(bytes(""));
        gatewayModule.onUninstall(bytes(""));

        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = EXECUTE_SELECTOR;

        ERC8128AAValidationModuleV2.InstallPresetConfig memory installConfig = ERC8128AAValidationModuleV2.InstallPresetConfig({
            account: address(account),
            entityId: 7,
            allowedSelectors: selectors,
            defaultAllowDelegateCall: false,
            minTtlSeconds: 10,
            maxTtlSeconds: 1000
        });

        vm.prank(address(account));
        aaModule.onInstall(abi.encode(installConfig));

        (bytes4[] memory installedSelectors, bool defaultAllowDelegateCall, uint32 minTtl, uint32 maxTtl, bool initialized) =
            aaModule.getInstallPreset(address(account), 7);
        assertTrue(initialized);
        assertEq(installedSelectors.length, 1);
        assertEq(installedSelectors[0], EXECUTE_SELECTOR);
        assertFalse(defaultAllowDelegateCall);
        assertEq(minTtl, 10);
        assertEq(maxTtl, 1000);

        ERC8128AAValidationModuleV2.UninstallPresetConfig memory uninstallConfig =
            ERC8128AAValidationModuleV2.UninstallPresetConfig({account: address(account), entityId: 7});

        vm.prank(address(account));
        aaModule.onUninstall(abi.encode(uninstallConfig));

        (bytes4[] memory removedSelectors,,, , bool removedInitialized) = aaModule.getInstallPreset(address(account), 7);
        assertFalse(removedInitialized);
        assertEq(removedSelectors.length, 0);
    }

    function test_UnsupportedValidationStubs() public {
        PackedUserOperation memory op;
        assertEq(gatewayModule.validateUserOp(0, op, bytes32(0)), SIG_VALIDATION_FAILED);
        assertEq(aaModule.validateSignature(address(0), 0, address(0), bytes32(0), bytes("")), ERC1271_INVALID);

        vm.expectRevert(ERC8128GatewayValidationModuleV2.RuntimeValidationNotSupported.selector);
        gatewayModule.validateRuntime(address(0), 0, address(0), 0, bytes(""), bytes(""));

        vm.expectRevert(ERC8128AAValidationModuleV2.RuntimeValidationNotSupported.selector);
        aaModule.validateRuntime(address(0), 0, address(0), 0, bytes(""), bytes(""));
    }

    function test_RegistryEdge_ZeroAddressSessionKeyRejected() public {
        vm.expectRevert(abi.encodeWithSelector(ERC8128PolicyRegistry.InvalidSessionKey.selector, address(0)));
        vm.prank(owner);
        registry.setPolicy(address(account), 1, address(0), 0, 0, 100, bytes32(uint256(1)), 0, 0, 0);

        vm.expectRevert(abi.encodeWithSelector(ERC8128PolicyRegistry.InvalidSessionKey.selector, address(0)));
        vm.prank(owner);
        registry.revokeSessionKey(address(account), 1, address(0));

        vm.expectRevert(abi.encodeWithSelector(ERC8128PolicyRegistry.InvalidSessionKey.selector, address(0)));
        vm.prank(owner);
        registry.rotateScopeRoot(address(account), 1, address(0), bytes32(uint256(2)));
    }

    function test_RegistryEdge_RotateScopeRootOnInactivePolicyReverts() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                ERC8128PolicyRegistry.PolicyNotActive.selector, address(account), uint32(3), sessionSigner
            )
        );
        vm.prank(owner);
        registry.rotateScopeRoot(address(account), 3, sessionSigner, bytes32(uint256(123)));
    }

    function test_ValidationEdge_CreatedGteExpiresRejected() public {
        uint32 entityId = 9;
        bytes32 requestHash = keccak256("request-created-gte-expires");

        GatewayClaimsV2 memory claims = _gatewayClaims(requestHash);
        _setPolicy(entityId, claims.scopeLeaf, 0, 0, 1000);

        (, uint64 epoch, uint64 policyNonce) = registry.getPolicy(address(account), entityId, sessionSigner);

        SessionAuthV2 memory auth = _buildGatewayAuth(
            uint8(0),
            entityId,
            epoch,
            policyNonce,
            requestHash,
            claims,
            uint48(500),
            uint48(500),
            address(gatewayModule)
        );

        bytes4 result = gatewayModule.validateSignature(address(account), entityId, address(0), requestHash, abi.encode(auth));
        assertEq(result, ERC1271_INVALID);
    }

    function test_ValidationEdge_ValidUntilZeroUnboundedUpperWindow() public {
        uint32 entityId = 10;
        bytes32 requestHash = keccak256("request-unbounded-window");

        GatewayClaimsV2 memory claims = _gatewayClaims(requestHash);
        _setPolicy(entityId, claims.scopeLeaf, 0, 0, 1000);

        vm.warp(5_000_000);

        (, uint64 epoch, uint64 policyNonce) = registry.getPolicy(address(account), entityId, sessionSigner);

        SessionAuthV2 memory auth = _buildGatewayAuth(
            uint8(0),
            entityId,
            epoch,
            policyNonce,
            requestHash,
            claims,
            uint48(block.timestamp - 1),
            uint48(block.timestamp + 300),
            address(gatewayModule)
        );

        bytes4 result = gatewayModule.validateSignature(address(account), entityId, address(0), requestHash, abi.encode(auth));
        assertEq(result, ERC1271_MAGICVALUE);
    }

    function test_RegistryEvents_AllMutationEventsEmitted() public {
        uint32 entityId = 11;
        bytes32 rootOne = bytes32(uint256(0x111));
        bytes32 rootTwo = bytes32(uint256(0x222));

        vm.expectEmit(true, true, true, true);
        emit ERC8128PolicyRegistry.PolicySetV2(address(account), entityId, sessionSigner, 1, 0, 0, 600, rootOne, 1, 2, 3);
        vm.prank(owner);
        registry.setPolicy(address(account), entityId, sessionSigner, 0, 0, 600, rootOne, 1, 2, 3);

        vm.expectEmit(true, true, true, true);
        emit ERC8128PolicyRegistry.PolicyRevokedV2(address(account), entityId, sessionSigner, 2);
        vm.prank(owner);
        registry.revokeSessionKey(address(account), entityId, sessionSigner);

        vm.expectEmit(true, true, false, true);
        emit ERC8128PolicyRegistry.EpochRevokedV2(address(account), entityId, 1);
        vm.prank(owner);
        registry.revokeAllSessionKeys(address(account), entityId);

        vm.prank(owner);
        registry.setPolicy(address(account), entityId, sessionSigner, 0, 0, 600, rootOne, 0, 0, 0);

        vm.expectEmit(true, true, true, true);
        emit ERC8128PolicyRegistry.ScopeRootRotatedV2(address(account), entityId, sessionSigner, 1, rootTwo);
        vm.prank(owner);
        registry.rotateScopeRoot(address(account), entityId, sessionSigner, rootTwo);

        vm.expectEmit(true, true, true, true);
        emit ERC8128PolicyRegistry.GuardianPauseSetV2(address(account), entityId, sessionSigner, true);
        vm.prank(owner);
        registry.pausePolicy(address(account), entityId, sessionSigner);

        vm.expectEmit(true, true, true, true);
        emit ERC8128PolicyRegistry.GuardianPauseSetV2(address(account), entityId, address(0), true);
        vm.prank(owner);
        registry.pauseEntity(address(account), entityId);

        vm.expectEmit(true, true, true, true);
        emit ERC8128PolicyRegistry.GuardianPauseSetV2(address(account), 0, address(0), true);
        vm.prank(owner);
        registry.pauseAccount(address(account));
    }

    function test_ModeMismatch_GatewayRejectsMode1AndAARejectsMode0() public {
        uint32 entityId = 12;

        bytes32 requestHash = keccak256("request-mode-mismatch");
        bytes32 userOpHash = keccak256("userop-mode-mismatch");

        GatewayClaimsV2 memory gatewayClaims = _gatewayClaims(requestHash);
        _setPolicy(entityId, _hashPair(gatewayClaims.scopeLeaf, _aaLeaf()), 0, 0, 1000);

        _installAaPreset(entityId);

        (, uint64 epoch, uint64 policyNonce) = registry.getPolicy(address(account), entityId, sessionSigner);

        SessionAuthV2 memory gatewayWrongMode = _buildGatewayAuth(
            uint8(1),
            entityId,
            epoch,
            policyNonce,
            requestHash,
            gatewayClaims,
            uint48(block.timestamp - 1),
            uint48(block.timestamp + 300),
            address(gatewayModule)
        );

        bytes4 gatewayResult =
            gatewayModule.validateSignature(address(account), entityId, address(0), requestHash, abi.encode(gatewayWrongMode));
        assertEq(gatewayResult, ERC1271_INVALID);

        AAClaimsV2 memory aaClaims = _aaClaims();
        SessionAuthV2 memory aaWrongMode = _buildAAAuth(
            uint8(0),
            entityId,
            epoch,
            policyNonce,
            userOpHash,
            aaClaims,
            uint48(block.timestamp - 1),
            uint48(block.timestamp + 300),
            address(aaModule)
        );

        PackedUserOperation memory userOp = _buildUserOp(address(account), _aaCallData(), abi.encode(aaWrongMode));
        assertEq(aaModule.validateUserOp(entityId, userOp, userOpHash), SIG_VALIDATION_FAILED);
    }

    function _setPolicy(uint32 entityId, bytes32 scopeRoot, uint48 validAfter, uint48 validUntil, uint32 maxTtlSeconds)
        internal
    {
        vm.prank(owner);
        registry.setPolicy(
            address(account), entityId, sessionSigner, validAfter, validUntil, maxTtlSeconds, scopeRoot, 0, 0, 0
        );
    }

    function _installAaPreset(uint32 entityId) internal {
        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = EXECUTE_SELECTOR;

        ERC8128AAValidationModuleV2.InstallPresetConfig memory installConfig = ERC8128AAValidationModuleV2.InstallPresetConfig({
            account: address(account),
            entityId: entityId,
            allowedSelectors: selectors,
            defaultAllowDelegateCall: false,
            minTtlSeconds: 10,
            maxTtlSeconds: 1200
        });

        vm.prank(address(account));
        aaModule.onInstall(abi.encode(installConfig));
    }

    function _gatewayClaims(bytes32 requestHash) internal pure returns (GatewayClaimsV2 memory claims) {
        claims.methodBit = 1;
        claims.authorityHash = keccak256("api.example.com");
        claims.pathPrefixHash = keccak256("/v1");
        claims.isReadOnly = true;
        claims.allowReplayable = true;
        claims.allowClassBound = true;
        claims.maxBodyBytes = 4096;
        claims.isReplayable = false;
        claims.isClassBound = false;
        claims.nonceHash = keccak256(abi.encodePacked("nonce", requestHash));
        claims.scopeLeaf = keccak256(
            abi.encode(
                "AW_ERC8128_SCOPE_LEAF_V2",
                claims.methodBit,
                claims.authorityHash,
                claims.pathPrefixHash,
                claims.isReadOnly,
                claims.allowReplayable,
                claims.allowClassBound,
                claims.maxBodyBytes
            )
        );
        claims.scopeProof = new bytes32[](0);
    }

    function _aaLeaf() internal view returns (bytes32) {
        return aaModule.computeAAScopeLeaf(aaTarget, bytes4(keccak256("runWork()")), 1 ether, false);
    }

    function _aaClaims() internal view returns (AAClaimsV2 memory claims) {
        AACallClaimV2[] memory callClaims = new AACallClaimV2[](1);
        callClaims[0] = AACallClaimV2({
            target: aaTarget,
            selector: bytes4(keccak256("runWork()")),
            valueLimit: 1 ether,
            allowDelegateCall: false,
            scopeLeaf: _aaLeaf(),
            scopeProof: new bytes32[](0)
        });

        claims = AAClaimsV2({
            callClaims: callClaims,
            multiproof: new bytes32[](0),
            proofFlags: new bool[](0),
            leafOrderHash: bytes32(0)
        });
    }

    function _aaCallData() internal view returns (bytes memory) {
        return abi.encodeWithSelector(
            EXECUTE_SELECTOR, aaTarget, 0.1 ether, abi.encodeWithSelector(bytes4(keccak256("runWork()")))
        );
    }

    function _buildGatewayAuth(
        uint8 mode,
        uint32 entityId,
        uint64 epoch,
        uint64 policyNonce,
        bytes32 requestHash,
        GatewayClaimsV2 memory claims,
        uint48 created,
        uint48 expires,
        address moduleAddress
    ) internal view returns (SessionAuthV2 memory auth) {
        auth = SessionAuthV2({
            mode: mode,
            sessionKey: sessionSigner,
            epoch: epoch,
            policyNonce: policyNonce,
            created: created,
            expires: expires,
            requestHash: requestHash,
            claimsHash: keccak256(abi.encode(claims)),
            sessionSignature: "",
            claims: abi.encode(claims)
        });
        auth.sessionSignature = _sign(SESSION_KEY, _sessionDigest(moduleAddress, address(account), entityId, auth));
    }

    function _buildAAAuth(
        uint8 mode,
        uint32 entityId,
        uint64 epoch,
        uint64 policyNonce,
        bytes32 userOpHash,
        AAClaimsV2 memory claims,
        uint48 created,
        uint48 expires,
        address moduleAddress
    ) internal view returns (SessionAuthV2 memory auth) {
        auth = SessionAuthV2({
            mode: mode,
            sessionKey: sessionSigner,
            epoch: epoch,
            policyNonce: policyNonce,
            created: created,
            expires: expires,
            requestHash: userOpHash,
            claimsHash: keccak256(abi.encode(claims)),
            sessionSignature: "",
            claims: abi.encode(claims)
        });
        auth.sessionSignature = _sign(SESSION_KEY, _sessionDigest(moduleAddress, address(account), entityId, auth));
    }

    function _sessionDigest(address moduleAddress, address accountAddr, uint32 entityId, SessionAuthV2 memory auth)
        internal
        view
        returns (bytes32)
    {
        bytes32 domainSeparator =
            keccak256(abi.encode(EIP712_DOMAIN_TYPEHASH, DOMAIN_NAME_HASH, DOMAIN_VERSION_HASH, block.chainid, moduleAddress));

        bytes32 structHash = keccak256(
            abi.encode(
                SESSION_AUTHORIZATION_V2_TYPEHASH,
                auth.mode,
                accountAddr,
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

    function _hashPair(bytes32 a, bytes32 b) internal pure returns (bytes32) {
        return a < b ? keccak256(abi.encodePacked(a, b)) : keccak256(abi.encodePacked(b, a));
    }

    function _sign(uint256 key, bytes32 digest) internal pure returns (bytes memory signature) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest);
        signature = abi.encodePacked(r, s, v);
    }
}
