// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";

import {ERC8128PolicyRegistry} from "../../src/core/ERC8128PolicyRegistry.sol";
import {ERC8128GatewayValidationModuleV2} from "../../src/modules/validation/ERC8128GatewayValidationModuleV2.sol";
import {ERC8128AAValidationModuleV2} from "../../src/modules/validation/ERC8128AAValidationModuleV2.sol";
import {SessionAuthV2, GatewayClaimsV2, AAClaimsV2, AACallClaimV2} from "../../src/libraries/ERC8128Types.sol";
import {Call} from "../../src/libraries/ModuleTypes.sol";
import {Mock6551Account} from "../mocks/OwnerValidationMocks.sol";

contract ERC8128V2CrossCuttingTest is Test {
    uint256 internal constant SECP256K1_N =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

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

    function setUp() public {
        registry = new ERC8128PolicyRegistry();
        gatewayModule = new ERC8128GatewayValidationModuleV2(address(registry));
        aaModule = new ERC8128AAValidationModuleV2(address(registry));
    }

    // **Feature: erc8128-v2-unified-policy, Property 4: Session key revocation invalidates both modules**
    function testFuzz_Property4_SessionKeyRevocationInvalidatesBothModules(
        uint256 ownerKeySeed,
        uint256 sessionKeySeed,
        uint32 entityId,
        bytes32 requestHash,
        bytes32 userOpHash
    ) public {
        (Mock6551Account account, address owner, address sessionSigner) = _setupAccount(ownerKeySeed, sessionKeySeed);

        (GatewayClaimsV2 memory gatewayClaims, AAClaimsV2 memory aaClaims, bytes memory aaCallData) =
            _setupPolicyAndClaims(owner, address(account), entityId, sessionSigner, requestHash, true);

        (, uint64 epoch, uint64 policyNonce) = registry.getPolicy(address(account), entityId, sessionSigner);

        SessionAuthV2 memory gatewayAuth = _buildGatewayAuth(
            sessionKeySeed,
            address(account),
            entityId,
            sessionSigner,
            epoch,
            policyNonce,
            requestHash,
            gatewayClaims,
            uint48(block.timestamp - 1),
            uint48(block.timestamp + 300),
            address(gatewayModule)
        );

        SessionAuthV2 memory aaAuth = _buildAAAuth(
            sessionKeySeed,
            address(account),
            entityId,
            sessionSigner,
            epoch,
            policyNonce,
            userOpHash,
            aaClaims,
            uint48(block.timestamp - 1),
            uint48(block.timestamp + 300),
            address(aaModule)
        );

        PackedUserOperation memory userOp = _buildUserOp(address(account), aaCallData, abi.encode(aaAuth));

        assertEq(
            gatewayModule.validateSignature(address(account), entityId, address(0), requestHash, abi.encode(gatewayAuth)),
            ERC1271_MAGICVALUE
        );
        assertNotEq(aaModule.validateUserOp(entityId, userOp, userOpHash), SIG_VALIDATION_FAILED);

        vm.prank(owner);
        registry.revokeSessionKey(address(account), entityId, sessionSigner);

        assertEq(
            gatewayModule.validateSignature(address(account), entityId, address(0), requestHash, abi.encode(gatewayAuth)),
            ERC1271_INVALID
        );
        assertEq(aaModule.validateUserOp(entityId, userOp, userOpHash), SIG_VALIDATION_FAILED);
    }

    // **Feature: erc8128-v2-unified-policy, Property 5: Epoch revocation invalidates all session keys**
    function testFuzz_Property5_EpochRevocationInvalidatesAllSessionKeys(
        uint256 ownerKeySeed,
        uint256 sessionKeyASeed,
        uint256 sessionKeyBSeed,
        uint32 entityId,
        bytes32 requestHash,
        bytes32 userOpHash
    ) public {
        uint256 ownerKey = bound(ownerKeySeed, 1, SECP256K1_N - 1);
        uint256 sessionKeyA = bound(sessionKeyASeed, 1, SECP256K1_N - 1);
        uint256 sessionKeyB = bound(sessionKeyBSeed, 1, SECP256K1_N - 1);
        vm.assume(ownerKey != sessionKeyA && ownerKey != sessionKeyB && sessionKeyA != sessionKeyB);

        address owner = vm.addr(ownerKey);
        address signerA = vm.addr(sessionKeyA);
        address signerB = vm.addr(sessionKeyB);
        Mock6551Account account = new Mock6551Account(owner);

        (GatewayClaimsV2 memory gatewayClaimsA, AAClaimsV2 memory aaClaimsA, bytes memory aaCallDataA) =
            _setupPolicyAndClaims(owner, address(account), entityId, signerA, requestHash, true);

        (GatewayClaimsV2 memory gatewayClaimsB, AAClaimsV2 memory aaClaimsB, bytes memory aaCallDataB) =
            _setupPolicyAndClaims(owner, address(account), entityId, signerB, requestHash, true);

        (, uint64 epochA, uint64 nonceA) = registry.getPolicy(address(account), entityId, signerA);
        (, uint64 epochB, uint64 nonceB) = registry.getPolicy(address(account), entityId, signerB);

        SessionAuthV2 memory gatewayAuthA = _buildGatewayAuth(
            sessionKeyA,
            address(account),
            entityId,
            signerA,
            epochA,
            nonceA,
            requestHash,
            gatewayClaimsA,
            uint48(block.timestamp - 1),
            uint48(block.timestamp + 300),
            address(gatewayModule)
        );
        SessionAuthV2 memory gatewayAuthB = _buildGatewayAuth(
            sessionKeyB,
            address(account),
            entityId,
            signerB,
            epochB,
            nonceB,
            requestHash,
            gatewayClaimsB,
            uint48(block.timestamp - 1),
            uint48(block.timestamp + 300),
            address(gatewayModule)
        );

        SessionAuthV2 memory aaAuthA = _buildAAAuth(
            sessionKeyA,
            address(account),
            entityId,
            signerA,
            epochA,
            nonceA,
            userOpHash,
            aaClaimsA,
            uint48(block.timestamp - 1),
            uint48(block.timestamp + 300),
            address(aaModule)
        );
        SessionAuthV2 memory aaAuthB = _buildAAAuth(
            sessionKeyB,
            address(account),
            entityId,
            signerB,
            epochB,
            nonceB,
            userOpHash,
            aaClaimsB,
            uint48(block.timestamp - 1),
            uint48(block.timestamp + 300),
            address(aaModule)
        );

        PackedUserOperation memory userOpA = _buildUserOp(address(account), aaCallDataA, abi.encode(aaAuthA));
        PackedUserOperation memory userOpB = _buildUserOp(address(account), aaCallDataB, abi.encode(aaAuthB));

        assertEq(
            gatewayModule.validateSignature(address(account), entityId, address(0), requestHash, abi.encode(gatewayAuthA)),
            ERC1271_MAGICVALUE
        );
        assertEq(
            gatewayModule.validateSignature(address(account), entityId, address(0), requestHash, abi.encode(gatewayAuthB)),
            ERC1271_MAGICVALUE
        );
        assertNotEq(aaModule.validateUserOp(entityId, userOpA, userOpHash), SIG_VALIDATION_FAILED);
        assertNotEq(aaModule.validateUserOp(entityId, userOpB, userOpHash), SIG_VALIDATION_FAILED);

        vm.prank(owner);
        registry.revokeAllSessionKeys(address(account), entityId);

        assertEq(
            gatewayModule.validateSignature(address(account), entityId, address(0), requestHash, abi.encode(gatewayAuthA)),
            ERC1271_INVALID
        );
        assertEq(
            gatewayModule.validateSignature(address(account), entityId, address(0), requestHash, abi.encode(gatewayAuthB)),
            ERC1271_INVALID
        );
        assertEq(aaModule.validateUserOp(entityId, userOpA, userOpHash), SIG_VALIDATION_FAILED);
        assertEq(aaModule.validateUserOp(entityId, userOpB, userOpHash), SIG_VALIDATION_FAILED);
    }

    // **Feature: erc8128-v2-unified-policy, Property 6: Scope root rotation updates active policy**
    function testFuzz_Property6_ScopeRootRotationUpdatesActivePolicy(
        uint256 ownerKeySeed,
        uint256 sessionKeySeed,
        uint32 entityId,
        bytes32 requestHash,
        bytes32 userOpHash
    ) public {
        (Mock6551Account account, address owner, address sessionSigner) = _setupAccount(ownerKeySeed, sessionKeySeed);

        (GatewayClaimsV2 memory oldGatewayClaims, AAClaimsV2 memory oldAAClaims, bytes memory oldCallData) =
            _setupPolicyAndClaims(owner, address(account), entityId, sessionSigner, requestHash, true);

        (, uint64 epoch, uint64 policyNonce) = registry.getPolicy(address(account), entityId, sessionSigner);

        SessionAuthV2 memory oldGatewayAuth = _buildGatewayAuth(
            sessionKeySeed,
            address(account),
            entityId,
            sessionSigner,
            epoch,
            policyNonce,
            requestHash,
            oldGatewayClaims,
            uint48(block.timestamp - 1),
            uint48(block.timestamp + 300),
            address(gatewayModule)
        );

        SessionAuthV2 memory oldAAAuth = _buildAAAuth(
            sessionKeySeed,
            address(account),
            entityId,
            sessionSigner,
            epoch,
            policyNonce,
            userOpHash,
            oldAAClaims,
            uint48(block.timestamp - 1),
            uint48(block.timestamp + 300),
            address(aaModule)
        );

        PackedUserOperation memory oldUserOp = _buildUserOp(address(account), oldCallData, abi.encode(oldAAAuth));

        assertEq(
            gatewayModule.validateSignature(address(account), entityId, address(0), requestHash, abi.encode(oldGatewayAuth)),
            ERC1271_MAGICVALUE
        );
        assertNotEq(aaModule.validateUserOp(entityId, oldUserOp, userOpHash), SIG_VALIDATION_FAILED);

        bytes32 newGatewayLeaf = _computeGatewayLeaf(keccak256("authority:new"), keccak256("/v2"), true, true, true, 8192);
        bytes4 newSelector = bytes4(keccak256("runV2()"));
        bytes32 newAALeaf = _computeAALeaf(makeAddr("aa-v2-target"), newSelector, 2 ether, false);
        bytes32 newRoot = _hashPair(newGatewayLeaf, newAALeaf);

        vm.prank(owner);
        registry.rotateScopeRoot(address(account), entityId, sessionSigner, newRoot);

        assertEq(
            gatewayModule.validateSignature(address(account), entityId, address(0), requestHash, abi.encode(oldGatewayAuth)),
            ERC1271_INVALID
        );
        assertEq(aaModule.validateUserOp(entityId, oldUserOp, userOpHash), SIG_VALIDATION_FAILED);

        bytes32[] memory newGatewayProof = new bytes32[](1);
        newGatewayProof[0] = newAALeaf;
        GatewayClaimsV2 memory newGatewayClaims = _buildGatewayClaims(
            requestHash,
            1,
            keccak256("authority:new"),
            keccak256("/v2"),
            true,
            true,
            true,
            8192,
            false,
            false,
            newGatewayLeaf,
            newGatewayProof
        );

        bytes32[] memory newAAProof = new bytes32[](1);
        newAAProof[0] = newGatewayLeaf;
        AACallClaimV2[] memory newCallClaims = new AACallClaimV2[](1);
        address newTarget = makeAddr("aa-v2-target");
        newCallClaims[0] = AACallClaimV2({
            target: newTarget,
            selector: newSelector,
            valueLimit: 2 ether,
            allowDelegateCall: false,
            scopeLeaf: newAALeaf,
            scopeProof: newAAProof
        });
        AAClaimsV2 memory newAAClaims = AAClaimsV2({
            callClaims: newCallClaims,
            multiproof: new bytes32[](0),
            proofFlags: new bool[](0),
            leafOrderHash: bytes32(0)
        });

        bytes memory newCallData =
            abi.encodeWithSelector(EXECUTE_SELECTOR, newTarget, 0.5 ether, abi.encodeWithSelector(newSelector));

        SessionAuthV2 memory newGatewayAuth = _buildGatewayAuth(
            sessionKeySeed,
            address(account),
            entityId,
            sessionSigner,
            epoch,
            policyNonce,
            requestHash,
            newGatewayClaims,
            uint48(block.timestamp - 1),
            uint48(block.timestamp + 300),
            address(gatewayModule)
        );

        SessionAuthV2 memory newAAAuth = _buildAAAuth(
            sessionKeySeed,
            address(account),
            entityId,
            sessionSigner,
            epoch,
            policyNonce,
            userOpHash,
            newAAClaims,
            uint48(block.timestamp - 1),
            uint48(block.timestamp + 300),
            address(aaModule)
        );

        PackedUserOperation memory newUserOp = _buildUserOp(address(account), newCallData, abi.encode(newAAAuth));

        assertEq(
            gatewayModule.validateSignature(address(account), entityId, address(0), requestHash, abi.encode(newGatewayAuth)),
            ERC1271_MAGICVALUE
        );
        assertNotEq(aaModule.validateUserOp(entityId, newUserOp, userOpHash), SIG_VALIDATION_FAILED);
    }

    // **Feature: erc8128-v2-unified-policy, Property 18: Cross-module and cross-mode replay prevention**
    function testFuzz_Property18_CrossModuleAndCrossModeReplayPrevention(
        uint256 ownerKeySeed,
        uint256 sessionKeySeed,
        uint32 entityId,
        bytes32 requestHash,
        bytes32 userOpHash
    ) public {
        (Mock6551Account account, address owner, address sessionSigner) = _setupAccount(ownerKeySeed, sessionKeySeed);

        (GatewayClaimsV2 memory gatewayClaims, AAClaimsV2 memory aaClaims, bytes memory aaCallData) =
            _setupPolicyAndClaims(owner, address(account), entityId, sessionSigner, requestHash, true);

        (, uint64 epoch, uint64 policyNonce) = registry.getPolicy(address(account), entityId, sessionSigner);

        SessionAuthV2 memory validGatewayAuth = _buildGatewayAuth(
            sessionKeySeed,
            address(account),
            entityId,
            sessionSigner,
            epoch,
            policyNonce,
            requestHash,
            gatewayClaims,
            uint48(block.timestamp - 1),
            uint48(block.timestamp + 300),
            address(gatewayModule)
        );

        SessionAuthV2 memory validAAAuth = _buildAAAuth(
            sessionKeySeed,
            address(account),
            entityId,
            sessionSigner,
            epoch,
            policyNonce,
            userOpHash,
            aaClaims,
            uint48(block.timestamp - 1),
            uint48(block.timestamp + 300),
            address(aaModule)
        );

        PackedUserOperation memory userOp = _buildUserOp(address(account), aaCallData, abi.encode(validAAAuth));

        assertEq(
            gatewayModule.validateSignature(address(account), entityId, address(0), requestHash, abi.encode(validGatewayAuth)),
            ERC1271_MAGICVALUE
        );
        assertNotEq(aaModule.validateUserOp(entityId, userOp, userOpHash), SIG_VALIDATION_FAILED);

        // Cross-mode replay: gateway envelope presented to AA module.
        PackedUserOperation memory wrongModeOp = _buildUserOp(address(account), aaCallData, abi.encode(validGatewayAuth));
        assertEq(aaModule.validateUserOp(entityId, wrongModeOp, userOpHash), SIG_VALIDATION_FAILED);

        // Cross-module replay: AA envelope signed with gateway verifyingContract.
        SessionAuthV2 memory wrongDomainAAAuth = validAAAuth;
        wrongDomainAAAuth.sessionSignature = _sign(sessionKeySeed, _sessionDigest(address(gatewayModule), address(account), entityId, wrongDomainAAAuth));
        PackedUserOperation memory wrongDomainOp = _buildUserOp(address(account), aaCallData, abi.encode(wrongDomainAAAuth));
        assertEq(aaModule.validateUserOp(entityId, wrongDomainOp, userOpHash), SIG_VALIDATION_FAILED);

        // Cross-module replay in opposite direction: gateway envelope signed for AA module.
        SessionAuthV2 memory wrongDomainGatewayAuth = validGatewayAuth;
        wrongDomainGatewayAuth.sessionSignature = _sign(
            sessionKeySeed, _sessionDigest(address(aaModule), address(account), entityId, wrongDomainGatewayAuth)
        );
        assertEq(
            gatewayModule.validateSignature(
                address(account), entityId, address(0), requestHash, abi.encode(wrongDomainGatewayAuth)
            ),
            ERC1271_INVALID
        );
    }

    // **Feature: erc8128-v2-unified-policy, Property 20: Claims hash binding**
    function testFuzz_Property20_ClaimsHashBinding(
        uint256 ownerKeySeed,
        uint256 sessionKeySeed,
        uint32 entityId,
        bytes32 requestHash,
        bytes32 userOpHash
    ) public {
        (Mock6551Account account, address owner, address sessionSigner) = _setupAccount(ownerKeySeed, sessionKeySeed);

        (GatewayClaimsV2 memory gatewayClaims, AAClaimsV2 memory aaClaims, bytes memory aaCallData) =
            _setupPolicyAndClaims(owner, address(account), entityId, sessionSigner, requestHash, true);

        (, uint64 epoch, uint64 policyNonce) = registry.getPolicy(address(account), entityId, sessionSigner);

        SessionAuthV2 memory gatewayAuth = _buildGatewayAuth(
            sessionKeySeed,
            address(account),
            entityId,
            sessionSigner,
            epoch,
            policyNonce,
            requestHash,
            gatewayClaims,
            uint48(block.timestamp - 1),
            uint48(block.timestamp + 300),
            address(gatewayModule)
        );

        SessionAuthV2 memory aaAuth = _buildAAAuth(
            sessionKeySeed,
            address(account),
            entityId,
            sessionSigner,
            epoch,
            policyNonce,
            userOpHash,
            aaClaims,
            uint48(block.timestamp - 1),
            uint48(block.timestamp + 300),
            address(aaModule)
        );

        PackedUserOperation memory userOp = _buildUserOp(address(account), aaCallData, abi.encode(aaAuth));

        assertEq(
            gatewayModule.validateSignature(address(account), entityId, address(0), requestHash, abi.encode(gatewayAuth)),
            ERC1271_MAGICVALUE
        );
        assertNotEq(aaModule.validateUserOp(entityId, userOp, userOpHash), SIG_VALIDATION_FAILED);

        GatewayClaimsV2 memory tamperedGatewayClaims = gatewayClaims;
        tamperedGatewayClaims.maxBodyBytes = gatewayClaims.maxBodyBytes + 1;
        SessionAuthV2 memory tamperedGatewayAuth = gatewayAuth;
        tamperedGatewayAuth.claims = abi.encode(tamperedGatewayClaims);

        assertEq(
            gatewayModule.validateSignature(
                address(account), entityId, address(0), requestHash, abi.encode(tamperedGatewayAuth)
            ),
            ERC1271_INVALID
        );

        AAClaimsV2 memory tamperedAAClaims = aaClaims;
        tamperedAAClaims.callClaims[0].valueLimit = aaClaims.callClaims[0].valueLimit + 1;
        SessionAuthV2 memory tamperedAAAuth = aaAuth;
        tamperedAAAuth.claims = abi.encode(tamperedAAClaims);

        PackedUserOperation memory tamperedUserOp = _buildUserOp(address(account), aaCallData, abi.encode(tamperedAAAuth));
        assertEq(aaModule.validateUserOp(entityId, tamperedUserOp, userOpHash), SIG_VALIDATION_FAILED);
    }

    // **Feature: erc8128-v2-unified-policy, Property 21: Request hash binding**
    function testFuzz_Property21_RequestHashBinding(
        uint256 ownerKeySeed,
        uint256 sessionKeySeed,
        uint32 entityId,
        bytes32 requestHash,
        bytes32 userOpHash
    ) public {
        (Mock6551Account account, address owner, address sessionSigner) = _setupAccount(ownerKeySeed, sessionKeySeed);

        (GatewayClaimsV2 memory gatewayClaims, AAClaimsV2 memory aaClaims, bytes memory aaCallData) =
            _setupPolicyAndClaims(owner, address(account), entityId, sessionSigner, requestHash, true);

        (, uint64 epoch, uint64 policyNonce) = registry.getPolicy(address(account), entityId, sessionSigner);

        SessionAuthV2 memory gatewayAuth = _buildGatewayAuth(
            sessionKeySeed,
            address(account),
            entityId,
            sessionSigner,
            epoch,
            policyNonce,
            requestHash,
            gatewayClaims,
            uint48(block.timestamp - 1),
            uint48(block.timestamp + 300),
            address(gatewayModule)
        );

        SessionAuthV2 memory aaAuth = _buildAAAuth(
            sessionKeySeed,
            address(account),
            entityId,
            sessionSigner,
            epoch,
            policyNonce,
            userOpHash,
            aaClaims,
            uint48(block.timestamp - 1),
            uint48(block.timestamp + 300),
            address(aaModule)
        );

        PackedUserOperation memory userOp = _buildUserOp(address(account), aaCallData, abi.encode(aaAuth));

        assertEq(
            gatewayModule.validateSignature(address(account), entityId, address(0), requestHash, abi.encode(gatewayAuth)),
            ERC1271_MAGICVALUE
        );
        assertNotEq(aaModule.validateUserOp(entityId, userOp, userOpHash), SIG_VALIDATION_FAILED);

        bytes32 wrongRequestHash = bytes32(uint256(requestHash) + 1);
        bytes32 wrongUserOpHash = bytes32(uint256(userOpHash) + 1);

        assertEq(
            gatewayModule.validateSignature(address(account), entityId, address(0), wrongRequestHash, abi.encode(gatewayAuth)),
            ERC1271_INVALID
        );
        assertEq(aaModule.validateUserOp(entityId, userOp, wrongUserOpHash), SIG_VALIDATION_FAILED);
    }

    function _setupAccount(uint256 ownerKeySeed, uint256 sessionKeySeed)
        internal
        returns (Mock6551Account account, address owner, address sessionSigner)
    {
        uint256 ownerKey = bound(ownerKeySeed, 1, SECP256K1_N - 1);
        uint256 sessionKey = bound(sessionKeySeed, 1, SECP256K1_N - 1);
        vm.assume(ownerKey != sessionKey);

        owner = vm.addr(ownerKey);
        sessionSigner = vm.addr(sessionKey);
        account = new Mock6551Account(owner);
    }

    function _setupPolicyAndClaims(
        address owner,
        address account,
        uint32 entityId,
        address sessionSigner,
        bytes32 requestHash,
        bool installPreset
    ) internal returns (GatewayClaimsV2 memory gatewayClaims, AAClaimsV2 memory aaClaims, bytes memory aaCallData) {
        address aaTarget = makeAddr("aa-target");
        bytes4 aaSelector = bytes4(keccak256("executeWork()"));

        bytes32 gatewayLeaf = _computeGatewayLeaf(
            keccak256("api.example.com"), keccak256("/v1"), true, true, true, 4096
        );
        bytes32 aaLeaf = _computeAALeaf(aaTarget, aaSelector, 1 ether, false);

        bytes32[] memory gatewayProof = new bytes32[](1);
        gatewayProof[0] = aaLeaf;

        bytes32[] memory aaProof = new bytes32[](1);
        aaProof[0] = gatewayLeaf;

        gatewayClaims = _buildGatewayClaims(
            requestHash,
            1,
            keccak256("api.example.com"),
            keccak256("/v1"),
            true,
            true,
            true,
            4096,
            false,
            false,
            gatewayLeaf,
            gatewayProof
        );

        AACallClaimV2[] memory callClaims = new AACallClaimV2[](1);
        callClaims[0] = AACallClaimV2({
            target: aaTarget,
            selector: aaSelector,
            valueLimit: 1 ether,
            allowDelegateCall: false,
            scopeLeaf: aaLeaf,
            scopeProof: aaProof
        });
        aaClaims = AAClaimsV2({
            callClaims: callClaims,
            multiproof: new bytes32[](0),
            proofFlags: new bool[](0),
            leafOrderHash: bytes32(0)
        });

        aaCallData = abi.encodeWithSelector(EXECUTE_SELECTOR, aaTarget, 0.1 ether, abi.encodeWithSelector(aaSelector));

        bytes32 root = _hashPair(gatewayLeaf, aaLeaf);
        vm.prank(owner);
        registry.setPolicy(account, entityId, sessionSigner, 0, 0, 900, root, 0, 0, 0);

        if (installPreset) {
            bytes4[] memory selectors = new bytes4[](1);
            selectors[0] = EXECUTE_SELECTOR;
            ERC8128AAValidationModuleV2.InstallPresetConfig memory config = ERC8128AAValidationModuleV2.InstallPresetConfig({
                account: account,
                entityId: entityId,
                allowedSelectors: selectors,
                defaultAllowDelegateCall: false,
                minTtlSeconds: 10,
                maxTtlSeconds: 1200
            });
            vm.prank(account);
            aaModule.onInstall(abi.encode(config));
        }
    }

    function _buildGatewayAuth(
        uint256 signerKey,
        address account,
        uint32 entityId,
        address sessionSigner,
        uint64 epoch,
        uint64 policyNonce,
        bytes32 requestHash,
        GatewayClaimsV2 memory claims,
        uint48 created,
        uint48 expires,
        address moduleAddress
    ) internal view returns (SessionAuthV2 memory auth) {
        auth = SessionAuthV2({
            mode: 0,
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

        auth.sessionSignature = _sign(signerKey, _sessionDigest(moduleAddress, account, entityId, auth));
    }

    function _buildAAAuth(
        uint256 signerKey,
        address account,
        uint32 entityId,
        address sessionSigner,
        uint64 epoch,
        uint64 policyNonce,
        bytes32 userOpHash,
        AAClaimsV2 memory claims,
        uint48 created,
        uint48 expires,
        address moduleAddress
    ) internal view returns (SessionAuthV2 memory auth) {
        auth = SessionAuthV2({
            mode: 1,
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

        auth.sessionSignature = _sign(signerKey, _sessionDigest(moduleAddress, account, entityId, auth));
    }

    function _sessionDigest(address moduleAddress, address account, uint32 entityId, SessionAuthV2 memory auth)
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

    function _buildGatewayClaims(
        bytes32 requestHash,
        uint16 methodBit,
        bytes32 authorityHash,
        bytes32 pathPrefixHash,
        bool isReadOnly,
        bool allowReplayable,
        bool allowClassBound,
        uint32 maxBodyBytes,
        bool isReplayable,
        bool isClassBound,
        bytes32 scopeLeaf,
        bytes32[] memory scopeProof
    ) internal pure returns (GatewayClaimsV2 memory claims) {
        claims = GatewayClaimsV2({
            methodBit: methodBit,
            authorityHash: authorityHash,
            pathPrefixHash: pathPrefixHash,
            isReadOnly: isReadOnly,
            allowReplayable: allowReplayable,
            allowClassBound: allowClassBound,
            maxBodyBytes: maxBodyBytes,
            isReplayable: isReplayable,
            isClassBound: isClassBound,
            nonceHash: keccak256(abi.encodePacked("nonce", requestHash)),
            scopeLeaf: scopeLeaf,
            scopeProof: scopeProof
        });
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

    function _computeGatewayLeaf(
        bytes32 authorityHash,
        bytes32 pathPrefixHash,
        bool isReadOnly,
        bool allowReplayable,
        bool allowClassBound,
        uint32 maxBodyBytes
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                "AW_ERC8128_SCOPE_LEAF_V2",
                uint16(1),
                authorityHash,
                pathPrefixHash,
                isReadOnly,
                allowReplayable,
                allowClassBound,
                maxBodyBytes
            )
        );
    }

    function _computeAALeaf(address target, bytes4 selector, uint256 valueLimit, bool allowDelegateCall)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode("AW_ERC8128_AA_SCOPE_LEAF_V2", target, selector, valueLimit, allowDelegateCall));
    }

    function _hashPair(bytes32 a, bytes32 b) internal pure returns (bytes32) {
        return a < b ? keccak256(abi.encodePacked(a, b)) : keccak256(abi.encodePacked(b, a));
    }

    function _sign(uint256 privateKeySeed, bytes32 digest) internal pure returns (bytes memory signature) {
        uint256 privateKey = bound(privateKeySeed, 1, SECP256K1_N - 1);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        signature = abi.encodePacked(r, s, v);
    }
}
