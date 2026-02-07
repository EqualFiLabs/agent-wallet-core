// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {IAccount, IAccountExecute, PackedUserOperation} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";

import {ERC721BoundMSCA} from "../../src/core/ERC721BoundMSCA.sol";
import {NFTBoundMSCA} from "../../src/core/NFTBoundMSCA.sol";
import {IERC165} from "../../src/interfaces/IERC165.sol";
import {IERC6551Account} from "../../src/interfaces/IERC6551Account.sol";
import {IERC6551Executable} from "../../src/interfaces/IERC6551Executable.sol";
import {IERC6900Account} from "../../src/interfaces/IERC6900Account.sol";
import {ExecutionFlowLib} from "../../src/libraries/ExecutionFlowLib.sol";
import {ExecutionManagementLib} from "../../src/libraries/ExecutionManagementLib.sol";
import {ModuleEntityLib} from "../../src/libraries/ModuleEntityLib.sol";
import {ValidationConfigLib} from "../../src/libraries/ValidationConfigLib.sol";
import {
    ExecutionManifest,
    ManifestExecutionFunction,
    ManifestExecutionHook,
    ModuleEntity,
    ValidationConfig
} from "../../src/libraries/ModuleTypes.sol";
import {
    ERC6551DelegateProxy,
    ERC721BoundMSCATestHarness,
    MockERC721,
    MockExecutionModule,
    MockValidationModule,
    RecursiveHookModule,
    SelfModExecutionModule
} from "../mocks/CoreTestMocks.sol";

contract ERC721BoundMSCATest is Test {
    uint256 internal constant SECP256K1_N =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    address internal entryPoint;
    uint256 internal ownerPk;
    address internal owner;

    MockERC721 internal boundToken;
    ERC721BoundMSCATestHarness internal account;

    event BootstrapDisabled(address indexed account, uint256 timestamp);

    function setUp() public {
        entryPoint = makeAddr("entryPoint");
        ownerPk = 0xA11CE;
        owner = vm.addr(ownerPk);

        boundToken = new MockERC721();
        boundToken.mint(owner, 1);

        account = new ERC721BoundMSCATestHarness(entryPoint, block.chainid, address(boundToken), 1);
    }

    // **Feature: standalone-nft-agent-wallet, Property 1: ERC-721 ownership resolution consistency**
    function testFuzz_Property1_ERC721OwnershipResolutionConsistency(uint96 tokenIdSeed, uint256 ownerPkSeed) public {
        uint256 tokenId = uint256(tokenIdSeed) + 1;
        uint256 boundedPk = bound(ownerPkSeed, 1, SECP256K1_N - 1);
        address expectedOwner = vm.addr(boundedPk);

        MockERC721 token = new MockERC721();
        token.mint(expectedOwner, tokenId);

        ERC721BoundMSCATestHarness localAccount =
            new ERC721BoundMSCATestHarness(entryPoint, block.chainid, address(token), tokenId);

        assertEq(localAccount.owner(), expectedOwner);
    }

    // **Feature: standalone-nft-agent-wallet, Property 3: Token binding data extraction**
    function testFuzz_Property3_TokenBindingDataExtraction(
        bytes32 salt,
        uint256 chainId,
        address tokenContract,
        uint256 tokenId
    ) public {
        vm.assume(tokenContract != address(0));

        ERC721BoundMSCA implementation = new ERC721BoundMSCA(entryPoint);
        address proxy = address(new ERC6551DelegateProxy(address(implementation), salt, chainId, tokenContract, tokenId));

        (uint256 resolvedChainId, address resolvedToken, uint256 resolvedTokenId) = IERC6551Account(proxy).token();

        assertEq(resolvedChainId, chainId);
        assertEq(resolvedToken, tokenContract);
        assertEq(resolvedTokenId, tokenId);
    }

    // **Feature: standalone-nft-agent-wallet, Property 4: Module installation round trip**
    function testFuzz_Property4_ModuleInstallationRoundTrip(uint32 entityId) public {
        MockValidationModule validationModule = new MockValidationModule();
        MockExecutionModule executionModule = new MockExecutionModule();

        ValidationConfig validationConfig =
            ValidationConfigLib.pack(address(validationModule), entityId, false, true, false);
        ModuleEntity validationFunction = ModuleEntityLib.pack(address(validationModule), entityId);
        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = IERC1271.isValidSignature.selector;

        vm.prank(owner);
        account.installValidation(validationConfig, selectors, bytes(""), new bytes[](0));

        bytes memory encodedSignature = abi.encode(validationFunction, bytes("module-sig"));
        bytes4 moduleValidationResult = account.isValidSignature(keccak256("module-signature"), encodedSignature);
        assertEq(moduleValidationResult, IERC1271.isValidSignature.selector);

        vm.prank(owner);
        account.uninstallValidation(validationFunction, bytes(""), new bytes[](0));

        (bool okAfterUninstall, bytes memory returnDataAfterUninstall) = address(account).staticcall(
            abi.encodeCall(IERC1271.isValidSignature, (keccak256("module-signature"), encodedSignature))
        );
        if (okAfterUninstall) {
            bytes4 validationResult = abi.decode(returnDataAfterUninstall, (bytes4));
            assertEq(validationResult, bytes4(0xffffffff));
        } else {
            assertFalse(okAfterUninstall);
        }

        bytes4 interfaceId = 0x9abc1234;
        ManifestExecutionFunction[] memory executionFunctions = new ManifestExecutionFunction[](1);
        executionFunctions[0] = ManifestExecutionFunction({
            executionSelector: MockExecutionModule.ping.selector,
            skipRuntimeValidation: false,
            allowGlobalValidation: false
        });

        bytes4[] memory interfaceIds = new bytes4[](1);
        interfaceIds[0] = interfaceId;

        ExecutionManifest memory manifest = ExecutionManifest({
            executionFunctions: executionFunctions,
            executionHooks: new ManifestExecutionHook[](0),
            interfaceIds: interfaceIds
        });

        vm.prank(owner);
        account.installExecution(address(executionModule), manifest, bytes(""));

        assertTrue(account.supportsInterface(interfaceId));

        vm.prank(owner);
        uint256 pingValue = MockExecutionModule(address(account)).ping();
        assertEq(pingValue, 42);

        vm.prank(owner);
        account.uninstallExecution(address(executionModule), manifest, bytes(""));

        assertFalse(account.supportsInterface(interfaceId));

        vm.prank(owner);
        (bool ok, ) = address(account).call(abi.encodeWithSelector(MockExecutionModule.ping.selector));
        assertFalse(ok);
    }

    // **Feature: standalone-nft-agent-wallet, Property 5: Module self-modification prevention**
    function testFuzz_Property5_ModuleSelfModificationPrevention(uint96 tokenIdSeed) public {
        uint256 tokenId = uint256(tokenIdSeed) + 1;
        SelfModExecutionModule selfModule = new SelfModExecutionModule();

        MockERC721 localToken = new MockERC721();
        localToken.mint(address(selfModule), tokenId);

        ERC721BoundMSCATestHarness localAccount =
            new ERC721BoundMSCATestHarness(entryPoint, block.chainid, address(localToken), tokenId);

        vm.expectRevert(abi.encodeWithSelector(NFTBoundMSCA.ModuleSelfModification.selector, address(selfModule)));
        selfModule.attemptInstallSelf(address(localAccount), MockExecutionModule.ping.selector);
    }

    // **Feature: standalone-nft-agent-wallet, Property 6: Native selector conflict detection**
    function testFuzz_Property6_NativeSelectorConflictDetection(uint96 selectorSeed) public {
        MockExecutionModule executionModule = new MockExecutionModule();

        bytes4 nativeConflictSelector = selectorSeed % 2 == 0
            ? IERC6900Account.execute.selector
            : IAccountExecute.executeUserOp.selector;

        ManifestExecutionFunction[] memory executionFunctions = new ManifestExecutionFunction[](1);
        executionFunctions[0] = ManifestExecutionFunction({
            executionSelector: nativeConflictSelector,
            skipRuntimeValidation: true,
            allowGlobalValidation: false
        });

        ExecutionManifest memory manifest = ExecutionManifest({
            executionFunctions: executionFunctions,
            executionHooks: new ManifestExecutionHook[](0),
            interfaceIds: new bytes4[](0)
        });

        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(ExecutionManagementLib.NativeSelectorConflict.selector, nativeConflictSelector));
        account.installExecution(address(executionModule), manifest, bytes(""));
    }

    // **Feature: standalone-nft-agent-wallet, Property 17: Bootstrap disable irreversibility**
    function testFuzz_Property17_BootstrapDisableIrreversibility(bytes32 digest) public {
        bytes memory bootstrapSignature = _sign(ownerPk, digest);

        assertEq(account.isValidSignature(digest, bootstrapSignature), IERC1271.isValidSignature.selector);

        vm.expectEmit(true, true, true, true);
        emit BootstrapDisabled(address(account), block.timestamp);

        vm.prank(owner);
        account.disableBootstrap();

        assertFalse(account.bootstrapActive());
        assertEq(account.isValidSignature(digest, bootstrapSignature), bytes4(0xffffffff));

        PackedUserOperation memory userOp = _buildUserOp(abi.encodeCall(IERC6900Account.accountId, ()), bootstrapSignature);
        vm.prank(entryPoint);
        uint256 validationData = account.validateUserOp(userOp, digest, 0);
        assertEq(validationData, 1);

        vm.prank(owner);
        vm.expectRevert(NFTBoundMSCA.BootstrapAlreadyDisabled.selector);
        account.disableBootstrap();
    }

    // **Feature: standalone-nft-agent-wallet, Property 18: EntryPoint exclusivity**
    function testFuzz_Property18_EntryPointExclusivity(address caller, bytes32 userOpHash) public {
        vm.assume(caller != entryPoint);

        PackedUserOperation memory userOp = _buildUserOp(abi.encodeCall(IERC6900Account.accountId, ()), bytes(""));

        vm.prank(caller);
        vm.expectRevert(abi.encodeWithSelector(NFTBoundMSCA.InvalidEntryPoint.selector, caller));
        account.validateUserOp(userOp, userOpHash, 0);

        vm.prank(caller);
        vm.expectRevert(abi.encodeWithSelector(NFTBoundMSCA.InvalidEntryPoint.selector, caller));
        account.executeUserOp(userOp, userOpHash);
    }

    // **Feature: standalone-nft-agent-wallet, Property 19: ERC-721 token reception**
    function testFuzz_Property19_ERC721TokenReception(uint96 tokenIdSeed) public {
        uint256 tokenId = uint256(tokenIdSeed) + 10_000;
        MockERC721 nft = new MockERC721();
        nft.mint(address(this), tokenId);

        nft.safeTransferFrom(address(this), address(account), tokenId);
        assertEq(nft.ownerOf(tokenId), address(account));
    }

    // **Feature: standalone-nft-agent-wallet, Property 20: Hook depth enforcement**
    function testFuzz_Property20_HookDepthEnforcement(uint96 tokenIdSeed) public {
        uint256 tokenId = uint256(tokenIdSeed) + 100;

        MockERC721 tokenA = new MockERC721();
        tokenA.mint(owner, tokenId);

        ERC721BoundMSCATestHarness depthAccount =
            new ERC721BoundMSCATestHarness(entryPoint, block.chainid, address(tokenA), tokenId);
        MockExecutionModule depthModule = new MockExecutionModule();

        ManifestExecutionFunction[] memory depthFunctions = new ManifestExecutionFunction[](1);
        depthFunctions[0] = ManifestExecutionFunction({
            executionSelector: MockExecutionModule.ping.selector,
            skipRuntimeValidation: true,
            allowGlobalValidation: false
        });

        ExecutionManifest memory depthManifest = ExecutionManifest({
            executionFunctions: depthFunctions,
            executionHooks: new ManifestExecutionHook[](0),
            interfaceIds: new bytes4[](0)
        });

        vm.prank(owner);
        depthAccount.installExecution(address(depthModule), depthManifest, bytes(""));

        depthAccount.setHookGuard(8, false);
        vm.prank(owner);
        vm.expectRevert(ExecutionFlowLib.MaxHookDepthExceeded.selector);
        MockExecutionModule(address(depthAccount)).ping();

        MockERC721 tokenB = new MockERC721();
        tokenB.mint(owner, tokenId + 1);

        ERC721BoundMSCATestHarness recursiveAccount =
            new ERC721BoundMSCATestHarness(entryPoint, block.chainid, address(tokenB), tokenId + 1);
        RecursiveHookModule recursiveModule = new RecursiveHookModule();

        ManifestExecutionFunction[] memory recursiveFunctions = new ManifestExecutionFunction[](1);
        recursiveFunctions[0] = ManifestExecutionFunction({
            executionSelector: RecursiveHookModule.ping.selector,
            skipRuntimeValidation: true,
            allowGlobalValidation: false
        });

        ManifestExecutionHook[] memory recursiveHooks = new ManifestExecutionHook[](1);
        recursiveHooks[0] = ManifestExecutionHook({
            executionSelector: RecursiveHookModule.ping.selector,
            entityId: 1,
            isPreHook: true,
            isPostHook: false
        });

        ExecutionManifest memory recursiveManifest = ExecutionManifest({
            executionFunctions: recursiveFunctions,
            executionHooks: recursiveHooks,
            interfaceIds: new bytes4[](0)
        });

        recursiveModule.configure(address(recursiveAccount), abi.encodeWithSelector(RecursiveHookModule.ping.selector));

        vm.prank(owner);
        recursiveAccount.installExecution(address(recursiveModule), recursiveManifest, bytes(""));

        vm.prank(owner);
        vm.expectRevert(ExecutionFlowLib.RecursiveHookDetected.selector);
        RecursiveHookModule(address(recursiveAccount)).ping();
    }

    function _sign(uint256 privateKey, bytes32 digest) internal pure returns (bytes memory signature) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        signature = abi.encodePacked(r, s, v);
    }

    function _buildUserOp(bytes memory callData, bytes memory signature)
        internal
        pure
        returns (PackedUserOperation memory userOp)
    {
        userOp.sender = address(0);
        userOp.nonce = 0;
        userOp.initCode = bytes("");
        userOp.callData = callData;
        userOp.accountGasLimits = bytes32(0);
        userOp.preVerificationGas = 0;
        userOp.gasFees = bytes32(0);
        userOp.paymasterAndData = bytes("");
        userOp.signature = signature;
    }
}
