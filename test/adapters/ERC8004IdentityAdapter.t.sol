// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";

import {ERC8004IdentityAdapter} from "../../src/adapters/ERC8004IdentityAdapter.sol";
import {IERC6551Account} from "../../src/interfaces/IERC6551Account.sol";
import {IERC6551Executable} from "../../src/interfaces/IERC6551Executable.sol";

contract MockERC8004IdentityRegistry {
    uint256 private _nextAgentId = 1;

    mapping(uint256 => address) public ownerOf;
    mapping(uint256 => string) public agentURIs;
    mapping(uint256 => address) public agentWallets;

    function register() external returns (uint256 agentId) {
        agentId = _nextAgentId++;
        ownerOf[agentId] = msg.sender;
    }

    function register(string calldata agentURI) external returns (uint256 agentId) {
        agentId = _nextAgentId++;
        ownerOf[agentId] = msg.sender;
        agentURIs[agentId] = agentURI;
    }

    function setAgentURI(uint256 agentId, string calldata newURI) external {
        require(ownerOf[agentId] == msg.sender, "not owner");
        agentURIs[agentId] = newURI;
    }

    function setAgentWallet(uint256 agentId, address newWallet, uint256, bytes calldata) external {
        require(ownerOf[agentId] == msg.sender, "not owner");
        agentWallets[agentId] = newWallet;
    }

    /// @dev Test helper to simulate agent transfer.
    function transferOwnership(uint256 agentId, address newOwner) external {
        ownerOf[agentId] = newOwner;
    }
}

/// @dev Registry mock that can toggle ownerOf reverts.
contract ToggleRevertingRegistry {
    bool public shouldRevert;
    mapping(uint256 => address) public ownerOfMap;

    function setOwner(uint256 agentId, address owner_) external {
        ownerOfMap[agentId] = owner_;
    }

    function setShouldRevert(bool value) external {
        shouldRevert = value;
    }

    function ownerOf(uint256 agentId) external view returns (address) {
        if (shouldRevert) {
            revert("registry down");
        }
        return ownerOfMap[agentId];
    }
}

contract Mock6551ExecutableAccount is IERC6551Account, IERC6551Executable {
    address private _owner;

    constructor(address owner_) {
        _owner = owner_;
    }

    function setOwner(address owner_) external {
        _owner = owner_;
    }

    function token() external view returns (uint256 chainId, address tokenContract, uint256 tokenId) {
        return (block.chainid, address(0xBEEF), 1);
    }

    function owner() external view returns (address) {
        return _owner;
    }

    function nonce() external pure returns (uint256) {
        return 0;
    }

    function isValidSigner(address, bytes calldata) external pure returns (bytes4 magicValue) {
        return bytes4(0xffffffff);
    }

    function execute(address to, uint256 value, bytes calldata data, uint8 operation)
        external
        payable
        returns (bytes memory result)
    {
        require(msg.sender == _owner, "not owner");
        require(operation == 0, "bad op");
        (bool ok, bytes memory returnData) = to.call{value: value}(data);
        require(ok, "call failed");
        return returnData;
    }
}

contract ERC8004IdentityAdapterTest is Test {
    bytes4 internal constant REGISTER_SELECTOR = bytes4(keccak256("register()"));
    bytes4 internal constant REGISTER_WITH_URI_SELECTOR = bytes4(keccak256("register(string)"));

    MockERC8004IdentityRegistry private _registry;
    ERC8004IdentityAdapter private _adapter;
    Mock6551ExecutableAccount private _account;

    address private _owner;

    function setUp() public {
        _owner = makeAddr("owner");
        _registry = new MockERC8004IdentityRegistry();
        _adapter = new ERC8004IdentityAdapter(address(_registry));
        _account = new Mock6551ExecutableAccount(_owner);
    }

    function test_RecordAgentRegistration_FromTBAExecutionResult() public {
        bytes memory registerCall = abi.encodeWithSignature("register(string)", "ipfs://agent");

        vm.prank(_owner);
        bytes memory result = _account.execute(address(_registry), 0, registerCall, 0);
        uint256 agentId = abi.decode(result, (uint256));

        vm.expectEmit(true, true, true, true);
        emit ERC8004IdentityAdapter.AgentRegistrationRecorded(address(_account), agentId, _owner);

        vm.prank(_owner);
        uint256 recordedAgentId = _adapter.recordAgentRegistrationFromResult(address(_account), result);
        assertEq(recordedAgentId, agentId);
        assertEq(_adapter.getAgentId(address(_account)), agentId);
        assertEq(_adapter.getAccount(agentId), address(_account));
        assertTrue(_adapter.isAgentRegistered(address(_account)));
    }

    function test_RevertWhenRecorderIsNotAccountOwner() public {
        vm.prank(_owner);
        bytes memory result = _account.execute(address(_registry), 0, abi.encodeWithSignature("register()"), 0);
        uint256 agentId = abi.decode(result, (uint256));

        address outsider = makeAddr("outsider");
        vm.expectRevert(
            abi.encodeWithSelector(ERC8004IdentityAdapter.UnauthorizedRecorder.selector, address(_account), outsider, _owner)
        );
        vm.prank(outsider);
        _adapter.recordAgentRegistration(address(_account), agentId);
    }

    function test_RevertWhenAgentOwnerDoesNotMatchAccount() public {
        Mock6551ExecutableAccount otherAccount = new Mock6551ExecutableAccount(_owner);

        vm.prank(_owner);
        bytes memory result = otherAccount.execute(address(_registry), 0, abi.encodeWithSignature("register()"), 0);
        uint256 agentId = abi.decode(result, (uint256));

        vm.expectRevert(
            abi.encodeWithSelector(
                ERC8004IdentityAdapter.AgentNotOwnedByAccount.selector, address(_account), agentId, address(otherAccount)
            )
        );
        vm.prank(_owner);
        _adapter.recordAgentRegistration(address(_account), agentId);
    }

    function test_EncodeHelpers_ReturnCanonicalSelectors() public view {
        bytes memory registerData = _adapter.encodeRegister();
        bytes memory registerWithURIData = _adapter.encodeRegisterWithURI("ipfs://agent");

        bytes4 registerSelector;
        bytes4 registerWithURISelector;
        assembly {
            registerSelector := mload(add(registerData, 32))
            registerWithURISelector := mload(add(registerWithURIData, 32))
        }

        assertEq(registerSelector, REGISTER_SELECTOR);
        assertEq(registerWithURISelector, REGISTER_WITH_URI_SELECTOR);
    }

    function test_BuildRegisterExecution_TargetsConfiguredRegistry() public view {
        (address target,, bytes memory data, uint8 operation) = _adapter.buildRegisterExecutionWithURI("ipfs://agent");

        assertEq(target, address(_registry));
        assertEq(operation, 0);

        bytes4 selector;
        assembly {
            selector := mload(add(data, 32))
        }
        assertEq(selector, REGISTER_WITH_URI_SELECTOR);
    }

    // ---------------------------------------------------------------
    // Idempotent re-recording
    // ---------------------------------------------------------------

    function test_IdempotentReRecording_SameMapping() public {
        // Register and record once
        vm.prank(_owner);
        bytes memory result = _account.execute(address(_registry), 0, abi.encodeWithSignature("register()"), 0);
        uint256 agentId = abi.decode(result, (uint256));

        vm.prank(_owner);
        _adapter.recordAgentRegistration(address(_account), agentId);

        // Record the exact same mapping again — should not revert
        vm.prank(_owner);
        _adapter.recordAgentRegistration(address(_account), agentId);

        assertEq(_adapter.getAgentId(address(_account)), agentId);
        assertEq(_adapter.getAccount(agentId), address(_account));
    }

    // ---------------------------------------------------------------
    // AccountAlreadyMapped
    // ---------------------------------------------------------------

    function test_RevertWhenAccountAlreadyMappedToDifferentAgentId() public {
        // Register first agent via account
        vm.prank(_owner);
        bytes memory result1 = _account.execute(address(_registry), 0, abi.encodeWithSignature("register()"), 0);
        uint256 agentId1 = abi.decode(result1, (uint256));

        vm.prank(_owner);
        _adapter.recordAgentRegistration(address(_account), agentId1);

        // Register second agent via account
        vm.prank(_owner);
        bytes memory result2 = _account.execute(address(_registry), 0, abi.encodeWithSignature("register()"), 0);
        uint256 agentId2 = abi.decode(result2, (uint256));

        // Try to map account to a different agentId
        vm.expectRevert(
            abi.encodeWithSelector(ERC8004IdentityAdapter.AccountAlreadyMapped.selector, address(_account), agentId1)
        );
        vm.prank(_owner);
        _adapter.recordAgentRegistration(address(_account), agentId2);
    }

    // ---------------------------------------------------------------
    // AgentIdAlreadyMapped
    // ---------------------------------------------------------------

    function test_RevertWhenAgentIdAlreadyMappedToDifferentAccount() public {
        // Register agent via first account
        vm.prank(_owner);
        bytes memory result = _account.execute(address(_registry), 0, abi.encodeWithSignature("register()"), 0);
        uint256 agentId = abi.decode(result, (uint256));

        vm.prank(_owner);
        _adapter.recordAgentRegistration(address(_account), agentId);

        // Create second account, transfer agent ownership to it in registry
        Mock6551ExecutableAccount account2 = new Mock6551ExecutableAccount(_owner);
        _registry.transferOwnership(agentId, address(account2));

        // Try to map the same agentId to account2
        vm.expectRevert(
            abi.encodeWithSelector(ERC8004IdentityAdapter.AgentIdAlreadyMapped.selector, agentId, address(_account))
        );
        vm.prank(_owner);
        _adapter.recordAgentRegistration(address(account2), agentId);
    }

    // ---------------------------------------------------------------
    // isAgentRegistered — stale after ownership transfer
    // ---------------------------------------------------------------

    function test_IsAgentRegistered_ReturnsFalseAfterOwnershipTransfer() public {
        vm.prank(_owner);
        bytes memory result = _account.execute(address(_registry), 0, abi.encodeWithSignature("register()"), 0);
        uint256 agentId = abi.decode(result, (uint256));

        vm.prank(_owner);
        _adapter.recordAgentRegistration(address(_account), agentId);
        assertTrue(_adapter.isAgentRegistered(address(_account)));

        // Transfer agent to a different address in the registry
        Mock6551ExecutableAccount newOwnerAccount = new Mock6551ExecutableAccount(_owner);
        _registry.transferOwnership(agentId, address(newOwnerAccount));

        // Mapping still exists but liveness check should fail
        assertEq(_adapter.getAgentId(address(_account)), agentId);
        assertFalse(_adapter.isAgentRegistered(address(_account)));
    }

    // ---------------------------------------------------------------
    // isAgentRegistered — false when registry call reverts
    // ---------------------------------------------------------------

    function test_IsAgentRegistered_ReturnsFalseWhenRegistryReverts() public {
        // Deploy adapter pointing to a registry that can later revert.
        ToggleRevertingRegistry badRegistry = new ToggleRevertingRegistry();
        ERC8004IdentityAdapter badAdapter = new ERC8004IdentityAdapter(address(badRegistry));
        address localOwner = makeAddr("localOwner");
        Mock6551ExecutableAccount localAccount = new Mock6551ExecutableAccount(localOwner);
        uint256 agentId = 77;

        badRegistry.setOwner(agentId, address(localAccount));
        vm.prank(localOwner);
        badAdapter.recordAgentRegistration(address(localAccount), agentId);
        assertTrue(badAdapter.isAgentRegistered(address(localAccount)));

        badRegistry.setShouldRevert(true);
        assertFalse(badAdapter.isAgentRegistered(address(localAccount)));
    }

    // ---------------------------------------------------------------
    // InvalidAccount — zero address
    // ---------------------------------------------------------------

    function test_RevertWhenAccountIsZeroAddress() public {
        vm.expectRevert(abi.encodeWithSelector(ERC8004IdentityAdapter.InvalidAccount.selector, address(0)));
        vm.prank(_owner);
        _adapter.recordAgentRegistration(address(0), 1);
    }

    // ---------------------------------------------------------------
    // InvalidAccount — EOA (no code)
    // ---------------------------------------------------------------

    function test_RevertWhenAccountIsEOA() public {
        address eoa = makeAddr("eoa");
        vm.expectRevert(abi.encodeWithSelector(ERC8004IdentityAdapter.InvalidAccount.selector, eoa));
        vm.prank(_owner);
        _adapter.recordAgentRegistration(eoa, 1);
    }

    // ---------------------------------------------------------------
    // InvalidAgentId — zero
    // ---------------------------------------------------------------

    function test_RevertWhenAgentIdIsZero() public {
        vm.expectRevert(abi.encodeWithSelector(ERC8004IdentityAdapter.InvalidAgentId.selector, uint256(0)));
        vm.prank(_owner);
        _adapter.recordAgentRegistration(address(_account), 0);
    }

    // ---------------------------------------------------------------
    // InvalidExecutionResult — wrong-length bytes
    // ---------------------------------------------------------------

    function test_RevertWhenExecutionResultTooShort() public {
        bytes memory shortResult = abi.encodePacked(uint128(42));
        vm.expectRevert(abi.encodeWithSelector(ERC8004IdentityAdapter.InvalidExecutionResult.selector, shortResult));
        vm.prank(_owner);
        _adapter.recordAgentRegistrationFromResult(address(_account), shortResult);
    }

    function test_RevertWhenExecutionResultTooLong() public {
        bytes memory longResult = abi.encodePacked(uint256(1), uint256(2));
        vm.expectRevert(abi.encodeWithSelector(ERC8004IdentityAdapter.InvalidExecutionResult.selector, longResult));
        vm.prank(_owner);
        _adapter.recordAgentRegistrationFromResult(address(_account), longResult);
    }

    function test_RevertWhenExecutionResultEmpty() public {
        bytes memory emptyResult = "";
        vm.expectRevert(abi.encodeWithSelector(ERC8004IdentityAdapter.InvalidExecutionResult.selector, emptyResult));
        vm.prank(_owner);
        _adapter.recordAgentRegistrationFromResult(address(_account), emptyResult);
    }

    // ---------------------------------------------------------------
    // Fuzz: random account/agentId pairs with valid registry state
    // ---------------------------------------------------------------

    function testFuzz_RecordAndQuery_WithValidRegistryState(uint256 agentIdSeed) public {
        // Bound agentId to non-zero
        uint256 agentId = bound(agentIdSeed, 1, type(uint128).max);

        // Set up registry to report _account as owner of this agentId
        _registry.transferOwnership(agentId, address(_account));

        vm.prank(_owner);
        _adapter.recordAgentRegistration(address(_account), agentId);

        assertEq(_adapter.getAgentId(address(_account)), agentId);
        assertEq(_adapter.getAccount(agentId), address(_account));
        assertTrue(_adapter.isAgentRegistered(address(_account)));
    }

    function testFuzz_RecordAndQuery_RandomAccountAndAgentIdPair(uint256 ownerSeed, uint256 agentIdSeed) public {
        uint256 agentId = bound(agentIdSeed, 1, type(uint128).max);
        address randomOwner = address(uint160(uint256(keccak256(abi.encode(ownerSeed, "owner")))));
        vm.assume(randomOwner != address(0));

        Mock6551ExecutableAccount randomAccount = new Mock6551ExecutableAccount(randomOwner);
        _registry.transferOwnership(agentId, address(randomAccount));

        vm.prank(randomOwner);
        _adapter.recordAgentRegistration(address(randomAccount), agentId);

        assertEq(_adapter.getAgentId(address(randomAccount)), agentId);
        assertEq(_adapter.getAccount(agentId), address(randomAccount));
        assertTrue(_adapter.isAgentRegistered(address(randomAccount)));
    }

    function testFuzz_RejectZeroAgentId(uint8) public {
        vm.expectRevert(abi.encodeWithSelector(ERC8004IdentityAdapter.InvalidAgentId.selector, uint256(0)));
        vm.prank(_owner);
        _adapter.recordAgentRegistration(address(_account), 0);
    }

    function testFuzz_RejectEOAAccount(address eoa) public {
        // Only test with addresses that have no code and are non-zero
        vm.assume(eoa != address(0));
        vm.assume(eoa.code.length == 0);

        vm.expectRevert(abi.encodeWithSelector(ERC8004IdentityAdapter.InvalidAccount.selector, eoa));
        vm.prank(_owner);
        _adapter.recordAgentRegistration(eoa, 1);
    }

    function testFuzz_DecodeRejectsBadLength(bytes memory badResult) public {
        vm.assume(badResult.length != 32);
        vm.expectRevert(abi.encodeWithSelector(ERC8004IdentityAdapter.InvalidExecutionResult.selector, badResult));
        _adapter.decodeRegisterResult(badResult);
    }
}
