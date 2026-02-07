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
}
