// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IERC6551Account} from "../interfaces/IERC6551Account.sol";

interface IERC8004IdentityRegistry {
    function ownerOf(uint256 tokenId) external view returns (address);
}

/// @title ERC8004IdentityAdapter
/// @notice Optional helper adapter for ERC-8004 registration flows with NFT-bound accounts
contract ERC8004IdentityAdapter {
    bytes4 internal constant REGISTER_SELECTOR = bytes4(keccak256("register()"));
    bytes4 internal constant REGISTER_WITH_URI_SELECTOR = bytes4(keccak256("register(string)"));
    bytes4 internal constant SET_AGENT_URI_SELECTOR = bytes4(keccak256("setAgentURI(uint256,string)"));
    bytes4 internal constant SET_AGENT_WALLET_SELECTOR = bytes4(keccak256("setAgentWallet(uint256,address,uint256,bytes)"));
    uint8 internal constant CALL_OPERATION = 0;

    address public immutable identityRegistry;

    mapping(address => uint256) private _accountToAgentId;
    mapping(uint256 => address) private _agentIdToAccount;

    error InvalidIdentityRegistry(address registry);
    error InvalidAccount(address account);
    error InvalidAgentId(uint256 agentId);
    error InvalidExecutionResult(bytes executeResult);
    error UnauthorizedRecorder(address account, address caller, address accountOwner);
    error AgentNotOwnedByAccount(address account, uint256 agentId, address registryOwner);
    error AccountAlreadyMapped(address account, uint256 existingAgentId);
    error AgentIdAlreadyMapped(uint256 agentId, address existingAccount);

    event AgentRegistrationRecorded(address indexed account, uint256 indexed agentId, address indexed recorder);

    constructor(address identityRegistry_) {
        if (identityRegistry_.code.length == 0) {
            revert InvalidIdentityRegistry(identityRegistry_);
        }
        identityRegistry = identityRegistry_;
    }

    /// @notice Build canonical `register()` calldata for execution via the TBA.
    function encodeRegister() external pure returns (bytes memory) {
        return abi.encodeWithSelector(REGISTER_SELECTOR);
    }

    /// @notice Build canonical `register(string)` calldata for execution via the TBA.
    function encodeRegisterWithURI(string calldata agentURI) external pure returns (bytes memory) {
        return abi.encodeWithSelector(REGISTER_WITH_URI_SELECTOR, agentURI);
    }

    /// @notice Build canonical `setAgentURI(uint256,string)` calldata for execution via the TBA.
    function encodeSetAgentURI(uint256 agentId, string calldata agentURI) external pure returns (bytes memory) {
        return abi.encodeWithSelector(SET_AGENT_URI_SELECTOR, agentId, agentURI);
    }

    /// @notice Build canonical `setAgentWallet(uint256,address,uint256,bytes)` calldata for execution via the TBA.
    function encodeSetAgentWallet(uint256 agentId, address newWallet, uint256 deadline, bytes calldata signature)
        external
        pure
        returns (bytes memory)
    {
        return abi.encodeWithSelector(SET_AGENT_WALLET_SELECTOR, agentId, newWallet, deadline, signature);
    }

    /// @notice Return execution tuple for `register()`.
    function buildRegisterExecution() external view returns (address target, uint256 value, bytes memory data, uint8 operation) {
        return (identityRegistry, 0, abi.encodeWithSelector(REGISTER_SELECTOR), CALL_OPERATION);
    }

    /// @notice Return execution tuple for `register(string)`.
    function buildRegisterExecutionWithURI(string calldata agentURI)
        external
        view
        returns (address target, uint256 value, bytes memory data, uint8 operation)
    {
        return (identityRegistry, 0, abi.encodeWithSelector(REGISTER_WITH_URI_SELECTOR, agentURI), CALL_OPERATION);
    }

    /// @notice Decode the returned bytes from TBA execution of ERC-8004 register calls.
    function decodeRegisterResult(bytes calldata executeResult) public pure returns (uint256 agentId) {
        if (executeResult.length != 32) {
            revert InvalidExecutionResult(executeResult);
        }
        agentId = abi.decode(executeResult, (uint256));
    }

    /// @notice Record and verify an account -> agentId mapping after successful TBA registration.
    function recordAgentRegistration(address account, uint256 agentId) external {
        _recordAgentRegistration(account, agentId);
    }

    /// @notice Record from raw TBA execution return bytes (`abi.decode(result, (uint256))`).
    function recordAgentRegistrationFromResult(address account, bytes calldata executeResult)
        external
        returns (uint256 agentId)
    {
        agentId = decodeRegisterResult(executeResult);
        _recordAgentRegistration(account, agentId);
    }

    /// @notice Return mapped agentId for account.
    function getAgentId(address account) external view returns (uint256) {
        return _accountToAgentId[account];
    }

    /// @notice Return mapped account for agentId.
    function getAccount(uint256 agentId) external view returns (address) {
        return _agentIdToAccount[agentId];
    }

    /// @notice Return true if mapping exists and registry ownership still points to the mapped account.
    function isAgentRegistered(address account) external view returns (bool) {
        uint256 agentId = _accountToAgentId[account];
        if (agentId == 0) {
            return false;
        }

        try IERC8004IdentityRegistry(identityRegistry).ownerOf(agentId) returns (address registryOwner) {
            return registryOwner == account;
        } catch {
            return false;
        }
    }

    function _recordAgentRegistration(address account, uint256 agentId) internal {
        if (account == address(0) || account.code.length == 0) {
            revert InvalidAccount(account);
        }
        if (agentId == 0) {
            revert InvalidAgentId(agentId);
        }

        address accountOwner = _resolveOwner(account);
        if (msg.sender != account && msg.sender != accountOwner) {
            revert UnauthorizedRecorder(account, msg.sender, accountOwner);
        }

        address registryOwner = IERC8004IdentityRegistry(identityRegistry).ownerOf(agentId);
        if (registryOwner != account) {
            revert AgentNotOwnedByAccount(account, agentId, registryOwner);
        }

        uint256 existingAgentId = _accountToAgentId[account];
        if (existingAgentId != 0 && existingAgentId != agentId) {
            revert AccountAlreadyMapped(account, existingAgentId);
        }

        address existingAccount = _agentIdToAccount[agentId];
        if (existingAccount != address(0) && existingAccount != account) {
            revert AgentIdAlreadyMapped(agentId, existingAccount);
        }

        _accountToAgentId[account] = agentId;
        _agentIdToAccount[agentId] = account;

        emit AgentRegistrationRecorded(account, agentId, msg.sender);
    }

    function _resolveOwner(address account) internal view returns (address accountOwner) {
        try IERC6551Account(account).owner() returns (address owner_) {
            return owner_;
        } catch {
            return address(0);
        }
    }
}
