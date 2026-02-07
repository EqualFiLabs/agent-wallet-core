// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title BeaconGovernance
/// @notice Timelock governance helper for beacon upgrades and mutable resolver updates
contract BeaconGovernance {
    bytes32 public constant BEACON_UPGRADE_OP = keccak256("BEACON_UPGRADE_OP");
    bytes32 public constant RESOLVER_UPDATE_OP = keccak256("RESOLVER_UPDATE_OP");

    address public immutable admin;
    uint64 public immutable minDelay;

    struct Operation {
        uint64 executeAfter;
        bytes32 opType;
        address target;
        bytes data;
    }

    mapping(bytes32 => Operation) private _operations;

    error Unauthorized(address caller);
    error InvalidAdmin(address admin_);
    error InvalidMinDelay(uint64 delay);
    error InvalidTarget(address target);
    error InvalidImplementation(address implementation);
    error InvalidResolver(address resolver);
    error OperationAlreadyQueued(bytes32 opId);
    error OperationNotQueued(bytes32 opId);
    error OperationNotReady(bytes32 opId, uint64 executeAfter, uint64 currentTime);
    error OperationCallFailed(bytes32 opId, bytes revertData);

    event OperationQueued(
        bytes32 indexed opId, bytes32 indexed opType, address indexed target, bytes data, uint64 executeAfter
    );
    event OperationExecuted(bytes32 indexed opId, bytes32 indexed opType, address indexed target, bytes data);
    event OperationCancelled(bytes32 indexed opId, bytes32 indexed opType, address indexed target, bytes data);

    constructor(address admin_, uint64 minDelay_) {
        if (admin_ == address(0)) {
            revert InvalidAdmin(admin_);
        }
        if (minDelay_ == 0) {
            revert InvalidMinDelay(minDelay_);
        }
        admin = admin_;
        minDelay = minDelay_;
    }

    function queueBeaconUpgrade(address beacon, address newImplementation, bytes32 salt)
        external
        onlyAdmin
        returns (bytes32 opId)
    {
        if (beacon == address(0)) {
            revert InvalidTarget(beacon);
        }
        if (newImplementation == address(0)) {
            revert InvalidImplementation(newImplementation);
        }
        bytes memory data = abi.encodeCall(IUpgradeableBeacon.upgradeTo, (newImplementation));
        opId = _queue(BEACON_UPGRADE_OP, beacon, data, salt);
    }

    function queueResolverUpdate(address resolverManager, address newResolver, bytes32 salt)
        external
        onlyAdmin
        returns (bytes32 opId)
    {
        if (resolverManager == address(0)) {
            revert InvalidTarget(resolverManager);
        }
        if (newResolver == address(0)) {
            revert InvalidResolver(newResolver);
        }
        bytes memory data = abi.encodeCall(IMutableResolverTarget.setResolver, (newResolver));
        opId = _queue(RESOLVER_UPDATE_OP, resolverManager, data, salt);
    }

    function execute(bytes32 opId) external onlyAdmin {
        Operation memory op = _operations[opId];
        if (op.executeAfter == 0) {
            revert OperationNotQueued(opId);
        }
        uint64 nowTs = uint64(block.timestamp);
        if (nowTs < op.executeAfter) {
            revert OperationNotReady(opId, op.executeAfter, nowTs);
        }

        delete _operations[opId];

        (bool ok, bytes memory revertData) = op.target.call(op.data);
        if (!ok) {
            revert OperationCallFailed(opId, revertData);
        }

        emit OperationExecuted(opId, op.opType, op.target, op.data);
    }

    function cancel(bytes32 opId) external onlyAdmin {
        Operation memory op = _operations[opId];
        if (op.executeAfter == 0) {
            revert OperationNotQueued(opId);
        }
        delete _operations[opId];
        emit OperationCancelled(opId, op.opType, op.target, op.data);
    }

    function getOperation(bytes32 opId) external view returns (Operation memory) {
        return _operations[opId];
    }

    function computeOperationId(bytes32 opType, address target, bytes calldata data, bytes32 salt)
        external
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(opType, target, data, salt));
    }

    function _queue(bytes32 opType, address target, bytes memory data, bytes32 salt) internal returns (bytes32 opId) {
        opId = keccak256(abi.encode(opType, target, data, salt));
        if (_operations[opId].executeAfter != 0) {
            revert OperationAlreadyQueued(opId);
        }
        uint64 executeAfter = uint64(block.timestamp) + minDelay;
        _operations[opId] = Operation({executeAfter: executeAfter, opType: opType, target: target, data: data});

        emit OperationQueued(opId, opType, target, data, executeAfter);
    }

    modifier onlyAdmin() {
        if (msg.sender != admin) {
            revert Unauthorized(msg.sender);
        }
        _;
    }
}

interface IUpgradeableBeacon {
    function upgradeTo(address newImplementation) external;
}

interface IMutableResolverTarget {
    function setResolver(address newResolver) external;
}
