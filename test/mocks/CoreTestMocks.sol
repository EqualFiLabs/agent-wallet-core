// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ERC721} from "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";

import {IOwnerResolver} from "../../src/adapters/IOwnerResolver.sol";
import {ERC721BoundMSCA} from "../../src/core/ERC721BoundMSCA.sol";
import {ResolverBoundMSCA} from "../../src/core/ResolverBoundMSCA.sol";
import {IERC165} from "../../src/interfaces/IERC165.sol";
import {IERC6900Account} from "../../src/interfaces/IERC6900Account.sol";
import {IERC6900ExecutionHookModule} from "../../src/interfaces/IERC6900ExecutionHookModule.sol";
import {IERC6900Module} from "../../src/interfaces/IERC6900Module.sol";
import {IERC6900ValidationModule} from "../../src/interfaces/IERC6900ValidationModule.sol";
import {
    ExecutionManifest,
    ManifestExecutionFunction,
    ManifestExecutionHook,
    Call
} from "../../src/libraries/ModuleTypes.sol";
import {MSCAStorage} from "../../src/libraries/MSCAStorage.sol";

contract MockERC721 is ERC721 {
    constructor() ERC721("MockNFT", "MNFT") {}

    function mint(address to, uint256 tokenId) external {
        _mint(to, tokenId);
    }
}

contract MockValidationModule is IERC6900ValidationModule {
    uint256 public validationDataToReturn;

    function setValidationDataToReturn(uint256 value) external {
        validationDataToReturn = value;
    }

    function validateUserOp(uint32, PackedUserOperation calldata, bytes32) external view returns (uint256) {
        return validationDataToReturn;
    }

    function validateRuntime(address, uint32, address, uint256, bytes calldata, bytes calldata) external pure {}

    function validateSignature(address, uint32, address, bytes32, bytes calldata)
        external
        pure
        returns (bytes4)
    {
        return IERC1271.isValidSignature.selector;
    }

    function onInstall(bytes calldata) external pure {}

    function onUninstall(bytes calldata) external pure {}

    function moduleId() external pure returns (string memory) {
        return "mock.validation.module";
    }

    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return interfaceId == type(IERC165).interfaceId || interfaceId == type(IERC6900ValidationModule).interfaceId
            || interfaceId == type(IERC6900Module).interfaceId;
    }
}

contract MockExecutionModule is IERC6900Module {
    function ping() external returns (uint256) {
        return 42;
    }

    function onInstall(bytes calldata) external pure {}

    function onUninstall(bytes calldata) external pure {}

    function moduleId() external pure returns (string memory) {
        return "mock.execution.module";
    }

    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return interfaceId == type(IERC165).interfaceId || interfaceId == type(IERC6900Module).interfaceId;
    }
}

contract SelfModExecutionModule is MockExecutionModule {
    function attemptInstallSelf(address account, bytes4 executionSelector) external {
        ManifestExecutionFunction[] memory functions = new ManifestExecutionFunction[](1);
        functions[0] = ManifestExecutionFunction({
            executionSelector: executionSelector,
            skipRuntimeValidation: true,
            allowGlobalValidation: false
        });

        ExecutionManifest memory manifest =
            ExecutionManifest({executionFunctions: functions, executionHooks: new ManifestExecutionHook[](0), interfaceIds: new bytes4[](0)});

        IERC6900Account(account).installExecution(address(this), manifest, bytes(""));
    }

    function attemptUninstallSelf(address account, bytes4 executionSelector) external {
        ManifestExecutionFunction[] memory functions = new ManifestExecutionFunction[](1);
        functions[0] = ManifestExecutionFunction({
            executionSelector: executionSelector,
            skipRuntimeValidation: true,
            allowGlobalValidation: false
        });

        ExecutionManifest memory manifest =
            ExecutionManifest({executionFunctions: functions, executionHooks: new ManifestExecutionHook[](0), interfaceIds: new bytes4[](0)});

        IERC6900Account(account).uninstallExecution(address(this), manifest, bytes(""));
    }
}

contract RecursiveHookModule is IERC6900ExecutionHookModule {
    address public targetAccount;
    bytes public reentryCallData;

    function ping() external returns (uint256) {
        return 7;
    }

    function configure(address account_, bytes calldata callData_) external {
        targetAccount = account_;
        reentryCallData = callData_;
    }

    function preExecutionHook(uint32, address, uint256, bytes calldata) external returns (bytes memory) {
        (bool ok, bytes memory returnData) = targetAccount.call(reentryCallData);
        if (!ok) {
            assembly {
                revert(add(returnData, 0x20), mload(returnData))
            }
        }
        return bytes("");
    }

    function postExecutionHook(uint32, bytes calldata) external pure {}

    function onInstall(bytes calldata) external pure {}

    function onUninstall(bytes calldata) external pure {}

    function moduleId() external pure returns (string memory) {
        return "mock.recursive.hook.module";
    }

    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return interfaceId == type(IERC165).interfaceId || interfaceId == type(IERC6900ExecutionHookModule).interfaceId
            || interfaceId == type(IERC6900Module).interfaceId;
    }
}

contract MockOwnerResolver is IOwnerResolver {
    mapping(bytes32 => address) public resolvedOwners;

    function setOwner(uint256 chainId, address tokenContract, uint256 tokenId, address owner) external {
        bytes32 key = keccak256(abi.encode(chainId, tokenContract, tokenId));
        resolvedOwners[key] = owner;
    }

    function resolveOwner(uint256 chainId, address tokenContract, uint256 tokenId)
        external
        view
        returns (address owner)
    {
        bytes32 key = keccak256(abi.encode(chainId, tokenContract, tokenId));
        owner = resolvedOwners[key];
    }
}

contract ERC721BoundMSCATestHarness is ERC721BoundMSCA {
    uint256 private _testChainId;
    address private _testTokenContract;
    uint256 private _testTokenId;

    constructor(address entryPoint_, uint256 chainId_, address tokenContract_, uint256 tokenId_)
        ERC721BoundMSCA(entryPoint_)
    {
        _testChainId = chainId_;
        _testTokenContract = tokenContract_;
        _testTokenId = tokenId_;
    }

    function setTokenData(uint256 chainId_, address tokenContract_, uint256 tokenId_) external {
        _testChainId = chainId_;
        _testTokenContract = tokenContract_;
        _testTokenId = tokenId_;
    }

    function setHookGuard(uint256 depth, bool active) external {
        MSCAStorage.Layout storage ds = MSCAStorage.layout();
        ds.hookDepth = depth;
        ds.hookExecutionActive = active;
    }

    function token() public view override returns (uint256 chainId, address tokenContract, uint256 tokenId) {
        return (_testChainId, _testTokenContract, _testTokenId);
    }
}

contract ResolverBoundMSCATestHarness is ResolverBoundMSCA {
    uint256 private _testChainId;
    address private _testTokenContract;
    uint256 private _testTokenId;

    constructor(address entryPoint_, address resolver_, uint256 chainId_, address tokenContract_, uint256 tokenId_)
        ResolverBoundMSCA(entryPoint_, resolver_)
    {
        _testChainId = chainId_;
        _testTokenContract = tokenContract_;
        _testTokenId = tokenId_;
    }

    function setTokenData(uint256 chainId_, address tokenContract_, uint256 tokenId_) external {
        _testChainId = chainId_;
        _testTokenContract = tokenContract_;
        _testTokenId = tokenId_;
    }

    function token() public view override returns (uint256 chainId, address tokenContract, uint256 tokenId) {
        return (_testChainId, _testTokenContract, _testTokenId);
    }
}

contract ERC6551DelegateProxy {
    constructor(address implementation, bytes32 salt, uint256 chainId, address tokenContract, uint256 tokenId) payable {
        bytes memory runtime = abi.encodePacked(
            hex"363d3d373d3d3d363d73",
            implementation,
            hex"5af43d82803e903d91602b57fd5bf3",
            abi.encode(salt, chainId, tokenContract, tokenId)
        );
        assembly {
            return(add(runtime, 0x20), mload(runtime))
        }
    }
}

contract MockTarget {
    uint256 public lastValue;
    bytes public lastData;

    function store(uint256 value, bytes calldata data) external payable returns (bytes32) {
        lastValue = value;
        lastData = data;
        return keccak256(data);
    }
}
