// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {IBeacon} from "@openzeppelin/contracts/proxy/beacon/IBeacon.sol";

import {BeaconProxy} from "../../src/core/BeaconProxy.sol";
import {ERC721BoundMSCA} from "../../src/core/ERC721BoundMSCA.sol";
import {IERC6551Account} from "../../src/interfaces/IERC6551Account.sol";
import {IERC6551Registry} from "../../src/interfaces/IERC6551Registry.sol";
import {ERC6551DelegateProxy, MockERC721} from "../mocks/CoreTestMocks.sol";

contract MockERC6551Registry is IERC6551Registry {
    function createAccount(
        address implementation,
        bytes32 salt,
        uint256 chainId,
        address tokenContract,
        uint256 tokenId
    ) external returns (address accountAddress) {
        accountAddress = account(implementation, salt, chainId, tokenContract, tokenId);
        if (accountAddress.code.length != 0) {
            return accountAddress;
        }

        bytes memory initCode = abi.encodePacked(
            type(ERC6551DelegateProxy).creationCode,
            abi.encode(implementation, salt, chainId, tokenContract, tokenId)
        );
        assembly {
            accountAddress := create2(0, add(initCode, 0x20), mload(initCode), salt)
            if iszero(accountAddress) { revert(0, 0) }
        }
    }

    function account(address implementation, bytes32 salt, uint256 chainId, address tokenContract, uint256 tokenId)
        public
        view
        returns (address accountAddress)
    {
        bytes memory initCode = abi.encodePacked(
            type(ERC6551DelegateProxy).creationCode,
            abi.encode(implementation, salt, chainId, tokenContract, tokenId)
        );
        bytes32 initCodeHash = keccak256(initCode);
        accountAddress =
            address(uint160(uint256(keccak256(abi.encodePacked(bytes1(0xff), address(this), salt, initCodeHash)))));
    }
}

contract IntegrationMockBeacon is IBeacon {
    address private _implementation;

    constructor(address implementation_) {
        _implementation = implementation_;
    }

    function implementation() external view returns (address) {
        return _implementation;
    }
}

contract ERC6551RegistryBeaconIntegrationTest is Test {
    function test_Integration_ProxyCreatedAccountStartsWithBootstrapEnabledAndAcceptsOwnerERC1271Signature() public {
        address entryPoint = makeAddr("entryPoint");
        uint256 ownerPk = 0xA11CE;
        address owner = vm.addr(ownerPk);
        bytes32 salt = keccak256("erc6551-bootstrap-account");
        uint256 tokenId = 7;
        bytes32 digest = keccak256("erc6551-bootstrap-signature");

        MockERC721 token = new MockERC721();
        token.mint(owner, tokenId);

        ERC721BoundMSCA accountImplementation = new ERC721BoundMSCA(entryPoint);
        IntegrationMockBeacon beacon = new IntegrationMockBeacon(address(accountImplementation));
        BeaconProxy beaconProxyImplementation = new BeaconProxy(address(beacon));
        MockERC6551Registry registry = new MockERC6551Registry();

        address accountAddress = registry.createAccount(
            address(beaconProxyImplementation), salt, block.chainid, address(token), tokenId
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPk, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        assertTrue(ERC721BoundMSCA(payable(accountAddress)).bootstrapActive());
        assertEq(IERC1271(accountAddress).isValidSignature(digest, signature), IERC1271.isValidSignature.selector);
    }

    function test_Integration_EndToEndRegistryBeaconProxyAccountCreationOwnershipResolution() public {
        address entryPoint = makeAddr("entryPoint");
        address initialOwner = makeAddr("initialOwner");
        address newOwner = makeAddr("newOwner");
        bytes32 salt = keccak256("erc6551-account");
        uint256 tokenId = 42;

        MockERC721 token = new MockERC721();
        token.mint(initialOwner, tokenId);

        ERC721BoundMSCA accountImplementation = new ERC721BoundMSCA(entryPoint);
        IntegrationMockBeacon beacon = new IntegrationMockBeacon(address(accountImplementation));
        BeaconProxy beaconProxyImplementation = new BeaconProxy(address(beacon));
        MockERC6551Registry registry = new MockERC6551Registry();

        address predicted = registry.account(
            address(beaconProxyImplementation), salt, block.chainid, address(token), tokenId
        );
        address accountAddress = registry.createAccount(
            address(beaconProxyImplementation), salt, block.chainid, address(token), tokenId
        );

        assertEq(accountAddress, predicted);
        assertTrue(accountAddress.code.length > 0);
        assertEq(IERC6551Account(accountAddress).owner(), initialOwner);

        (uint256 boundChainId, address boundToken, uint256 boundTokenId) = IERC6551Account(accountAddress).token();
        assertEq(boundChainId, block.chainid);
        assertEq(boundToken, address(token));
        assertEq(boundTokenId, tokenId);

        vm.prank(initialOwner);
        token.transferFrom(initialOwner, newOwner, tokenId);
        assertEq(IERC6551Account(accountAddress).owner(), newOwner);
    }
}
