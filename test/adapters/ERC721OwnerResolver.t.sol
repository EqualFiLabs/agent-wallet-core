// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {ERC721} from "@openzeppelin/contracts/token/ERC721/ERC721.sol";

import {ERC721OwnerResolver} from "../../src/adapters/ERC721OwnerResolver.sol";

contract ResolverMockNFT is ERC721 {
    constructor() ERC721("ResolverMockNFT", "RMN") {}

    function mint(address to, uint256 tokenId) external {
        _mint(to, tokenId);
    }
}

contract ERC721OwnerResolverTest is Test {
    function test_ResolveOwner_ReturnsZeroForChainMismatch() public {
        ERC721OwnerResolver resolver = new ERC721OwnerResolver();
        address owner = resolver.resolveOwner(block.chainid + 1, address(0x1234), 1);
        assertEq(owner, address(0));
    }

    function test_ResolveOwner_ReturnsZeroForZeroTokenContract() public {
        ERC721OwnerResolver resolver = new ERC721OwnerResolver();
        address owner = resolver.resolveOwner(block.chainid, address(0), 1);
        assertEq(owner, address(0));
    }

    function testFuzz_ResolveOwner_UsesOwnerOf(uint96 tokenIdSeed, uint256 ownerKeySeed) public {
        uint256 tokenId = uint256(tokenIdSeed) + 1;
        uint256 ownerKey = bound(ownerKeySeed, 1, type(uint128).max);
        address tokenOwner = vm.addr(ownerKey);

        ResolverMockNFT token = new ResolverMockNFT();
        token.mint(tokenOwner, tokenId);

        ERC721OwnerResolver resolver = new ERC721OwnerResolver();
        address owner = resolver.resolveOwner(block.chainid, address(token), tokenId);
        assertEq(owner, tokenOwner);
    }
}
