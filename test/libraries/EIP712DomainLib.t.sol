// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";

import {EIP712DomainLib} from "../../src/libraries/EIP712DomainLib.sol";

contract EIP712DomainLibHarness {
    function parse(string calldata encoded)
        external
        pure
        returns (string memory name, string memory version, uint256 chainId, address verifyingContract)
    {
        return EIP712DomainLib.parse(encoded);
    }
}

contract EIP712DomainLibTest is Test {
    EIP712DomainLibHarness private _harness;

    function setUp() public {
        _harness = new EIP712DomainLibHarness();
    }

    // **Feature: standalone-nft-agent-wallet, Property 10: EIP-712 domain serialization round trip**
    function testFuzz_Property10_EIP712DomainSerializationRoundTrip(
        uint256 chainId,
        address verifyingContract,
        uint64 nameSeed,
        uint64 versionSeed
    ) public {
        string memory name = string.concat("name-", Strings.toString(nameSeed));
        string memory version = string.concat("v-", Strings.toString(versionSeed));

        string memory encoded = EIP712DomainLib.serialize(name, version, chainId, verifyingContract);
        (
            string memory parsedName,
            string memory parsedVersion,
            uint256 parsedChainId,
            address parsedVerifyingContract
        ) = _harness.parse(encoded);

        assertEq(parsedName, name);
        assertEq(parsedVersion, version);
        assertEq(parsedChainId, chainId);
        assertEq(parsedVerifyingContract, verifyingContract);

        string memory reEncoded =
            EIP712DomainLib.serialize(parsedName, parsedVersion, parsedChainId, parsedVerifyingContract);
        assertEq(reEncoded, encoded);
    }

    function test_Parse_RevertsForInvalidFormat() public {
        vm.expectRevert(EIP712DomainLib.InvalidDomainFormat.selector);
        _harness.parse("EIP712Domain(name=\"a\",version=\"b\",chainId=1,verifyingContract=0x1234)");
    }
}
