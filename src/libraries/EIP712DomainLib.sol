// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";

/// @title EIP712DomainLib
/// @notice Serialize and parse canonical EIP-712 domain string representations
library EIP712DomainLib {
    error InvalidDomainFormat();
    error InvalidCharacter(uint8 charCode);

    bytes private constant PREFIX_NAME = 'EIP712Domain(name="';
    bytes private constant PREFIX_VERSION = ',version="';
    bytes private constant PREFIX_CHAIN_ID = ",chainId=";
    bytes private constant PREFIX_VERIFYING = ",verifyingContract=";

    function serialize(string memory name, string memory version, uint256 chainId, address verifyingContract)
        internal
        pure
        returns (string memory)
    {
        return string.concat(
            "EIP712Domain(name=\"",
            name,
            "\",version=\"",
            version,
            "\",chainId=",
            Strings.toString(chainId),
            ",verifyingContract=",
            Strings.toHexString(verifyingContract),
            ")"
        );
    }

    function parse(string memory encoded)
        internal
        pure
        returns (string memory name, string memory version, uint256 chainId, address verifyingContract)
    {
        bytes memory data = bytes(encoded);
        uint256 cursor = 0;

        cursor = _expect(data, cursor, PREFIX_NAME);
        (name, cursor) = _readQuotedString(data, cursor);

        cursor = _expect(data, cursor, PREFIX_VERSION);
        (version, cursor) = _readQuotedString(data, cursor);

        cursor = _expect(data, cursor, PREFIX_CHAIN_ID);
        (chainId, cursor) = _readUint(data, cursor);

        cursor = _expect(data, cursor, PREFIX_VERIFYING);
        (verifyingContract, cursor) = _readAddress(data, cursor);

        if (cursor != data.length) {
            revert InvalidDomainFormat();
        }
    }

    function _expect(bytes memory data, uint256 cursor, bytes memory expected) private pure returns (uint256) {
        if (cursor + expected.length > data.length) {
            revert InvalidDomainFormat();
        }

        for (uint256 i = 0; i < expected.length; i++) {
            if (data[cursor + i] != expected[i]) {
                revert InvalidDomainFormat();
            }
        }

        return cursor + expected.length;
    }

    function _readQuotedString(bytes memory data, uint256 cursor) private pure returns (string memory value, uint256 next) {
        uint256 start = cursor;
        while (cursor < data.length && data[cursor] != '"') {
            cursor++;
        }
        if (cursor >= data.length) {
            revert InvalidDomainFormat();
        }

        value = _sliceToString(data, start, cursor - start);
        next = cursor + 1;
    }

    function _readUint(bytes memory data, uint256 cursor) private pure returns (uint256 value, uint256 next) {
        uint256 start = cursor;
        while (cursor < data.length && data[cursor] >= "0" && data[cursor] <= "9") {
            value = value * 10 + (uint8(data[cursor]) - 48);
            cursor++;
        }

        if (cursor == start) {
            revert InvalidDomainFormat();
        }

        next = cursor;
    }

    function _readAddress(bytes memory data, uint256 cursor) private pure returns (address parsed, uint256 next) {
        if (cursor + 43 > data.length) {
            revert InvalidDomainFormat();
        }
        if (data[cursor] != "0" || data[cursor + 1] != "x") {
            revert InvalidDomainFormat();
        }

        uint160 acc = 0;
        for (uint256 i = 0; i < 40; i++) {
            acc = (acc << 4) | _hexNibble(uint8(data[cursor + 2 + i]));
        }

        uint256 end = cursor + 42;
        if (data[end] != ")") {
            revert InvalidDomainFormat();
        }

        parsed = address(acc);
        next = end + 1;
    }

    function _hexNibble(uint8 c) private pure returns (uint160) {
        if (c >= 48 && c <= 57) {
            return uint160(c - 48);
        }
        if (c >= 65 && c <= 70) {
            return uint160(c - 55);
        }
        if (c >= 97 && c <= 102) {
            return uint160(c - 87);
        }
        revert InvalidCharacter(c);
    }

    function _sliceToString(bytes memory data, uint256 start, uint256 len) private pure returns (string memory) {
        bytes memory out = new bytes(len);
        for (uint256 i = 0; i < len; i++) {
            out[i] = data[start + i];
        }
        return string(out);
    }
}
