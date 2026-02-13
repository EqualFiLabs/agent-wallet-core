// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";

import {SIWACoreLib} from "../../src/libraries/SIWACoreLib.sol";
import {SIWAAuthV1, SIWAClaimsV1} from "../../src/libraries/SIWATypes.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";

contract SIWACoreLibHarness {
    function encodeSIWAAuth(SIWAAuthV1 calldata auth) external pure returns (bytes memory) {
        return abi.encode(auth);
    }

    function decodeSIWAAuth(bytes calldata data) external pure returns (SIWAAuthV1 memory auth) {
        auth = abi.decode(data, (SIWAAuthV1));
    }

    function computeSIWAClaimsHash(SIWAClaimsV1 calldata claims) external pure returns (bytes32) {
        return SIWACoreLib.computeSIWAClaimsHash(claims);
    }

    function isValidSIWASigner(address account, address signer, bytes32 digest, bytes calldata signature)
        external
        view
        returns (bool)
    {
        return SIWACoreLib.isValidSIWASigner(account, signer, digest, signature);
    }
}

contract MockSIWA1271Signer is IERC1271 {
    address public immutable signer;

    constructor(address signer_) {
        signer = signer_;
    }

    function isValidSignature(bytes32 hash, bytes memory signature) external view returns (bytes4) {
        (uint8 v, bytes32 r, bytes32 s) = _split(signature);
        address recovered = ecrecover(hash, v, r, s);
        if (recovered == signer) {
            return IERC1271.isValidSignature.selector;
        }
        return 0xffffffff;
    }

    function _split(bytes memory signature) private pure returns (uint8 v, bytes32 r, bytes32 s) {
        if (signature.length != 65) {
            return (0, bytes32(0), bytes32(0));
        }

        assembly {
            r := mload(add(signature, 0x20))
            s := mload(add(signature, 0x40))
            v := byte(0, mload(add(signature, 0x60)))
        }
    }
}

contract MockReverting1271Account is IERC1271 {
    function isValidSignature(bytes32, bytes memory) external pure returns (bytes4) {
        revert("revert-account-1271");
    }
}

contract SIWATypesAndCoreLibTest is Test {
    uint256 internal constant SECP256K1_N =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    SIWACoreLibHarness private _harness;

    function setUp() public {
        _harness = new SIWACoreLibHarness();
    }

    // **Feature: siwa-compat-layer, Property 1: SIWAAuthV1 ABI Encoding Round-Trip**
    function testFuzz_Property1_SIWAAuthV1ABIEncodingRoundTrip(
        address signer,
        uint48 created,
        uint48 expires,
        bytes32 requestHash,
        bytes32 claimsHash,
        bytes calldata signature,
        bytes calldata claims
    ) public view {
        SIWAAuthV1 memory original = SIWAAuthV1({
            signer: signer,
            created: created,
            expires: expires,
            requestHash: requestHash,
            claimsHash: claimsHash,
            signature: signature,
            claims: claims
        });

        bytes memory encoded = _harness.encodeSIWAAuth(original);
        SIWAAuthV1 memory decoded = _harness.decodeSIWAAuth(encoded);

        assertEq(decoded.signer, original.signer);
        assertEq(decoded.created, original.created);
        assertEq(decoded.expires, original.expires);
        assertEq(decoded.requestHash, original.requestHash);
        assertEq(decoded.claimsHash, original.claimsHash);
        assertEq(keccak256(decoded.signature), keccak256(original.signature));
        assertEq(keccak256(decoded.claims), keccak256(original.claims));
    }

    // **Feature: siwa-compat-layer, Property 10: Claims Hash Determinism**
    function testFuzz_Property10_ClaimsHashDeterminism(
        uint256 agentId,
        address registryAddress,
        uint256 registryChainId
    ) public view {
        SIWAClaimsV1 memory claims = SIWAClaimsV1({
            agentId: agentId,
            registryAddress: registryAddress,
            registryChainId: registryChainId
        });

        bytes32 expected = keccak256(abi.encode(claims));
        bytes32 actual = _harness.computeSIWAClaimsHash(claims);
        assertEq(actual, expected);
    }

    // **Feature: siwa-compat-layer, Property 11: SIWA Signer Verification Correctness**
    function testFuzz_Property11_SIWASignerVerificationCorrectness(
        uint256 signerKeySeed,
        uint256 otherKeySeed,
        bytes32 digest
    ) public {
        uint256 signerKey = bound(signerKeySeed, 1, SECP256K1_N - 1);
        uint256 otherKey = bound(otherKeySeed, 1, SECP256K1_N - 1);
        vm.assume(signerKey != otherKey);

        address signer = vm.addr(signerKey);
        address otherSigner = vm.addr(otherKey);

        bytes memory validSig = _sign(signerKey, digest);
        bytes memory invalidSig = _sign(otherKey, digest);

        assertTrue(_harness.isValidSIWASigner(address(0xA11CE), signer, digest, validSig));
        assertFalse(_harness.isValidSIWASigner(address(0xA11CE), signer, digest, invalidSig));

        MockSIWA1271Signer scaSigner = new MockSIWA1271Signer(signer);
        assertTrue(_harness.isValidSIWASigner(address(0xA11CE), address(scaSigner), digest, validSig));
        assertFalse(_harness.isValidSIWASigner(address(0xA11CE), address(scaSigner), digest, invalidSig));

        MockReverting1271Account account = new MockReverting1271Account();
        assertFalse(_harness.isValidSIWASigner(address(account), address(account), digest, validSig));

        // Ensure signer path does not depend on account ERC-1271 when signer != account.
        MockSIWA1271Signer otherScaSigner = new MockSIWA1271Signer(otherSigner);
        bytes memory otherSig = _sign(otherKey, digest);
        assertTrue(_harness.isValidSIWASigner(address(account), address(otherScaSigner), digest, otherSig));
    }

    function _sign(uint256 key, bytes32 digest) internal pure returns (bytes memory signature) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest);
        signature = abi.encodePacked(r, s, v);
    }
}
