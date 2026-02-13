// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Vm} from "forge-std/Vm.sol";

import {SIWAAuthV1, SIWAClaimsV1} from "../../src/libraries/SIWATypes.sol";
import {GatewayClaimsV2} from "../../src/libraries/ERC8128Types.sol";
import {ERC8128CoreLib} from "../../src/libraries/ERC8128CoreLib.sol";

library SIWATestHelper {
    uint256 internal constant SECP256K1_N =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    function buildClaims(uint256 agentId, address registryAddress, uint256 registryChainId)
        internal
        pure
        returns (SIWAClaimsV1 memory)
    {
        return SIWAClaimsV1({agentId: agentId, registryAddress: registryAddress, registryChainId: registryChainId});
    }

    function computeClaimsHash(SIWAClaimsV1 memory claims) internal pure returns (bytes32) {
        return keccak256(abi.encode(claims));
    }

    function signRequestHash(Vm vm, uint256 privateKey, bytes32 requestHash)
        internal
        pure
        returns (bytes memory signature)
    {
        uint256 normalizedKey = _normalizePrivateKey(privateKey);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(normalizedKey, requestHash);
        signature = abi.encodePacked(r, s, v);
    }

    function buildAuth(
        Vm vm,
        uint256 privateKey,
        address signer,
        uint48 created,
        uint48 expires,
        bytes32 requestHash,
        SIWAClaimsV1 memory claims
    ) internal pure returns (SIWAAuthV1 memory auth) {
        auth = SIWAAuthV1({
            signer: signer,
            created: created,
            expires: expires,
            requestHash: requestHash,
            claimsHash: computeClaimsHash(claims),
            signature: signRequestHash(vm, privateKey, requestHash),
            claims: abi.encode(claims)
        });
    }

    function normalizePrivateKey(uint256 privateKey) internal pure returns (uint256) {
        return _normalizePrivateKey(privateKey);
    }

    function buildGatewayClaims(bytes32 requestHash) internal pure returns (GatewayClaimsV2 memory claims) {
        claims.methodBit = 1;
        claims.authorityHash = keccak256("api.example.com");
        claims.pathPrefixHash = keccak256("/v1");
        claims.isReadOnly = true;
        claims.allowReplayable = true;
        claims.allowClassBound = true;
        claims.maxBodyBytes = 4096;
        claims.isReplayable = false;
        claims.isClassBound = false;
        claims.nonceHash = keccak256(abi.encodePacked("nonce", requestHash));
        claims.scopeLeaf = ERC8128CoreLib.computeGatewayScopeLeaf(
            claims.methodBit,
            claims.authorityHash,
            claims.pathPrefixHash,
            claims.isReadOnly,
            claims.allowReplayable,
            claims.allowClassBound,
            claims.maxBodyBytes
        );
        claims.scopeProof = new bytes32[](0);
    }

    function computeGatewayClaimsHash(GatewayClaimsV2 memory claims) internal pure returns (bytes32) {
        return ERC8128CoreLib.computeGatewayClaimsHash(claims);
    }

    function buildGatewayAuth(
        Vm vm,
        uint256 privateKey,
        address signer,
        uint48 created,
        uint48 expires,
        bytes32 requestHash,
        GatewayClaimsV2 memory claims
    ) internal pure returns (SIWAAuthV1 memory auth) {
        auth = SIWAAuthV1({
            signer: signer,
            created: created,
            expires: expires,
            requestHash: requestHash,
            claimsHash: computeGatewayClaimsHash(claims),
            signature: signRequestHash(vm, privateKey, requestHash),
            claims: abi.encode(claims)
        });
    }

    function _normalizePrivateKey(uint256 privateKey) private pure returns (uint256) {
        if (privateKey == 0) {
            return 1;
        }
        if (privateKey < SECP256K1_N) {
            return privateKey;
        }
        return (privateKey % (SECP256K1_N - 1)) + 1;
    }
}
