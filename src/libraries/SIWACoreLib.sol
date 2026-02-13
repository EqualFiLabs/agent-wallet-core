// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";

import {SIWAClaimsV1} from "./SIWATypes.sol";

/// @title SIWACoreLib
/// @notice Shared SIWA compatibility helpers for claims hashing and signer verification.
library SIWACoreLib {
    bytes4 internal constant ERC1271_MAGICVALUE = IERC1271.isValidSignature.selector;

    function computeSIWAClaimsHash(SIWAClaimsV1 memory claims) internal pure returns (bytes32) {
        return keccak256(abi.encode(claims));
    }

    function isValidSIWASigner(address account, address signer, bytes32 digest, bytes memory signature)
        internal
        view
        returns (bool)
    {
        if (signer.code.length == 0) {
            (address recovered, ECDSA.RecoverError err, ) = ECDSA.tryRecover(digest, signature);
            return err == ECDSA.RecoverError.NoError && recovered == signer;
        }

        if (signer == account) {
            return false;
        }

        (bool ok, bytes memory data) =
            signer.staticcall(abi.encodeWithSelector(IERC1271.isValidSignature.selector, digest, signature));
        return ok && data.length == 32 && bytes4(data) == ERC1271_MAGICVALUE;
    }
}
