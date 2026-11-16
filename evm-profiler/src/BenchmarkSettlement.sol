// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./verifiers/IZkVMVerifier.sol";

contract BenchmarkSettlement {
    IZkVMVerifier public immutable verifier;
    bytes32 public latestBatchDigest;

    constructor(address _verifier) {
        verifier = IZkVMVerifier(_verifier);
    }

    /// Policy P1 (RawCommitArray + Keccak-256): Hashes 32*n + 4 bytes on-chain via opcode 0x20 (30 + 6*words gas)
    function settleRawCommitArrayKeccak(
        bytes32 programVKey,
        bytes calldata publicValues,
        bytes calldata proofBytes
    ) external {
        verifier.verifyProof(programVKey, publicValues, proofBytes);
        latestBatchDigest = keccak256(publicValues);
    }

    /// Policy P1 (RawCommitArray + SHA-256): Hashes 32*n + 4 bytes on-chain via precompile 0x02 (60 + 12*words gas)
    function settleRawCommitArraySha256(
        bytes32 programVKey,
        bytes calldata publicValues,
        bytes calldata proofBytes
    ) external {
        verifier.verifyProof(programVKey, publicValues, proofBytes);
        latestBatchDigest = sha256(publicValues);
    }

    /// Policy P2 (HashCommit): O(1) constant 36-byte folded journal (32-byte digest + 4-byte batch count)
    function settleHashCommit(
        bytes32 programVKey,
        bytes calldata publicValues,
        bytes calldata proofBytes
    ) external {
        require(publicValues.length == 36, "Invalid P2 journal length");
        verifier.verifyProof(programVKey, publicValues, proofBytes);
        bytes32 digest;
        assembly {
            digest := calldataload(publicValues.offset)
        }
        latestBatchDigest = digest;
    }
}
