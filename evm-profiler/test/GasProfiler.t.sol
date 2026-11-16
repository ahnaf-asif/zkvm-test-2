// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/BenchmarkSettlement.sol";
import "../src/verifiers/IZkVMVerifier.sol";

/// Mock verifier for smoke-testing EIP-2028 calldata and P1 vs P2 journal hashing divergence
/// before real Groth16 / PLONK fixtures are loaded from proofs/.
contract MockBn254Verifier is IZkVMVerifier {
    function verifyProof(
        bytes32,
        bytes calldata,
        bytes calldata proofBytes
    ) external pure override {
        require(proofBytes.length >= 256, "Invalid SNARK proof length");
    }
}

contract GasProfilerTest is Test {
    IZkVMVerifier public verifier;
    BenchmarkSettlement public settlement;

    function setUp() public {
        verifier = new MockBn254Verifier();
        settlement = new BenchmarkSettlement(address(verifier));
    }

    function test_ProfileP1_vs_P2_GasDivergence() public {
        bytes32 vkey = bytes32(uint256(0x123456));
        bytes memory proof = new bytes(260); // Standard Groth16 proof size
        for (uint256 i = 0; i < proof.length; i++) {
            proof[i] = bytes1(uint8((i % 251) + 1));
        }

        // Batch size n = 64
        // P1 journal: 32 * 64 + 4 = 2052 bytes
        bytes memory pubP1 = new bytes(32 * 64 + 4);
        for (uint256 i = 0; i < pubP1.length; i++) {
            pubP1[i] = bytes1(uint8(((i * 31) % 255) + 1));
        }

        // P2 journal: 36 bytes (32-byte digest + 4-byte count)
        bytes memory pubP2 = new bytes(36);
        for (uint256 i = 0; i < 32; i++) {
            pubP2[i] = bytes1(uint8(i + 1));
        }
        pubP2[32] = 0x40; // n = 64 in little-endian

        // 1. P1 (SHA-256)
        uint256 dataGasP1Sha = computeCalldataGas(
            abi.encodeCall(BenchmarkSettlement.settleRawCommitArraySha256, (vkey, pubP1, proof))
        );
        uint256 g0 = gasleft();
        settlement.settleRawCommitArraySha256(vkey, pubP1, proof);
        uint256 execGasP1Sha = g0 - gasleft();
        uint256 totalP1Sha = 21000 + dataGasP1Sha + execGasP1Sha;

        // 2. P1 (Keccak-256)
        uint256 dataGasP1Keccak = computeCalldataGas(
            abi.encodeCall(BenchmarkSettlement.settleRawCommitArrayKeccak, (vkey, pubP1, proof))
        );
        uint256 g1 = gasleft();
        settlement.settleRawCommitArrayKeccak(vkey, pubP1, proof);
        uint256 execGasP1Keccak = g1 - gasleft();
        uint256 totalP1Keccak = 21000 + dataGasP1Keccak + execGasP1Keccak;

        // 3. P2 (HashCommit O(1))
        uint256 dataGasP2 = computeCalldataGas(
            abi.encodeCall(BenchmarkSettlement.settleHashCommit, (vkey, pubP2, proof))
        );
        uint256 g2 = gasleft();
        settlement.settleHashCommit(vkey, pubP2, proof);
        uint256 execGasP2 = g2 - gasleft();
        uint256 totalP2 = 21000 + dataGasP2 + execGasP2;

        emit log_named_uint("P1_SHA256_Total_Gas_n64", totalP1Sha);
        emit log_named_uint("P1_Keccak_Total_Gas_n64", totalP1Keccak);
        emit log_named_uint("P2_HashCommit_Total_Gas_n64", totalP2);

        // Verify mathematical guarantee (Equation 6): P1 costs significantly more than P2 at n=64
        assertGt(totalP1Sha, totalP2 + 30000);
        assertGt(totalP1Keccak, totalP2 + 30000);
    }

    function computeCalldataGas(bytes memory data) internal pure returns (uint256 gasCost) {
        for (uint256 i = 0; i < data.length; i++) {
            gasCost += (data[i] == 0) ? 4 : 16; // EIP-2028 calldata pricing
        }
    }
}
