use alloc::vec::Vec;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tiny_keccak::{Hasher, Keccak};

use crate::{finalize_journal_with_alg, HashAlg, OutputPolicy};

/// Compute a 32-byte digest over a single slice using the requested hash algorithm.
#[inline]
pub fn hash_bytes(alg: HashAlg, data: &[u8]) -> [u8; 32] {
    match alg {
        HashAlg::Sha256 => {
            let mut h = Sha256::new();
            h.update(data);
            h.finalize().into()
        }
        HashAlg::Keccak256 => {
            let mut k = Keccak::v256();
            let mut out = [0u8; 32];
            k.update(data);
            k.finalize(&mut out);
            out
        }
    }
}

/// Compute a 32-byte digest over two concatenated slices `left || right`.
#[inline]
pub fn hash_pair(alg: HashAlg, left: &[u8], right: &[u8]) -> [u8; 32] {
    match alg {
        HashAlg::Sha256 => {
            let mut h = Sha256::new();
            h.update(left);
            h.update(right);
            h.finalize().into()
        }
        HashAlg::Keccak256 => {
            let mut k = Keccak::v256();
            let mut out = [0u8; 32];
            k.update(left);
            k.update(right);
            k.finalize(&mut out);
            out
        }
    }
}

/// W4 Input: Cryptographic State & Merkle Membership Checks (SHA-256 W4a & Keccak-256 W4b).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MerkleBatchInput {
    pub leaves: Vec<[u8; 32]>,       // n secret leaves
    pub paths: Vec<Vec<[u8; 32]>>,   // d=8 sibling hashes per leaf
    pub indices: Vec<u32>,           // Leaf position bits
    pub expected_root: [u8; 32],     // Public Merkle state root
    pub hash_alg: HashAlg,           // W4a (Sha256) vs W4b (Keccak256)
    pub policy: OutputPolicy,
}

/// Verifies n Merkle inclusion paths of depth d under SHA-256 (W4a) or Keccak-256 (W4b).
pub fn verify_merkle_batch(input: &MerkleBatchInput) -> Vec<u8> {
    let n = input.leaves.len();
    assert_eq!(n, input.paths.len(), "Leaves and paths length mismatch");
    assert_eq!(n, input.indices.len(), "Leaves and indices length mismatch");

    let mut payload = Vec::with_capacity(n * 32);
    for i in 0..n {
        let mut curr = input.leaves[i];
        let mut idx = input.indices[i];
        for sibling in &input.paths[i] {
            curr = if (idx & 1) == 0 {
                hash_pair(input.hash_alg, &curr, sibling)
            } else {
                hash_pair(input.hash_alg, sibling, &curr)
            };
            idx >>= 1;
        }
        assert_eq!(curr, input.expected_root, "Merkle path verification failed");
        payload.extend_from_slice(&input.leaves[i]);
    }
    finalize_journal_with_alg(payload, n as u32, input.policy, input.hash_alg)
}
