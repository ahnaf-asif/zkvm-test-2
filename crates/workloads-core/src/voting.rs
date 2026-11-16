use alloc::vec::Vec;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{finalize_journal, OutputPolicy};

/// W1 Input: Binary (b=1) and One-Hot Ballot Validation with Cryptographic Nullifiers.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct VotingBatchInput {
    pub ballots: Vec<Vec<u8>>, // n secret ballots, each of length k candidates
    pub salts: Vec<[u8; 32]>,  // n secret voter trapdoor salts for nullifiers
    pub policy: OutputPolicy,
}

/// Enforces R_vote(v^(i)) = 1: Boolean validity (v_{i,j} in {0,1}) and exact one-hot sum == 1,
/// deriving a 32-byte nullifier N_i = SHA256(s_i || v^(i)) for each validated ballot.
pub fn verify_voting_batch(input: &VotingBatchInput) -> Vec<u8> {
    assert_eq!(
        input.ballots.len(),
        input.salts.len(),
        "Batch length mismatch"
    );
    let mut commitments_payload = Vec::with_capacity(input.ballots.len() * 32);
    let mut valid_count: u32 = 0;

    for (ballot, salt) in input.ballots.iter().zip(input.salts.iter()) {
        assert!(!ballot.is_empty(), "Ballot candidate vector cannot be empty");
        let mut sum: u8 = 0;
        for &bit in ballot {
            assert!(bit == 0 || bit == 1, "Invalid non-binary vote bit");
            sum = sum.wrapping_add(bit);
        }
        assert!(sum == 1, "Ballot violates one-hot selection constraint");
        valid_count += 1;

        let mut item_hasher = Sha256::new();
        item_hasher.update(salt);
        item_hasher.update(ballot);
        commitments_payload.extend_from_slice(&item_hasher.finalize());
    }

    finalize_journal(commitments_payload, valid_count, input.policy)
}
