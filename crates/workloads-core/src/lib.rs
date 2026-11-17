#![no_std]
extern crate alloc;

use alloc::vec::Vec;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tiny_keccak::{Hasher, Keccak};

pub mod allowlist;
pub mod auction;
pub mod bigint_mod;
pub mod hashing;
pub mod voting;

pub use allowlist::{verify_allowlist_membership, AllowlistInput};
pub use auction::{verify_auction_range, AuctionRangeInput};
pub use bigint_mod::{
    bigint_mod_exp_limbs, bigint_mul_mod_limbs, montgomery_inv32, verify_bigint_batch,
    BigIntBatchInput,
};
pub use hashing::{hash_bytes, hash_pair, verify_merkle_batch, MerkleBatchInput};
pub use voting::{verify_voting_batch, VotingBatchInput};

/// Cryptographic hash function selector for `W4` (`W4a` vs `W4b`) and Policy `P2` digest folding.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashAlg {
    Sha256,
    Keccak256,
}

/// Public Output Commitment Policy (`P_io`) governing host-to-EVM journal structure.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutputPolicy {
    /// Policy `P1`: Commit all `n` 32-byte item commitments + 4-byte count (`32 * n + 4` bytes).
    RawCommitArray,
    /// Policy `P2` (SHA-256): Fold into single 32-byte SHA-256 digest + 4-byte count (`36` bytes).
    HashCommit,
    /// Policy `P2` (Keccak-256): Fold into single 32-byte Keccak-256 digest + 4-byte count (`36` bytes).
    HashCommitKeccak,
}

/// Unified workload envelope enabling a single deterministic guest binary to dispatch `W1`..`W5`.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum WorkloadPayload {
    W1Voting(VotingBatchInput),
    W2Auction(AuctionRangeInput),
    W3Allowlist(AllowlistInput),
    W4Merkle(MerkleBatchInput),
    W5BigInt(BigIntBatchInput),
}

/// Dispatches any workload variant (`W1`..`W5`) and returns the serialized public journal bytes.
#[must_use]
pub fn execute_workload(payload: &WorkloadPayload) -> Vec<u8> {
    match payload {
        WorkloadPayload::W1Voting(input) => verify_voting_batch(input),
        WorkloadPayload::W2Auction(input) => verify_auction_range(input),
        WorkloadPayload::W3Allowlist(input) => verify_allowlist_membership(input),
        WorkloadPayload::W4Merkle(input) => verify_merkle_batch(input),
        WorkloadPayload::W5BigInt(input) => verify_bigint_batch(input),
    }
}

/// Finalizes the public journal according to [`OutputPolicy`] (defaulting [`OutputPolicy::HashCommit`] to SHA-256).
#[must_use]
pub fn finalize_journal(raw_commits: Vec<u8>, count: u32, policy: OutputPolicy) -> Vec<u8> {
    finalize_journal_with_alg(raw_commits, count, policy, HashAlg::Sha256)
}

/// Finalizes the public journal with explicit hash algorithm selection for [`OutputPolicy::HashCommit`] mode.
#[must_use]
pub fn finalize_journal_with_alg(
    mut raw_commits: Vec<u8>,
    count: u32,
    policy: OutputPolicy,
    default_alg: HashAlg,
) -> Vec<u8> {
    match policy {
        OutputPolicy::RawCommitArray => {
            raw_commits.extend_from_slice(&count.to_le_bytes());
            raw_commits
        }
        OutputPolicy::HashCommit => {
            let digest = match default_alg {
                HashAlg::Sha256 => {
                    let mut hasher = Sha256::new();
                    hasher.update(&raw_commits);
                    let d: [u8; 32] = hasher.finalize().into();
                    d
                }
                HashAlg::Keccak256 => {
                    let mut k = Keccak::v256();
                    let mut d = [0u8; 32];
                    k.update(&raw_commits);
                    k.finalize(&mut d);
                    d
                }
            };
            let mut out = Vec::with_capacity(36);
            out.extend_from_slice(&digest);
            out.extend_from_slice(&count.to_le_bytes());
            out
        }
        OutputPolicy::HashCommitKeccak => {
            let mut k = Keccak::v256();
            let mut digest = [0u8; 32];
            k.update(&raw_commits);
            k.finalize(&mut digest);
            let mut out = Vec::with_capacity(36);
            out.extend_from_slice(&digest);
            out.extend_from_slice(&count.to_le_bytes());
            out
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_w1_voting_valid_p1_and_p2() {
        let input_p1 = VotingBatchInput {
            ballots: vec![vec![0, 1, 0], vec![1, 0, 0]],
            salts: vec![[1u8; 32], [2u8; 32]],
            policy: OutputPolicy::RawCommitArray,
        };
        let journal_p1 = verify_voting_batch(&input_p1);
        assert_eq!(journal_p1.len(), 32 * 2 + 4);

        let mut input_p2 = input_p1;
        input_p2.policy = OutputPolicy::HashCommit;
        let journal_p2 = verify_voting_batch(&input_p2);
        assert_eq!(journal_p2.len(), 36);
    }

    #[test]
    #[should_panic(expected = "Ballot violates one-hot selection constraint")]
    fn test_w1_voting_rejects_multi_choice() {
        let bad = VotingBatchInput {
            ballots: vec![vec![1, 1, 0]],
            salts: vec![[0u8; 32]],
            policy: OutputPolicy::HashCommit,
        };
        let _ = verify_voting_batch(&bad);
    }

    #[test]
    fn test_w2_auction_range_across_bit_widths() {
        for &b in &[8u32, 16, 32, 64, 96, 120] {
            let input = AuctionRangeInput {
                bids_lo: vec![100, 250],
                bids_hi: vec![0, u64::from(b > 64)],
                blindings: vec![[3u8; 32], [4u8; 32]],
                bit_width: b,
                reserve_lo: 50,
                reserve_hi: 0,
                policy: OutputPolicy::HashCommit,
            };
            let out = verify_auction_range(&input);
            assert_eq!(out.len(), 36);
        }
    }

    #[test]
    #[should_panic(expected = "Bid exceeds 2^b")]
    fn test_w2_auction_rejects_overflow_bid() {
        let bad = AuctionRangeInput {
            bids_lo: vec![256], // >= 2^8
            bids_hi: vec![0],
            blindings: vec![[0u8; 32]],
            bit_width: 8,
            reserve_lo: 10,
            reserve_hi: 0,
            policy: OutputPolicy::HashCommit,
        };
        let _ = verify_auction_range(&bad);
    }

    #[test]
    fn test_w3_allowlist_valid_and_sorted() {
        let input = AllowlistInput {
            members: vec![20, 40],
            salts: vec![[5u8; 32], [6u8; 32]],
            allowlist: vec![10, 20, 30, 40, 50],
            policy: OutputPolicy::HashCommit,
        };
        let out = verify_allowlist_membership(&input);
        assert_eq!(out.len(), 36);
    }

    #[test]
    #[should_panic(expected = "Allowlist must be strictly sorted")]
    fn test_w3_allowlist_rejects_unsorted() {
        let bad = AllowlistInput {
            members: vec![20],
            salts: vec![[5u8; 32]],
            allowlist: vec![10, 30, 20],
            policy: OutputPolicy::HashCommit,
        };
        let _ = verify_allowlist_membership(&bad);
    }

    #[test]
    fn test_w4_merkle_sha256_and_keccak256() {
        for &alg in &[HashAlg::Sha256, HashAlg::Keccak256] {
            let leaf = [7u8; 32];
            let sib0 = [8u8; 32];
            let sib1 = [9u8; 32];
            let h0 = hash_pair(alg, &leaf, &sib0);
            let root = hash_pair(alg, &sib1, &h0);

            let input = MerkleBatchInput {
                leaves: vec![leaf],
                paths: vec![vec![sib0, sib1]],
                indices: vec![2],
                expected_root: root,
                hash_alg: alg,
                policy: OutputPolicy::HashCommit,
            };
            let out = verify_merkle_batch(&input);
            assert_eq!(out.len(), 36);
        }
    }

    #[test]
    fn test_w5_bigint_montgomery_mod_exp() {
        let k = 8; // 256-bit (8 x u32 limbs)
        let mut modulus = vec![0xFFFF_FFFDu32; k];
        modulus[0] = 0xFFFF_FFC3; // odd modulus
        let base = vec![0x1234_5678u32; k];

        let input = BigIntBatchInput {
            bases: vec![base],
            modulus,
            exponent: 17,
            policy: OutputPolicy::HashCommit,
        };
        let out = verify_bigint_batch(&input);
        assert_eq!(out.len(), 36);
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn test_w5_montgomery_exact_equivalence_against_u128() {
        let m: u64 = 0xFFFF_FFFF_FFFF_FFC5;
        let a: u64 = 0x1234_5678_9ABC_DEF1;
        let b: u64 = 0x0FED_CBA9_8765_4321;

        let m_limbs = [m as u32, (m >> 32) as u32];
        let a_limbs = [a as u32, (a >> 32) as u32];
        let b_limbs = [b as u32, (b >> 32) as u32];

        let res_limbs = bigint_mul_mod_limbs(&a_limbs, &b_limbs, &m_limbs);
        let res_u64 = u64::from(res_limbs[0]) | (u64::from(res_limbs[1]) << 32);

        let r_mod_m: u128 = (1u128 << 64) % u128::from(m);
        let lhs: u128 = (u128::from(res_u64) * r_mod_m) % u128::from(m);
        let rhs: u128 = (u128::from(a) * u128::from(b)) % u128::from(m);
        assert_eq!(
            lhs, rhs,
            "Montgomery reduction must satisfy res * R == a * b (mod M)"
        );
    }
}
