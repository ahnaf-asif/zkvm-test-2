use alloc::vec::Vec;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{finalize_journal, OutputPolicy};

/// `W3` Input: Set-Membership and Allowlist Validation (`M in {16, 64, 256}`).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AllowlistInput {
    pub members: Vec<u64>,    // n secret participant IDs
    pub salts: Vec<[u8; 32]>, // n secret nullifier salts
    pub allowlist: Vec<u64>,  // Sorted public allowlist S of size M
    pub policy: OutputPolicy,
}

/// Verifies strict ascending order of `S` (`a_1 < a_2 < ... < a_M`), proves membership via `O(log_2 M)`
/// binary search for each secret participant `m_i`, and commits salted participant nullifiers + allowlist root.
///
/// # Panics
///
/// Panics if the allowlist is empty or unsorted, if `members` and `salts` differ in length,
/// or if any member is not present in the allowlist.
#[must_use]
#[allow(clippy::cast_possible_truncation)]
pub fn verify_allowlist_membership(input: &AllowlistInput) -> Vec<u8> {
    assert!(!input.allowlist.is_empty(), "Allowlist cannot be empty");
    assert_eq!(
        input.members.len(),
        input.salts.len(),
        "Members and salts length mismatch"
    );

    for w in input.allowlist.windows(2) {
        assert!(w[0] < w[1], "Allowlist must be strictly sorted");
    }

    let mut root_hasher = Sha256::new();
    for &entry in &input.allowlist {
        root_hasher.update(entry.to_le_bytes());
    }
    let allowlist_root: [u8; 32] = root_hasher.finalize().into();

    let mut payload = Vec::with_capacity(input.members.len() * 32);
    for (m, salt) in input.members.iter().zip(input.salts.iter()) {
        assert!(
            input.allowlist.binary_search(m).is_ok(),
            "Member not in allowlist"
        );
        let mut h = Sha256::new();
        h.update(m.to_le_bytes());
        h.update(salt);
        h.update(allowlist_root);
        payload.extend_from_slice(&h.finalize());
    }

    finalize_journal(payload, input.members.len() as u32, input.policy)
}
