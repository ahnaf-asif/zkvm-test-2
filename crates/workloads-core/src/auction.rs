use alloc::vec::Vec;
use core::cmp::Ordering;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{finalize_journal, OutputPolicy};

/// `W2` Input: Numerical Range Validation with Bid Commitments (`b in {8, 16, 32, 64, 96, 120}`).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AuctionRangeInput {
    pub bids_lo: Vec<u64>,        // Lower 64 bits of secret bid u_i
    pub bids_hi: Vec<u64>,        // Upper 64 bits of secret bid u_i (for b > 64)
    pub blindings: Vec<[u8; 32]>, // Secret blinding factors r_i for bid commitments
    pub bit_width: u32,           // b in {8, 16, 32, 64, 96, 120}
    pub reserve_lo: u64,          // Reserve price R_min (lower 64 bits)
    pub reserve_hi: u64,          // Reserve price R_min (upper 64 bits)
    pub policy: OutputPolicy,
}

/// Enforces `R_range(u_i, b, R_min) = 1 <==> R_min <= u_i < 2^b` over two-word `(u64, u64)` pairs
/// so LLVM `instcombine` cannot eliminate upper bounds as dead code, then commits `C_i = SHA256(u_i || r_i)`.
///
/// # Panics
///
/// Panics if input slice lengths mismatch, if `bit_width` is outside `1..127`, or if any bid
/// falls below the reserve price or exceeds `2^b`.
#[must_use]
#[allow(clippy::cast_possible_truncation)]
pub fn verify_auction_range(input: &AuctionRangeInput) -> Vec<u8> {
    let n = input.bids_lo.len();
    assert_eq!(
        n,
        input.bids_hi.len(),
        "bids_lo and bids_hi length mismatch"
    );
    assert_eq!(
        n,
        input.blindings.len(),
        "bids_lo and blindings length mismatch"
    );
    assert!(
        input.bit_width >= 1 && input.bit_width < 128,
        "bit_width must be in 1..127 to prevent u128 tautology elimination"
    );

    let mut commitments_payload = Vec::with_capacity(n * 32);
    for idx in 0..n {
        let lo = input.bids_lo[idx];
        let hi = input.bids_hi[idx];
        let ge_reserve =
            (hi > input.reserve_hi) || (hi == input.reserve_hi && lo >= input.reserve_lo);
        assert!(ge_reserve, "Bid below 128-bit reserve price");

        match input.bit_width.cmp(&64) {
            Ordering::Less => {
                let bound_lo: u64 = 1u64 << input.bit_width;
                assert!(hi == 0 && lo < bound_lo, "Bid exceeds 2^b (b < 64)");
            }
            Ordering::Equal => {
                assert!(hi == 0, "Bid exceeds 2^64");
            }
            Ordering::Greater => {
                let bound_hi: u64 = 1u64 << (input.bit_width - 64);
                assert!(hi < bound_hi, "Bid exceeds 2^b (64 < b < 128)");
            }
        }

        let mut bid_hasher = Sha256::new();
        bid_hasher.update(lo.to_le_bytes());
        bid_hasher.update(hi.to_le_bytes());
        bid_hasher.update(input.blindings[idx]);
        commitments_payload.extend_from_slice(&bid_hasher.finalize());
    }

    finalize_journal(commitments_payload, n as u32, input.policy)
}
