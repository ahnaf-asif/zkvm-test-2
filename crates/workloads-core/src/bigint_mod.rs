use alloc::vec::Vec;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{finalize_journal, OutputPolicy};

/// `W5` Input: Deterministic Fixed-Limb Multi-Precision Modular Arithmetic
/// over `L`-bit integers (`L in {256, 512, 1024, 2048}`, `k = L / 32` limbs of type `u32`).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BigIntBatchInput {
    pub bases: Vec<Vec<u32>>, // n base integers x_i, each of k u32 limbs (little-endian)
    pub modulus: Vec<u32>,    // Odd L-bit modulus M_L of k u32 limbs (little-endian)
    pub exponent: u32,        // Public exponent e (e.g., 65537)
    pub policy: OutputPolicy,
}

/// Computes `-m_0^{-1} mod 2^32` using Hensel lifting (`Newton-Raphson` over `Z / 2^32 Z`)
/// using pure `u32` wrapping multiplications (zero division instructions for `RV32I` compatibility).
#[inline]
#[must_use]
pub fn montgomery_inv32(m0: u32) -> u32 {
    debug_assert!(m0 & 1 == 1, "Modulus must be odd for Montgomery reduction");
    let mut inv: u32 = 1;
    for _ in 0..5 {
        inv = inv.wrapping_mul(2u32.wrapping_sub(m0.wrapping_mul(inv)));
    }
    inv.wrapping_neg()
}

/// Multi-precision fixed-limb modular multiplication over `[u32; k]` using schoolbook
/// `O(k^2)` multiplication followed by Montgomery reduction over all `2k` limbs.
///
/// Crucially, every upper limb (`prod[k..2*k]`) and lower limb (`prod[0..k]`) contributes to the
/// reduced `k`-limb output, preventing LLVM Dead Store Elimination (DSE) while avoiding `u128`
/// division traps on `RV32I` targets (Jolt and Nexus).
///
/// # Panics
///
/// Panics if `modulus` is empty or even, or if `a` or `b` differ in limb length from `modulus`.
#[must_use]
#[allow(
    clippy::many_single_char_names,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
pub fn bigint_mul_mod_limbs(a: &[u32], b: &[u32], modulus: &[u32]) -> Vec<u32> {
    let k = modulus.len();
    assert!(k > 0, "Limb length k must be positive");
    assert_eq!(a.len(), k, "Operand a limb count mismatch");
    assert_eq!(b.len(), k, "Operand b limb count mismatch");
    assert!(modulus[0] & 1 == 1, "Modulus must be odd");

    // 1. Schoolbook k x k -> 2k limb multiplication (u32 * u32 -> u64 carry propagation)
    let mut prod = alloc::vec![0u32; k * 2 + 1];
    for i in 0..k {
        let mut carry: u64 = 0;
        for j in 0..k {
            let t = u64::from(prod[i + j]) + u64::from(a[i]) * u64::from(b[j]) + carry;
            prod[i + j] = t as u32;
            carry = t >> 32;
        }
        prod[i + k] = carry as u32;
    }

    // 2. Multi-precision Montgomery reduction across all 2k limbs
    let m_prime = montgomery_inv32(modulus[0]);
    for i in 0..k {
        let u = prod[i].wrapping_mul(m_prime);
        let mut carry: u64 = 0;
        for j in 0..k {
            let t = u64::from(prod[i + j]) + u64::from(u) * u64::from(modulus[j]) + carry;
            prod[i + j] = t as u32;
            carry = t >> 32;
        }
        let mut idx = i + k;
        while carry > 0 && idx < prod.len() {
            let sum = u64::from(prod[idx]) + carry;
            prod[idx] = sum as u32;
            carry = sum >> 32;
            idx += 1;
        }
    }

    // 3. Extract the upper reduced limbs prod[k..2*k] and perform conditional subtraction of modulus
    let mut out = prod[k..2 * k].to_vec();
    let mut sub = alloc::vec![0u32; k];
    let mut borrow: i64 = 0;
    for i in 0..k {
        let diff = i64::from(out[i]) - i64::from(modulus[i]) - borrow;
        if diff < 0 {
            sub[i] = (diff + (1i64 << 32)) as u32;
            borrow = 1;
        } else {
            sub[i] = diff as u32;
            borrow = 0;
        }
    }

    if prod[2 * k] > 0 || borrow == 0 {
        sub
    } else {
        out.copy_from_slice(&prod[k..2 * k]);
        out
    }
}

/// Square-and-multiply modular exponentiation `z_i = x_i^e (mod M_L)` in the Montgomery domain
/// over `k`-limb `u32` arrays.
///
/// # Panics
///
/// Panics if `exp == 0` or if `base` and `modulus` have invalid limb lengths.
#[must_use]
pub fn bigint_mod_exp_limbs(base: &[u32], exp: u32, modulus: &[u32]) -> Vec<u32> {
    let k = modulus.len();
    assert!(exp > 0, "Exponent must be positive");
    let mut acc = base.to_vec();
    let mut cur = base.to_vec();
    let mut e = exp - 1;
    while e > 0 {
        if (e & 1) == 1 {
            acc = bigint_mul_mod_limbs(&acc, &cur, modulus);
        }
        e >>= 1;
        if e > 0 {
            cur = bigint_mul_mod_limbs(&cur, &cur, modulus);
        }
    }
    debug_assert_eq!(acc.len(), k);
    acc
}

/// `W5` Batch Predicate: Executes `n` fixed-limb modular exponentiations over `L`-bit moduli
/// (`k in {8, 16, 32, 64}` limbs) and commits SHA-256 digests of the resulting `k`-limb vectors.
///
/// # Panics
///
/// Panics if `modulus` limb count is not in `{8, 16, 32, 64}`, if `modulus` is even,
/// if `bases` is empty, or if any modular exponentiation result is zero.
#[must_use]
#[allow(clippy::cast_possible_truncation)]
pub fn verify_bigint_batch(input: &BigIntBatchInput) -> Vec<u8> {
    let k = input.modulus.len();
    assert!(
        k == 8 || k == 16 || k == 32 || k == 64,
        "Limb count k must be in [8, 16, 32, 64] corresponding to L in [256, 512, 1024, 2048]"
    );
    assert!(input.modulus[0] & 1 == 1, "Modulus M_L must be odd");
    assert!(!input.bases.is_empty(), "Bases batch cannot be empty");

    let n = input.bases.len();
    let mut payload = Vec::with_capacity(n * 32);

    for base in &input.bases {
        assert_eq!(base.len(), k, "Base limb length mismatch with modulus");
        let z = bigint_mod_exp_limbs(base, input.exponent, &input.modulus);
        assert!(
            z.iter().any(|&limb| limb != 0),
            "Degenerate zero modular result"
        );

        let mut h = Sha256::new();
        for &limb in &z {
            h.update(limb.to_le_bytes());
        }
        payload.extend_from_slice(&h.finalize());
    }

    finalize_journal(payload, n as u32, input.policy)
}
