use std::cmp::Ordering;
use std::fs;
use std::path::Path;

use workloads_core::{
    execute_workload, hash_pair, AllowlistInput, AuctionRangeInput, BigIntBatchInput, HashAlg,
    MerkleBatchInput, OutputPolicy, VotingBatchInput, WorkloadPayload,
};

use crate::config::{BenchmarkConfig, W2AuctionConfig, W3AllowlistConfig};
use crate::rng::{derive_config_rng, ChaCha20Rng};
use crate::types::{hash_alg_slug, policy_slug, WorkloadKind};

/// A single point in the 4D experimental input space `(W, n, b/M/L, P_io)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VectorCoordinate {
    pub workload: WorkloadKind,
    pub batch_n: usize,
    pub param_value: u32,
    pub policy: OutputPolicy,
    pub hash_alg: HashAlg,
}

impl VectorCoordinate {
    #[must_use]
    pub fn filename(&self) -> String {
        canonical_input_filename(
            self.workload,
            self.batch_n,
            self.param_value,
            self.policy,
            self.hash_alg,
        )
    }
}

/// Returns the canonical filename for a pre-generated input vector in `data/`.
#[must_use]
pub fn canonical_input_filename(
    workload: WorkloadKind,
    batch_n: usize,
    param_value: u32,
    policy: OutputPolicy,
    hash_alg: HashAlg,
) -> String {
    let p_slug = policy_slug(policy);
    match workload {
        WorkloadKind::W4Merkle => format!(
            "{}_{}_n{}_d{}_{}.json",
            workload.slug(),
            hash_alg_slug(hash_alg),
            batch_n,
            param_value,
            p_slug
        ),
        WorkloadKind::W1Voting => format!(
            "{}_n{}_k{}_{}.json",
            workload.slug(),
            batch_n,
            param_value,
            p_slug
        ),
        WorkloadKind::W2Auction => format!(
            "{}_n{}_b{}_{}.json",
            workload.slug(),
            batch_n,
            param_value,
            p_slug
        ),
        WorkloadKind::W3Allowlist => format!(
            "{}_n{}_m{}_{}.json",
            workload.slug(),
            batch_n,
            param_value,
            p_slug
        ),
        WorkloadKind::W5BigInt => format!(
            "{}_n{}_l{}_{}.json",
            workload.slug(),
            batch_n,
            param_value,
            p_slug
        ),
    }
}

/// Reads and deserializes a [`WorkloadPayload`] JSON file from disk.
///
/// # Errors
///
/// Returns an error if the file cannot be read or deserialized.
pub fn read_payload_from_file(path: &Path) -> Result<WorkloadPayload, String> {
    let content = fs::read_to_string(path)
        .map_err(|e| format!("Failed to read input payload file {}: {e}", path.display()))?;
    serde_json::from_str(&content).map_err(|e| {
        format!(
            "Failed to deserialize WorkloadPayload from {}: {e}",
            path.display()
        )
    })
}

/// Writes a [`WorkloadPayload`] as canonical JSON to `path`.
///
/// # Errors
///
/// Returns an error if parent directories cannot be created or writing fails.
pub fn write_payload_to_file(payload: &WorkloadPayload, path: &Path) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create directory {}: {e}", parent.display()))?;
        }
    }
    let json = serde_json::to_string(payload)
        .map_err(|e| format!("Failed to serialize WorkloadPayload: {e}"))?;
    fs::write(path, json)
        .map_err(|e| format!("Failed to write WorkloadPayload to {}: {e}", path.display()))
}

fn generate_w1_voting(
    rng: &mut ChaCha20Rng,
    batch_n: usize,
    k: usize,
    policy: OutputPolicy,
) -> WorkloadPayload {
    let mut ballots = Vec::with_capacity(batch_n);
    let mut salts = Vec::with_capacity(batch_n);
    for _ in 0..batch_n {
        let mut ballot = vec![0u8; k];
        let choice = (rng.next_u32() as usize) % k;
        ballot[choice] = 1;
        ballots.push(ballot);

        let mut salt = [0u8; 32];
        rng.fill_bytes(&mut salt);
        salts.push(salt);
    }
    WorkloadPayload::W1Voting(VotingBatchInput {
        ballots,
        salts,
        policy,
    })
}

fn generate_w2_auction(
    rng: &mut ChaCha20Rng,
    batch_n: usize,
    b: u32,
    policy: OutputPolicy,
    w2_cfg: &W2AuctionConfig,
) -> WorkloadPayload {
    let reserve_lo: u64 = if b < 64 && w2_cfg.reserve_lo >= (1u64 << b) {
        0
    } else {
        w2_cfg.reserve_lo
    };
    let reserve_hi: u64 = w2_cfg.reserve_hi;

    let mut bids_lo = Vec::with_capacity(batch_n);
    let mut bids_hi = Vec::with_capacity(batch_n);
    let mut blindings = Vec::with_capacity(batch_n);

    for _ in 0..batch_n {
        let (lo, hi) = match b.cmp(&64) {
            Ordering::Less => {
                let bound_lo = 1u64 << b;
                let span = bound_lo - reserve_lo;
                (reserve_lo + (rng.next_u64() % span), 0u64)
            }
            Ordering::Equal => {
                let span = u64::MAX - reserve_lo;
                (reserve_lo + (rng.next_u64() % span), 0u64)
            }
            Ordering::Greater => {
                let bound_hi = 1u64 << (b - 64);
                let sampled_hi = if bound_hi > 1 {
                    1 + (rng.next_u64() % (bound_hi - 1))
                } else {
                    0
                };
                (rng.next_u64(), sampled_hi)
            }
        };
        bids_lo.push(lo);
        bids_hi.push(hi);

        let mut blinding = [0u8; 32];
        rng.fill_bytes(&mut blinding);
        blindings.push(blinding);
    }

    WorkloadPayload::W2Auction(AuctionRangeInput {
        bids_lo,
        bids_hi,
        blindings,
        bit_width: b,
        reserve_lo,
        reserve_hi,
        policy,
    })
}

fn generate_w3_allowlist(
    rng: &mut ChaCha20Rng,
    batch_n: usize,
    m: usize,
    policy: OutputPolicy,
    w3_cfg: &W3AllowlistConfig,
) -> WorkloadPayload {
    let max_step = w3_cfg.max_step.max(1);
    let mut allowlist = Vec::with_capacity(m);
    let mut cursor: u64 = w3_cfg.base_member_id;
    for _ in 0..m {
        cursor += u64::from(rng.next_u32() % max_step + 1);
        allowlist.push(cursor);
    }

    let mut members = Vec::with_capacity(batch_n);
    let mut salts = Vec::with_capacity(batch_n);
    for _ in 0..batch_n {
        let idx = (rng.next_u32() as usize) % m;
        members.push(allowlist[idx]);

        let mut salt = [0u8; 32];
        rng.fill_bytes(&mut salt);
        salts.push(salt);
    }

    WorkloadPayload::W3Allowlist(AllowlistInput {
        members,
        salts,
        allowlist,
        policy,
    })
}

#[allow(clippy::cast_possible_truncation)]
fn generate_w4_merkle(
    rng: &mut ChaCha20Rng,
    batch_n: usize,
    d: usize,
    policy: OutputPolicy,
    hash_alg: HashAlg,
) -> WorkloadPayload {
    let num_tree_leaves = 1usize << d;
    let mut levels: Vec<Vec<[u8; 32]>> = Vec::with_capacity(d + 1);
    let mut base_leaves = Vec::with_capacity(num_tree_leaves);
    for _ in 0..num_tree_leaves {
        let mut leaf = [0u8; 32];
        rng.fill_bytes(&mut leaf);
        base_leaves.push(leaf);
    }
    levels.push(base_leaves);

    for level in 0..d {
        let prev = &levels[level];
        let mut next = Vec::with_capacity(prev.len() / 2);
        let mut i = 0;
        while i < prev.len() {
            next.push(hash_pair(hash_alg, &prev[i], &prev[i + 1]));
            i += 2;
        }
        levels.push(next);
    }
    let expected_root = levels[d][0];

    let mut leaves = Vec::with_capacity(batch_n);
    let mut paths = Vec::with_capacity(batch_n);
    let mut indices = Vec::with_capacity(batch_n);

    for _ in 0..batch_n {
        let leaf_idx = (rng.next_u32() as usize) % num_tree_leaves;
        leaves.push(levels[0][leaf_idx]);
        indices.push(leaf_idx as u32);

        let mut auth_path = Vec::with_capacity(d);
        let mut curr_idx = leaf_idx;
        for level in &levels[0..d] {
            auth_path.push(level[curr_idx ^ 1]);
            curr_idx >>= 1;
        }
        paths.push(auth_path);
    }

    WorkloadPayload::W4Merkle(MerkleBatchInput {
        leaves,
        paths,
        indices,
        expected_root,
        hash_alg,
        policy,
    })
}

fn generate_w5_bigint(
    rng: &mut ChaCha20Rng,
    batch_n: usize,
    k: usize,
    exponent: u32,
    policy: OutputPolicy,
) -> WorkloadPayload {
    let mut modulus = Vec::with_capacity(k);
    for _ in 0..k {
        modulus.push(rng.next_u32());
    }
    modulus[0] |= 1;
    modulus[k - 1] |= 0x8000_0000;

    let mut bases = Vec::with_capacity(batch_n);
    for _ in 0..batch_n {
        let mut base = Vec::with_capacity(k);
        for _ in 0..k {
            base.push(rng.next_u32());
        }
        base[0] |= 2;
        base[k - 1] &= 0x7FFF_FFFF;
        bases.push(base);
    }

    WorkloadPayload::W5BigInt(BigIntBatchInput {
        bases,
        modulus,
        exponent,
        policy,
    })
}

/// Deterministically generates and self-verifies a [`WorkloadPayload`] using parameters from `config`.
///
/// # Errors
///
/// Returns an error if `coord` parameters are invalid or if self-verification fails.
pub fn generate_workload_payload(
    config: &BenchmarkConfig,
    coord: VectorCoordinate,
) -> Result<WorkloadPayload, String> {
    if coord.batch_n == 0 {
        return Err("batch_n must be >= 1".to_string());
    }
    let param_value = coord.workload.normalize_param(coord.param_value)?;
    let mut rng = derive_config_rng(
        config.seed,
        coord.workload,
        coord.batch_n,
        param_value,
        coord.policy,
        coord.hash_alg,
    );

    let payload = match coord.workload {
        WorkloadKind::W1Voting => {
            generate_w1_voting(&mut rng, coord.batch_n, param_value as usize, coord.policy)
        }
        WorkloadKind::W2Auction => generate_w2_auction(
            &mut rng,
            coord.batch_n,
            param_value,
            coord.policy,
            &config.workloads.w2_auction,
        ),
        WorkloadKind::W3Allowlist => generate_w3_allowlist(
            &mut rng,
            coord.batch_n,
            param_value as usize,
            coord.policy,
            &config.workloads.w3_allowlist,
        ),
        WorkloadKind::W4Merkle => generate_w4_merkle(
            &mut rng,
            coord.batch_n,
            param_value as usize,
            coord.policy,
            coord.hash_alg,
        ),
        WorkloadKind::W5BigInt => generate_w5_bigint(
            &mut rng,
            coord.batch_n,
            (param_value / 32) as usize,
            config.workloads.w5_bigint.exponent,
            coord.policy,
        ),
    };

    let journal = execute_workload(&payload);
    let expected_len = match coord.policy {
        OutputPolicy::RawCommitArray => 32 * coord.batch_n + 4,
        OutputPolicy::HashCommit | OutputPolicy::HashCommitKeccak => 36,
    };
    if journal.len() != expected_len {
        return Err(format!(
            "Generated journal length mismatch: expected {expected_len}, got {}",
            journal.len()
        ));
    }

    Ok(payload)
}
