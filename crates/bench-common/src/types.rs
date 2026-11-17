use serde::{Deserialize, Serialize};
use workloads_core::{HashAlg, OutputPolicy};

/// Execution stage corresponding to Sections 5.3 - 5.5 of Test Run #2.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProvingMode {
    /// Stage A: Off-chain execution-only simulation.
    ExecOnly,
    /// Stage B: Local Core STARK / Lookup / IVC proof generation.
    CoreProve,
    /// Stage C: Recursive STARK-to-SNARK Groth16 compression.
    SnarkWrapGroth16,
    /// Stage C: Recursive STARK-to-SNARK PLONK compression.
    SnarkWrapPlonk,
}

impl ProvingMode {
    /// Parses a CLI or configuration label into a [`ProvingMode`].
    ///
    /// # Errors
    ///
    /// Returns an error if `s` does not match a known proving mode.
    pub fn from_str_label(s: &str) -> Result<Self, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "execonly" | "exec" | "execute" | "sim" | "stage-a" => Ok(Self::ExecOnly),
            "coreprove" | "core" | "stark" | "prove" | "stage-b" => Ok(Self::CoreProve),
            "snarkwrapgroth16" | "groth16" | "wrap-groth16" | "stage-c" => {
                Ok(Self::SnarkWrapGroth16)
            }
            "snarkwrapplonk" | "plonk" | "wrap-plonk" => Ok(Self::SnarkWrapPlonk),
            other => Err(format!(
                "Invalid ProvingMode '{other}': expected exec, core, groth16, or plonk"
            )),
        }
    }

    #[must_use]
    pub const fn slug(&self) -> &'static str {
        match self {
            Self::ExecOnly => "exec",
            Self::CoreProve => "core",
            Self::SnarkWrapGroth16 => "groth16",
            Self::SnarkWrapPlonk => "plonk",
        }
    }
}

/// Identifier for the five workload families (`W1`--`W5`).
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkloadKind {
    W1Voting,
    W2Auction,
    W3Allowlist,
    W4Merkle,
    W5BigInt,
}

impl WorkloadKind {
    /// Parses a CLI or config workload label. Returns `(WorkloadKind, Option<HashAlg>)`
    /// where labels like `"w4a"` or `"w4b"` also carry an implied hash algorithm.
    ///
    /// # Errors
    ///
    /// Returns an error if `s` does not match a valid workload identifier.
    pub fn from_str_label(s: &str) -> Result<(Self, Option<HashAlg>), String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "w1" | "voting" | "w1_voting" | "w1-voting" => Ok((Self::W1Voting, None)),
            "w2" | "auction" | "w2_auction" | "w2-auction" => Ok((Self::W2Auction, None)),
            "w3" | "allowlist" | "w3_allowlist" | "w3-allowlist" => Ok((Self::W3Allowlist, None)),
            "w4" | "merkle" | "hashing" | "w4_merkle" | "w4-merkle" => Ok((Self::W4Merkle, None)),
            "w4a" | "w4_sha256" | "w4-sha256" => Ok((Self::W4Merkle, Some(HashAlg::Sha256))),
            "w4b" | "w4_keccak" | "w4-keccak" | "w4_keccak256" | "w4-keccak256" => {
                Ok((Self::W4Merkle, Some(HashAlg::Keccak256)))
            }
            "w5" | "bigint" | "w5_bigint" | "w5-bigint" => Ok((Self::W5BigInt, None)),
            other => Err(format!(
                "Invalid workload '{other}': expected w1, w2, w3, w4 (or w4a/w4b), or w5"
            )),
        }
    }

    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::W1Voting => "W1",
            Self::W2Auction => "W2",
            Self::W3Allowlist => "W3",
            Self::W4Merkle => "W4",
            Self::W5BigInt => "W5",
        }
    }

    #[must_use]
    pub const fn slug(&self) -> &'static str {
        match self {
            Self::W1Voting => "w1",
            Self::W2Auction => "w2",
            Self::W3Allowlist => "w3",
            Self::W4Merkle => "w4",
            Self::W5BigInt => "w5",
        }
    }

    /// Validates and normalizes a raw parameter value for this workload
    /// (e.g., mapping `W5` limb counts `k` in `{8, 16, 32, 64}` to bit-widths `L = 32 * k`).
    ///
    /// # Errors
    ///
    /// Returns an error if `raw_param` is out of bounds for this workload.
    pub fn normalize_param(&self, raw_param: u32) -> Result<u32, String> {
        match self {
            Self::W1Voting => {
                if raw_param == 0 {
                    return Err("W1 candidate count k must be >= 1".to_string());
                }
                Ok(raw_param)
            }
            Self::W2Auction => {
                if raw_param == 0 || raw_param >= 128 {
                    return Err(format!(
                        "W2 bit_width b must be in 1..127 (got {raw_param})"
                    ));
                }
                Ok(raw_param)
            }
            Self::W3Allowlist => {
                if raw_param == 0 {
                    return Err("W3 allowlist cardinality M must be >= 1".to_string());
                }
                Ok(raw_param)
            }
            Self::W4Merkle => {
                if raw_param == 0 || raw_param > 20 {
                    return Err(format!(
                        "W4 Merkle tree depth d must be in 1..20 (got {raw_param})"
                    ));
                }
                Ok(raw_param)
            }
            Self::W5BigInt => match raw_param {
                8 | 16 | 32 | 64 => Ok(raw_param * 32),
                256 | 512 | 1024 | 2048 => Ok(raw_param),
                other => Err(format!(
                    "W5 modulus bit-width L must be in [256, 512, 1024, 2048] (or limbs k in [8, 16, 32, 64]), got {other}"
                )),
            },
        }
    }
}

/// Parses an [`OutputPolicy`] from CLI or configuration strings.
///
/// # Errors
///
/// Returns an error if `s` does not match a known output policy.
pub fn parse_output_policy(s: &str) -> Result<OutputPolicy, String> {
    match s.trim().to_ascii_lowercase().as_str() {
        "p1" | "raw" | "rawcommitarray" | "raw_commit_array" | "raw-commit-array" => {
            Ok(OutputPolicy::RawCommitArray)
        }
        "p2" | "hash" | "hashcommit" | "hash_commit" | "hash-commit" | "p2-sha256" => {
            Ok(OutputPolicy::HashCommit)
        }
        "p2-keccak"
        | "p2_keccak"
        | "hashcommitkeccak"
        | "hash_commit_keccak"
        | "hash-commit-keccak" => Ok(OutputPolicy::HashCommitKeccak),
        other => Err(format!(
            "Invalid OutputPolicy '{other}': expected p1 (RawCommitArray), p2 (HashCommit), or p2-keccak (HashCommitKeccak)"
        )),
    }
}

/// Parses a [`HashAlg`] from CLI or configuration strings.
///
/// # Errors
///
/// Returns an error if `s` does not match `sha256` or `keccak256`.
pub fn parse_hash_alg(s: &str) -> Result<HashAlg, String> {
    match s.trim().to_ascii_lowercase().as_str() {
        "sha256" | "sha-256" | "sha_256" | "w4a" => Ok(HashAlg::Sha256),
        "keccak256" | "keccak-256" | "keccak_256" | "keccak" | "w4b" => Ok(HashAlg::Keccak256),
        other => Err(format!(
            "Invalid HashAlg '{other}': expected sha256 or keccak256"
        )),
    }
}

/// Canonical short slug for [`OutputPolicy`] in filenames.
#[must_use]
pub const fn policy_slug(policy: OutputPolicy) -> &'static str {
    match policy {
        OutputPolicy::RawCommitArray => "p1",
        OutputPolicy::HashCommit => "p2",
        OutputPolicy::HashCommitKeccak => "p2k",
    }
}

/// Canonical short slug for [`HashAlg`] in filenames.
#[must_use]
pub const fn hash_alg_slug(alg: HashAlg) -> &'static str {
    match alg {
        HashAlg::Sha256 => "sha256",
        HashAlg::Keccak256 => "keccak256",
    }
}
