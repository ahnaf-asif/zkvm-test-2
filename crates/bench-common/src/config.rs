use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use workloads_core::{HashAlg, OutputPolicy};

use crate::types::{parse_hash_alg, parse_output_policy, ProvingMode, WorkloadKind};

/// Default relative path to the workspace benchmark configuration file.
pub const DEFAULT_CONFIG_PATH: &str = "config/benchmark_matrix.json";

/// Compile-time snapshot of `config/benchmark_matrix.json` used only when running binaries
/// or unit tests outside the repository root without an explicit `--config` path.
const EMBEDDED_CONFIG_JSON: &str = include_str!("../../../config/benchmark_matrix.json");

/// Top-level declarative configuration governing seeds, directories, batch progressions,
/// and workload parameter sweeps across the benchmark suite.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct BenchmarkConfig {
    pub seed: u64,
    pub paths: PathsConfig,
    pub defaults: DefaultsConfig,
    pub presets: BTreeMap<String, SuitePresetConfig>,
    pub workloads: WorkloadsConfig,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PathsConfig {
    pub data_dir: PathBuf,
    pub results_dir: PathBuf,
    pub proofs_dir: PathBuf,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct DefaultsConfig {
    pub workload: String,
    pub batch_n: usize,
    pub policy: OutputPolicy,
    pub hash_alg: HashAlg,
    pub mode: ProvingMode,
    pub precompiles_enabled: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct SuitePresetConfig {
    pub main_batches: Vec<usize>,
    pub param_sweep_batches: Vec<usize>,
    pub w5_base_batches: Vec<usize>,
    pub w5_limb_sweep_batches: Vec<usize>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct WorkloadsConfig {
    pub w1_voting: W1VotingConfig,
    pub w2_auction: W2AuctionConfig,
    pub w3_allowlist: W3AllowlistConfig,
    pub w4_merkle: W4MerkleConfig,
    pub w5_bigint: W5BigIntConfig,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct W1VotingConfig {
    pub default_candidates: u32,
    pub candidate_counts: Vec<u32>,
    pub policies: Vec<OutputPolicy>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct W2AuctionConfig {
    pub default_bit_width: u32,
    pub sweep_bit_widths: Vec<u32>,
    pub reserve_lo: u64,
    pub reserve_hi: u64,
    pub policies: Vec<OutputPolicy>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct W3AllowlistConfig {
    pub default_cardinality: u32,
    pub sweep_cardinalities: Vec<u32>,
    pub base_member_id: u64,
    pub max_step: u32,
    pub policies: Vec<OutputPolicy>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct W4MerkleConfig {
    pub default_depth: u32,
    pub depths: Vec<u32>,
    pub sha256_policies: Vec<OutputPolicy>,
    pub keccak256_policies: Vec<OutputPolicy>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct W5BigIntConfig {
    pub default_modulus_bits: u32,
    pub sweep_modulus_bits: Vec<u32>,
    pub exponent: u32,
    pub policies: Vec<OutputPolicy>,
}

impl BenchmarkConfig {
    /// Loads the benchmark configuration in priority order:
    /// 1. Explicit `custom_path` (from `--config <path>`)
    /// 2. `BENCH_CONFIG` environment variable
    /// 3. `config/benchmark_matrix.json` in the current working directory
    /// 4. Embedded compile-time snapshot of `config/benchmark_matrix.json`
    ///
    /// # Errors
    ///
    /// Returns an error if reading or parsing the configuration JSON fails.
    pub fn load(custom_path: Option<&Path>) -> Result<Self, String> {
        if let Some(path) = custom_path {
            return Self::from_file(path);
        }
        if let Ok(env_path) = std::env::var("BENCH_CONFIG") {
            if !env_path.trim().is_empty() {
                return Self::from_file(Path::new(&env_path));
            }
        }
        let default_path = Path::new(DEFAULT_CONFIG_PATH);
        let mut cfg = if default_path.exists() {
            Self::from_file(default_path)?
        } else {
            Self::from_json_str(EMBEDDED_CONFIG_JSON)?
        };

        if let Ok(env_seed) = std::env::var("BENCH_SEED") {
            if !env_seed.trim().is_empty() {
                cfg.seed = env_seed
                    .trim()
                    .parse::<u64>()
                    .map_err(|e| format!("Invalid BENCH_SEED '{env_seed}': {e}"))?;
            }
        }
        Ok(cfg)
    }

    /// Reads and parses a [`BenchmarkConfig`] JSON file from disk.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or contains invalid JSON.
    pub fn from_file(path: &Path) -> Result<Self, String> {
        let content = fs::read_to_string(path).map_err(|e| {
            format!(
                "Failed to read benchmark config file {}: {e}",
                path.display()
            )
        })?;
        Self::from_json_str(&content)
    }

    /// Parses a [`BenchmarkConfig`] from a JSON string.
    ///
    /// # Errors
    ///
    /// Returns an error if `json` does not match the [`BenchmarkConfig`] schema.
    pub fn from_json_str(json: &str) -> Result<Self, String> {
        serde_json::from_str(json)
            .map_err(|e| format!("Failed to parse benchmark config JSON: {e}"))
    }

    /// Returns the configured default parameter for a workload (`k`, `b`, `M`, `d`, or `L`).
    #[must_use]
    pub fn default_param_for(&self, workload: WorkloadKind) -> u32 {
        match workload {
            WorkloadKind::W1Voting => self.workloads.w1_voting.default_candidates,
            WorkloadKind::W2Auction => self.workloads.w2_auction.default_bit_width,
            WorkloadKind::W3Allowlist => self.workloads.w3_allowlist.default_cardinality,
            WorkloadKind::W4Merkle => self.workloads.w4_merkle.default_depth,
            WorkloadKind::W5BigInt => self.workloads.w5_bigint.default_modulus_bits,
        }
    }

    /// Resolves a preset by name (supporting aliases such as `"full"` -> `"all"`, `"quick"` -> `"smoke"`).
    ///
    /// # Errors
    ///
    /// Returns an error if `name` does not match any configured preset.
    pub fn preset<'a>(&'a self, name: &str) -> Result<(&'a str, &'a SuitePresetConfig), String> {
        let normalized = name.trim().to_ascii_lowercase();
        let key = match normalized.as_str() {
            "all" | "full" => "all",
            "stage-a" | "stage_a" | "exec" => "stage-a",
            "stage-b" | "stage_b" | "core" => "stage-b",
            "stage-c" | "stage_c" | "evm" | "snark" => "stage-c",
            "smoke" | "quick" => "smoke",
            other => other,
        };
        if let Some((k, v)) = self.presets.get_key_value(key) {
            Ok((k.as_str(), v))
        } else {
            let available: Vec<&str> = self.presets.keys().map(String::as_str).collect();
            Err(format!(
                "Unknown suite preset '{name}' (available presets: {})",
                available.join(", ")
            ))
        }
    }

    /// Parses the default workload configured in `self.defaults.workload`.
    ///
    /// # Errors
    ///
    /// Returns an error if `self.defaults.workload` is invalid.
    pub fn default_workload(&self) -> Result<WorkloadKind, String> {
        let (w, _) = WorkloadKind::from_str_label(&self.defaults.workload)?;
        Ok(w)
    }

    /// Validates the loaded configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if any default field is invalid or out of bounds.
    pub fn validate(&self) -> Result<(), String> {
        let _ = self.default_workload()?;
        let _ = parse_output_policy(&format!("{:?}", self.defaults.policy))?;
        let _ = parse_hash_alg(&format!("{:?}", self.defaults.hash_alg))?;
        if self.defaults.batch_n == 0 {
            return Err("defaults.batch_n must be >= 1".to_string());
        }
        Ok(())
    }
}
