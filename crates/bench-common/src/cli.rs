use std::path::PathBuf;

use workloads_core::{HashAlg, OutputPolicy, WorkloadPayload};

use crate::config::BenchmarkConfig;
use crate::generator::{
    canonical_input_filename, generate_workload_payload, read_payload_from_file, VectorCoordinate,
};
use crate::types::{parse_hash_alg, parse_output_policy, ProvingMode, WorkloadKind};

/// Shared CLI configuration parsed across all five host runners (`sp1`, `risc0`, `pico`, `jolt`, `nexus`).
///
/// Defaults are populated dynamically from `config/benchmark_matrix.json` (or `--config <path>`),
/// ensuring zero hardcoded benchmark constants in runner binaries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunnerCliArgs {
    pub config: BenchmarkConfig,
    pub workload: WorkloadKind,
    pub batch_n: usize,
    pub param_value: u32,
    pub policy: OutputPolicy,
    pub hash_alg: HashAlg,
    pub precompiles_enabled: bool,
    pub mode: ProvingMode,
    pub input_path: Option<PathBuf>,
    pub data_dir: PathBuf,
    pub output_csv: Option<PathBuf>,
    pub output_json: Option<PathBuf>,
    pub proof_out: Option<PathBuf>,
}

fn find_custom_config_path(args: &[String]) -> Result<Option<PathBuf>, String> {
    let mut idx = 0;
    let mut custom_path = None;
    while idx < args.len() {
        if args[idx] == "--config" {
            idx += 1;
            let val = args
                .get(idx)
                .ok_or_else(|| "--config requires a file path".to_string())?;
            custom_path = Some(PathBuf::from(val));
        }
        idx += 1;
    }
    Ok(custom_path)
}

fn require_arg<'a>(args: &'a [String], idx: usize, flag: &str) -> Result<&'a str, String> {
    args.get(idx)
        .map(String::as_str)
        .ok_or_else(|| format!("{flag} requires a value"))
}

impl RunnerCliArgs {
    /// Parses CLI arguments from `std::env::args().skip(1)`.
    ///
    /// # Errors
    ///
    /// Returns an error if any CLI flag or configuration value is invalid.
    pub fn parse_from_env() -> Result<Self, String> {
        Self::parse_from_iter(std::env::args().skip(1))
    }

    /// Parses CLI arguments from an arbitrary string iterator, loading base defaults from
    /// `--config <path>` or `config/benchmark_matrix.json`.
    ///
    /// # Errors
    ///
    /// Returns an error if any CLI flag or configuration value is invalid.
    pub fn parse_from_iter<I, S>(iter: I) -> Result<Self, String>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let args: Vec<String> = iter.into_iter().map(|s| s.as_ref().to_string()).collect();
        let custom_config_path = find_custom_config_path(&args)?;
        let config = BenchmarkConfig::load(custom_config_path.as_deref())?;
        config.validate()?;

        let default_workload = config.default_workload()?;
        let mut state = Self {
            workload: default_workload,
            batch_n: config.defaults.batch_n,
            param_value: config.default_param_for(default_workload),
            policy: config.defaults.policy,
            hash_alg: config.defaults.hash_alg,
            precompiles_enabled: config.defaults.precompiles_enabled,
            mode: config.defaults.mode,
            input_path: None,
            data_dir: config.paths.data_dir.clone(),
            output_csv: None,
            output_json: None,
            proof_out: None,
            config,
        };

        state.apply_flags(&args, default_workload)?;
        Ok(state)
    }

    #[allow(clippy::too_many_lines)]
    fn apply_flags(
        &mut self,
        args: &[String],
        default_workload: WorkloadKind,
    ) -> Result<(), String> {
        let mut explicit_param: Option<u32> = None;
        let mut explicit_alg: Option<HashAlg> = None;
        let mut implied_alg: Option<HashAlg> = None;

        let mut i = 0;
        while i < args.len() {
            let flag = args[i].as_str();
            match flag {
                "--config" => i += 1,
                "--seed" => {
                    i += 1;
                    let val = require_arg(args, i, flag)?;
                    self.config.seed = val
                        .parse::<u64>()
                        .map_err(|e| format!("Invalid --seed '{val}': {e}"))?;
                }
                "--workload" | "-w" => {
                    i += 1;
                    let (w, alg) = WorkloadKind::from_str_label(require_arg(args, i, flag)?)?;
                    self.workload = w;
                    if alg.is_some() {
                        implied_alg = alg;
                    }
                }
                "--batch-n" | "-n" => {
                    i += 1;
                    let val = require_arg(args, i, flag)?;
                    self.batch_n = val
                        .parse::<usize>()
                        .map_err(|e| format!("Invalid --batch-n '{val}': {e}"))?;
                    if self.batch_n == 0 {
                        return Err("--batch-n must be >= 1".to_string());
                    }
                }
                "--param" | "--bits" | "--candidates" | "--allowlist-size" | "--depth"
                | "--limb-bits" => {
                    i += 1;
                    let val = require_arg(args, i, flag)?;
                    explicit_param = Some(
                        val.parse::<u32>()
                            .map_err(|e| format!("Invalid {flag} '{val}': {e}"))?,
                    );
                }
                "--policy" | "-p" => {
                    i += 1;
                    self.policy = parse_output_policy(require_arg(args, i, flag)?)?;
                }
                "--hash-alg" => {
                    i += 1;
                    explicit_alg = Some(parse_hash_alg(require_arg(args, i, flag)?)?);
                }
                "--precompiles" => {
                    if let Some(next) = args.get(i + 1) {
                        match next.to_ascii_lowercase().as_str() {
                            "true" | "1" | "yes" => {
                                self.precompiles_enabled = true;
                                i += 1;
                            }
                            "false" | "0" | "no" => {
                                self.precompiles_enabled = false;
                                i += 1;
                            }
                            _ => self.precompiles_enabled = true,
                        }
                    } else {
                        self.precompiles_enabled = true;
                    }
                }
                "--mode" | "-m" => {
                    i += 1;
                    self.mode = ProvingMode::from_str_label(require_arg(args, i, flag)?)?;
                }
                "--input" | "-i" => {
                    i += 1;
                    self.input_path = Some(PathBuf::from(require_arg(args, i, flag)?));
                }
                "--data-dir" => {
                    i += 1;
                    self.data_dir = PathBuf::from(require_arg(args, i, flag)?);
                }
                "--output-csv" => {
                    i += 1;
                    self.output_csv = Some(PathBuf::from(require_arg(args, i, flag)?));
                }
                "--output-json" => {
                    i += 1;
                    self.output_json = Some(PathBuf::from(require_arg(args, i, flag)?));
                }
                "--proof-out" => {
                    i += 1;
                    self.proof_out = Some(PathBuf::from(require_arg(args, i, flag)?));
                }
                other => return Err(format!("Unrecognized CLI argument '{other}'")),
            }
            i += 1;
        }

        let raw_param = explicit_param.unwrap_or_else(|| {
            if self.workload == default_workload {
                self.param_value
            } else {
                self.config.default_param_for(self.workload)
            }
        });
        self.param_value = self.workload.normalize_param(raw_param)?;
        self.hash_alg = explicit_alg.or(implied_alg).unwrap_or(
            if self.policy == OutputPolicy::HashCommitKeccak {
                HashAlg::Keccak256
            } else {
                self.config.defaults.hash_alg
            },
        );
        Ok(())
    }

    /// Returns the 4D input coordinate represented by these CLI arguments.
    #[must_use]
    pub fn coordinate(&self) -> VectorCoordinate {
        VectorCoordinate {
            workload: self.workload,
            batch_n: self.batch_n,
            param_value: self.param_value,
            policy: self.policy,
            hash_alg: self.hash_alg,
        }
    }

    /// Returns the canonical pre-generated file path in `self.data_dir` for this configuration.
    #[must_use]
    pub fn canonical_data_path(&self) -> PathBuf {
        let filename = canonical_input_filename(
            self.workload,
            self.batch_n,
            self.param_value,
            self.policy,
            self.hash_alg,
        );
        self.data_dir.join(filename)
    }

    /// Loads the [`WorkloadPayload`] from `--input <path>` if specified, or from the canonical
    /// pre-generated file in `data/` if present on disk, or deterministically generates the
    /// exact bit-identical [`WorkloadPayload`] using `self.config`.
    ///
    /// # Errors
    ///
    /// Returns an error if reading or generating the payload fails.
    pub fn load_or_generate_payload(&self) -> Result<WorkloadPayload, String> {
        if let Some(ref path) = self.input_path {
            return read_payload_from_file(path);
        }
        let canonical = self.canonical_data_path();
        if canonical.exists() {
            return read_payload_from_file(&canonical);
        }
        generate_workload_payload(&self.config, self.coordinate())
    }
}
