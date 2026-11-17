use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

use serde::{Deserialize, Serialize};
use workloads_core::{HashAlg, OutputPolicy};

use crate::types::ProvingMode;

/// Standardized dependent metrics recorded across all zkVMs in Test Run #2 (Table 2).
/// Prevents fragile stdout scraping by writing validated JSON/CSV rows directly to disk.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct RunMetrics {
    pub vm: String,
    pub workload: String,
    pub batch_n: usize,
    pub param_value: u32, // k (W1), b (W2), M (W3), d (W4), or L (W5)
    pub policy: OutputPolicy,
    pub hash_alg: HashAlg,
    pub precompiles_enabled: bool,
    pub mode: ProvingMode,
    /// `C_user`: Unpadded RISC-V instruction count executed by guest (including I/O).
    pub cycles_user: u64,
    /// `C_predicate`: Pure computational predicate cycles (excluding guest I/O deserialization).
    pub cycles_predicate: u64,
    /// `C_padded`: Padded trace length committed into AIR/STARK segments.
    pub cycles_padded: u64,
    /// `N_shards`: Number of trace segments/shards generated during execution.
    pub shards: u32,
    /// `T_exec` (ms): Native execution-only runtime.
    pub exec_ms: f64,
    /// `T_core` (ms): Wall-clock time to generate Core STARK / Lookup / IVC proof.
    pub prove_ms: f64,
    /// `T_wrap` (ms): Wall-clock time to recursively compress Core STARK into BN254 SNARK.
    pub wrap_ms: f64,
    /// Off-chain verification time (ms).
    pub verify_ms: f64,
    /// `pi_core` (Bytes): Serialized byte length of uncompressed Core proof artifact.
    pub core_proof_bytes: usize,
    /// `pi_evm` (Bytes): Serialized byte length of wrapped EVM SNARK proof.
    pub evm_proof_bytes: usize,
    /// Serialized public journal byte length (`32 * n + 4` for P1 vs `36` for P2).
    pub journal_bytes: usize,
    /// `M_peak` (MB): Peak physical RAM (Resident Set Size) via macOS `/usr/bin/time -l`.
    pub peak_rss_mb: f64,
    /// Execution status (`"OK"`, `"OOM"`, `"TIMEOUT"`).
    pub status: String,
}

impl RunMetrics {
    pub const CSV_HEADER: &'static str = "vm,workload,batch_n,param_value,policy,hash_alg,precompiles,mode,cycles_user,cycles_predicate,cycles_padded,shards,exec_ms,prove_ms,wrap_ms,verify_ms,core_proof_bytes,evm_proof_bytes,journal_bytes,peak_rss_mb,status";

    #[must_use]
    pub fn to_csv_row(&self) -> String {
        format!(
            "{},{},{},{},{:?},{:?},{},{:?},{},{},{},{},{:.3},{:.3},{:.3},{:.3},{},{},{},{:.2},{}",
            self.vm,
            self.workload,
            self.batch_n,
            self.param_value,
            self.policy,
            self.hash_alg,
            self.precompiles_enabled,
            self.mode,
            self.cycles_user,
            self.cycles_predicate,
            self.cycles_padded,
            self.shards,
            self.exec_ms,
            self.prove_ms,
            self.wrap_ms,
            self.verify_ms,
            self.core_proof_bytes,
            self.evm_proof_bytes,
            self.journal_bytes,
            self.peak_rss_mb,
            self.status
        )
    }

    /// Writes [`RunMetrics`] as pretty-printed JSON to `path`.
    ///
    /// # Errors
    ///
    /// Returns an error if parent directories cannot be created or writing fails.
    pub fn write_json(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)
                    .map_err(|e| format!("Failed to create directory {}: {e}", parent.display()))?;
            }
        }
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("Failed to serialize RunMetrics JSON: {e}"))?;
        fs::write(path, json)
            .map_err(|e| format!("Failed to write RunMetrics JSON to {}: {e}", path.display()))
    }

    /// Appends a CSV row to `path`, automatically writing [`Self::CSV_HEADER`] first if the file
    /// does not yet exist or is empty.
    ///
    /// # Errors
    ///
    /// Returns an error if opening or writing to `path` fails.
    pub fn append_csv(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)
                    .map_err(|e| format!("Failed to create directory {}: {e}", parent.display()))?;
            }
        }
        let write_header = !path.exists() || fs::metadata(path).map_or(true, |m| m.len() == 0);
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| format!("Failed to open CSV file {}: {e}", path.display()))?;
        if write_header {
            writeln!(file, "{}", Self::CSV_HEADER)
                .map_err(|e| format!("Failed to write CSV header: {e}"))?;
        }
        writeln!(file, "{}", self.to_csv_row())
            .map_err(|e| format!("Failed to append CSV row: {e}"))
    }
}
