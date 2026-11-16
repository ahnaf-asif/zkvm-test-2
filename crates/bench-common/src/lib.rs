use serde::{Deserialize, Serialize};
use workloads_core::{HashAlg, OutputPolicy};

/// Execution stage corresponding to Sections 5.3 - 5.5 of Test Run #2.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProvingMode {
    /// Stage A: Off-chain execution-only simulation (up to n = 1024).
    ExecOnly,
    /// Stage B: Local Apple M1 Core STARK / Lookup / IVC proof generation (n = 1..64/128).
    CoreProve,
    /// Stage C: Recursive STARK-to-SNARK Groth16 / PLONK compression (n in {1, 4, 16, 64, 256}).
    SnarkWrapGroth16,
    /// Stage C (PLONK variant for SP1):
    SnarkWrapPlonk,
}

/// Standardized dependent metrics recorded across all zkVMs in Test Run #2 (Table 2).
/// Prevents fragile stdout scraping by writing validated JSON/CSV rows directly to disk.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RunMetrics {
    pub vm: String,
    pub workload: String,
    pub batch_n: usize,
    pub param_value: u32, // b (W2), M (W3), d (W4), or L (W5)
    pub policy: OutputPolicy,
    pub hash_alg: HashAlg,
    pub precompiles_enabled: bool,
    pub mode: ProvingMode,
    /// C_user: Unpadded RISC-V instruction count executed by guest (including I/O).
    pub cycles_user: u64,
    /// C_predicate: Pure computational predicate cycles (excluding guest I/O deserialization).
    pub cycles_predicate: u64,
    /// C_padded: Padded trace length (\sum 2^{k_i}) committed into AIR/STARK segments.
    pub cycles_padded: u64,
    /// N_shards: Number of trace segments/shards generated during execution.
    pub shards: u32,
    /// T_exec (ms): Native execution-only runtime.
    pub exec_ms: f64,
    /// T_core (ms): Wall-clock time to generate Core STARK / Lookup / IVC proof.
    pub prove_ms: f64,
    /// T_wrap (ms): Wall-clock time to recursively compress Core STARK into BN254 SNARK.
    pub wrap_ms: f64,
    /// Off-chain verification time (ms).
    pub verify_ms: f64,
    /// \pi_core (Bytes): Serialized byte length of uncompressed Core proof artifact.
    pub core_proof_bytes: usize,
    /// \pi_evm (Bytes): Serialized byte length of wrapped EVM SNARK proof.
    pub evm_proof_bytes: usize,
    /// Serialized public journal byte length (32*n + 4 for P1 vs 36 for P2).
    pub journal_bytes: usize,
    /// M_peak (MB): Peak physical RAM (Resident Set Size) via macOS /usr/bin/time -l.
    pub peak_rss_mb: f64,
    /// Execution status ("OK", "OOM", "TIMEOUT").
    pub status: String,
}

impl RunMetrics {
    pub const CSV_HEADER: &'static str = "vm,workload,batch_n,param_value,policy,hash_alg,precompiles,mode,cycles_user,cycles_predicate,cycles_padded,shards,exec_ms,prove_ms,wrap_ms,verify_ms,core_proof_bytes,evm_proof_bytes,journal_bytes,peak_rss_mb,status";

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
}
