use std::fs;
use std::path::Path;

use bench_common::{encode_hex_prefixed, read_payload_from_file};
use serde::{Deserialize, Serialize};
use workloads_core::{execute_workload, hash_bytes, HashAlg, OutputPolicy};

/// Metadata entry written to `data/manifest.json` for each pre-generated test vector.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ManifestEntry {
    pub filename: String,
    pub workload: String,
    pub batch_n: usize,
    pub param_value: u32,
    pub policy: OutputPolicy,
    pub hash_alg: HashAlg,
    pub journal_bytes: usize,
    /// Expected `0x`-prefixed SHA-256 digest of the guest's public journal output,
    /// guaranteeing bit-for-bit cross-VM output equivalence across all 5 zkVMs.
    pub journal_sha256: String,
}

/// Complete dataset manifest stored at `data/manifest.json`.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct DatasetManifest {
    pub generator: String,
    pub seed: u64,
    pub suite: String,
    pub total_vectors: usize,
    pub entries: Vec<ManifestEntry>,
}

impl DatasetManifest {
    pub fn write_to_dir(&self, out_dir: &Path) -> Result<(), String> {
        let manifest_path = out_dir.join("manifest.json");
        let manifest_json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("Failed to serialize manifest.json: {e}"))?;
        fs::write(&manifest_path, manifest_json)
            .map_err(|e| format!("Failed to write {}: {e}", manifest_path.display()))
    }
}

/// Verifies every vector listed in `out_dir/manifest.json` by re-executing `execute_workload`
/// and comparing both byte length and SHA-256 public journal digest.
pub fn verify_manifest(out_dir: &Path) -> Result<usize, String> {
    let manifest_path = out_dir.join("manifest.json");
    let content = fs::read_to_string(&manifest_path)
        .map_err(|e| format!("Failed to read {}: {e}", manifest_path.display()))?;
    let manifest: DatasetManifest = serde_json::from_str(&content)
        .map_err(|e| format!("Failed to parse {}: {e}", manifest_path.display()))?;

    for entry in &manifest.entries {
        let vec_path = out_dir.join(&entry.filename);
        let payload = read_payload_from_file(&vec_path)?;
        let journal = execute_workload(&payload);
        if journal.len() != entry.journal_bytes {
            return Err(format!(
                "Journal byte length mismatch for {}: expected {}, got {}",
                entry.filename,
                entry.journal_bytes,
                journal.len()
            ));
        }
        let actual_digest = encode_hex_prefixed(&hash_bytes(HashAlg::Sha256, &journal));
        if actual_digest != entry.journal_sha256 {
            return Err(format!(
                "Journal SHA-256 mismatch for {}: expected {}, got {}",
                entry.filename, entry.journal_sha256, actual_digest
            ));
        }
    }

    Ok(manifest.entries.len())
}
