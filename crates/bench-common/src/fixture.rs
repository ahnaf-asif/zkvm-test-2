use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use workloads_core::{HashAlg, OutputPolicy};

use crate::types::WorkloadKind;

/// Serialized Stage C SNARK proof fixture consumed by Foundry's `GasProfiler.t.sol`
/// (`vm.parseJsonBytes32(json, ".vkey")`, `vm.parseJsonBytes(json, ".publicValues")`,
/// and `vm.parseJsonBytes(json, ".proof")`).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EvmProofFixture {
    pub vm: String,
    pub proving_system: String,
    pub workload: String,
    pub batch_n: usize,
    pub param_value: u32,
    pub policy: OutputPolicy,
    pub hash_alg: HashAlg,
    /// 32-byte program verification key / image ID encoded as `0x`-prefixed 64-char hex.
    pub vkey: String,
    /// Public journal bytes encoded as `0x`-prefixed hex (`32 * n + 4` bytes for P1, `36` bytes for P2).
    pub public_values: String,
    /// Serialized BN254 Groth16 or PLONK proof bytes encoded as `0x`-prefixed hex.
    pub proof: String,
}

impl EvmProofFixture {
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        vm: impl Into<String>,
        proving_system: impl Into<String>,
        workload: WorkloadKind,
        batch_n: usize,
        param_value: u32,
        policy: OutputPolicy,
        hash_alg: HashAlg,
        vkey_bytes: &[u8; 32],
        public_values_bytes: &[u8],
        proof_bytes: &[u8],
    ) -> Self {
        Self {
            vm: vm.into(),
            proving_system: proving_system.into(),
            workload: workload.as_str().to_string(),
            batch_n,
            param_value,
            policy,
            hash_alg,
            vkey: encode_hex_prefixed(vkey_bytes),
            public_values: encode_hex_prefixed(public_values_bytes),
            proof: encode_hex_prefixed(proof_bytes),
        }
    }

    /// Writes the fixture as pretty-printed JSON to `path`.
    ///
    /// # Errors
    ///
    /// Returns an error if directory creation, serialization, or file writing fails.
    pub fn write_to_path(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)
                    .map_err(|e| format!("Failed to create directory {}: {e}", parent.display()))?;
            }
        }
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("Failed to serialize EvmProofFixture: {e}"))?;
        fs::write(path, json)
            .map_err(|e| format!("Failed to write EvmProofFixture to {}: {e}", path.display()))
    }
}

/// Encodes a byte slice as a `0x`-prefixed lowercase hex string.
#[must_use]
pub fn encode_hex_prefixed(bytes: &[u8]) -> String {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(2 + bytes.len() * 2);
    out.push_str("0x");
    for &b in bytes {
        out.push(HEX_CHARS[(b >> 4) as usize] as char);
        out.push(HEX_CHARS[(b & 0x0f) as usize] as char);
    }
    out
}

/// Decodes a hex string (with or without `0x` prefix) into raw bytes.
///
/// # Errors
///
/// Returns an error if the hex string has odd length or contains non-hex characters.
pub fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    let trimmed = s.trim();
    let hex = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    if (hex.len() & 1) != 0 {
        return Err(format!(
            "Hex string must have even length, got {}",
            hex.len()
        ));
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    let bytes = hex.as_bytes();
    let mut idx = 0;
    while idx < bytes.len() {
        let hi = decode_nibble(bytes[idx])?;
        let lo = decode_nibble(bytes[idx + 1])?;
        out.push((hi << 4) | lo);
        idx += 2;
    }
    Ok(out)
}

fn decode_nibble(b: u8) -> Result<u8, String> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        other => Err(format!("Invalid hex character '{}'", other as char)),
    }
}
