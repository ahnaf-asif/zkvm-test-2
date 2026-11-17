use std::path::Path;

use bench_common::{
    encode_hex_prefixed, generate_workload_payload, write_payload_to_file, BenchmarkConfig,
    SuitePresetConfig, VectorCoordinate, WorkloadKind,
};
use workloads_core::{execute_workload, hash_bytes, HashAlg};

use crate::manifest::ManifestEntry;

fn append_w1_coords(
    coords: &mut Vec<VectorCoordinate>,
    config: &BenchmarkConfig,
    preset: &SuitePresetConfig,
) {
    let w1 = &config.workloads.w1_voting;
    for &k in &w1.candidate_counts {
        for &n in &preset.main_batches {
            for &policy in &w1.policies {
                coords.push(VectorCoordinate {
                    workload: WorkloadKind::W1Voting,
                    batch_n: n,
                    param_value: k,
                    policy,
                    hash_alg: HashAlg::Sha256,
                });
            }
        }
    }
}

fn append_w2_coords(
    coords: &mut Vec<VectorCoordinate>,
    config: &BenchmarkConfig,
    preset: &SuitePresetConfig,
) {
    let w2 = &config.workloads.w2_auction;
    for &n in &preset.main_batches {
        for &policy in &w2.policies {
            coords.push(VectorCoordinate {
                workload: WorkloadKind::W2Auction,
                batch_n: n,
                param_value: w2.default_bit_width,
                policy,
                hash_alg: HashAlg::Sha256,
            });
        }
    }
    for &b in &w2.sweep_bit_widths {
        for &n in &preset.param_sweep_batches {
            for &policy in &w2.policies {
                coords.push(VectorCoordinate {
                    workload: WorkloadKind::W2Auction,
                    batch_n: n,
                    param_value: b,
                    policy,
                    hash_alg: HashAlg::Sha256,
                });
            }
        }
    }
}

fn append_w3_coords(
    coords: &mut Vec<VectorCoordinate>,
    config: &BenchmarkConfig,
    preset: &SuitePresetConfig,
) {
    let w3 = &config.workloads.w3_allowlist;
    for &n in &preset.main_batches {
        for &policy in &w3.policies {
            coords.push(VectorCoordinate {
                workload: WorkloadKind::W3Allowlist,
                batch_n: n,
                param_value: w3.default_cardinality,
                policy,
                hash_alg: HashAlg::Sha256,
            });
        }
    }
    for &m in &w3.sweep_cardinalities {
        for &n in &preset.param_sweep_batches {
            for &policy in &w3.policies {
                coords.push(VectorCoordinate {
                    workload: WorkloadKind::W3Allowlist,
                    batch_n: n,
                    param_value: m,
                    policy,
                    hash_alg: HashAlg::Sha256,
                });
            }
        }
    }
}

fn append_w4_coords(
    coords: &mut Vec<VectorCoordinate>,
    config: &BenchmarkConfig,
    preset: &SuitePresetConfig,
) {
    let w4 = &config.workloads.w4_merkle;
    for &d in &w4.depths {
        for &n in &preset.main_batches {
            for &policy in &w4.sha256_policies {
                coords.push(VectorCoordinate {
                    workload: WorkloadKind::W4Merkle,
                    batch_n: n,
                    param_value: d,
                    policy,
                    hash_alg: HashAlg::Sha256,
                });
            }
            for &policy in &w4.keccak256_policies {
                coords.push(VectorCoordinate {
                    workload: WorkloadKind::W4Merkle,
                    batch_n: n,
                    param_value: d,
                    policy,
                    hash_alg: HashAlg::Keccak256,
                });
            }
        }
    }
}

fn append_w5_coords(
    coords: &mut Vec<VectorCoordinate>,
    config: &BenchmarkConfig,
    preset: &SuitePresetConfig,
) {
    let w5 = &config.workloads.w5_bigint;
    for &n in &preset.w5_base_batches {
        for &policy in &w5.policies {
            coords.push(VectorCoordinate {
                workload: WorkloadKind::W5BigInt,
                batch_n: n,
                param_value: w5.default_modulus_bits,
                policy,
                hash_alg: HashAlg::Sha256,
            });
        }
    }
    for &l in &w5.sweep_modulus_bits {
        for &n in &preset.w5_limb_sweep_batches {
            for &policy in &w5.policies {
                coords.push(VectorCoordinate {
                    workload: WorkloadKind::W5BigInt,
                    batch_n: n,
                    param_value: l,
                    policy,
                    hash_alg: HashAlg::Sha256,
                });
            }
        }
    }
}

/// Builds the ordered list of 4D input coordinates `(W, n, b/M/L, P_io)`
/// dynamically from `config` (`config/benchmark_matrix.json`) for the requested `preset_name`.
pub fn build_suite_coordinates(
    config: &BenchmarkConfig,
    preset_name: &str,
) -> Result<(String, Vec<VectorCoordinate>), String> {
    let (canonical_name, preset) = config.preset(preset_name)?;
    let mut coords = Vec::new();
    append_w1_coords(&mut coords, config, preset);
    append_w2_coords(&mut coords, config, preset);
    append_w3_coords(&mut coords, config, preset);
    append_w4_coords(&mut coords, config, preset);
    append_w5_coords(&mut coords, config, preset);
    Ok((canonical_name.to_string(), coords))
}

/// Generates, self-verifies, and writes a single [`VectorCoordinate`] to `out_dir`.
pub fn generate_and_write_coordinate(
    config: &BenchmarkConfig,
    out_dir: &Path,
    coord: VectorCoordinate,
) -> Result<ManifestEntry, String> {
    let payload = generate_workload_payload(config, coord)?;
    let journal = execute_workload(&payload);
    let digest = hash_bytes(HashAlg::Sha256, &journal);
    let filename = coord.filename();
    let path = out_dir.join(&filename);
    write_payload_to_file(&payload, &path)?;

    Ok(ManifestEntry {
        filename,
        workload: coord.workload.as_str().to_string(),
        batch_n: coord.batch_n,
        param_value: coord.param_value,
        policy: coord.policy,
        hash_alg: coord.hash_alg,
        journal_bytes: journal.len(),
        journal_sha256: encode_hex_prefixed(&digest),
    })
}
