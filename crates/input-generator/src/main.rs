mod manifest;
mod suite;

use std::fs;
use std::path::PathBuf;
use std::process;

use bench_common::{
    encode_hex_prefixed, generate_workload_payload, parse_hash_alg, parse_output_policy,
    write_payload_to_file, BenchmarkConfig, VectorCoordinate, WorkloadKind,
};
use workloads_core::{execute_workload, hash_bytes, HashAlg, OutputPolicy};

use crate::manifest::{verify_manifest, DatasetManifest};
use crate::suite::{build_suite_coordinates, generate_and_write_coordinate};

struct GeneratorCliOptions {
    config: BenchmarkConfig,
    out_dir: PathBuf,
    suite_name: String,
    verify_only: bool,
    help_requested: bool,
    single_workload: Option<WorkloadKind>,
    single_implied_alg: Option<HashAlg>,
    single_batch_n: Option<usize>,
    single_param: Option<u32>,
    single_policy: Option<OutputPolicy>,
    single_alg: Option<HashAlg>,
    single_out: Option<PathBuf>,
}

fn find_config_arg(args: &[String]) -> Result<Option<PathBuf>, String> {
    let mut idx = 0;
    let mut config_path = None;
    while idx < args.len() {
        if args[idx] == "--config" {
            idx += 1;
            let val = args
                .get(idx)
                .ok_or_else(|| "--config requires a file path".to_string())?;
            config_path = Some(PathBuf::from(val));
        }
        idx += 1;
    }
    Ok(config_path)
}

fn require_val<'a>(args: &'a [String], idx: usize, flag: &str) -> Result<&'a str, String> {
    args.get(idx)
        .map(String::as_str)
        .ok_or_else(|| format!("{flag} requires a value"))
}

fn parse_cli(args: &[String]) -> Result<GeneratorCliOptions, String> {
    let config_path = find_config_arg(args)?;
    let config = BenchmarkConfig::load(config_path.as_deref())?;
    config.validate()?;

    let mut opts = GeneratorCliOptions {
        out_dir: config.paths.data_dir.clone(),
        config,
        suite_name: "all".to_string(),
        verify_only: false,
        help_requested: false,
        single_workload: None,
        single_implied_alg: None,
        single_batch_n: None,
        single_param: None,
        single_policy: None,
        single_alg: None,
        single_out: None,
    };

    let mut i = 0;
    while i < args.len() {
        let flag = args[i].as_str();
        match flag {
            "--config" => i += 1,
            "--out-dir" | "--data-dir" => {
                i += 1;
                opts.out_dir = PathBuf::from(require_val(args, i, flag)?);
            }
            "--seed" => {
                i += 1;
                let val = require_val(args, i, flag)?;
                opts.config.seed = val
                    .parse::<u64>()
                    .map_err(|e| format!("Invalid --seed '{val}': {e}"))?;
            }
            "--suite" => {
                i += 1;
                require_val(args, i, flag)?.clone_into(&mut opts.suite_name);
            }
            "--smoke" => "smoke".clone_into(&mut opts.suite_name),
            "--verify" => opts.verify_only = true,
            "--workload" | "-w" => {
                i += 1;
                let (w, alg) = WorkloadKind::from_str_label(require_val(args, i, flag)?)?;
                opts.single_workload = Some(w);
                if alg.is_some() {
                    opts.single_implied_alg = alg;
                }
            }
            "--batch-n" | "-n" => {
                i += 1;
                let val = require_val(args, i, flag)?;
                opts.single_batch_n = Some(
                    val.parse::<usize>()
                        .map_err(|e| format!("Invalid --batch-n '{val}': {e}"))?,
                );
            }
            "--param" | "--bits" | "--candidates" | "--allowlist-size" | "--depth"
            | "--limb-bits" => {
                i += 1;
                let val = require_val(args, i, flag)?;
                opts.single_param = Some(
                    val.parse::<u32>()
                        .map_err(|e| format!("Invalid {flag} '{val}': {e}"))?,
                );
            }
            "--policy" | "-p" => {
                i += 1;
                opts.single_policy = Some(parse_output_policy(require_val(args, i, flag)?)?);
            }
            "--hash-alg" => {
                i += 1;
                opts.single_alg = Some(parse_hash_alg(require_val(args, i, flag)?)?);
            }
            "--out" | "-o" => {
                i += 1;
                opts.single_out = Some(PathBuf::from(require_val(args, i, flag)?));
            }
            "--help" | "-h" => opts.help_requested = true,
            other => return Err(format!("Unrecognized argument '{other}'")),
        }
        i += 1;
    }

    Ok(opts)
}

fn run_single_vector(opts: &GeneratorCliOptions, workload: WorkloadKind) -> Result<(), String> {
    let batch_n = opts.single_batch_n.unwrap_or(opts.config.defaults.batch_n);
    let raw_param = opts
        .single_param
        .unwrap_or_else(|| opts.config.default_param_for(workload));
    let param_value = workload.normalize_param(raw_param)?;
    let policy = opts.single_policy.unwrap_or(opts.config.defaults.policy);
    let hash_alg = opts.single_alg.or(opts.single_implied_alg).unwrap_or(
        if policy == OutputPolicy::HashCommitKeccak {
            HashAlg::Keccak256
        } else {
            opts.config.defaults.hash_alg
        },
    );

    let coord = VectorCoordinate {
        workload,
        batch_n,
        param_value,
        policy,
        hash_alg,
    };
    let payload = generate_workload_payload(&opts.config, coord)?;
    let journal = execute_workload(&payload);
    let digest = encode_hex_prefixed(&hash_bytes(HashAlg::Sha256, &journal));

    let out_path = opts
        .single_out
        .clone()
        .unwrap_or_else(|| opts.out_dir.join(coord.filename()));
    write_payload_to_file(&payload, &out_path)?;
    println!(
        "[input-generator] Wrote {} (journal={} B, sha256={})",
        out_path.display(),
        journal.len(),
        digest
    );
    Ok(())
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let opts = parse_cli(&args)?;

    if opts.help_requested {
        println!(
            "Usage: input-generator [--config config/benchmark_matrix.json] [--suite all|stage-a|stage-b|stage-c|smoke] [--out-dir data] [--verify]\n\
             Or single vector: input-generator --workload <w1..w5> --batch-n <n> [--param <p>] [--policy <p1|p2>] [--out <path>]"
        );
        return Ok(());
    }

    if opts.verify_only {
        let count = verify_manifest(&opts.out_dir)?;
        println!(
            "[input-generator] Verified {count} deterministic vectors in {} against manifest.json",
            opts.out_dir.display()
        );
        return Ok(());
    }

    if let Some(workload) = opts.single_workload {
        return run_single_vector(&opts, workload);
    }

    fs::create_dir_all(&opts.out_dir)
        .map_err(|e| format!("Failed to create {}: {e}", opts.out_dir.display()))?;

    let (canonical_suite, coords) = build_suite_coordinates(&opts.config, &opts.suite_name)?;
    let mut entries = Vec::with_capacity(coords.len());
    for coord in coords {
        entries.push(generate_and_write_coordinate(
            &opts.config,
            &opts.out_dir,
            coord,
        )?);
    }

    let manifest = DatasetManifest {
        generator: format!("ChaCha20Rng::seed_from_u64({})", opts.config.seed),
        seed: opts.config.seed,
        suite: canonical_suite,
        total_vectors: entries.len(),
        entries,
    };
    manifest.write_to_dir(&opts.out_dir)?;

    println!(
        "[input-generator] Generated and self-verified {} deterministic input vectors (seed={}) in {}",
        manifest.total_vectors,
        opts.config.seed,
        opts.out_dir.display()
    );
    Ok(())
}

fn main() {
    if let Err(err) = run() {
        eprintln!("Error: {err}");
        process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_smoke_suite_generation_and_manifest_verification() {
        let cfg = BenchmarkConfig::load(None).expect("config should load");
        let tmp_dir = std::env::temp_dir().join("zkvm_tr2_input_gen_modular_test");
        let _ = fs::remove_dir_all(&tmp_dir);
        fs::create_dir_all(&tmp_dir).unwrap();

        let (canonical_suite, coords) = build_suite_coordinates(&cfg, "smoke").unwrap();
        assert_ne!(coords, Vec::new());

        let mut entries = Vec::new();
        for coord in coords {
            entries.push(generate_and_write_coordinate(&cfg, &tmp_dir, coord).unwrap());
        }

        let manifest = DatasetManifest {
            generator: format!("ChaCha20Rng::seed_from_u64({})", cfg.seed),
            seed: cfg.seed,
            suite: canonical_suite,
            total_vectors: entries.len(),
            entries,
        };
        manifest.write_to_dir(&tmp_dir).unwrap();

        let verified_count = verify_manifest(&tmp_dir).unwrap();
        assert_eq!(verified_count, manifest.total_vectors);

        let _ = fs::remove_dir_all(&tmp_dir);
    }
}
