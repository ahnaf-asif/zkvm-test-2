pub mod cli;
pub mod config;
pub mod fixture;
pub mod generator;
pub mod metrics;
pub mod rng;
pub mod types;

pub use cli::RunnerCliArgs;
pub use config::{BenchmarkConfig, SuitePresetConfig, DEFAULT_CONFIG_PATH};
pub use fixture::{decode_hex, encode_hex_prefixed, EvmProofFixture};
pub use generator::{
    canonical_input_filename, generate_workload_payload, read_payload_from_file,
    write_payload_to_file, VectorCoordinate,
};
pub use metrics::RunMetrics;
pub use rng::{derive_config_rng, ChaCha20Rng};
pub use types::{
    hash_alg_slug, parse_hash_alg, parse_output_policy, policy_slug, ProvingMode, WorkloadKind,
};

#[cfg(test)]
mod tests {
    use super::*;
    use workloads_core::{execute_workload, HashAlg, OutputPolicy};

    #[test]
    fn test_config_loads_and_validates() {
        let cfg = BenchmarkConfig::load(None).expect("config should load");
        cfg.validate().expect("config should be valid");
        assert!(cfg.presets.contains_key("all"));
        assert!(cfg.presets.contains_key("smoke"));
    }

    #[test]
    fn test_chacha20_rng_determinism() {
        let cfg = BenchmarkConfig::load(None).unwrap();
        let mut rng1 = ChaCha20Rng::seed_from_u64(cfg.seed);
        let mut rng2 = ChaCha20Rng::seed_from_u64(cfg.seed);
        for _ in 0..100 {
            assert_eq!(rng1.next_u64(), rng2.next_u64());
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn test_generate_all_workloads_from_config() {
        let cfg = BenchmarkConfig::load(None).unwrap();
        let cases = [
            (
                WorkloadKind::W1Voting,
                1,
                1,
                OutputPolicy::HashCommit,
                HashAlg::Sha256,
            ),
            (
                WorkloadKind::W1Voting,
                8,
                4,
                OutputPolicy::RawCommitArray,
                HashAlg::Sha256,
            ),
            (
                WorkloadKind::W2Auction,
                4,
                8,
                OutputPolicy::HashCommit,
                HashAlg::Sha256,
            ),
            (
                WorkloadKind::W2Auction,
                4,
                32,
                OutputPolicy::RawCommitArray,
                HashAlg::Sha256,
            ),
            (
                WorkloadKind::W2Auction,
                4,
                64,
                OutputPolicy::HashCommit,
                HashAlg::Sha256,
            ),
            (
                WorkloadKind::W2Auction,
                4,
                96,
                OutputPolicy::HashCommit,
                HashAlg::Sha256,
            ),
            (
                WorkloadKind::W2Auction,
                4,
                120,
                OutputPolicy::HashCommit,
                HashAlg::Sha256,
            ),
            (
                WorkloadKind::W3Allowlist,
                4,
                16,
                OutputPolicy::HashCommit,
                HashAlg::Sha256,
            ),
            (
                WorkloadKind::W3Allowlist,
                4,
                64,
                OutputPolicy::RawCommitArray,
                HashAlg::Sha256,
            ),
            (
                WorkloadKind::W4Merkle,
                4,
                8,
                OutputPolicy::HashCommit,
                HashAlg::Sha256,
            ),
            (
                WorkloadKind::W4Merkle,
                4,
                8,
                OutputPolicy::HashCommitKeccak,
                HashAlg::Keccak256,
            ),
            (
                WorkloadKind::W5BigInt,
                2,
                256,
                OutputPolicy::HashCommit,
                HashAlg::Sha256,
            ),
            (
                WorkloadKind::W5BigInt,
                1,
                2048,
                OutputPolicy::RawCommitArray,
                HashAlg::Sha256,
            ),
        ];

        for (workload, batch_n, param_value, policy, hash_alg) in cases {
            let coord = VectorCoordinate {
                workload,
                batch_n,
                param_value,
                policy,
                hash_alg,
            };
            let p1 = generate_workload_payload(&cfg, coord).expect("generation should succeed");
            let p2 =
                generate_workload_payload(&cfg, coord).expect("repeated generation should succeed");
            assert_eq!(
                execute_workload(&p1),
                execute_workload(&p2),
                "Deterministic payload execution must produce identical public journals"
            );
        }
    }

    #[test]
    fn test_cli_args_parser_and_config_defaults() {
        let parsed = RunnerCliArgs::parse_from_iter([
            "--workload",
            "w2",
            "--batch-n",
            "16",
            "--bits",
            "32",
            "--mode",
            "core",
            "--precompiles",
            "true",
            "--policy",
            "p1",
        ])
        .expect("CLI parse should succeed");

        assert_eq!(parsed.workload, WorkloadKind::W2Auction);
        assert_eq!(parsed.batch_n, 16);
        assert_eq!(parsed.param_value, 32);
        assert_eq!(parsed.mode, ProvingMode::CoreProve);
        assert!(parsed.precompiles_enabled);
        assert_eq!(parsed.policy, OutputPolicy::RawCommitArray);
    }

    #[test]
    fn test_evm_proof_fixture_hex_and_camel_case_json() {
        let vkey = [0xABu8; 32];
        let pub_vals = [1u8, 2, 3, 4];
        let proof = [0xCDu8; 8];

        let fixture = EvmProofFixture::new(
            "sp1",
            "groth16",
            WorkloadKind::W2Auction,
            64,
            32,
            OutputPolicy::HashCommit,
            HashAlg::Sha256,
            &vkey,
            &pub_vals,
            &proof,
        );
        let json = serde_json::to_string(&fixture).unwrap();
        assert!(json.contains("\"vkey\":\"0x"));
        assert!(json.contains("\"publicValues\":\"0x01020304\""));
        assert!(json.contains("\"proof\":\"0xcdcdcdcdcdcdcdcd\""));

        let decoded = decode_hex(&fixture.public_values).unwrap();
        assert_eq!(decoded, pub_vals);
    }
}
