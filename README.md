# Test Run #2: Multi-zkVM and EVM Gas Benchmarking Suite Across Application-Level Privacy Workloads

> **Experimental Design and Implementation Monorepo (`zkvm-evm-benchmark-suite-tr2`)**  
> **Authors:** Arman Ferdous (22241155), Ahnaf Shahriar Asif (22301787)  
> **Supervisor:** Dr. Md Sadek Ferdous, Professor, Department of CSE, Brac University  
> **Reference Blueprint:** [`documentation/context.pdf`](./documentation/context.pdf) | **Architecture Guide:** [`documentation/ARCHITECTURE_AND_METHODOLOGY.md`](./documentation/ARCHITECTURE_AND_METHODOLOGY.md)

---

## 1. Overview & Research Objective

Modern Zero-Knowledge Virtual Machines (zkVMs) compile standard high-level Rust programs targeting 32-bit RISC-V (`RV32I` / `RV32IM`) into succinct cryptographic proofs. While existing studies evaluate isolated micro-benchmarks (e.g., Fibonacci) or compiler passes in isolation, no peer-reviewed benchmark systematically maps **multi-dimensional application-level privacy predicates** to **end-to-end prover complexities** and **deployed Ethereum Virtual Machine (EVM) settlement gas costs** across competing **STARK**, **Lookup-Singularity**, and **IVC Folding** zkVM architectures.

This repository implements **Test Run #2** of our thesis, isolating general-purpose zkVM guest execution, recursive STARK-to-SNARK proof compression, and Cancun EVM smart contract settlement across **five zkVMs** and **five privacy/state-validation workload families ($`W_1`$–$`W_5`$)**.

---

## 2. Target zkVM Lineup & Architectural Taxonomy

To cover the full spectrum of modern zkVM paradigms within a reproducible local-plus-cloud workflow, the five target systems are partitioned into two experimental tiers:

| Tier | zkVM System | Target ISA | Core Proof & Finite Field | EVM Settlement Wrapper |
| :--- | :--- | :--- | :--- | :--- |
| **Tier A** *(Full E2E + EVM Gas)* | **SP1** | `RV32IM` + Precompiles | Plonky3 FRI-STARK (BabyBear) | Groth16 (BN254) & PLONK (BN254) via Succinct Network |
| **Tier A** *(Full E2E + EVM Gas)* | **RISC Zero** | `RV32IM` + Accelerators | AIR FRI-STARK (BabyBear) | Groth16 (BN254) via Bonsai / Docker |
| **Tier A** *(Full E2E + EVM Gas)* | **Pico (Brevis)** | Modular `RV32IM` | Plonky3 FRI-STARK (BabyBear / KoalaBear) | Groth16 (BN254) Solidity Verifier (64 GB Cloud Host) |
| **Tier B** *(Off-Chain Trace/Proof)* | **Jolt (a16z)** | `RV32I` / `RV32IM` | Lasso Lookup + Sumcheck (BN254 / HyKZG) | Off-chain native verifier |
| **Tier B** *(Off-Chain Trace/Proof)* | **Nexus** | `RV32I` / Stwo VM | Nova IVC Folding / Circle STARK (M31) | Off-chain folded / native proof verification |

---

## 3. Taxonomy of Experimental Inputs (Independent Variables)

We evaluate a four-dimensional input space $`\mathcal{I} = (W, n, b, \mathcal{P}_{\text{io}})`$:

### 3.1 Dimension 1: Workload Type ($`W_1`$–$`W_5`$)

All five computational predicates are implemented in a single `#![no_std]` + `alloc` shared crate ([`crates/workloads-core`](./crates/workloads-core/src/lib.rs)) to guarantee zero source drift across VMs:

1. **$`W_1`$ — Binary and One-Hot Ballot Validation with Cryptographic Nullifiers ([`voting.rs`](./crates/workloads-core/src/voting.rs))**:
   - Given $`n`$ secret ballot vectors $`v^{(i)} = (v_{i,1}, \dots, v_{i,k}) \in \mathbb{Z}^k`$ for $`k`$ candidates and secret voter trapdoors $`s_i`$, enforces Boolean validity and single-choice selection:

     ```math
     \mathcal{R}_{\text{vote}}(v^{(i)}) = 1 \iff (\forall j \in \{1, \dots, k\} : v_{i,j} \in \{0, 1\}) \land \left(\sum_{j=1}^k v_{i,j} = 1\right)
     ```

   - Derives a 32-byte nullifier $`N_i = \text{SHA256}(s_i \parallel v^{(i)})`$ per ballot without leaking cleartext votes.

2. **$`W_2`$ — Numerical Range Validation with Bid Commitments ([`auction.rs`](./crates/workloads-core/src/auction.rs))**:
   - Given $`n`$ secret auction bids $`u_1, \dots, u_n \in \mathbb{Z}`$, blinding nonces $`r_1, \dots, r_n`$, bit-width $`b \in \{8, 16, 32, 64, 96, 120\}`$, and reserve price $`R_{\min}`$, verifies interval membership:

     ```math
     \mathcal{R}_{\text{range}}(u_i, b, R_{\min}) = 1 \iff R_{\min} \le u_i < 2^b
     ```

   - Uses explicit two-word `(lo: u64, hi: u64)` representations and tests $`b \in \{96, 120\}`$ rather than $`b = 128`$ so LLVM's `instcombine` pass cannot eliminate $`u_i < 2^{128}`$ as a compile-time tautology. Produces binding commitments $`C_i = \text{SHA256}(u_i \parallel r_i)`$.

3. **$`W_3`$ — Set-Membership and Allowlist Validation ([`allowlist.rs`](./crates/workloads-core/src/allowlist.rs))**:
   - Given $`n`$ secret participant IDs $`m_1, \dots, m_n`$, salts $`s_1, \dots, s_n`$, and a sorted allowlist $`\mathcal{S} = \{a_1, \dots, a_M\}`$ of cardinality $`M \in \{16, 64, 256\}`$, verifies strict ascending order ($`a_1 < a_2 < \dots < a_M`$), proves membership via $`\mathcal{O}(\log_2 M)`$ binary search, and binds $`H(\mathcal{S})`$ to each participant nullifier.
   - Stresses random-access memory reads (`LW`) and lookup/permutation memory tables (Lasso/Spice vs. Grand Product/LogUp).

4. **$`W_4`$ — Cryptographic State & Merkle Membership Checks ([`hashing.rs`](./crates/workloads-core/src/hashing.rs))**:
   - Given $`n`$ secret leaves and depth $`d = 8`$ Merkle authentication paths, verifies state root inclusion under:
     - **$`W_{4a}`$ (SHA-256)**: 32-bit bitwise rotations (`ROR`), `XOR`, and logical shifts.
     - **$`W_{4b}`$ (Keccak-256)**: 64-bit bitwise sponge lane permutations.
   - Evaluated in two sub-modes per VM: **Unpatched Software Execution** (`guest-unpatched`) vs. **Precompile-Accelerated Execution** (`guest-precompiled`).

5. **$`W_5`$ — Deterministic Fixed-Limb Multi-Precision Modular Arithmetic ([`bigint_mod.rs`](./crates/workloads-core/src/bigint_mod.rs))**:
   - Computes $`n`$ modular multiplications and modular exponentiations over $`L`$-bit integers ($`L \in \{256, 512, 1024, 2048\}`$, $`k = \lceil L/32 \rceil \in \{8, 16, 32, 64\}`$ limbs of type `u32`):

     ```math
     z_i \equiv x_i^e \pmod{M_L}
     ```

   - Uses explicit fixed-limb `[u32; k]` schoolbook multiplication (`u32 * u32 -> u64` carry propagation) paired with division-free Hensel-lifted Montgomery reduction over all $`2k`$ limbs. This prevents `u128` software-emulation panics on `RV32I` targets (Jolt/Nexus) and prevents LLVM Dead Store Elimination.

### 3.2 Dimension 2: Workload Scale (Batch Size $`n`$)
- **Stage A (Execution-Only Simulation)**: $`n \in \{1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024\}`$
- **Stage B (Local Core Proof on Apple M1 8 GB RAM)**: $`n \in \{1, 2, 4, 8, 16, 32, 64\}`$ (and $`n = 128`$ up to the 8 GB OOM boundary)
- **Stage C (SNARK-Wrapped EVM Verification)**: $`n \in \{1, 4, 16, 64, 256\}`$

### 3.3 Dimension 3: Public Output Commitment Policy ($`\mathcal{P}_{\text{io}}`$)
- **Policy $`\mathcal{P}_1`$ (`RawCommitArray`)**: Commits all $`n`$ 32-byte item commitments/nullifiers plus 4-byte count ($`32n + 4`$ bytes) to the public journal. The Solidity contract receives all $`32n + 4`$ bytes via transaction calldata (EIP-2028: 16 gas/non-zero byte, 4 gas/zero byte) and hashes them on-chain (`keccak256` or `sha256`):

  ```math
  G_{\text{total}}^{\mathcal{P}_1}(n) = 21,000 + G_{\text{pairing}} + \Theta(n) \cdot (G_{\text{calldata}} + G_{\text{evm\_hash}})
  ```

- **Policy $`\mathcal{P}_2`$ (`HashCommit` / `HashCommitKeccak`)**: Folds all $`n`$ commitments inside the zkVM into a single 32-byte accumulator digest $`D = H(C_1 \parallel \dots \parallel C_n)`$ plus 4-byte batch count ($`36`$ bytes total), achieving strictly constant $`\mathcal{O}(1)`$ on-chain EVM verification gas regardless of batch size $`n`$.

---

## 4. Repository Architecture & Compiler Control

To eliminate the up to 45% cycle variance caused by LLVM middle-end pass drift (Gassmann et al., ASPLOS '26), the root workspace enforces a unified release profile (`opt-level = 3`, `lto = "fat"`, `codegen-units = 1`, `panic = "abort"`) while isolating guest workspaces for clean `[patch.crates-io]` precompile control:

```text
zkvm-test-2/
├── Cargo.toml                        # Root workspace (opt-level=3, lto="fat", codegen-units=1)
├── rust-toolchain.toml               # Pins Rust toolchain across host builds
├── Makefile                          # 1-command build, test, and smoke-test automation
├── .env.example                      # Template for SP1_PRIVATE_KEY, BONSAI_API_KEY, CLOUD_SSH
├── config/
│   └── benchmark_matrix.json         # Declarative seed, presets, & W1-W5 parameter sweeps
├── documentation/
│   ├── context.pdf                   # Complete Test Run #2 Experimental Design Blueprint
│   └── ARCHITECTURE_AND_METHODOLOGY.md # Engineering hardenings & AEC reproducibility notes
├── crates/
│   ├── workloads-core/               # 1. SHARED WORKLOAD CRATE (#![no_std] + alloc)
│   │   └── src/
│   │       ├── lib.rs                # OutputPolicy, HashAlg, WorkloadPayload & unit tests
│   │       ├── voting.rs             # W1: Binary (b=1) & One-Hot ballot + nullifiers
│   │       ├── auction.rs            # W2: Range checks (b=8..120) + bid commitments
│   │       ├── allowlist.rs          # W3: Sorted set-membership binary search
│   │       ├── hashing.rs            # W4: SHA-256 (W4a) & Keccak-256 (W4b) Merkle checks
│   │       └── bigint_mod.rs         # W5: Fixed-limb [u32; k] Montgomery modular math
│   ├── bench-common/                 # Typed RunMetrics, config loader, ChaCha20 PRNG & CLI
│   └── input-generator/              # Deterministic ChaCha20 PRNG test vector generator
├── data/                             # 2. PRE-GENERATED DETERMINISTIC INPUT VECTORS
├── results/                          # Output CSVs and raw timing logs
├── runners/                          # 3. ZKVM HOST & ISOLATED GUEST IMPLEMENTATIONS
│   ├── sp1-runner/                   # Host CLI + guest-unpatched/ + guest-precompiled/
│   ├── risc0-runner/                 # Host CLI + guest-unpatched/ + guest-precompiled/
│   ├── pico-runner/                  # Host CLI + guest-unpatched/ + guest-precompiled/
│   ├── jolt-runner/                  # Host CLI + guest-unpatched/ + guest-precompiled/
│   └── nexus-runner/                 # Host CLI + guest-unpatched/ + guest-precompiled/
├── evm-profiler/                     # 4. FOUNDRY / ANVIL BLOCKCHAIN TESTBED
│   ├── foundry.toml                  # Solc 0.8.24, Cancun EVM, gas_reports = ["*"]
│   ├── src/
│   │   ├── verifiers/                # IZkVMVerifier.sol & vendor Solidity verifiers
│   │   └── BenchmarkSettlement.sol   # Enforces P1 (RawCommitArray) vs P2 (HashCommit)
│   ├── test/
│   │   └── GasProfiler.t.sol         # Decomposes G_data (EIP-2028) vs G_exec
│   └── proofs/                       # Serialized BN254 Groth16 / PLONK proof fixtures
└── scripts/                          # 5. AUTOMATED BENCHMARK & PLOTTING SCRIPTS
```

---

## 5. Dependent Metrics Matrix

Every benchmark run collects the standardized metrics defined in [`crates/bench-common`](./crates/bench-common/src/lib.rs):

| Layer | Symbol | Unit | Definition and Measurement Tool |
| :--- | :--- | :--- | :--- |
| **Execution** | $`C_{\text{user}}`$ | Cycles | Unpadded RISC-V instruction count executed by guest (including I/O). |
| **Execution** | $`C_{\text{predicate}}`$ | Cycles | Pure computational predicate cycles (excluding guest deserialization). |
| **Execution** | $`C_{\text{padded}}`$ | Cycles | Padded trace length ($`\sum 2^{k_i}`$) committed into AIR/STARK segments. |
| **Execution** | $`N_{\text{shards}}`$ | Shards | Number of trace segments/shards generated during execution. |
| **Execution** | $`T_{\text{exec}}`$ | ms | Native execution-only runtime (`std::time::Instant`). |
| **Proving** | $`T_{\text{core}}`$ | ms / sec | Local M1 wall-clock time to generate Core STARK / Lookup / IVC proof. |
| **Proving** | $`T_{\text{wrap}}`$ | ms / sec | Time to recursively compress Core STARK into BN254 Groth16 or PLONK. |
| **Proving** | $`M_{\text{peak}}`$ | MB | Peak physical RAM (Resident Set Size) via macOS `/usr/bin/time -l`. |
| **Proving** | $`\pi_{\text{core}}`$ | Bytes | Serialized byte length of uncompressed Core proof artifact. |
| **Proving** | $`\pi_{\text{evm}}`$ | Bytes | Serialized byte length of wrapped EVM SNARK proof ($`\sim 260\text{--}800\text{ B}`$). |
| **Blockchain (EVM)** | $`G_{\text{exec}}`$ | Gas | EVM opcode + BN254 `ecPairing` (`0x08`) + journal hashing execution gas. |
| **Blockchain (EVM)** | $`G_{\text{data}}`$ | Gas | EIP-2028 calldata gas ($`16 \cdot B_{\ne 0} + 4 \cdot B_{=0}`$) for proof + journal. |
| **Blockchain (EVM)** | $`G_{\text{total}}`$ | Gas | Total L1 transaction gas: $`21,000 + G_{\text{data}} + G_{\text{exec}}`$. |
| **Blockchain (EVM)** | $`G_{\text{amort}}(n)`$ | Gas/item | Amortized gas per validated input: $`G_{\text{total}}(n) / n`$. |

---

## 6. Mathematical Guarantees & Crossover Equations

1. **Exact L1 Gas Divergence Between $`\mathcal{P}_1`$ and $`\mathcal{P}_2`$**:
   Under Policy $`\mathcal{P}_1`$, each validated item appends a uniformly distributed 32-byte commitment $`C_i \in \{0, \dots, 255\}^{32}`$ to calldata ($`32 \times \frac{255}{256} = 31.875`$ expected non-zero bytes $`\implies 510.5`$ calldata gas/item), plus $`6`$ gas/item (`keccak256`) or $`12`$ gas/item (`sha256`):

   ```math
   \Delta G_{\text{L1}}(n) = G_{\text{total}}^{\mathcal{P}_1}(n) - G_{\text{total}}^{\mathcal{P}_2}(n) \approx 516.5 \cdot (n - 1) \text{ gas (Keccak)} \quad \text{or} \quad 522.5 \cdot (n - 1) \text{ gas (SHA-256)}
   ```

2. **Shard-Boundary Step Function**:

   ```math
   T_{\text{core}}(n) \approx T_{\text{setup}} + \tau_{\text{shard}} \cdot \left\lceil \frac{C_{\text{base}} + n \cdot c_{\text{item}}}{S_{\text{shard}}} \right\rceil
   ```

3. **Range Bit-Width Invariance ($`b \le 64`$)** : Two-register `SLTU` comparisons execute in $`\Theta(n)`$ independent of $`b`$, contrasting with $`\Theta(n \cdot b)`$ bit-decomposition circuits.
4. **Quadratic/Cubic Multi-Limb Wall ($`W_5`$)** : Scaling $`L`$ from $`256`$ bits ($`k=8`$) to $`2048`$ bits ($`k=64`$) increases schoolbook limb multiplications per reduction by $`(64/8)^2 = 64\times`$ and full $`L`$-bit exponentiation work by $`(64/8)^3 = 512\times`$.

---

## 7. Quickstart & Verification Commands

### Prerequisites
- **Rust**: `stable` (`cargo`, `rustc`)
- **Foundry**: `v1.9.0+` (`forge`, `anvil`, `cast` installed in `~/.foundry/bin`)

### Run All Unit Tests & EVM Gas Profiler Smoke Tests
```bash
# Run both Rust workload unit tests (W1-W5 completeness + soundness) and Foundry EVM gas tests
make smoke
```

### Individual Commands
```bash
# 1. Verify Rust workspace compilation & formatting
make check

# 2. Run W1-W5 completeness & negative soundness tests in workloads-core
cargo test --workspace

# 3. Generate & verify deterministic input vectors in data/
make generate-inputs

# 4. Run Foundry EVM settlement & EIP-2028 P1 vs P2 gas decomposition tests
cd evm-profiler && ~/.foundry/bin/forge test -vv
```
