# Architectural Refinements & Experimental Methodology (Test Run #2)

This document accompanies the primary blueprint in [`context.pdf`](./context.pdf) and details the software engineering and methodological hardenings applied to the repository to meet **Artifact Evaluation Committee (AEC)** standards at top systems and security venues (IEEE S&P, ACM CCS, USENIX Security, ASPLOS, AFT, and IEEE BRAINS).

---

## 1. Summary of the Six Architectural Hardenings

While [`context.pdf`](./context.pdf) defines the theoretical and experimental structure of Test Run #2, real-world Rust/RISC-V multi-zkVM compilation and EVM settlement profiling introduce subtle pitfalls that can invalidate benchmarks or break compilation. Below are the six engineering upgrades implemented in this repository:

### 1.1 Isolated Guest Workspaces for `[patch.crates-io]` and Custom RISC-V Targets
- **Issue in Naive Monorepos**: Cargo forbids `[patch.crates-io]` inside workspace member crates (it is only honored at a `[workspace]` root), and Cargo features cannot conditionally toggle `[patch.crates-io]`. Furthermore, combining SP1, RISC Zero, Pico, Jolt, and Nexus guest SDKs in a single root `Cargo.lock` triggers conflicting transitive dependencies (`plonky3`, `arkworks`, `serde`) and collides across vendor-specific `riscv32im-*` toolchains.
- **Implemented Architecture**:
  - The root [`Cargo.toml`](../Cargo.toml) manages shared core libraries (`crates/workloads-core`, `crates/bench-common`, `crates/input-generator`) and host runner CLIs (`runners/*-runner`), while explicitly listing all guest crates in `exclude = [...]`.
  - Every runner directory (`runners/<vm>-runner/`) contains two standalone guest roots:
    - `guest-unpatched/`: Pure RISC-V ALU execution without syscall overrides.
    - `guest-precompiled/`: Enables `workloads-core/precompiles-enabled` and defines its own isolated `[workspace]` and vendor-specific `[patch.crates-io]` table (`sha2`, `tiny-keccak`).
  - Both guest ELFs compile independently and can be selected at runtime via `--precompiles true|false` without modifying source or manifest files mid-benchmark.

### 1.2 Elimination of Guest Deserialization Drift ($C_{\text{user}}$ vs. $C_{\text{predicate}}$)
- **Issue**: Different zkVMs use different host-to-guest deserializers (`bincode` in SP1 vs. word-aligned custom `serde` in RISC Zero). On nested inputs (`Vec<Vec<u8>>` in $W_1$ or `Vec<Vec<[u8; 32]>>` in $W_4$), deserialization + bump-allocator overhead inside the guest distorts cycle counts at small batch sizes ($n \in \{1 \dots 16\}$).
- **Implemented Architecture**:
  - [`crates/workloads-core/src/lib.rs`](../crates/workloads-core/src/lib.rs) provides a unified `WorkloadPayload` envelope (`W1Voting`, `W2Auction`, `W3Allowlist`, `W4Merkle`, `W5BigInt`) and `execute_workload(&WorkloadPayload) -> Vec<u8>`.
  - [`crates/bench-common/src/lib.rs`](../crates/bench-common/src/lib.rs) records **both** `cycles_user` (total guest instructions including I/O) and `cycles_predicate` (pure predicate instructions isolated via cycle-tracking markers).

### 1.3 Cryptographically Sound Multi-Precision Montgomery Reduction in $W_5$
- **Issue**: A naive $k$-limb modular multiplication that computes the $2k$-limb product `prod[0..2*k]` and truncates to `prod[0..k]` only computes $(a \cdot b) \bmod 2^{32k}$, leaving the upper limbs `prod[k..2*k]` unused and vulnerable to **LLVM Dead Store Elimination (DSE)**.
- **Implemented Architecture**:
  - [`crates/workloads-core/src/bigint_mod.rs`](../crates/workloads-core/src/bigint_mod.rs) implements division-free Hensel lifting (`montgomery_inv32` via 5 Newton-Raphson iterations in $\mathbb{Z}/2^{32}\mathbb{Z}$) and full $2k$-limb **Montgomery reduction** (`bigint_mul_mod_limbs`) wrapped inside square-and-multiply modular exponentiation (`bigint_mod_exp_limbs` and `verify_bigint_batch`).
  - Every upper limb `prod[k..2*k]` and lower limb `prod[0..k]` propagates into the final reduced $k$-limb output and is hashed into the public journal, making dead-code elimination impossible while avoiding 128-bit software division panics (`__udivti3`) on minimal `RV32I` targets (Jolt and Nexus).

### 1.4 Full Dual-Hash Support (`Sha256` & `Keccak256`) Across $W_4$ and $\mathcal{P}_2$
- **Implemented Architecture**:
  - [`crates/workloads-core/src/hashing.rs`](../crates/workloads-core/src/hashing.rs) and [`crates/workloads-core/src/lib.rs`](../crates/workloads-core/src/lib.rs) define `HashAlg::{Sha256, Keccak256}` and `OutputPolicy::{RawCommitArray, HashCommit, HashCommitKeccak}`.
  - This allows systematic evaluation of $W_{4a}$ (SHA-256, 32-bit ROR/XOR) vs. $W_{4b}$ (Keccak-256, 64-bit lane sponge permutations) and aligns off-chain journal folding ($\mathcal{P}_2$) with both `sha256` (`0x02` precompile) and `keccak256` (`0x20` opcode) on the EVM.

### 1.5 Typed Metric Serialization (`crates/bench-common`)
- **Implemented Architecture**:
  - [`crates/bench-common/src/lib.rs`](../crates/bench-common/src/lib.rs) defines the canonical `RunMetrics` schema and `CSV_HEADER` matching Table 2 of [`context.pdf`](./context.pdf), preventing stdout/stderr log pollution from corrupting benchmark CSVs.

### 1.6 Completeness & Soundness Test Suite + Top-Level `Makefile`
- **Implemented Architecture**:
  - [`crates/workloads-core/src/lib.rs`](../crates/workloads-core/src/lib.rs) includes unit tests for valid witnesses and `#[should_panic]` soundness tests for malformed witnesses across $W_1$–$W_5$.
  - [`evm-profiler/test/GasProfiler.t.sol`](../evm-profiler/test/GasProfiler.t.sol) verifies EIP-2028 calldata pricing and asserts the exact L1 gas divergence ($\Delta G_{\text{L1}}(n)$) between $\mathcal{P}_1$ and $\mathcal{P}_2$.
  - [`Makefile`](../Makefile) provides one-command verification (`make smoke`, `make test`, `make evm-test`).
