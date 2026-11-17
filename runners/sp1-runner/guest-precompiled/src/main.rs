// SP1 Precompile-Accelerated Guest (Syscall-accelerated SHA-256 & Keccak-256)
// #![no_main]
// sp1_zkvm::entrypoint!(main);
use workloads_core::{execute_workload, WorkloadPayload};

#[must_use]
pub fn dispatch(payload: &WorkloadPayload) -> Vec<u8> {
    execute_workload(payload)
}

fn main() {}
