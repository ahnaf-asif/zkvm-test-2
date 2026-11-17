// Pico Precompile-Accelerated Guest
use workloads_core::{execute_workload, WorkloadPayload};

#[must_use]
pub fn dispatch(payload: &WorkloadPayload) -> Vec<u8> {
    execute_workload(payload)
}

fn main() {}
