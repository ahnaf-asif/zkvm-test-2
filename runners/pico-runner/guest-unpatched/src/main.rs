// Pico Unpatched Guest (Pure Modular RV32IM execution)
use workloads_core::{execute_workload, WorkloadPayload};

pub fn dispatch(payload: &WorkloadPayload) -> Vec<u8> {
    execute_workload(payload)
}

fn main() {}
