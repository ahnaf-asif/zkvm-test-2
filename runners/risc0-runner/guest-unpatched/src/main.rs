// RISC Zero Unpatched Guest (Pure RISC-V ALU execution)
use workloads_core::{execute_workload, WorkloadPayload};

pub fn dispatch(payload: &WorkloadPayload) -> Vec<u8> {
    execute_workload(payload)
}

fn main() {}
