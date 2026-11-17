// Jolt Guest (#[jolt::provable] Lookup-Singularity execution)
use workloads_core::{execute_workload, WorkloadPayload};

#[must_use]
pub fn dispatch(payload: &WorkloadPayload) -> Vec<u8> {
    execute_workload(payload)
}

fn main() {}
