# Test Run #2: Multi-zkVM and EVM Gas Benchmarking Suite
# Artifact Evaluation & Reproducibility Makefile

FOUNDRY_BIN ?= $(HOME)/.foundry/bin
FORGE := $(FOUNDRY_BIN)/forge
VMS := sp1 risc0 pico jolt nexus

.PHONY: all check check-guests test generate-inputs evm-test smoke clean

all: check check-guests test evm-test

check:
	cargo fmt --all -- --check
	cargo check --workspace
	cargo clippy --workspace --all-targets -- -D warnings -D clippy::pedantic

check-guests:
	@for vm in $(VMS); do \
		echo "Checking isolated guests for $$vm-runner..."; \
		CARGO_TARGET_DIR="$(CURDIR)/target/guest-check" cargo clippy --manifest-path runners/$$vm-runner/guest-unpatched/Cargo.toml --all-targets -- -D warnings -D clippy::pedantic; \
		CARGO_TARGET_DIR="$(CURDIR)/target/guest-check" cargo clippy --manifest-path runners/$$vm-runner/guest-precompiled/Cargo.toml --all-targets -- -D warnings -D clippy::pedantic; \
	done

test:
	cargo test --workspace

generate-inputs:
	./scripts/01_generate_inputs.sh

evm-test:
	cd evm-profiler && $(FORGE) test -vv

smoke: check check-guests test evm-test
	@echo "=== Smoke Test Passed (Workspace + 10 Guest Crates + W1-W5 Tests + EVM Gas Profiler Verified) ==="

clean:
	cargo clean
	rm -rf runners/*/*/target
	rm -f data/*.json data/*.bin
	cd evm-profiler && $(FORGE) clean
