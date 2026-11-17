## Summary
Closes #

## Changes Made
- 

## Pre-Merge Verification Checklist
- [ ] `make check` (`cargo fmt --all -- --check` & `cargo clippy --workspace --all-targets -- -D warnings -D clippy::pedantic`) passes
- [ ] `make check-guests` (all 10 isolated `guest-unpatched` & `guest-precompiled` crates) passes
- [ ] `make test` (`cargo test --workspace`) passes
- [ ] `make evm-test` (`cd evm-profiler && forge test -vv`) passes
