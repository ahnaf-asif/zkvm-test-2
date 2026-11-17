use workloads_core::{hash_bytes, HashAlg, OutputPolicy};

use crate::types::WorkloadKind;

/// RFC 8439 20-round `ChaCha20` deterministic stream cipher PRNG.
///
/// Implemented without external crate dependencies to prevent version collisions across
/// vendor zkVM Cargo workspaces while guaranteeing bit-identical cross-platform determinism.
#[derive(Clone, Debug)]
pub struct ChaCha20Rng {
    key: [u32; 8],
    counter: u64,
    block: [u8; 64],
    offset: usize,
}

impl ChaCha20Rng {
    /// Initializes [`ChaCha20Rng`] from a 64-bit integer seed using `SplitMix64` key expansion.
    #[must_use]
    pub fn seed_from_u64(mut state: u64) -> Self {
        let mut seed_bytes = [0u8; 32];
        for i in 0..4 {
            state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z = z ^ (z >> 31);
            seed_bytes[i * 8..(i + 1) * 8].copy_from_slice(&z.to_le_bytes());
        }
        Self::from_seed(seed_bytes)
    }

    /// Initializes [`ChaCha20Rng`] from a 32-byte key seed.
    #[must_use]
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let mut key = [0u32; 8];
        for (i, word) in key.iter_mut().enumerate() {
            let offset = i * 4;
            *word = u32::from_le_bytes([
                seed[offset],
                seed[offset + 1],
                seed[offset + 2],
                seed[offset + 3],
            ]);
        }
        let mut rng = Self {
            key,
            counter: 0,
            block: [0u8; 64],
            offset: 64,
        };
        rng.refill_block();
        rng
    }

    #[inline]
    fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
        state[a] = state[a].wrapping_add(state[b]);
        state[d] = (state[d] ^ state[a]).rotate_left(16);

        state[c] = state[c].wrapping_add(state[d]);
        state[b] = (state[b] ^ state[c]).rotate_left(12);

        state[a] = state[a].wrapping_add(state[b]);
        state[d] = (state[d] ^ state[a]).rotate_left(8);

        state[c] = state[c].wrapping_add(state[d]);
        state[b] = (state[b] ^ state[c]).rotate_left(7);
    }

    #[allow(clippy::cast_possible_truncation)]
    fn refill_block(&mut self) {
        let mut state: [u32; 16] = [
            0x6170_7865,
            0x3320_646e,
            0x7962_2d32,
            0x6b20_6574,
            self.key[0],
            self.key[1],
            self.key[2],
            self.key[3],
            self.key[4],
            self.key[5],
            self.key[6],
            self.key[7],
            self.counter as u32,
            (self.counter >> 32) as u32,
            0,
            0,
        ];
        let initial = state;

        for _ in 0..10 {
            Self::quarter_round(&mut state, 0, 4, 8, 12);
            Self::quarter_round(&mut state, 1, 5, 9, 13);
            Self::quarter_round(&mut state, 2, 6, 10, 14);
            Self::quarter_round(&mut state, 3, 7, 11, 15);

            Self::quarter_round(&mut state, 0, 5, 10, 15);
            Self::quarter_round(&mut state, 1, 6, 11, 12);
            Self::quarter_round(&mut state, 2, 7, 8, 13);
            Self::quarter_round(&mut state, 3, 4, 9, 14);
        }

        for (i, word) in state.iter().enumerate() {
            let sum = word.wrapping_add(initial[i]);
            self.block[i * 4..(i + 1) * 4].copy_from_slice(&sum.to_le_bytes());
        }
        self.counter = self.counter.wrapping_add(1);
        self.offset = 0;
    }

    pub fn fill_bytes(&mut self, dest: &mut [u8]) {
        let mut written = 0;
        while written < dest.len() {
            if self.offset >= 64 {
                self.refill_block();
            }
            let avail = 64 - self.offset;
            let take = avail.min(dest.len() - written);
            dest[written..written + take]
                .copy_from_slice(&self.block[self.offset..self.offset + take]);
            self.offset += take;
            written += take;
        }
    }

    pub fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.fill_bytes(&mut buf);
        u32::from_le_bytes(buf)
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.fill_bytes(&mut buf);
        u64::from_le_bytes(buf)
    }
}

/// Derives an order-independent sub-seed anchored at `ChaCha20Rng::seed_from_u64(base_seed)`
/// for a specific `(workload, batch_n, param_value, policy, hash_alg)` coordinate.
#[must_use]
pub fn derive_config_rng(
    base_seed: u64,
    workload: WorkloadKind,
    batch_n: usize,
    param_value: u32,
    policy: OutputPolicy,
    hash_alg: HashAlg,
) -> ChaCha20Rng {
    let mut master_rng = ChaCha20Rng::seed_from_u64(base_seed);
    let mut root_key = [0u8; 32];
    master_rng.fill_bytes(&mut root_key);

    let domain = format!(
        "zkvm-tr2:{}:{}:{}:{:?}:{:?}",
        workload.as_str(),
        batch_n,
        param_value,
        policy,
        hash_alg
    );
    let mut material = Vec::with_capacity(32 + domain.len());
    material.extend_from_slice(&root_key);
    material.extend_from_slice(domain.as_bytes());
    let sub_seed = hash_bytes(HashAlg::Sha256, &material);
    ChaCha20Rng::from_seed(sub_seed)
}
