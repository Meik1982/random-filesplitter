//! Hardware-nahes Entropie-Harvesting mit 2 MB Sattolo Cache-Line Permutationspool.

use std::time::Instant;

/// 32K Elemente * 64 Bytes (1 Cache-Line) = 2 MB Puffer
/// Sprengt L1 und L2 Caches zur Erzeugung von echter Hardware- und Bus-Latenz
pub(crate) const POOL_NODES: usize = 32768;

#[repr(C, align(64))]
pub(crate) struct CacheLineNode {
    pub(crate) next: u32,
    pub(crate) _pad: [u8; 60],
}

pub(crate) fn init_permutation_pool(pool: &mut [CacheLineNode], seed_val: u64) {
    let mut perm: Vec<u32> = (0..POOL_NODES as u32).collect();
    let mut state = seed_val.wrapping_mul(6364136223846793005).wrapping_add(1);
    for i in (1..POOL_NODES).rev() {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        let j = (state >> 33) as usize % i;
        perm.swap(i, j);
    }
    for (i, node) in pool.iter_mut().enumerate() {
        node.next = perm[i];
    }
}

/// Universeller Entropie-Harvester: Erntet hochwertige 256-Bit Schlüssel und 96-Bit Nonce.
pub struct UniversalEntropyHarvester;

impl UniversalEntropyHarvester {
    /// Erntet kryptografisch sichere 32-Byte Key und 12-Byte Nonce mit automatischer RAII-Nullung
    pub fn harvest_seed() -> (zeroize::Zeroizing<[u8; 32]>, zeroize::Zeroizing<[u8; 12]>) {
        let mut key = zeroize::Zeroizing::new([0u8; 32]);
        let mut nonce = zeroize::Zeroizing::new([0u8; 12]);

        // 1. Primärquelle: OS-Kernel CSPRNG (getrandom)
        getrandom::getrandom(key.as_mut_slice()).expect("OS CSPRNG Fehler bei Key");
        getrandom::getrandom(nonce.as_mut_slice()).expect("OS CSPRNG Fehler bei Nonce");

        // 2. Defence-in-Depth: CPU-Jitter und High-Res Clock einmischen
        let now = Instant::now();
        let nanos = now.elapsed().as_nanos();
        let jitter = Self::sample_cpu_jitter();

        for (i, b) in key.iter_mut().enumerate() {
            *b ^= ((nanos >> (i * 2)) as u8) ^ jitter[i % jitter.len()];
        }
        for (i, b) in nonce.iter_mut().enumerate() {
            *b ^= ((nanos >> (i * 3 + 1)) as u8) ^ jitter[(i + 7) % jitter.len()];
        }

        (key, nonce)
    }

    /// Schneller CPU-Jitter-Sampler für Entropie-Mischung
    fn sample_cpu_jitter() -> [u8; 16] {
        let mut out = [0u8; 16];
        let mut prev = Instant::now();
        for (i, b) in out.iter_mut().enumerate() {
            let mut acc = 0u64;
            for _ in 0..64 {
                let curr = Instant::now();
                let delta = curr.duration_since(prev).as_nanos() as u64;
                acc = acc.wrapping_mul(6364136223846793005).wrapping_add(delta);
                prev = curr;
            }
            *b = (acc ^ (acc >> 8) ^ (acc >> 16) ^ (acc >> 24) ^ (i as u64)) as u8;
        }
        out
    }
}
