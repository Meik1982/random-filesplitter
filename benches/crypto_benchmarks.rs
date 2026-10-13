use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use blks_core::BlksHasher;
use rfs_core::crypto::{self, ChaChaRng};

fn bench_simd_xor(c: &mut Criterion) {
    let mut group = c.benchmark_group("simd_xor");
    let sizes = [64 * 1024, 1024 * 1024, 4 * 1024 * 1024];

    for &size in &sizes {
        group.throughput(Throughput::Bytes(size as u64));

        let mut dst = vec![0x55u8; size];
        let src = vec![0xAAu8; size];

        group.bench_with_input(BenchmarkId::new("as_chunks_64", size), &size, |b, _| {
            b.iter(|| {
                crypto::xor_in_place(black_box(&mut dst), black_box(&src));
            });
        });
    }
    group.finish();
}

fn bench_chacha20_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("chacha20_prng");
    let sizes = [64 * 1024, 1024 * 1024];

    for &size in &sizes {
        group.throughput(Throughput::Bytes(size as u64));
        let mut buf = vec![0u8; size];
        let key = [0x42u8; 32];
        let nonce = [0x13u8; 12];

        group.bench_with_input(BenchmarkId::new("fill_bytes", size), &size, |b, _| {
            let mut rng = ChaChaRng::new(&key, &nonce);
            b.iter(|| {
                rng.fill_bytes(black_box(&mut buf));
            });
        });
    }
    group.finish();
}

fn bench_blks384_hashing(c: &mut Criterion) {
    let mut group = c.benchmark_group("blks384_hash");
    let sizes = [64 * 1024, 1024 * 1024];

    for &size in &sizes {
        group.throughput(Throughput::Bytes(size as u64));
        let data = vec![0x77u8; size];

        group.bench_with_input(BenchmarkId::new("update", size), &size, |b, _| {
            b.iter(|| {
                let mut hasher = BlksHasher::new();
                hasher.update(black_box(&data));
                black_box(hasher.finalize());
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_simd_xor, bench_chacha20_throughput, bench_blks384_hashing);
criterion_main!(benches);
