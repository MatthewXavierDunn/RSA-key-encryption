use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use rsa::{rsa_decrypt, rsa_encrypt, seeded_gen_prime, seeded_gen_rsa_keysets};

fn encrypt_decrypt() {
    let ((public_key, modulus), private_key) = seeded_gen_rsa_keysets(black_box(256));
    let msg = 12345u128;
    let ct = rsa_encrypt(msg, public_key, modulus.clone());
    black_box(rsa_decrypt(ct, private_key, modulus.clone()));
}

fn fast_prime_gen() {
    black_box(seeded_gen_prime(black_box(256)));
}

fn rsa_keyset_gen(size: usize) {
    black_box(seeded_gen_rsa_keysets(size));
}

fn benchmark(c: &mut Criterion) {
    c.bench_function("encrypt_decrypt", |b| b.iter(|| encrypt_decrypt()));
    c.bench_function("fast_prime_gen", |b| b.iter(|| fast_prime_gen()));

    let mut group = c.benchmark_group("key-sizes-gen");
    for size in [128, 256, 512, 1024, 2048].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            b.iter(|| rsa_keyset_gen(size));
        });
    }
    group.finish();
}

criterion_group!(benches, benchmark);
criterion_main!(benches);
