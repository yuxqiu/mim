use criterion::{criterion_group, criterion_main, Criterion};
use sig::bls::{get_bls_instance, Signature};

fn bls_verify_bench(c: &mut Criterion) {
    let (msg, params, _, pk, sig) = get_bls_instance::<ark_bls12_381::Config>();
    let mut group = c.benchmark_group("BLS Signature");

    group.bench_function("verify (2 pairings)", |b| {
        b.iter(|| Signature::verify_slow(msg.as_bytes(), &sig, &pk, &params));
    });
    group.bench_function("verify (2 miller's loop + 1 final exponentiation)", |b| {
        b.iter(|| Signature::verify(msg.as_bytes(), &sig, &pk, &params));
    });
    group.finish();
}

criterion_group!(benches, bls_verify_bench);
criterion_main!(benches);
