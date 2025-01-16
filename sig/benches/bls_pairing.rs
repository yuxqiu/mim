use criterion::{criterion_group, criterion_main, Criterion};
use rand::thread_rng;
use sig::bls::{Parameters, PublicKey, SecretKey, Signature};

fn get_instance() -> (&'static str, Parameters, SecretKey, PublicKey, Signature) {
    let msg = "Hello World";
    let mut rng = thread_rng();

    let params = Parameters::setup();
    let sk = SecretKey::new(&mut rng);
    let pk = PublicKey::new(&sk, &params);

    let sig = Signature::sign(msg.as_bytes(), &sk, &params);

    (msg, params, sk, pk, sig)
}

fn criterion_benchmark(c: &mut Criterion) {
    let (msg, params, _, pk, sig) = get_instance();
    let mut group = c.benchmark_group("BLS Signature");

    group.bench_function("verify (2 pairings)", |b| {
        b.iter(|| Signature::verify_slow(msg.as_bytes(), &sig, &pk, &params))
    });
    group.bench_function("verify (2 miller's loop + 1 final exponentiation)", |b| {
        b.iter(|| Signature::verify(msg.as_bytes(), &sig, &pk, &params))
    });
    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
