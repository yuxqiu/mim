use ark_ec::bls12::Bls12Config;
use ark_groth16::Groth16;
use ark_r1cs_std::fields::fp::FpVar;
use ark_snark::{CircuitSpecificSetupSNARK, SNARK};
use criterion::{criterion_group, criterion_main, Criterion};
use rand::thread_rng;
use sig::bls::{get_bls_instance, BLSCircuit};

fn bench_groth16(c: &mut Criterion) {
    type BlsSigConfig = ark_bls12_377::Config;
    type BaseSigCurveField = <BlsSigConfig as Bls12Config>::Fp;
    type BaseSNARKField = BaseSigCurveField;
    type SNARKCurve = ark_bw6_761::BW6_761;

    let (msg, params, _, pk_bls, sig) = get_bls_instance::<BlsSigConfig>();
    let mut rng = thread_rng();

    // ===============Setup pk and vk===============
    let mut pk_vk_gen = || {
        // in setup node, we don't need to provide assignment
        let msg = vec![None; msg.len()];
        let circuit = BLSCircuit::<BlsSigConfig, FpVar<BaseSNARKField>, BaseSNARKField>::new(
            None, None, &msg, None,
        );
        Groth16::<SNARKCurve>::setup(circuit.clone(), &mut rng).unwrap()
    };

    {
        c.bench_function("pk and vk generation", |b| {
            b.iter(|| pk_vk_gen());
        });
    }

    let (pk, vk) = pk_vk_gen();

    let pvk_gen = || Groth16::<SNARKCurve>::process_vk(&vk).unwrap();

    {
        c.bench_function("pvk generation", |b| {
            b.iter(|| pvk_gen());
        });
    }

    let pvk = Groth16::<SNARKCurve>::process_vk(&vk).unwrap();

    // ===============Setup circuit===============
    let msg = msg
        .as_bytes()
        .iter()
        .copied()
        .map(Option::Some)
        .collect::<Vec<_>>();

    let circuit = BLSCircuit::<BlsSigConfig, FpVar<BaseSNARKField>, BaseSNARKField>::new(
        Some(params),
        Some(pk_bls),
        &msg,
        Some(sig),
    );

    // ===============Get public inputs===============
    let public_inputs = circuit.get_public_inputs().unwrap();

    // ===============Create a proof===============
    let proof_gen =
        || Groth16::<SNARKCurve>::create_proof_with_reduction_no_zk(circuit.clone(), &pk).unwrap();

    {
        c.bench_function("proof generation", |b| {
            b.iter(|| proof_gen());
        });
    }

    let proof = proof_gen();

    // ===============Verify the proof===============
    let verification =
        || Groth16::<SNARKCurve>::verify_with_processed_vk(&pvk, &public_inputs, &proof).unwrap();

    {
        c.bench_function("verification", |b| {
            b.iter(|| verification());
        });
    }

    let verified = verification();
    assert!(verified);
    println!("Proof verified successfully!");
}

// set the minimum possible sample size because running each of them takes time
criterion_group! {name = benches; config = Criterion::default().sample_size(10); targets = bench_groth16}
criterion_main!(benches);
