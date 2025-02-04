use ark_groth16::{prepare_verifying_key, Groth16};
use ark_snark::SNARK;
use rand::thread_rng;
use sig::bls::{BLSCircuit, Parameters, PublicKey, SNARKCurve, SecretKey, Signature};

fn get_instance() -> (&'static str, Parameters, SecretKey, PublicKey, Signature) {
    let msg = "Hello World";
    let mut rng = thread_rng();

    let params = Parameters::setup();
    let sk = SecretKey::new(&mut rng);
    let pk = PublicKey::new(&sk, &params);

    let sig = Signature::sign(msg.as_bytes(), &sk, &params);

    (msg, params, sk, pk, sig)
}

fn bench_groth16() {
    let (msg, params, _, pk, sig) = get_instance();
    let mut rng = thread_rng();

    let msg = msg
        .as_bytes()
        .iter()
        .copied()
        .map(Option::Some)
        .collect::<Vec<_>>();

    let circuit = BLSCircuit::new(Some(params), Some(pk), &msg, Some(sig));

    // Setup pk and vk
    let pk = {
        // in setup node, we don't need to provide assignment
        let msg = vec![None; msg.len()];
        let circuit = BLSCircuit::new(None, None, &msg, None);
        Groth16::<SNARKCurve>::generate_random_parameters_with_reduction(circuit.clone(), &mut rng)
            .unwrap()
    };
    let pvk = prepare_verifying_key(&pk.vk);

    // Get public inputs
    let public_inputs = circuit.get_public_inputs().unwrap();

    // Create a proof
    let proof = Groth16::<SNARKCurve>::prove(&pk, circuit.clone(), &mut rng).unwrap();

    // Verify the proof
    let verified = Groth16::<SNARKCurve>::verify_proof(&pvk, &proof, &public_inputs).unwrap();

    assert!(verified);
    println!("Proof verified successfully!");
}

fn main() {
    bench_groth16();
}
