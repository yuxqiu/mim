use ark_groth16::Groth16;
use ark_snark::{CircuitSpecificSetupSNARK, SNARK};
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
    let (pk, vk) = {
        // in setup node, we don't need to provide assignment
        let msg = vec![None; msg.len()];
        let circuit = BLSCircuit::new(None, None, &msg, None);
        Groth16::<SNARKCurve>::setup(circuit.clone(), &mut rng).unwrap()
    };
    let pvk = Groth16::<SNARKCurve>::process_vk(&vk).unwrap();

    // Get public inputs
    let public_inputs = circuit.get_public_inputs().unwrap();

    // Create a proof
    let proof = Groth16::<SNARKCurve>::prove(&pk, circuit.clone(), &mut rng).unwrap();

    // Verify the proof
    let verified =
        Groth16::<SNARKCurve>::verify_with_processed_vk(&pvk, &public_inputs, &proof).unwrap();

    assert!(verified);
    println!("Proof verified successfully!");
}

fn main() {
    bench_groth16();
}
