pub mod bls;

use ark_bls12_381::Bls12_381;
use ark_crypto_primitives::snark::SNARK;
use ark_groth16::{prepare_verifying_key, Groth16};
use ark_r1cs_std::{alloc::AllocVar, uint8::UInt8};
use ark_relations::r1cs::ConstraintSystem;
use bls::{
    BLSAggregateSignatureVerifyGadget, BLSCircuit, BaseField, Parameters, ParametersVar, PublicKey,
    PublicKeyVar, SecretKey, Signature, SignatureVar,
};
use rand::thread_rng;

fn get_instance() -> (&'static str, Parameters, SecretKey, PublicKey, Signature) {
    let msg = "Hello World";
    let mut rng = thread_rng();

    let params = Parameters::setup();
    let sk = SecretKey::new(&mut rng);
    let pk = PublicKey::new(&sk, &params);

    let sig = Signature::sign(msg.as_bytes(), &sk, &params);

    (msg, params, sk, pk, sig)
}

fn get_aggregate_instances() -> (
    &'static str,
    Parameters,
    Vec<SecretKey>,
    Vec<PublicKey>,
    Signature,
) {
    const N: usize = 1000;

    let msg = "Hello World";
    let mut rng = thread_rng();

    let params = Parameters::setup();
    let secret_keys: Vec<SecretKey> = (0..N).map(|_| SecretKey::new(&mut rng)).collect();
    let public_keys: Vec<PublicKey> = secret_keys
        .iter()
        .map(|sk| PublicKey::new(sk, &params))
        .collect();

    let sig = Signature::aggregate_sign(msg.as_bytes(), &secret_keys, &params).unwrap();

    (msg, params, secret_keys, public_keys, sig)
}

fn check_signature() {
    let (msg, params, _, pk, sig) = get_instance();
    assert!(Signature::verify(msg.as_bytes(), &sig, &pk, &params));
}

fn check_aggregate_signature() {
    let (msg, params, _, public_keys, sig) = get_aggregate_instances();
    assert!(Signature::aggregate_verify(msg.as_bytes(), &sig, &public_keys, &params).unwrap());
}

fn check_r1cs() {
    let cs = ConstraintSystem::new_ref();
    let (msg, params, _, pk, sig) = get_instance();

    let msg_var: Vec<UInt8<BaseField>> = msg
        .as_bytes()
        .iter()
        .map(|b| UInt8::new_input(cs.clone(), || Ok(b)).unwrap())
        .collect();
    let params_var = ParametersVar::new_input(cs.clone(), || Ok(params)).unwrap();
    let pk_var = PublicKeyVar::new_input(cs.clone(), || Ok(pk)).unwrap();
    let sig_var = SignatureVar::new_input(cs.clone(), || Ok(sig)).unwrap();

    BLSAggregateSignatureVerifyGadget::verify(&params_var, &pk_var, &msg_var, &sig_var).unwrap();

    println!("Number of constraints: {}", cs.num_constraints());
    assert!(cs.is_satisfied().unwrap());

    println!("RC1S is satisfied!")
}

fn check_snark() {
    let (msg, params, _, pk, sig) = get_instance();
    let mut rng = thread_rng();

    let circuit = BLSCircuit::new(params, pk, msg.as_bytes(), sig);

    // Setup pk
    let pk =
        Groth16::<Bls12_381>::generate_random_parameters_with_reduction(circuit.clone(), &mut rng)
            .unwrap();

    // Create a proof
    let proof = Groth16::<Bls12_381>::prove(&pk, circuit.clone(), &mut rng).unwrap();

    // Verify the proof
    let pvk = prepare_verifying_key(&pk.vk);
    let verified =
        Groth16::<Bls12_381>::verify_proof(&pvk, &proof, &circuit.get_public_inputs().unwrap())
            .unwrap();
    assert!(verified);

    println!("Proof verified successfully!");
}

fn main() {
    check_signature();
    check_aggregate_signature();
    check_r1cs();
    check_snark();
}
