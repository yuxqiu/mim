pub mod bls;

use ark_r1cs_std::{alloc::AllocVar, uint8::UInt8};
use ark_relations::r1cs::ConstraintSystem;
use bls::{
    BLSAggregateSignatureVerifyGadget, BaseField, Parameters, ParametersVar, PublicKey,
    PublicKeyVar, SecretKey, Signature, SignatureVar,
};
use rand::thread_rng;

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

    return (msg, params, secret_keys, public_keys, sig);
}

fn check_r1cs() {
    let cs = ConstraintSystem::<BaseField>::new_ref();
    let (msg, params, _, public_keys, sig) = get_aggregate_instances();

    let msg_var: Vec<UInt8<BaseField>> = msg
        .as_bytes()
        .iter()
        .map(|b| UInt8::new_input(cs.clone(), || Ok(b)).unwrap())
        .collect();
    let params_var = ParametersVar::new_input(cs.clone(), || Ok(params)).unwrap();
    let pk_vars: Vec<PublicKeyVar> = public_keys
        .iter()
        .map(|pk| PublicKeyVar::new_input(cs.clone(), || Ok(pk)).unwrap())
        .collect();
    let sig_var = SignatureVar::new_input(cs.clone(), || Ok(sig)).unwrap();

    BLSAggregateSignatureVerifyGadget::verify(&params_var, &pk_vars, &msg_var, &sig_var).unwrap();

    println!("{}", cs.num_constraints());
    assert!(cs.is_satisfied().unwrap());
}

fn check_signature() {
    let msg = "Hello World";
    let mut rng = thread_rng();

    let params = Parameters::setup();
    let sk = SecretKey::new(&mut rng);
    let pk = PublicKey::new(&sk, &params);
    let sig = Signature::sign(msg.as_bytes(), &sk, &params);

    assert!(Signature::verify(msg.as_bytes(), &sig, &pk, &params));
}

fn check_aggregate_signature() {
    let (msg, params, _, public_keys, sig) = get_aggregate_instances();
    assert!(Signature::aggregate_verify(msg.as_bytes(), &sig, &public_keys, &params).unwrap());
}

fn main() {
    check_signature();
    check_aggregate_signature();
    check_r1cs();
}
