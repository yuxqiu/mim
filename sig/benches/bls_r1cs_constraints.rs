mod utils;

use ark_ec::{bls12::Bls12Config, pairing::Pairing};
use ark_r1cs_std::{
    alloc::AllocVar,
    fields::{emulated_fp::EmulatedFpVar, fp::FpVar},
    uint8::UInt8,
};
use ark_relations::r1cs::ConstraintSystem;
use sig::bls::{
    get_bls_instance, BLSAggregateSignatureVerifyGadget, ParametersVar, PublicKeyVar, SignatureVar,
};
use utils::register_tracing;

fn tracing_num_constraints_native() {
    type BlsSigConfig = ark_bls12_377::Config;
    type BaseSigCurveField = <BlsSigConfig as Bls12Config>::Fp;
    type BaseSNARKField = BaseSigCurveField;

    let cs = ConstraintSystem::new_ref();
    let (msg, params, _, pk, sig) = get_bls_instance::<BlsSigConfig>();

    let msg_var: Vec<UInt8<BaseSNARKField>> = msg
        .as_bytes()
        .iter()
        .map(|b| UInt8::new_input(cs.clone(), || Ok(b)).unwrap())
        .collect();

    let params_var: ParametersVar<BlsSigConfig, FpVar<BaseSNARKField>, BaseSNARKField> =
        ParametersVar::new_input(cs.clone(), || Ok(params)).unwrap();

    let pk_var = PublicKeyVar::new_input(cs.clone(), || Ok(pk)).unwrap();
    let sig_var = SignatureVar::new_input(cs.clone(), || Ok(sig)).unwrap();

    BLSAggregateSignatureVerifyGadget::verify(&params_var, &pk_var, &msg_var, &sig_var).unwrap();

    let num_constraints = cs.num_constraints();
    tracing::info!("Number of constraints: {}", num_constraints);
    assert!(cs.is_satisfied().unwrap());

    tracing::info!("R1CS is satisfied!");
}

fn tracing_num_constraints_emulated() {
    type BlsSigConfig = ark_bls12_381::Config;
    type BaseSigCurveField = <BlsSigConfig as Bls12Config>::Fp;
    type SNARKCurve = ark_bls12_377::Bls12_377;
    type BaseSNARKField = <SNARKCurve as Pairing>::ScalarField;

    let cs = ConstraintSystem::new_ref();
    let (msg, params, _, pk, sig) = get_bls_instance::<BlsSigConfig>();

    let msg_var: Vec<UInt8<BaseSNARKField>> = msg
        .as_bytes()
        .iter()
        .map(|b| UInt8::new_input(cs.clone(), || Ok(b)).unwrap())
        .collect();

    let params_var: ParametersVar<
        BlsSigConfig,
        EmulatedFpVar<BaseSigCurveField, BaseSNARKField>,
        BaseSNARKField,
    > = ParametersVar::new_input(cs.clone(), || Ok(params)).unwrap();

    let pk_var = PublicKeyVar::new_input(cs.clone(), || Ok(pk)).unwrap();
    let sig_var = SignatureVar::new_input(cs.clone(), || Ok(sig)).unwrap();

    BLSAggregateSignatureVerifyGadget::verify(&params_var, &pk_var, &msg_var, &sig_var).unwrap();

    let num_constraints = cs.num_constraints();
    tracing::info!("Number of constraints: {}", num_constraints);
    assert!(cs.is_satisfied().unwrap());

    tracing::info!("R1CS is satisfied!");
}

fn main() {
    register_tracing();

    tracing_num_constraints_native();
    tracing_num_constraints_emulated();
}
