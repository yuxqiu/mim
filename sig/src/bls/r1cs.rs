use std::borrow::Borrow;

use ark_r1cs_std::alloc::{AllocVar, AllocationMode};
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::prelude::{Boolean, PairingVar};
use ark_r1cs_std::uint8::UInt8;
use ark_r1cs_std::R1CSVar;
use ark_relations::r1cs::{ConstraintSystemRef, Namespace, SynthesisError};

// Assuming BLS-specific types
use ark_bls12_381::{
    g1::G1_GENERATOR_X, g1::G1_GENERATOR_Y, g2::G2_GENERATOR_X, g2::G2_GENERATOR_Y, G1Affine,
    G2Affine,
};
use ark_r1cs_std::groups::bls12::{G1PreparedVar, G1Var, G2PreparedVar, G2Var};
use ark_r1cs_std::pairing::bls12;

use super::params::BaseField;
use super::{Parameters, PublicKey, Signature};

type G1Gadget = G1Var<ark_bls12_381::Config>;
type G2Gadget = G2Var<ark_bls12_381::Config>;

#[derive(Clone)]
pub struct ParametersVar {
    pub g1_generator: G1Gadget,
    pub g2_generator: G2Gadget,
}

#[derive(Clone)]
pub struct PublicKeyVar {
    pub pub_key: G1Gadget,
}

#[derive(Clone)]
pub struct SignatureVar {
    pub signature: G2Gadget,
}

pub struct BLSAggregateSignatureVerifyGadget;

impl BLSAggregateSignatureVerifyGadget {
    pub fn verify(
        parameters: &ParametersVar,
        public_keys: &[PublicKeyVar],
        message: &[UInt8<BaseField>],
        signature: &SignatureVar,
    ) -> Result<(), SynthesisError> {
        let cs = parameters.g1_generator.cs();

        // Aggregate all public keys
        let mut aggregated_pk = public_keys[0].pub_key.clone();
        for pk in public_keys.iter().skip(1) {
            aggregated_pk += &pk.pub_key;
        }

        // Hash the message into the curve point (this requires using a hash-to-curve function)
        let hash_to_curve = Self::hash_to_curve(cs.clone(), message, &parameters.g2_generator)?;

        // Verify e(signature, G) == e(aggregated_pk, H(m))
        let signature_paired = bls12::PairingVar::pairing(
            G1PreparedVar::<ark_bls12_381::Config>::from_group_var(&parameters.g1_generator)?,
            G2PreparedVar::from_group_var(&signature.signature)?,
        )?;
        let aggregated_pk_paired = bls12::PairingVar::pairing(
            G1PreparedVar::<ark_bls12_381::Config>::from_group_var(&aggregated_pk)?,
            G2PreparedVar::from_group_var(&hash_to_curve)?,
        )?;

        signature_paired
            .is_eq(&aggregated_pk_paired)?
            .enforce_equal(&Boolean::TRUE)?;

        Ok(())
    }

    fn hash_to_curve(
        cs: ConstraintSystemRef<BaseField>,
        _: &[UInt8<BaseField>],
        _: &G2Gadget,
    ) -> Result<G2Gadget, SynthesisError> {
        // TODO: this is a placeholder for a valid hash-to-curve implementation such as BLS-specific hashing defined in the IETF spec.
        let hash = G2Gadget::new_variable(
            cs,
            || Ok(G2Affine::new(G2_GENERATOR_X, G2_GENERATOR_Y)),
            AllocationMode::Witness,
        )?;
        Ok(hash)
    }
}

impl AllocVar<Signature, BaseField> for SignatureVar {
    fn new_variable<T: Borrow<Signature>>(
        cs: impl Into<Namespace<BaseField>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let sig = f()?;
        Ok(Self {
            signature: G2Gadget::new_variable(cs, || Ok(sig.borrow().signature), mode)?,
        })
    }
}

impl AllocVar<PublicKey, BaseField> for PublicKeyVar {
    fn new_variable<T: Borrow<PublicKey>>(
        cs: impl Into<Namespace<BaseField>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let public_key = f()?;
        Ok(Self {
            pub_key: G1Gadget::new_variable(cs, || Ok(public_key.borrow().pub_key), mode)?,
        })
    }
}

impl AllocVar<Parameters, BaseField> for ParametersVar {
    fn new_variable<T: Borrow<Parameters>>(
        cs: impl Into<Namespace<BaseField>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into();
        let default_param = Parameters {
            g1_generator: G1Affine::new_unchecked(G1_GENERATOR_X, G1_GENERATOR_Y).into(),
            g2_generator: G2Affine::new_unchecked(G2_GENERATOR_X, G2_GENERATOR_Y).into(),
        };
        let value = f();
        let param = value.as_ref().map(Borrow::borrow).unwrap_or(&default_param);

        Ok(Self {
            g1_generator: G1Gadget::new_variable(cs.clone(), || Ok(param.g1_generator), mode)?,
            g2_generator: G2Gadget::new_variable(cs, || Ok(param.g2_generator), mode)?,
        })
    }
}
