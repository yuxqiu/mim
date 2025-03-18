use core::borrow::Borrow;

use ark_crypto_primitives::prf::blake2s::constraints::Blake2sGadget;
use ark_ec::bls12::Bls12;
use ark_ec::pairing::Pairing;
use ark_ec::{CurveConfig, CurveGroup};
use ark_ff::Field;
use ark_r1cs_std::alloc::{AllocVar, AllocationMode};
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::groups::CurveVar;
use ark_r1cs_std::pairing::bls12;
use ark_r1cs_std::prelude::{Boolean, PairingVar};
use ark_r1cs_std::uint8::UInt8;
use ark_r1cs_std::R1CSVar;
use ark_relations::r1cs::{Namespace, SynthesisError};

// Assuming the sig is running on BLS12 family of curves
use ark_r1cs_std::groups::bls12::{G1PreparedVar, G1Var, G2PreparedVar, G2Var};

use crate::fp_var;
use crate::hash::hash_to_curve::MapToCurveBasedHasherGadget;
use crate::hash::hash_to_field::default_hasher::DefaultFieldHasherGadget;
use crate::hash::map_to_curve::wb::WBMapGadget;
use crate::params::{
    BLSSigCurveConfig, BaseSNARKField, BaseSigCurveField, HashCurveGroup, HashCurveVar,
};

use super::{Parameters, PublicKey, Signature};

type G1Gadget =
    G1Var<BLSSigCurveConfig, fp_var!(BaseSigCurveField, BaseSNARKField), BaseSNARKField>;
type G2Gadget =
    G2Var<BLSSigCurveConfig, fp_var!(BaseSigCurveField, BaseSNARKField), BaseSNARKField>;

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
    #[tracing::instrument(skip_all)]
    pub fn verify(
        parameters: &ParametersVar,
        pk: &PublicKeyVar,
        message: &[UInt8<BaseSNARKField>],
        signature: &SignatureVar,
    ) -> Result<(), SynthesisError> {
        let cs = parameters.g1_generator.cs();

        tracing::info!(num_constraints = cs.num_constraints());

        let hash_to_curve = Self::hash_to_curve(message)?;

        // an optimised way to check two pairings are equal
        let prod = bls12::PairingVar::product_of_pairings(
            &[
                G1PreparedVar::<
                    BLSSigCurveConfig,
                    fp_var!(BaseSigCurveField, BaseSNARKField),
                    BaseSNARKField,
                >::from_group_var(&parameters.g1_generator.negate()?)?,
                G1PreparedVar::<
                    BLSSigCurveConfig,
                    fp_var!(BaseSigCurveField, BaseSNARKField),
                    BaseSNARKField,
                >::from_group_var(&pk.pub_key)?,
            ],
            &[
                G2PreparedVar::from_group_var(&signature.signature)?,
                G2PreparedVar::from_group_var(&hash_to_curve)?,
            ],
        )?;

        prod.is_eq(
            &<bls12::PairingVar<
                BLSSigCurveConfig,
                fp_var!(BaseSigCurveField, BaseSNARKField),
                BaseSNARKField,
            > as PairingVar<Bls12<BLSSigCurveConfig>, BaseSNARKField>>::GTVar::new_constant(
                cs.clone(),
                <<Bls12<BLSSigCurveConfig> as Pairing>::TargetField as Field>::ONE,
            )?,
        )?
        .enforce_equal(&Boolean::TRUE)?;

        tracing::info!(num_constraints = cs.num_constraints());

        Ok(())
    }

    pub fn verify_slow(
        parameters: &ParametersVar,
        pk: &PublicKeyVar,
        message: &[UInt8<BaseSNARKField>],
        signature: &SignatureVar,
    ) -> Result<(), SynthesisError> {
        let hash_to_curve = Self::hash_to_curve(message)?;

        // Verify e(signature, G) == e(aggregated_pk, H(m))
        let signature_paired = bls12::PairingVar::pairing(
            G1PreparedVar::<
                BLSSigCurveConfig,
                fp_var!(BaseSigCurveField, BaseSNARKField),
                BaseSNARKField,
            >::from_group_var(&parameters.g1_generator)?,
            G2PreparedVar::from_group_var(&signature.signature)?,
        )?;
        let aggregated_pk_paired = bls12::PairingVar::pairing(
            G1PreparedVar::<
                BLSSigCurveConfig,
                fp_var!(BaseSigCurveField, BaseSNARKField),
                BaseSNARKField,
            >::from_group_var(&pk.pub_key)?,
            G2PreparedVar::from_group_var(&hash_to_curve)?,
        )?;

        signature_paired
            .is_eq(&aggregated_pk_paired)?
            .enforce_equal(&Boolean::TRUE)?;

        Ok(())
    }

    /// Not recommended, public key aggregation can be moved outside the SNARK
    ///
    /// The time complexity will not change as we always need to pay the cost of
    /// deserializing public keys
    pub fn aggregate_verify(
        parameters: &ParametersVar,
        public_keys: &[PublicKeyVar],
        message: &[UInt8<BaseSNARKField>],
        signature: &SignatureVar,
    ) -> Result<(), SynthesisError> {
        // Aggregate all public keys
        let aggregated_pk =
            public_keys
                .iter()
                .skip(1)
                .fold(public_keys[0].clone(), |acc, new_pk| PublicKeyVar {
                    pub_key: acc.pub_key + &new_pk.pub_key,
                });

        // Verify e(signature, G) == e(aggregated_pk, H(m))
        Self::verify(parameters, &aggregated_pk, message, signature)
    }

    #[tracing::instrument(skip_all)]
    pub fn hash_to_curve(msg: &[UInt8<BaseSNARKField>]) -> Result<G2Gadget, SynthesisError> {
        type HashGroupBaseField =
            <<HashCurveGroup as CurveGroup>::Config as CurveConfig>::BaseField;

        type FieldHasherGadget = DefaultFieldHasherGadget<
            Blake2sGadget<BaseSNARKField>,
            HashGroupBaseField,
            BaseSNARKField,
            HashCurveVar<fp_var!(BaseSigCurveField, BaseSNARKField), BaseSNARKField>,
            128,
        >;
        type CurveMapGadget = WBMapGadget<<HashCurveGroup as CurveGroup>::Config>;
        type HasherGadget = MapToCurveBasedHasherGadget<
            HashCurveGroup,
            FieldHasherGadget,
            CurveMapGadget,
            BaseSNARKField,
            HashCurveVar<fp_var!(BaseSigCurveField, BaseSNARKField), BaseSNARKField>,
        >;

        let cs = msg.cs();
        tracing::info!(num_constraints = cs.num_constraints());

        let hasher_gadget = HasherGadget::new(&[]);
        let hash = hasher_gadget.hash(&msg);

        tracing::info!(num_constraints = cs.num_constraints());

        hash
    }
}

impl AllocVar<Signature, BaseSNARKField> for SignatureVar {
    fn new_variable<T: Borrow<Signature>>(
        cs: impl Into<Namespace<BaseSNARKField>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        Ok(Self {
            signature: G2Gadget::new_variable(
                cs,
                || f().map(|value| value.borrow().signature),
                mode,
            )?,
        })
    }
}

impl AllocVar<PublicKey, BaseSNARKField> for PublicKeyVar {
    fn new_variable<T: Borrow<PublicKey>>(
        cs: impl Into<Namespace<BaseSNARKField>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        Ok(Self {
            pub_key: G1Gadget::new_variable(cs, || f().map(|value| value.borrow().pub_key), mode)?,
        })
    }
}

impl AllocVar<Parameters, BaseSNARKField> for ParametersVar {
    fn new_variable<T: Borrow<Parameters>>(
        cs: impl Into<Namespace<BaseSNARKField>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into();
        let value = f();

        Ok(Self {
            g1_generator: G1Gadget::new_variable(
                cs.clone(),
                || {
                    value
                        .as_ref()
                        .map(|value| value.borrow().g1_generator)
                        .map_err(SynthesisError::clone)
                },
                mode,
            )?,
            g2_generator: G2Gadget::new_variable(
                cs,
                || {
                    value
                        .as_ref()
                        .map(|value| value.borrow().g2_generator)
                        .map_err(SynthesisError::clone)
                },
                mode,
            )?,
        })
    }
}

#[cfg(test)]
mod test {
    use crate::{
        bls::{
            get_bls_instance, BLSAggregateSignatureVerifyGadget, ParametersVar, PublicKeyVar,
            SignatureVar,
        },
        params::BaseSNARKField,
    };

    use ark_r1cs_std::{alloc::AllocVar, uint8::UInt8};
    use ark_relations::r1cs::ConstraintSystem;

    #[test]
    fn check_r1cs() {
        let cs = ConstraintSystem::new_ref();
        let (msg, params, _, pk, sig) = get_bls_instance();

        let msg_var: Vec<UInt8<BaseSNARKField>> = msg
            .as_bytes()
            .iter()
            .map(|b| UInt8::new_input(cs.clone(), || Ok(b)).unwrap())
            .collect();
        let params_var = ParametersVar::new_input(cs.clone(), || Ok(params)).unwrap();
        let pk_var = PublicKeyVar::new_input(cs.clone(), || Ok(pk)).unwrap();
        let sig_var = SignatureVar::new_input(cs.clone(), || Ok(sig)).unwrap();

        BLSAggregateSignatureVerifyGadget::verify(&params_var, &pk_var, &msg_var, &sig_var)
            .unwrap();

        println!("Number of constraints: {}", cs.num_constraints());
        assert!(cs.is_satisfied().unwrap());

        println!("RC1S is satisfied!");
    }
}
