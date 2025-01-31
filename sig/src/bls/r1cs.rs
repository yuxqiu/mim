use core::borrow::Borrow;

use ark_crypto_primitives::prf::blake2s::constraints::Blake2sGadget;
use ark_ec::bls12::Bls12;
use ark_ec::pairing::Pairing;
use ark_ec::{CurveConfig, CurveGroup};
use ark_r1cs_std::alloc::{AllocVar, AllocationMode};
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::groups::CurveVar;
use ark_r1cs_std::pairing::bls12;
use ark_r1cs_std::prelude::{Boolean, PairingVar};
use ark_r1cs_std::uint8::UInt8;
use ark_r1cs_std::R1CSVar;
use ark_relations::r1cs::{Namespace, SynthesisError};
use ark_std::One;

// Assuming BLS-specific types
use ark_bls12_381::{
    g1::G1_GENERATOR_X, g1::G1_GENERATOR_Y, g2::G2_GENERATOR_X, g2::G2_GENERATOR_Y, G1Affine,
    G2Affine,
};
use ark_r1cs_std::groups::bls12::{G1PreparedVar, G1Var, G2PreparedVar, G2Var};

use crate::bls::{HashCurveGroup, HashCurveVar};
use crate::hash::hash_to_curve::MapToCurveBasedHasherGadget;
use crate::hash::hash_to_field::default_hasher::DefaultFieldHasherGadget;
use crate::hash::map_to_curve::wb::WBMapGadget;

use super::params::BaseField;
use super::{BLSSigCurveConfig, Parameters, PublicKey, Signature, TargetField};

macro_rules! fp_var {
    // For experimentation: checking whether R1CS circuit is satisfied
    // ($type_a:ty, $type_b:ty) => {
    //     ark_r1cs_std::fields::fp::FpVar::<$type_a>
    // };
    ($type_a:ty, $type_b:ty) => {
        ark_r1cs_std::fields::emulated_fp::EmulatedFpVar::<$type_a, $type_b>
    };
}

type G1Gadget = G1Var<BLSSigCurveConfig, fp_var!(TargetField, BaseField), BaseField>;
type G2Gadget = G2Var<BLSSigCurveConfig, fp_var!(TargetField, BaseField), BaseField>;

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
        pk: &PublicKeyVar,
        message: &[UInt8<BaseField>],
        signature: &SignatureVar,
    ) -> Result<(), SynthesisError> {
        let cs = parameters.g1_generator.cs();

        // Hash the message into the curve point (this requires using a hash-to-curve function)
        let hash_to_curve = Self::hash_to_curve(message)?;

        // an optimised way to check two pairings are equal
        let prod =
            bls12::PairingVar::product_of_pairings(
                &[
                    G1PreparedVar::<
                        BLSSigCurveConfig,
                        fp_var!(TargetField, BaseField),
                        BaseField,
                    >::from_group_var(&parameters.g1_generator.negate()?)?,
                    G1PreparedVar::<
                        BLSSigCurveConfig,
                        fp_var!(TargetField, BaseField),
                        BaseField,
                    >::from_group_var(&pk.pub_key)?,
                ],
                &[
                    G2PreparedVar::from_group_var(&signature.signature)?,
                    G2PreparedVar::from_group_var(&hash_to_curve)?,
                ],
            )?;

        prod.is_eq(&<bls12::PairingVar<
            BLSSigCurveConfig,
            fp_var!(TargetField, BaseField),
            BaseField,
        > as PairingVar<Bls12<BLSSigCurveConfig>, BaseField>>::GTVar::new_constant(
            cs,
            <Bls12<BLSSigCurveConfig> as Pairing>::TargetField::one(),
        )?)?
        .enforce_equal(&Boolean::TRUE)?;

        Ok(())
    }

    pub fn verify_slow(
        parameters: &ParametersVar,
        pk: &PublicKeyVar,
        message: &[UInt8<BaseField>],
        signature: &SignatureVar,
    ) -> Result<(), SynthesisError> {
        // Hash the message into the curve point
        let hash_to_curve = Self::hash_to_curve(message)?;

        // Verify e(signature, G) == e(aggregated_pk, H(m))
        let signature_paired =
            bls12::PairingVar::pairing(
                G1PreparedVar::<
                    BLSSigCurveConfig,
                    fp_var!(TargetField, BaseField),
                    BaseField,
                >::from_group_var(&parameters.g1_generator)?,
                G2PreparedVar::from_group_var(&signature.signature)?,
            )?;
        let aggregated_pk_paired =
            bls12::PairingVar::pairing(
                G1PreparedVar::<
                    BLSSigCurveConfig,
                    fp_var!(TargetField, BaseField),
                    BaseField,
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
        message: &[UInt8<BaseField>],
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

    fn hash_to_curve(msg: &[UInt8<BaseField>]) -> Result<G2Gadget, SynthesisError> {
        type HashGroupBaseField =
            <<HashCurveGroup as CurveGroup>::Config as CurveConfig>::BaseField;

        type FieldHasherGadget = DefaultFieldHasherGadget<
            Blake2sGadget<BaseField>,
            HashGroupBaseField,
            BaseField,
            HashCurveVar<fp_var!(TargetField, BaseField), BaseField>,
            128,
        >;
        type CurveMapGadget = WBMapGadget<<HashCurveGroup as CurveGroup>::Config>;
        type HasherGadget = MapToCurveBasedHasherGadget<
            HashCurveGroup,
            FieldHasherGadget,
            CurveMapGadget,
            BaseField,
            HashCurveVar<fp_var!(TargetField, BaseField), BaseField>,
        >;

        let hasher_gadget = HasherGadget::new(&[]);
        hasher_gadget.hash(&msg)
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
