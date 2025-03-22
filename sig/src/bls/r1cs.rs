use core::borrow::Borrow;
use std::marker::PhantomData;

use ark_crypto_primitives::prf::blake2s::constraints::Blake2sGadget;
use ark_ec::bls12::{Bls12, Bls12Config};
use ark_ec::hashing::curve_maps::wb::WBConfig;
use ark_ec::pairing::Pairing;
use ark_ec::short_weierstrass::SWCurveConfig;
use ark_ec::{CurveConfig, CurveGroup};
use ark_ff::{Field, PrimeField};
use ark_r1cs_std::alloc::{AllocVar, AllocationMode};
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::{FieldOpsBounds, FieldVar};
use ark_r1cs_std::groups::CurveVar;
use ark_r1cs_std::pairing::bls12;
use ark_r1cs_std::prelude::{Boolean, PairingVar};
use ark_r1cs_std::uint8::UInt8;
use ark_r1cs_std::R1CSVar;
use ark_relations::r1cs::{Namespace, SynthesisError};

// Assuming the sig is running on BLS12 family of curves
use ark_r1cs_std::groups::bls12::{G1PreparedVar, G1Var, G2PreparedVar, G2Var};
use derivative::Derivative;

use crate::hash::hash_to_curve::cofactor::CofactorGadget;
use crate::hash::hash_to_curve::MapToCurveBasedHasherGadget;
use crate::hash::hash_to_field::default_hasher::DefaultFieldHasherGadget;
use crate::hash::{
    hash_to_field::from_base_field::FromBaseFieldVarGadget,
    map_to_curve::{sqrt::SqrtGadget, to_base_field::ToBaseFieldVarGadget, wb::WBMapGadget},
};
use crate::params::BlsSigField;

use super::params::{HashCurveConfig, HashCurveGroup, HashCurveVar};
use super::{Parameters, PublicKey, Signature};

#[derive(Derivative)]
#[derivative(
    Clone(bound = ""),
    Debug(bound = ""),
)]
pub struct ParametersVar<
    SigCurveConfig: Bls12Config,
    FV: FieldVar<BlsSigField<SigCurveConfig>, CF>,
    CF: PrimeField,
> where
    for<'a> &'a FV: FieldOpsBounds<'a, BlsSigField<SigCurveConfig>, FV>,
{
    pub g1_generator: G1Var<SigCurveConfig, FV, CF>,
    pub g2_generator: G2Var<SigCurveConfig, FV, CF>,
}

#[derive(Derivative)]
#[derivative(
    Clone(bound = ""),
    Debug(bound = ""),
)]
pub struct PublicKeyVar<
    SigCurveConfig: Bls12Config,
    FV: FieldVar<BlsSigField<SigCurveConfig>, CF>,
    CF: PrimeField,
> where
    for<'a> &'a FV: FieldOpsBounds<'a, BlsSigField<SigCurveConfig>, FV>,
{
    pub pub_key: G1Var<SigCurveConfig, FV, CF>,
}

#[derive(Derivative)]
#[derivative(
    Clone(bound = ""),
    Debug(bound = ""),
)]
pub struct SignatureVar<
    SigCurveConfig: Bls12Config,
    FV: FieldVar<BlsSigField<SigCurveConfig>, CF>,
    CF: PrimeField,
> where
    for<'a> &'a FV: FieldOpsBounds<'a, BlsSigField<SigCurveConfig>, FV>,
{
    pub signature: G2Var<SigCurveConfig, FV, CF>,
}

pub struct BLSAggregateSignatureVerifyGadget<
    SigCurveConfig: Bls12Config,
    FV: FieldVar<BlsSigField<SigCurveConfig>, CF>,
    CF: PrimeField,
>(PhantomData<(FV, SigCurveConfig, CF)>);

impl<
        SigCurveConfig: Bls12Config,
        FV: FieldVar<BlsSigField<SigCurveConfig>, CF>,
        CF: PrimeField,
    > BLSAggregateSignatureVerifyGadget<SigCurveConfig, FV, CF>
where
    FV: FromBaseFieldVarGadget<CF>
        + ToBaseFieldVarGadget<BlsSigField<SigCurveConfig>, CF>
        + SqrtGadget<BlsSigField<SigCurveConfig>, CF>,
    for<'a> &'a FV: FieldOpsBounds<'a, BlsSigField<SigCurveConfig>, FV>,
    <SigCurveConfig as Bls12Config>::G2Config: WBConfig,

    HashCurveConfig<SigCurveConfig>: SWCurveConfig,
    for<'a> &'a HashCurveVar<SigCurveConfig, FV, CF>: FieldOpsBounds<
        'a,
        <HashCurveGroup<SigCurveConfig> as CurveGroup>::BaseField,
        HashCurveVar<SigCurveConfig, FV, CF>,
    >,
    HashCurveVar<SigCurveConfig, FV, CF>:
        FieldVar<<HashCurveGroup<SigCurveConfig> as CurveGroup>::BaseField, CF>,
    HashCurveGroup<SigCurveConfig>: CofactorGadget<HashCurveVar<SigCurveConfig, FV, CF>, CF>,
{
    #[tracing::instrument(skip_all)]
    pub fn verify(
        parameters: &ParametersVar<SigCurveConfig, FV, CF>,
        pk: &PublicKeyVar<SigCurveConfig, FV, CF>,
        message: &[UInt8<CF>],
        signature: &SignatureVar<SigCurveConfig, FV, CF>,
    ) -> Result<(), SynthesisError> {
        let cs = parameters.g1_generator.cs();

        tracing::info!(num_constraints = cs.num_constraints());

        let hash_to_curve = Self::hash_to_curve(message)?;

        // an optimised way to check two pairings are equal
        let prod = bls12::PairingVar::product_of_pairings(
            &[
                G1PreparedVar::<SigCurveConfig, FV, CF>::from_group_var(
                    &parameters.g1_generator.negate()?,
                )?,
                G1PreparedVar::<SigCurveConfig, FV, CF>::from_group_var(&pk.pub_key)?,
            ],
            &[
                G2PreparedVar::<SigCurveConfig, FV, CF>::from_group_var(&signature.signature)?,
                G2PreparedVar::<SigCurveConfig, FV, CF>::from_group_var(&hash_to_curve)?,
            ],
        )?;

        prod.is_eq(
            &<bls12::PairingVar<SigCurveConfig, FV, CF> as PairingVar<
                Bls12<SigCurveConfig>,
                CF,
            >>::GTVar::new_constant(
                cs.clone(),
                <<Bls12<SigCurveConfig> as Pairing>::TargetField as Field>::ONE,
            )?,
        )?
        .enforce_equal(&Boolean::TRUE)?;

        tracing::info!(num_constraints = cs.num_constraints());

        Ok(())
    }

    pub fn verify_slow(
        parameters: &ParametersVar<SigCurveConfig, FV, CF>,
        pk: &PublicKeyVar<SigCurveConfig, FV, CF>,
        message: &[UInt8<CF>],
        signature: &SignatureVar<SigCurveConfig, FV, CF>,
    ) -> Result<(), SynthesisError> {
        let hash_to_curve = Self::hash_to_curve(message)?;

        // Verify e(signature, G) == e(aggregated_pk, H(m))
        let signature_paired = bls12::PairingVar::pairing(
            G1PreparedVar::<SigCurveConfig, FV, CF>::from_group_var(&parameters.g1_generator)?,
            G2PreparedVar::<SigCurveConfig, FV, CF>::from_group_var(&signature.signature)?,
        )?;
        let aggregated_pk_paired = bls12::PairingVar::pairing(
            G1PreparedVar::<SigCurveConfig, FV, CF>::from_group_var(&pk.pub_key)?,
            G2PreparedVar::<SigCurveConfig, FV, CF>::from_group_var(&hash_to_curve)?,
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
        parameters: &ParametersVar<SigCurveConfig, FV, CF>,
        public_keys: &[PublicKeyVar<SigCurveConfig, FV, CF>],
        message: &[UInt8<CF>],
        signature: &SignatureVar<SigCurveConfig, FV, CF>,
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
    pub fn hash_to_curve(
        msg: &[UInt8<CF>],
    ) -> Result<G2Var<SigCurveConfig, FV, CF>, SynthesisError> {
        type HashGroupBaseField<SigCurveConfig> =
            <HashCurveConfig<SigCurveConfig> as CurveConfig>::BaseField;

        type FieldHasherGadget<SigCurveConfig, FV, CF> = DefaultFieldHasherGadget<
            Blake2sGadget<CF>,
            HashGroupBaseField<SigCurveConfig>,
            CF,
            HashCurveVar<SigCurveConfig, FV, CF>,
            128,
        >;

        // this is slightly different from its counterpart in `bls.rs` because of how WBMapGadget is defined
        type CurveMapGadget<SigCurveConfig> =
            WBMapGadget<<SigCurveConfig as Bls12Config>::G2Config>;

        type HasherGadget<SigCurveConfig, FV, CF> = MapToCurveBasedHasherGadget<
            HashCurveGroup<SigCurveConfig>,
            FieldHasherGadget<SigCurveConfig, FV, CF>,
            CurveMapGadget<SigCurveConfig>,
            CF,
            HashCurveVar<SigCurveConfig, FV, CF>,
        >;

        let cs = msg.cs();
        tracing::info!(num_constraints = cs.num_constraints());

        let hasher_gadget = HasherGadget::<SigCurveConfig, FV, CF>::new(&[]);
        let hash = hasher_gadget.hash(msg);

        tracing::info!(num_constraints = cs.num_constraints());

        hash.map(|h| G2Var::<SigCurveConfig, FV, CF>::new(h.x, h.y, h.z))
    }
}

impl<
        SigCurveConfig: Bls12Config,
        FV: FieldVar<BlsSigField<SigCurveConfig>, SNARKField>,
        SNARKField: PrimeField,
    > AllocVar<Signature<SigCurveConfig>, SNARKField>
    for SignatureVar<SigCurveConfig, FV, SNARKField>
where
    for<'a> &'a FV: FieldOpsBounds<'a, BlsSigField<SigCurveConfig>, FV>,
{
    fn new_variable<T: Borrow<Signature<SigCurveConfig>>>(
        cs: impl Into<Namespace<SNARKField>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        Ok(Self {
            signature: G2Var::<SigCurveConfig, _, _>::new_variable(
                cs,
                || f().map(|value| value.borrow().signature),
                mode,
            )?,
        })
    }
}

impl<
        SigCurveConfig: Bls12Config,
        FV: FieldVar<BlsSigField<SigCurveConfig>, SNARKField>,
        SNARKField: PrimeField,
    > AllocVar<PublicKey<SigCurveConfig>, SNARKField>
    for PublicKeyVar<SigCurveConfig, FV, SNARKField>
where
    for<'a> &'a FV: FieldOpsBounds<'a, BlsSigField<SigCurveConfig>, FV>,
{
    fn new_variable<T: Borrow<PublicKey<SigCurveConfig>>>(
        cs: impl Into<Namespace<SNARKField>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        Ok(Self {
            pub_key: G1Var::<SigCurveConfig, _, _>::new_variable(
                cs,
                || f().map(|value| value.borrow().pub_key),
                mode,
            )?,
        })
    }
}

impl<
        SigCurveConfig: Bls12Config,
        FV: FieldVar<BlsSigField<SigCurveConfig>, SNARKField>,
        SNARKField: PrimeField,
    > AllocVar<Parameters<SigCurveConfig>, SNARKField>
    for ParametersVar<SigCurveConfig, FV, SNARKField>
where
    for<'a> &'a FV: FieldOpsBounds<'a, BlsSigField<SigCurveConfig>, FV>,
{
    fn new_variable<T: Borrow<Parameters<SigCurveConfig>>>(
        cs: impl Into<Namespace<SNARKField>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into();
        let value = f();

        Ok(Self {
            g1_generator: G1Var::<SigCurveConfig, _, _>::new_variable(
                cs.clone(),
                || {
                    value
                        .as_ref()
                        .map(|value| value.borrow().g1_generator)
                        .map_err(SynthesisError::clone)
                },
                mode,
            )?,
            g2_generator: G2Var::<SigCurveConfig, _, _>::new_variable(
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
    use crate::{bls::{
        get_bls_instance, BLSAggregateSignatureVerifyGadget, ParametersVar, PublicKeyVar,
        SignatureVar,
    }, params::BlsSigField};

    use ark_r1cs_std::{
        alloc::AllocVar,
        fields::{emulated_fp::EmulatedFpVar, fp::FpVar},
        uint8::UInt8,
    };
    use ark_relations::r1cs::ConstraintSystem;

    #[test]
    fn check_r1cs_native() {
        type BlsSigConfig = ark_bls12_377::Config;
        type BaseSigCurveField = BlsSigField<BlsSigConfig>;
        type BaseSNARKField = BaseSigCurveField;

        let cs = ConstraintSystem::new_ref();
        let (msg, params, _, pk, sig) = get_bls_instance::<BlsSigConfig>();

        let msg_var: Vec<UInt8<BaseSNARKField>> = msg
            .as_bytes()
            .iter()
            .map(|b| UInt8::new_input(cs.clone(), || Ok(b)).unwrap())
            .collect();
        let params_var: ParametersVar<BlsSigConfig, FpVar<BaseSigCurveField>, BaseSNARKField> =
            ParametersVar::new_input(cs.clone(), || Ok(params)).unwrap();
        let pk_var = PublicKeyVar::new_input(cs.clone(), || Ok(pk)).unwrap();
        let sig_var = SignatureVar::new_input(cs.clone(), || Ok(sig)).unwrap();

        BLSAggregateSignatureVerifyGadget::verify(&params_var, &pk_var, &msg_var, &sig_var)
            .unwrap();

        println!("Number of constraints: {}", cs.num_constraints());
        assert!(cs.is_satisfied().unwrap());

        println!("RC1S is satisfied!");
    }

    #[test]
    #[ignore = "field emulation takes a long time to finish running"]
    fn check_r1cs_emulated() {
        type BlsSigConfig = ark_bls12_377::Config;
        type BaseSigCurveField = BlsSigField<BlsSigConfig>;
        type BaseSNARKField = BlsSigField<ark_bls12_381::Config>;

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

        BLSAggregateSignatureVerifyGadget::verify(&params_var, &pk_var, &msg_var, &sig_var)
            .unwrap();

        println!("Number of constraints: {}", cs.num_constraints());
        assert!(cs.is_satisfied().unwrap());

        println!("RC1S is satisfied!");
    }
}
