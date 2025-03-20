use std::marker::PhantomData;

use ark_ec::{
    bls12::Bls12Config,
    hashing::curve_maps::wb::WBConfig,
    short_weierstrass::{Projective, SWCurveConfig},
    CurveGroup,
};
use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::AllocVar,
    fields::{fp2::Fp2Var, FieldOpsBounds, FieldVar},
    uint8::UInt8,
};
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError,
};
use derivative::Derivative;

use crate::hash::{
    hash_to_curve::cofactor::CofactorGadget,
    hash_to_field::from_base_field::FromBaseFieldVarGadget,
    map_to_curve::{sqrt::SqrtGadget, to_base_field::ToBaseFieldVarGadget},
};

use super::{
    BLSAggregateSignatureVerifyGadget, Parameters, ParametersVar, PublicKey, PublicKeyVar,
    Signature, SignatureVar,
};

#[derive(Derivative)]
#[derivative(Clone(bound = ""))]
pub struct BLSCircuit<
    'a,
    SigCurveConfig: Bls12Config,
    FV: FieldVar<BlsSigField<SigCurveConfig>, CF>,
    CF: PrimeField,
> {
    params: Option<Parameters<SigCurveConfig>>,
    pk: Option<PublicKey<SigCurveConfig>>,
    msg: &'a [Option<u8>],
    sig: Option<Signature<SigCurveConfig>>,
    _fv: PhantomData<(FV, CF)>,
}

type BlsSigField<SigCurveConfig> = <SigCurveConfig as Bls12Config>::Fp;

impl<
        'a,
        SigCurveConfig: Bls12Config,
        FV: FieldVar<BlsSigField<SigCurveConfig>, CF>,
        CF: PrimeField,
    > BLSCircuit<'a, SigCurveConfig, FV, CF>
where
    for<'b> &'b FV: FieldOpsBounds<'b, BlsSigField<SigCurveConfig>, FV>,
{
    #[must_use]
    pub const fn new(
        params: Option<Parameters<SigCurveConfig>>,
        pk: Option<PublicKey<SigCurveConfig>>,
        msg: &'a [Option<u8>],
        sig: Option<Signature<SigCurveConfig>>,
    ) -> Self {
        Self {
            params,
            pk,
            msg,
            sig,
            _fv: PhantomData,
        }
    }

    pub fn get_public_inputs(&self) -> Result<Vec<CF>, SynthesisError> {
        // inefficient as we recomputed public input here
        let cs = ConstraintSystem::new_ref();

        let _: Vec<UInt8<CF>> = self
            .msg
            .iter()
            .map(|b| UInt8::new_input(cs.clone(), || b.ok_or(SynthesisError::AssignmentMissing)))
            .collect::<Result<_, _>>()?;
        let _ = ParametersVar::<SigCurveConfig, FV, CF>::new_input(cs.clone(), || {
            self.params
                .as_ref()
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        let _ = PublicKeyVar::<SigCurveConfig, FV, CF>::new_input(cs.clone(), || {
            self.pk.as_ref().ok_or(SynthesisError::AssignmentMissing)
        })?;
        let _ = SignatureVar::<SigCurveConfig, FV, CF>::new_input(cs.clone(), || {
            self.sig.as_ref().ok_or(SynthesisError::AssignmentMissing)
        })?;

        // `instance_assignment` has a placeholder value at index 0, we need to skip it
        let mut public_inputs = cs
            .into_inner()
            .ok_or(SynthesisError::MissingCS)?
            .instance_assignment;
        public_inputs.remove(0);

        Ok(public_inputs)
    }
}

type G2<SigCurveConfig> = Projective<<SigCurveConfig as Bls12Config>::G2Config>;
type HashCurveGroup<SigCurveConfig> = G2<SigCurveConfig>;
type HashCurveConfig<SigCurveConfig> = <HashCurveGroup<SigCurveConfig> as CurveGroup>::Config;
type HashCurveVar<SigCurveConfig, F, CF> =
    Fp2Var<<SigCurveConfig as Bls12Config>::Fp2Config, F, CF>;

// impl this trait so that SNARK can operate on this circuit
impl<
        'b,
        SigCurveConfig: Bls12Config,
        FV: FieldVar<BlsSigField<SigCurveConfig>, CF>,
        CF: PrimeField,
    > ConstraintSynthesizer<CF> for BLSCircuit<'b, SigCurveConfig, FV, CF>
where
    for<'a> &'a FV: FieldOpsBounds<'a, BlsSigField<SigCurveConfig>, FV>,
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
    fn generate_constraints(self, cs: ConstraintSystemRef<CF>) -> Result<(), SynthesisError> {
        let msg_var: Vec<UInt8<CF>> = self
            .msg
            .iter()
            .map(|b| UInt8::new_input(cs.clone(), || b.ok_or(SynthesisError::AssignmentMissing)))
            .collect::<Result<_, _>>()?;
        let params_var = ParametersVar::<SigCurveConfig, FV, CF>::new_input(cs.clone(), || {
            self.params
                .as_ref()
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        let pk_var = PublicKeyVar::new_input(cs.clone(), || {
            self.pk.as_ref().ok_or(SynthesisError::AssignmentMissing)
        })?;
        let sig_var = SignatureVar::new_input(cs, || {
            self.sig.as_ref().ok_or(SynthesisError::AssignmentMissing)
        })?;

        BLSAggregateSignatureVerifyGadget::<SigCurveConfig, FV, CF>::verify(
            &params_var,
            &pk_var,
            &msg_var,
            &sig_var,
        )?;

        Ok(())
    }
}
