use std::cmp::Ordering;

use ark_r1cs_std::{
    alloc::AllocVar,
    eq::EqGadget,
    fields::{fp::FpVar, FieldVar},
    groups::{bls12::G1Var, CurveVar},
    prelude::Boolean,
    uint64::UInt64,
};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use folding_schemes::{frontend::FCircuit, Error};

use crate::{
    bc::{checkpoints::CheckPoint, params::STRONG_THRESHOLD},
    bls::{BLSAggregateSignatureVerifyGadget, Parameters, ParametersVar, PublicKeyVar},
    folding::bc::CommitteeVar,
    hash::{
        hash_to_field::from_base_field::FromBaseFieldVarGadget,
        map_to_curve::to_base_field::ToBaseFieldVarGadget,
    },
    params::{BLSSigCurveConfig, BaseSigCurveField},
};

use super::{bc::CheckPointVar, serialize::SerializeGadget};

#[derive(Clone, Debug)]
pub struct BCCircuitNoMerkle {
    params: Parameters,
}

impl FCircuit<BaseSigCurveField> for BCCircuitNoMerkle {
    type Params = Parameters;
    type ExternalInputs = CheckPoint;
    type ExternalInputsVar = CheckPointVar;

    fn new(params: Self::Params) -> Result<Self, Error> {
        Ok(Self { params })
    }

    fn state_len(&self) -> usize {
        // needs to be an upper bound of the committee size
        CommitteeVar::NUM_BASE_FIELD_VAR_NEEDED
    }

    /// generates the constraints for the step of F for the given z_i
    fn generate_step_constraints(
        &self,
        cs: ConstraintSystemRef<BaseSigCurveField>,
        _: usize,
        z_i: Vec<FpVar<BaseSigCurveField>>,
        external_inputs: Self::ExternalInputsVar,
    ) -> Result<Vec<FpVar<BaseSigCurveField>>, SynthesisError> {
        // reconstruct epoch and committee from z_i
        let mut iter = z_i.into_iter();
        let epoch = UInt64::from_base_field_var(iter.by_ref())?;
        let committee = CommitteeVar::from_base_field_var(iter)?;

        // 1. enforce epoch of new committee = epoch of old committee + 1
        external_inputs
            .epoch
            .is_eq(&(epoch.wrapping_add(&UInt64::constant(1))))?
            .enforce_equal(&Boolean::TRUE)?;

        // 2. enforce the signature matches
        let sig = &external_inputs.sig.sig;
        let signers = &external_inputs.sig.signers;

        // 2.1 aggregate public keys
        let mut weight = UInt64::constant(0);
        let mut aggregate_pk = G1Var::<BLSSigCurveConfig, _, _>::zero();
        for (signed, signer) in signers.iter().zip(committee.committee) {
            let pk = signed.select(
                &(signer.pk.pub_key),
                &G1Var::<BLSSigCurveConfig, _, _>::zero(),
            )?;
            let w = signed.select(&(signer.weight), &UInt64::constant(0))?;
            aggregate_pk += pk;
            weight.wrapping_add_in_place(&w);
        }
        let aggregate_pk = PublicKeyVar {
            pub_key: aggregate_pk,
        };

        // 2.2 check signature
        let params = ParametersVar::new_constant(cs.clone(), self.params)?;
        BLSAggregateSignatureVerifyGadget::verify(
            &params,
            &aggregate_pk,
            &external_inputs.serialize()?,
            sig,
        )?;

        // 2.3 check weight > threshold
        weight.to_fp()?.enforce_cmp(
            &FpVar::constant(STRONG_THRESHOLD.into()),
            Ordering::Greater,
            true,
        )?;

        // return the new state
        external_inputs.committee.to_base_field_vars()
    }
}
