use ark_r1cs_std::{alloc::AllocVar, uint8::UInt8};
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError,
};

use crate::params::BaseSNARKField;

use super::{
    BLSAggregateSignatureVerifyGadget, Parameters, ParametersVar, PublicKey, PublicKeyVar,
    Signature, SignatureVar,
};

#[derive(Clone)]
pub struct BLSCircuit<'a> {
    params: Option<Parameters>,
    pk: Option<PublicKey>,
    msg: &'a [Option<u8>],
    sig: Option<Signature>,
}

impl<'a> BLSCircuit<'a> {
    #[must_use]
    pub const fn new(
        params: Option<Parameters>,
        pk: Option<PublicKey>,
        msg: &'a [Option<u8>],
        sig: Option<Signature>,
    ) -> Self {
        Self {
            params,
            pk,
            msg,
            sig,
        }
    }

    pub fn get_public_inputs(&self) -> Result<Vec<BaseSNARKField>, SynthesisError> {
        // inefficient as we recomputed public input here
        let cs = ConstraintSystem::new_ref();

        let _: Vec<UInt8<BaseSNARKField>> = self
            .msg
            .iter()
            .map(|b| UInt8::new_input(cs.clone(), || b.ok_or(SynthesisError::AssignmentMissing)))
            .collect::<Result<_, _>>()?;
        let _ = ParametersVar::new_input(cs.clone(), || {
            self.params
                .as_ref()
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        let _ = PublicKeyVar::new_input(cs.clone(), || {
            self.pk.as_ref().ok_or(SynthesisError::AssignmentMissing)
        })?;
        let _ = SignatureVar::new_input(cs.clone(), || {
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

// impl this trait so that SNARK can operate on this circuit
impl<'a> ConstraintSynthesizer<BaseSNARKField> for BLSCircuit<'a> {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<BaseSNARKField>,
    ) -> Result<(), SynthesisError> {
        let msg_var: Vec<UInt8<BaseSNARKField>> = self
            .msg
            .iter()
            .map(|b| UInt8::new_input(cs.clone(), || b.ok_or(SynthesisError::AssignmentMissing)))
            .collect::<Result<_, _>>()?;
        let params_var = ParametersVar::new_input(cs.clone(), || {
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

        BLSAggregateSignatureVerifyGadget::verify(&params_var, &pk_var, &msg_var, &sig_var)?;

        Ok(())
    }
}
