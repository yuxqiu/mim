use ark_r1cs_std::{alloc::AllocVar, uint8::UInt8};
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError,
};

use super::{
    BLSAggregateSignatureVerifyGadget, BaseSNARKField, Parameters, ParametersVar, PublicKey,
    PublicKeyVar, Signature, SignatureVar,
};

#[derive(Clone)]
pub struct BLSCircuit<'a> {
    params: Parameters,
    pk: PublicKey,
    msg: &'a [u8],
    sig: Signature,
}

impl<'a> BLSCircuit<'a> {
    #[must_use]
    pub const fn new(params: Parameters, pk: PublicKey, msg: &'a [u8], sig: Signature) -> Self {
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
            .map(|b| UInt8::new_input(cs.clone(), || Ok(b)))
            .collect::<Result<_, _>>()?;
        let _ = ParametersVar::new_input(cs.clone(), || Ok(&self.params))?;
        let _ = PublicKeyVar::new_input(cs.clone(), || Ok(&self.pk))?;
        let _ = SignatureVar::new_input(cs.clone(), || Ok(&self.sig))?;

        Ok(cs
            .into_inner()
            .ok_or(SynthesisError::MissingCS)?
            .instance_assignment)
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
            .map(|b| UInt8::new_input(cs.clone(), || Ok(b)).unwrap())
            .collect();
        let params_var = ParametersVar::new_input(cs.clone(), || Ok(self.params))?;
        let pk_var = PublicKeyVar::new_input(cs.clone(), || Ok(&self.pk)).unwrap();
        let sig_var = SignatureVar::new_input(cs, || Ok(self.sig))?;

        BLSAggregateSignatureVerifyGadget::verify(&params_var, &pk_var, &msg_var, &sig_var)?;

        Ok(())
    }
}
