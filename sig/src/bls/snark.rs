use ark_r1cs_std::{
    alloc::AllocVar, convert::ToConstraintFieldGadget, fields::fp::FpVar, uint8::UInt8,
};
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError,
};

use super::{
    BLSAggregateSignatureVerifyGadget, BaseField, Parameters, ParametersVar, PublicKey,
    PublicKeyVar, Signature, SignatureVar,
};

#[derive(Clone)]
pub struct BLSCircuit<'a> {
    params: Parameters,
    pks: &'a [PublicKey],
    msg: &'a [u8],
    sig: Signature,
}

impl<'a> BLSCircuit<'a> {
    pub fn new(params: Parameters, pks: &'a [PublicKey], msg: &'a [u8], sig: Signature) -> Self {
        Self {
            params: params,
            pks: pks,
            msg: msg,
            sig: sig,
        }
    }

    // A hack, should implement `ToConstraintField` for each Var
    // Also, inefficient as we recomputed variables
    pub fn get_public_inputs(&self) -> Result<Vec<BaseField>, SynthesisError> {
        let cs = ConstraintSystem::new_ref();

        let msg_var = UInt8::new_input_vec(cs.clone(), &self.msg)?.to_constraint_field()?;
        let params_var = ParametersVar::new_input(cs.clone(), || Ok(&self.params))?;
        let g1 = params_var.g1_generator.to_constraint_field()?;
        let g2 = params_var.g2_generator.to_constraint_field()?;

        let mut pk_vars: Vec<_> = vec![];
        pk_vars.reserve_exact(self.pks.len());
        for pk in self.pks {
            PublicKeyVar::new_input(cs.clone(), || Ok(pk))
                .unwrap()
                .pub_key
                .to_constraint_field()?;
        }

        let sig_var = SignatureVar::new_input(cs.clone(), || Ok(&self.sig))?
            .signature
            .to_constraint_field()?;

        let mut field_elements = vec![];
        field_elements
            .reserve_exact(msg_var.len() + g1.len() + g2.len() + pk_vars.len() + sig_var.len());

        for fpvar in msg_var
            .iter()
            .chain(g1.iter())
            .chain(g2.iter())
            .chain(pk_vars.iter())
            .chain(sig_var.iter())
        {
            field_elements.push(match fpvar {
                FpVar::Constant(value) => value.clone(),
                FpVar::Var(_) => return Err(SynthesisError::AssignmentMissing),
            });
        }

        Ok(field_elements)
    }
}

// impl this trait so that SNARK can operate on this circuit
impl<'a> ConstraintSynthesizer<BaseField> for BLSCircuit<'a> {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<BaseField>,
    ) -> Result<(), SynthesisError> {
        let msg_var: Vec<UInt8<BaseField>> = self
            .msg
            .iter()
            .map(|b| UInt8::new_input(cs.clone(), || Ok(b)).unwrap())
            .collect();
        let params_var = ParametersVar::new_input(cs.clone(), || Ok(self.params))?;
        let pk_vars: Vec<PublicKeyVar> = self
            .pks
            .iter()
            .map(|pk| PublicKeyVar::new_input(cs.clone(), || Ok(pk)).unwrap())
            .collect();
        let sig_var = SignatureVar::new_input(cs.clone(), || Ok(self.sig))?;

        BLSAggregateSignatureVerifyGadget::verify(&params_var, &pk_vars, &msg_var, &sig_var)?;

        Ok(())
    }
}
