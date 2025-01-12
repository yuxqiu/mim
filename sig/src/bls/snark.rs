// use ark_r1cs_std::{alloc::AllocVar, uint8::UInt8};
// use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

// use super::{
//     BLSAggregateSignatureVerifyGadget, Parameters, ParametersVar, PublicKey, PublicKeyVar,
//     Signature, SignatureVar,
// };

// pub struct BLSCircuit<'a> {
//     params: Parameters,
//     pks: &'a [PublicKey],
//     msg: &'a [u8],
//     sig: Signature,
// }

// impl<'a> BLSCircuit<'a> {
//     pub fn new(params: Parameters, pks: &'a [PublicKey], msg: &'a [u8], sig: Signature) -> Self {
//         Self {
//             params: params,
//             pks: pks,
//             msg: msg,
//             sig: sig,
//         }
//     }
// }

// // impl this trait so that SNARK can operate on this circuit
// impl<'a> ConstraintSynthesizer<ark_bls12_381::Fr> for BLSCircuit<'a> {
//     fn generate_constraints(
//         self,
//         cs: ConstraintSystemRef<ark_bls12_381::Fr>,
//     ) -> Result<(), SynthesisError> {
//         let msg_var: Vec<UInt8<ark_bls12_381::Fr>> = self
//             .msg
//             .iter()
//             .map(|b| UInt8::new_input(cs.clone(), || Ok(b)).unwrap())
//             .collect();
//         let params_var = ParametersVar::new_input(cs.clone(), || Ok(self.params))?;
//         let pk_vars: Vec<PublicKeyVar> = self
//             .pks
//             .iter()
//             .map(|pk| PublicKeyVar::new_input(cs.clone(), || Ok(pk)).unwrap())
//             .collect();
//         let sig_var = SignatureVar::new_input(cs.clone(), || Ok(self.sig))?;

//         BLSAggregateSignatureVerifyGadget::verify(&params_var, &pk_vars, &msg_var, &sig_var)?;

//         Ok(())
//     }
// }
