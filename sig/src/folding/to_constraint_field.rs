use ark_ff::PrimeField;
use ark_r1cs_std::{
    convert::ToConstraintFieldGadget,
    fields::{emulated_fp::EmulatedFpVar, fp::FpVar, FieldOpsBounds, FieldVar},
};
use ark_relations::r1cs::SynthesisError;

use crate::{
    bls::PublicKeyVar,
    params::{BlsSigConfig, BlsSigField},
};

use super::bc::{CommitteeVar, SignerVar};

/// It should be able to interrop with `FromConstraintFieldGadget` trait to support serialization and deserialization for any variable.
impl<F: PrimeField, CF: PrimeField> ToConstraintFieldGadget<CF>
    for PublicKeyVar<BlsSigConfig, EmulatedFpVar<F, CF>, CF>
where
    EmulatedFpVar<F, CF>: FieldVar<BlsSigField<BlsSigConfig>, CF>,
    for<'a> &'a EmulatedFpVar<F, CF>:
        FieldOpsBounds<'a, BlsSigField<BlsSigConfig>, EmulatedFpVar<F, CF>>,
{
    fn to_constraint_field(&self) -> Result<Vec<FpVar<CF>>, SynthesisError> {
        let mut x = self.pub_key.x.to_constraint_field()?;
        x.extend(self.pub_key.y.to_constraint_field()?);
        x.extend(self.pub_key.z.to_constraint_field()?);
        Ok(x)
    }
}

// Failed Attempt. The following adds slightly more constraints in total.
//
// impl<F: PrimeField, CF: PrimeField> ToConstraintFieldGadget<CF>
//     for PublicKeyVar<BlsSigConfig, EmulatedFpVar<F, CF>, CF>
// where
//     EmulatedFpVar<F, CF>: FieldVar<BlsSigField<BlsSigConfig>, CF>,
//     for<'a> &'a EmulatedFpVar<F, CF>:
//         FieldOpsBounds<'a, BlsSigField<BlsSigConfig>, EmulatedFpVar<F, CF>>,
// {
//     fn to_constraint_field(&self) -> Result<Vec<FpVar<CF>>, SynthesisError> {
//         self.pub_key.to_constraint_field()
//     }
// }

impl<CF: PrimeField> ToConstraintFieldGadget<CF> for SignerVar<CF> {
    fn to_constraint_field(&self) -> Result<Vec<FpVar<CF>>, SynthesisError> {
        let mut pk = self.pk.to_constraint_field()?;
        let weight = self.weight.to_fp()?;
        pk.push(weight);
        Ok(pk)
    }
}

impl<CF: PrimeField> ToConstraintFieldGadget<CF> for CommitteeVar<CF> {
    fn to_constraint_field(&self) -> Result<Vec<FpVar<CF>>, SynthesisError> {
        self.committee
            .iter()
            .map(|v| v.to_constraint_field())
            .collect::<Result<Vec<_>, _>>()
            .map(|vecs| vecs.into_iter().flatten().collect::<Vec<_>>())
    }
}
