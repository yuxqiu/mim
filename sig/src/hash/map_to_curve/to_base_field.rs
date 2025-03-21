use ark_ff::{CubicExtConfig, PrimeField, QuadExtConfig};
use ark_r1cs_std::fields::{
    cubic_extension::{CubicExtVar, CubicExtVarConfig},
    emulated_fp::EmulatedFpVar,
    fp::FpVar,
    quadratic_extension::{QuadExtVar, QuadExtVarConfig},
    FieldOpsBounds, FieldVar,
};
use ark_relations::r1cs::SynthesisError;

/// Trait for converting any R1CS variable to a vector of `FieldVar<F: PrimeField, CF: PrimeField>`.
///
/// It should be able to interrop with `FromBaseFieldVarGadget` trait to support serialization and deserialization for any variable.
pub trait ToBaseFieldVarGadget<F: PrimeField, CF: PrimeField>: Sized {
    type BasePrimeFieldVar: ToBaseFieldVarGadget<F, CF> + FieldVar<F, CF>;

    fn to_base_field_vars(&self) -> Result<Vec<Self::BasePrimeFieldVar>, SynthesisError>;
}

impl<CF: PrimeField> ToBaseFieldVarGadget<CF, CF> for FpVar<CF> {
    type BasePrimeFieldVar = Self;

    fn to_base_field_vars(&self) -> Result<Vec<Self::BasePrimeFieldVar>, SynthesisError> {
        Ok(vec![self.clone()])
    }
}

impl<F: PrimeField, CF: PrimeField> ToBaseFieldVarGadget<F, CF> for EmulatedFpVar<F, CF> {
    type BasePrimeFieldVar = Self;

    fn to_base_field_vars(&self) -> Result<Vec<Self::BasePrimeFieldVar>, SynthesisError> {
        Ok(vec![self.clone()])
    }
}

impl<
        BF: FieldVar<P::BaseField, CF> + ToBaseFieldVarGadget<P::BasePrimeField, CF>,
        P: QuadExtVarConfig<BF, CF>,
        CF: PrimeField,
    > ToBaseFieldVarGadget<P::BasePrimeField, CF> for QuadExtVar<BF, P, CF>
where
    for<'a> &'a BF: FieldOpsBounds<'a, <P as QuadExtConfig>::BaseField, BF>,
{
    type BasePrimeFieldVar = BF::BasePrimeFieldVar;

    fn to_base_field_vars(&self) -> Result<Vec<Self::BasePrimeFieldVar>, SynthesisError> {
        let c0_vars = self.c0.to_base_field_vars()?;
        let c1_vars = self.c1.to_base_field_vars()?;
        Ok([c0_vars, c1_vars].concat())
    }
}

impl<
        BF: FieldVar<P::BaseField, CF> + ToBaseFieldVarGadget<P::BasePrimeField, CF>,
        P: CubicExtVarConfig<BF, CF>,
        CF: PrimeField,
    > ToBaseFieldVarGadget<P::BasePrimeField, CF> for CubicExtVar<BF, P, CF>
where
    for<'a> &'a BF: FieldOpsBounds<'a, <P as CubicExtConfig>::BaseField, BF>,
{
    type BasePrimeFieldVar = BF::BasePrimeFieldVar;

    fn to_base_field_vars(&self) -> Result<Vec<Self::BasePrimeFieldVar>, SynthesisError> {
        let c0_vars = self.c0.to_base_field_vars()?;
        let c1_vars = self.c1.to_base_field_vars()?;
        let c2_vars = self.c2.to_base_field_vars()?;
        Ok([c0_vars, c1_vars, c2_vars].concat())
    }
}
