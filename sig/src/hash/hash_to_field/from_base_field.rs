use ark_ff::{CubicExtConfig, PrimeField, QuadExtConfig};
use ark_r1cs_std::{
    fields::{
        cubic_extension::{CubicExtVar, CubicExtVarConfig},
        emulated_fp::EmulatedFpVar,
        fp::FpVar,
        quadratic_extension::{QuadExtVar, QuadExtVarConfig},
    },
    prelude::*,
};
use ark_relations::r1cs::SynthesisError;

pub trait FromBitsGadget<CF: PrimeField>: Sized {
    fn from_le_bits(bits: &[Boolean<CF>]) -> Self;
}

impl<CF: PrimeField> FromBitsGadget<CF> for FpVar<CF> {
    fn from_le_bits(bits: &[Boolean<CF>]) -> Self {
        // Assign a value only when we are constructing a constant.
        let should_construct_value = bits.is_constant();
        if should_construct_value {
            let bits = bits.iter().map(|b| b.value().unwrap()).collect::<Vec<_>>();
            let bytes = bits
                .chunks(8)
                .map(|c| {
                    let mut value = 0u8;
                    for (i, &bit) in c.iter().enumerate() {
                        value += u8::from(bit) << i;
                    }
                    value
                })
                .collect::<Vec<_>>();

            Self::constant(CF::from_le_bytes_mod_order(&bytes))
        } else {
            let mut power = CF::one();
            // Compute a linear combination for the new field variable, again
            // via double and add.

            let combined = bits
                .iter()
                .map(|b| {
                    let result = Self::from(b.clone()) * power;
                    power.double_in_place();
                    result
                })
                .reduce(core::ops::Add::add)
                .unwrap();

            combined
        }
    }
}

impl<F: PrimeField, CF: PrimeField> FromBitsGadget<CF> for EmulatedFpVar<F, CF> {
    fn from_le_bits(bits: &[Boolean<CF>]) -> Self {
        // Assign a value only when we are constructing a constant.
        let should_construct_value = bits.is_constant();
        if should_construct_value {
            let bits = bits.iter().map(|b| b.value().unwrap()).collect::<Vec<_>>();
            let bytes = bits
                .chunks(8)
                .map(|c| {
                    let mut value = 0u8;
                    for (i, &bit) in c.iter().enumerate() {
                        value += u8::from(bit) << i;
                    }
                    value
                })
                .collect::<Vec<_>>();
            Self::constant(F::from_le_bytes_mod_order(&bytes))
        } else {
            let mut power = F::one();
            // Compute a linear combination for the new field variable, again
            // via double and add.

            let combined = bits
                .iter()
                .map(|b| {
                    let result = Self::from(b.clone()) * power;
                    power.double_in_place();
                    result
                })
                .reduce(core::ops::Add::add)
                .unwrap();

            combined
        }
    }
}

/// Trait for constructing any R1CS variable from a vector of `FieldVar<F: PrimeField, CF: PrimeField>`.
/// It can interrop with `ToBaseFieldVarGadget` trait to support serialization and deserialization for any variable.
pub trait FromBaseFieldVarGadget<CF: PrimeField>: Sized {
    type BasePrimeFieldVar: FromBaseFieldVarGadget<CF> + FromBitsGadget<CF>;

    fn num_base_field_var_needed() -> usize;

    fn from_base_field_var(
        iter: impl Iterator<Item = Self::BasePrimeFieldVar>,
    ) -> Result<Self, SynthesisError>;
}

impl<CF: PrimeField> FromBaseFieldVarGadget<CF> for FpVar<CF> {
    type BasePrimeFieldVar = Self;

    fn from_base_field_var(
        mut iter: impl Iterator<Item = Self::BasePrimeFieldVar>,
    ) -> Result<Self, SynthesisError> {
        iter.next().ok_or(SynthesisError::AssignmentMissing)
    }

    fn num_base_field_var_needed() -> usize {
        1
    }
}

impl<F: PrimeField, CF: PrimeField> FromBaseFieldVarGadget<CF> for EmulatedFpVar<F, CF> {
    type BasePrimeFieldVar = Self;

    fn from_base_field_var(
        mut iter: impl Iterator<Item = Self::BasePrimeFieldVar>,
    ) -> Result<Self, SynthesisError> {
        iter.next().ok_or(SynthesisError::AssignmentMissing)
    }

    fn num_base_field_var_needed() -> usize {
        1
    }
}

impl<
        BF: FieldVar<P::BaseField, CF> + FromBaseFieldVarGadget<CF>,
        P: QuadExtVarConfig<BF, CF>,
        CF: PrimeField,
    > FromBaseFieldVarGadget<CF> for QuadExtVar<BF, P, CF>
where
    for<'a> &'a BF: FieldOpsBounds<'a, <P as QuadExtConfig>::BaseField, BF>,
{
    type BasePrimeFieldVar = BF::BasePrimeFieldVar;

    fn from_base_field_var(
        mut iter: impl Iterator<Item = Self::BasePrimeFieldVar>,
    ) -> Result<Self, SynthesisError> {
        // a better implementation could mimic `QuadExtField::from_base_prime_field_elems`
        let c0 = BF::from_base_field_var(iter.by_ref())?;
        let c1 = BF::from_base_field_var(iter.by_ref())?;
        Ok(Self::new(c0, c1))
    }

    fn num_base_field_var_needed() -> usize {
        BF::num_base_field_var_needed() * 2
    }
}

impl<
        BF: FieldVar<P::BaseField, CF> + FromBaseFieldVarGadget<CF>,
        P: CubicExtVarConfig<BF, CF>,
        CF: PrimeField,
    > FromBaseFieldVarGadget<CF> for CubicExtVar<BF, P, CF>
where
    for<'a> &'a BF: FieldOpsBounds<'a, <P as CubicExtConfig>::BaseField, BF>,
{
    type BasePrimeFieldVar = BF::BasePrimeFieldVar;

    fn from_base_field_var(
        mut iter: impl Iterator<Item = Self::BasePrimeFieldVar>,
    ) -> Result<Self, SynthesisError> {
        // a better implementation could mimic `CubicExtField::from_base_prime_field_elems`
        let c0 = BF::from_base_field_var(iter.by_ref())?;
        let c1 = BF::from_base_field_var(iter.by_ref())?;
        let c2 = BF::from_base_field_var(iter.by_ref())?;
        Ok(Self::new(c0, c1, c2))
    }

    fn num_base_field_var_needed() -> usize {
        BF::num_base_field_var_needed() * 3
    }
}
