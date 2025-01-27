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
        // Compute the value of the `FpVar` variable via double-and-add.
        let mut value = None;
        let cs = bits.cs();

        // Assign a value only when `cs` is in setup mode, or if we are constructing
        // a constant.
        let should_construct_value = (!cs.is_in_setup_mode()) || bits.is_constant();
        if should_construct_value {
            let bits = bits.iter().map(|b| b.value().unwrap()).collect::<Vec<_>>();
            let bytes = bits
                .chunks(8)
                .map(|c| {
                    let mut value = 0u8;
                    for (i, &bit) in c.iter().enumerate() {
                        value += (bit as u8) << i;
                    }
                    value
                })
                .collect::<Vec<_>>();
            value = Some(CF::from_le_bytes_mod_order(&bytes));
        }

        if bits.is_constant() {
            FpVar::constant(value.unwrap())
        } else {
            let mut power = CF::one();
            // Compute a linear combination for the new field variable, again
            // via double and add.

            let combined = bits
                .iter()
                .map(|b| {
                    let result = FpVar::from(b.clone()) * power;
                    power.double_in_place();
                    result
                })
                .reduce(std::ops::Add::add)
                .unwrap();

            combined
        }
    }
}

impl<F: PrimeField, CF: PrimeField> FromBitsGadget<CF> for EmulatedFpVar<F, CF> {
    fn from_le_bits(bits: &[Boolean<CF>]) -> Self {
        // Compute the value of the `EmulatedFpVar` variable via double-and-add.
        let mut value = None;
        let cs = bits.cs();

        // Assign a value only when `cs` is in setup mode, or if we are constructing
        // a constant.
        let should_construct_value = (!cs.is_in_setup_mode()) || bits.is_constant();
        if should_construct_value {
            let bits = bits.iter().map(|b| b.value().unwrap()).collect::<Vec<_>>();
            let bytes = bits
                .chunks(8)
                .map(|c| {
                    let mut value = 0u8;
                    for (i, &bit) in c.iter().enumerate() {
                        value += (bit as u8) << i;
                    }
                    value
                })
                .collect::<Vec<_>>();
            value = Some(F::from_le_bytes_mod_order(&bytes));
        }

        if bits.is_constant() {
            EmulatedFpVar::constant(value.unwrap())
        } else {
            let mut power = F::one();
            // Compute a linear combination for the new field variable, again
            // via double and add.

            let combined = bits
                .iter()
                .map(|b| {
                    let result = EmulatedFpVar::from(b.clone()) * power;
                    power.double_in_place();
                    result
                })
                .reduce(std::ops::Add::add)
                .unwrap();

            combined
        }
    }
}

pub trait FromBaseFieldGadget<CF: PrimeField>: Sized {
    type BaseFieldVar: FromBaseFieldGadget<CF>;
    type BasePrimeFieldVar: FromBaseFieldGadget<CF> + FromBitsGadget<CF>;

    fn from_base_prime_field_var<'a>(
        iter: impl Iterator<Item = Self::BasePrimeFieldVar>,
    ) -> Result<Self, SynthesisError>;
}

impl<CF: PrimeField> FromBaseFieldGadget<CF> for FpVar<CF> {
    type BaseFieldVar = Self;
    type BasePrimeFieldVar = Self;

    fn from_base_prime_field_var(
        mut iter: impl Iterator<Item = Self::BasePrimeFieldVar>,
    ) -> Result<Self, SynthesisError> {
        iter.next().ok_or(SynthesisError::AssignmentMissing)
    }
}

impl<F: PrimeField, CF: PrimeField> FromBaseFieldGadget<CF> for EmulatedFpVar<F, CF> {
    type BaseFieldVar = Self;
    type BasePrimeFieldVar = Self;

    fn from_base_prime_field_var(
        mut iter: impl Iterator<Item = Self::BasePrimeFieldVar>,
    ) -> Result<Self, SynthesisError> {
        iter.next().ok_or(SynthesisError::AssignmentMissing)
    }
}

impl<
        BF: FieldVar<P::BaseField, CF> + FromBaseFieldGadget<CF>,
        P: QuadExtVarConfig<BF, CF>,
        CF: PrimeField,
    > FromBaseFieldGadget<CF> for QuadExtVar<BF, P, CF>
where
    for<'a> &'a BF: FieldOpsBounds<'a, <P as QuadExtConfig>::BaseField, BF>,
{
    type BaseFieldVar = BF;
    type BasePrimeFieldVar = BF::BasePrimeFieldVar;

    fn from_base_prime_field_var(
        mut iter: impl Iterator<Item = Self::BasePrimeFieldVar>,
    ) -> Result<Self, SynthesisError> {
        // a better implementation could mimic `QuadExtField::from_base_prime_field_elems`
        let c0 = Self::BaseFieldVar::from_base_prime_field_var(iter.by_ref())?;
        let c1 = Self::BaseFieldVar::from_base_prime_field_var(iter.by_ref())?;
        Ok(QuadExtVar::new(c0, c1))
    }
}

impl<
        BF: FieldVar<P::BaseField, CF> + FromBaseFieldGadget<CF>,
        P: CubicExtVarConfig<BF, CF>,
        CF: PrimeField,
    > FromBaseFieldGadget<CF> for CubicExtVar<BF, P, CF>
where
    for<'a> &'a BF: FieldOpsBounds<'a, <P as CubicExtConfig>::BaseField, BF>,
{
    type BaseFieldVar = BF;
    type BasePrimeFieldVar = BF::BasePrimeFieldVar;

    fn from_base_prime_field_var(
        mut iter: impl Iterator<Item = Self::BasePrimeFieldVar>,
    ) -> Result<Self, SynthesisError> {
        // a better implementation could mimic `CubicExtField::from_base_prime_field_elems`
        let c0 = Self::BaseFieldVar::from_base_prime_field_var(iter.by_ref())?;
        let c1 = Self::BaseFieldVar::from_base_prime_field_var(iter.by_ref())?;
        let c2 = Self::BaseFieldVar::from_base_prime_field_var(iter.by_ref())?;
        Ok(CubicExtVar::new(c0, c1, c2))
    }
}
