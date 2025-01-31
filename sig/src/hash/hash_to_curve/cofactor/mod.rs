pub mod bls12_377;
pub mod bls12_381;

use ark_ec::{short_weierstrass::SWCurveConfig, CurveConfig, CurveGroup};
use ark_ff::{BigInteger, BigInteger64, PrimeField};
use ark_r1cs_std::{
    fields::{FieldOpsBounds, FieldVar},
    groups::curves::short_weierstrass::ProjectiveVar,
    prelude::Boolean,
};
use ark_relations::r1cs::SynthesisError;

/// Trait for clearing cofactor. When implementing this trait for different `CurveGroup`,
/// remember to check how they specialize in clearing the cofactor. Here, the trait provides
/// a default implementation by simply multiplying the given point by the cofactor. But sometimes,
/// faster method exists.
pub trait CofactorGadget<FP: FieldVar<Self::BaseField, CF>, CF: PrimeField>: CurveGroup
where
    for<'a> &'a FP: FieldOpsBounds<'a, <Self as CurveGroup>::BaseField, FP>,
    <Self as CurveGroup>::Config: SWCurveConfig,
{
    fn clear_cofactor_var(
        point: &ProjectiveVar<Self::Config, FP, CF>,
    ) -> Result<ProjectiveVar<Self::Config, FP, CF>, SynthesisError> {
        let cofactor_bits: Vec<_> = <Self::Config as CurveConfig>::COFACTOR
            .iter()
            .flat_map(|value| {
                BigInteger64::from(*value)
                    .to_bits_le()
                    .into_iter()
                    .map(Boolean::constant)
            })
            .collect();

        point.scalar_mul_le_unchecked(cofactor_bits.iter())
    }
}
