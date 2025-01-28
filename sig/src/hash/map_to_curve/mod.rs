mod isogeny_map;
mod norm;
mod sqrt;
mod swu;
mod to_base_field;
mod wb;

use ark_ec::{short_weierstrass::SWCurveConfig, CurveGroup};
use ark_ff::PrimeField;
use ark_r1cs_std::{
    fields::{FieldOpsBounds, FieldVar},
    groups::curves::short_weierstrass::AffineVar,
};
use ark_relations::r1cs::SynthesisError;

/// Trait for mapping a random field element `FieldVar<T::BaseField, CF: PrimeField>` to a random curve point
/// where the curve is specified by `T: CurveGroup`.
pub trait MapToCurveGadget<T: CurveGroup, CF: PrimeField, FP: FieldVar<T::BaseField, CF>>:
    Sized
{
    /// Map an arbitrary field element to a corresponding curve point.
    ///
    /// Ideally, we should relax this to any `AffineVar` (support both sw and ed curves)
    /// For simplificty, we first implement it for ed curve.
    fn map_to_curve(point: FP) -> Result<AffineVar<T::Config, FP, CF>, SynthesisError>
    where
        <T as CurveGroup>::Config: SWCurveConfig,
        for<'a> &'a FP: FieldOpsBounds<'a, <T as CurveGroup>::BaseField, FP>;
}
