use std::marker::PhantomData;

use ark_ec::{
    hashing::curve_maps::wb::WBConfig,
    short_weierstrass::{Affine, Projective},
    CurveConfig, CurveGroup,
};
use ark_ff::{Field, PrimeField};
use ark_r1cs_std::{
    fields::{FieldOpsBounds, FieldVar},
    groups::curves::short_weierstrass::AffineVar,
};
use ark_relations::r1cs::SynthesisError;

use super::{
    sqrt::SqrtGadget, swu::SWUMapGadget, to_base_field::ToBaseFieldGadget, MapToCurveGadget,
};

pub struct WBMapGadget<P: WBConfig> {
    swu_field_curve_hasher: PhantomData<SWUMapGadget<P::IsogenousCurve>>,
    curve_params: PhantomData<fn() -> P>,
}

impl<
        P: WBConfig,
        CF: PrimeField,
        FP: FieldVar<P::BaseField, CF>
            + ToBaseFieldGadget<<P::BaseField as Field>::BasePrimeField, CF>
            + SqrtGadget<P::BaseField, CF>,
    > MapToCurveGadget<Projective<P>, CF, FP> for WBMapGadget<P>
where
    for<'a> &'a FP: FieldOpsBounds<'a, <P as CurveConfig>::BaseField, FP>,
{
    /// Map random field point to a random curve point
    /// inspired from
    /// <https://github.com/zcash/pasta_curves/blob/main/src/hashtocurve.rs>
    fn map_to_curve(
        element: FP,
    ) -> Result<AffineVar<<Projective<P> as CurveGroup>::Config, FP, CF>, SynthesisError> {
        // first we need to map the field point to the isogenous curve
        let point_on_isogenious_curve =
            SWUMapGadget::<P::IsogenousCurve>::map_to_curve(element).unwrap();
        // P::ISOGENY_MAP.apply(point_on_isogenious_curve)
        todo!()
    }
}
