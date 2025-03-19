use std::marker::PhantomData;

use ark_ec::{
    hashing::curve_maps::wb::WBConfig, short_weierstrass::Projective, CurveConfig, CurveGroup,
};
use ark_ff::{Field, PrimeField};
use ark_r1cs_std::{
    fields::{FieldOpsBounds, FieldVar},
    groups::curves::short_weierstrass::AffineVar,
};
use ark_relations::r1cs::SynthesisError;

use super::{
    isogeny_map::IsogenyMapGadget, sqrt::SqrtGadget, swu::SWUMapGadget,
    to_base_field::ToBaseFieldVarGadget, MapToCurveGadget,
};

pub struct WBMapGadget<P: WBConfig> {
    swu_field_curve_hasher: PhantomData<SWUMapGadget<P::IsogenousCurve>>,
    curve_params: PhantomData<fn() -> P>,
}

impl<
        P: WBConfig,
        CF: PrimeField,
        FP: FieldVar<P::BaseField, CF>
            + ToBaseFieldVarGadget<<P::BaseField as Field>::BasePrimeField, CF>
            + SqrtGadget<P::BaseField, CF>,
    > MapToCurveGadget<Projective<P>, CF, FP> for WBMapGadget<P>
where
    for<'a> &'a FP: FieldOpsBounds<'a, <P as CurveConfig>::BaseField, FP>,
{
    /// Map random field point to a random curve point
    /// inspired from
    /// <https://github.com/zcash/pasta_curves/blob/main/src/hashtocurve.rs>
    #[tracing::instrument(skip_all)]
    fn map_to_curve(
        element: FP,
    ) -> Result<AffineVar<<Projective<P> as CurveGroup>::Config, FP, CF>, SynthesisError> {
        let cs = element.cs();
        tracing::info!(num_constraints = cs.num_constraints());

        // first we need to map the field point to the isogenous curve
        let point_on_isogenious_curve =
            SWUMapGadget::<P::IsogenousCurve>::map_to_curve(element).unwrap();

        // P::ISOGENY_MAP.apply(point_on_isogenious_curve)
        let ret = IsogenyMapGadget::apply(point_on_isogenious_curve);

        tracing::info!(num_constraints = cs.num_constraints());

        ret
    }
}

#[cfg(test)]
mod test {
    use ark_bls12_381::{Fq, Fq2, Fq2Config, Fr};
    use ark_ec::{
        hashing::{curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurve},
        short_weierstrass::Affine,
    };
    use ark_ff::{AdditiveGroup, Field, UniformRand};
    use ark_r1cs_std::{
        alloc::AllocVar,
        fields::{emulated_fp::EmulatedFpVar, fp::FpVar, fp2::Fp2Var, FieldVar},
        R1CSVar,
    };
    use ark_relations::r1cs::ConstraintSystem;
    use rand::thread_rng;

    use crate::hash::map_to_curve::{wb::WBMapGadget, MapToCurveGadget};

    macro_rules! generate_wb_map_tests {
        ($test_name:ident, $field:ty, $field_var:ty, $curve_config:ty) => {
            #[test]
            fn $test_name() {
                fn test_constant() {
                    let mut rng = thread_rng();

                    {
                        // test zero
                        let zero = <$field>::ZERO;
                        let zero_var = <$field_var>::constant(zero);
                        let wb_zero: Affine<$curve_config> =
                            WBMap::<$curve_config>::map_to_curve(zero).unwrap();
                        let wb_zero_var =
                            WBMapGadget::<$curve_config>::map_to_curve(zero_var).unwrap();
                        assert_eq!(wb_zero_var.value_unchecked().unwrap(), wb_zero);
                        assert!(wb_zero_var.x.is_constant());
                        assert!(wb_zero_var.y.is_constant());
                    }

                    {
                        // test one
                        let one = <$field>::ONE;
                        let one_var = <$field_var>::constant(one);
                        let wb_one: Affine<$curve_config> =
                            WBMap::<$curve_config>::map_to_curve(one).unwrap();
                        let wb_one_var =
                            WBMapGadget::<$curve_config>::map_to_curve(one_var).unwrap();
                        assert_eq!(wb_one_var.value_unchecked().unwrap(), wb_one);
                        assert!(wb_one_var.x.is_constant());
                        assert!(wb_one_var.y.is_constant());
                    }

                    {
                        // test random element
                        let r = <$field>::rand(&mut rng);
                        let r_var = <$field_var>::constant(r);
                        let wb_r: Affine<$curve_config> =
                            WBMap::<$curve_config>::map_to_curve(r).unwrap();
                        let wb_r_var = WBMapGadget::<$curve_config>::map_to_curve(r_var).unwrap();
                        assert_eq!(wb_r_var.value_unchecked().unwrap(), wb_r);
                        assert!(wb_r_var.x.is_constant());
                        assert!(wb_r_var.y.is_constant());
                    }
                }

                fn test_input() {
                    let mut rng = thread_rng();

                    {
                        // test zero
                        let cs = ConstraintSystem::new_ref();
                        let zero = <$field>::ZERO;
                        let zero_var = <$field_var>::new_input(cs.clone(), || Ok(zero)).unwrap();
                        let wb_zero: Affine<$curve_config> =
                            WBMap::<$curve_config>::map_to_curve(zero).unwrap();
                        let wb_zero_var =
                            WBMapGadget::<$curve_config>::map_to_curve(zero_var).unwrap();
                        assert_eq!(wb_zero_var.value_unchecked().unwrap(), wb_zero);
                        assert!(cs.is_satisfied().unwrap());
                    }

                    {
                        // test one
                        let cs = ConstraintSystem::new_ref();
                        let one = <$field>::ONE;
                        let one_var = <$field_var>::new_input(cs.clone(), || Ok(one)).unwrap();
                        let wb_one: Affine<$curve_config> =
                            WBMap::<$curve_config>::map_to_curve(one).unwrap();
                        let wb_one_var =
                            WBMapGadget::<$curve_config>::map_to_curve(one_var).unwrap();
                        assert_eq!(wb_one_var.value_unchecked().unwrap(), wb_one);
                        assert!(cs.is_satisfied().unwrap());
                    }

                    {
                        // test random element
                        let cs = ConstraintSystem::new_ref();
                        let r = <$field>::rand(&mut rng);
                        let r_var = <$field_var>::new_input(cs.clone(), || Ok(r)).unwrap();
                        let wb_r: Affine<$curve_config> =
                            WBMap::<$curve_config>::map_to_curve(r).unwrap();
                        let wb_r_var = WBMapGadget::<$curve_config>::map_to_curve(r_var).unwrap();
                        assert_eq!(wb_r_var.value_unchecked().unwrap(), wb_r);
                        assert!(cs.is_satisfied().unwrap());
                    }
                }

                test_constant();
                test_input();
            }
        };
    }

    generate_wb_map_tests!(test_swu_map_fp, Fq, FpVar<Fq>, ark_bls12_381::g1::Config);

    generate_wb_map_tests!(test_swu_map_fp_emu, Fq, EmulatedFpVar<Fq, Fr>, ark_bls12_381::g1::Config);

    generate_wb_map_tests!(
        test_swu_map_fp2,
        Fq2,
        Fp2Var<Fq2Config>,
        ark_bls12_381::g2::Config
    );
}
