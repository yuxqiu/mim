use core::marker::PhantomData;

use ark_ec::{
    hashing::curve_maps::swu::SWUConfig,
    short_weierstrass::{Projective, SWCurveConfig},
    CurveConfig, CurveGroup,
};
use ark_ff::{Field, PrimeField};
use ark_r1cs_std::{
    eq::EqGadget,
    fields::{FieldOpsBounds, FieldVar},
    groups::curves::short_weierstrass::AffineVar,
    prelude::{Boolean, ToBitsGadget},
};
use ark_relations::r1cs::SynthesisError;

use super::{sqrt::SqrtGadget, to_base_field::ToBaseFieldGadget, MapToCurveGadget};

pub struct SWUMapGadget<P: SWUConfig>(PhantomData<fn() -> P>);

#[expect(clippy::similar_names)]
impl<
        P: SWUConfig,
        CF: PrimeField,
        FP: FieldVar<P::BaseField, CF>
            + ToBaseFieldGadget<<<P as CurveConfig>::BaseField as Field>::BasePrimeField, CF>
            + SqrtGadget<P::BaseField, CF>,
    > MapToCurveGadget<Projective<P>, CF, FP> for SWUMapGadget<P>
{
    fn map_to_curve(
        point: FP,
    ) -> Result<AffineVar<<Projective<P> as CurveGroup>::Config, FP, CF>, SynthesisError>
    where
        <Projective<P> as CurveGroup>::Config: SWCurveConfig,
        for<'a> &'a FP: FieldOpsBounds<'a, <Projective<P> as CurveGroup>::BaseField, FP>,
    {
        // 1. tv1 = inv0(Z^2 * u^4 + Z * u^2)
        // 2. x1 = (-B / A) * (1 + tv1)
        // 3. If tv1 == 0, set x1 = B / (Z * A)
        // 4. gx1 = x1^3 + A * x1 + B
        //
        // We use the "Avoiding inversions" optimization in [WB2019, section 4.2]
        // (not to be confused with section 4.3):
        //
        //   here       [WB2019]
        //   -------    ---------------------------------
        //   Z          ξ
        //   u          t
        //   Z * u^2    ξ * t^2 (called u, confusingly)
        //   x1         X_0(t)
        //   x2         X_1(t)
        //   gx1        g(X_0(t))
        //   gx2        g(X_1(t))
        //
        // Using the "here" names:
        //    x1 = num_x1/div      = [B*(Z^2 * u^4 + Z * u^2 + 1)] / [-A*(Z^2 * u^4 + Z * u^2]
        //   gx1 = num_gx1/div_gx1 = [num_x1^3 + A * num_x1 * div^2 + B * div^3] / div^3
        let a = P::COEFF_A;
        let b = P::COEFF_B;

        let zeta_u2 = point.square()? * P::ZETA;
        let ta = zeta_u2.square()? + &zeta_u2;
        let num_x1 = (&ta + FP::one()) * b;

        // let div = a * if ta.is_zero()? { P::ZETA } else { -ta };
        let div_f = FP::constant(P::ZETA);
        let div_s = ta.negate()?;

        // safety: div is non-zero
        // - P::ZETA is not a quadratic residue => it's not zero
        // - when ta is not zero, div_s is not zero
        let div = ta.is_zero()?.select(&div_f, &div_s)? * a;

        let num2_x1 = num_x1.square()?;
        let div2 = div.square()?;

        // safety: div3 is non-zero as
        // - div is not zero
        // - square and multiply will not result 0
        let div3 = &div2 * &div;
        let num_gx1 = (num2_x1 + div2 * a) * &num_x1 + &div3 * b;

        // 5. x2 = Z * u^2 * x1
        let num_x2 = &zeta_u2 * &num_x1; // same div

        // 6. gx2 = x2^3 + A * x2 + B  [optimized out; see below]
        // 7. If is_square(gx1), set x = x1 and y = sqrt(gx1)
        // 8. Else set x = x2 and y = sqrt(gx2)

        // let gx1 = num_gx1 * div3.inverse()?;
        // - safety: div3 is non-zero
        let gx1 = num_gx1.mul_by_inverse_unchecked(&div3)?;

        // let y1 = if gx1.legendre().is_qr() {
        //     gx1_square = true;
        //     gx1.sqrt()
        //         .expect("We have checked that gx1 is a quadratic residue. Q.E.D")
        // } else {
        //     let zeta_gx1 = gx1 * P::ZETA;
        //     gx1_square = false;
        //     zeta_gx1
        //         .sqrt()
        //         .expect("ZETA * gx1 is a quadratic residue because legard is multiplicative. Q.E.D")
        // };
        let (gx1_square, gx1_sqrt) = gx1.sqrt()?;
        let (_, zeta_gx1_sqrt) = (gx1 * P::ZETA).sqrt()?;
        let y1 = gx1_square.select(&gx1_sqrt, &zeta_gx1_sqrt)?;

        // TODO:
        // - Understand Sarkar's square root algo
        // - Z / h is a square since both Z and h are nonsquares?
        //   - Wikipedia: "modulo a prime, the product of two nonresidues is a residue" <-
        //     - Euler's criterion / Legendre Symbol + Legendre Symbol is multiplicative
        //   - h is non-square => h^-1 is non-square (easy to show).
        //
        // This magic also comes from a generalization of [WB2019, section 4.2].
        //
        // The Sarkar square root algorithm with input s gives us a square root of
        // h * s for free when s is not square, where h is a fixed nonsquare.
        // In our implementation, h = ROOT_OF_UNITY.
        // We know that Z / h is a square since both Z and h are
        // nonsquares. Precompute theta as a square root of Z / ROOT_OF_UNITY.
        //
        // We have gx2 = g(Z * u^2 * x1) = Z^3 * u^6 * gx1
        //                               = (Z * u^3)^2 * (Z/h * h * gx1)
        //                               = (Z * theta * u^3)^2 * (h * gx1)
        //
        // When gx1 is not square, y1 is a square root of h * gx1, and so Z * theta *
        // u^3 * y1 is a square root of gx2. Note that we don't actually need to
        // compute gx2.

        let y2 = zeta_u2 * &point * &y1;

        // let num_x = if gx1_square { num_x1 } else { num_x2 };
        let num_x = gx1_square.select(&num_x1, &num_x2)?;

        // let y = if gx1_square { y1 } else { y2 };
        let y = gx1_square.select(&y1, &y2)?;

        // let x_affine = num_x * div.inverse()?;
        // - safety: div is non-zero
        let x_affine = num_x.mul_by_inverse_unchecked(&div)?;
        let parity_y = parity_var(&y)?;
        let parity_p = parity_var(&point)?;
        // let y_affine = if parity(&y) != parity(&point) { -y } else { y };
        let y_affine = parity_y.is_eq(&parity_p)?.select(&y, &y.negate()?)?;

        // let point_on_curve = Affine::<P>::new_unchecked(x_affine, y_affine);
        let point_on_curve = AffineVar::new(x_affine, y_affine, Boolean::constant(false));

        Ok(point_on_curve)
    }
}

pub fn parity_var<F: ToBitsGadget<CF> + ToBaseFieldGadget<TF, CF>, TF: Field, CF: PrimeField>(
    element: &F,
) -> Result<Boolean<CF>, SynthesisError> {
    // Based on the `sgn0` function documented in Section 4.1 of https://datatracker.ietf.org/doc/html/rfc9380
    let mut sign = Boolean::constant(false);
    let mut zero = Boolean::constant(true);

    for xi in element.to_base_prime_field_vars()? {
        let sign_i = &xi.to_bits_le()?[0];
        let zero_i = xi.is_zero()?;
        sign |= &zero & sign_i;
        zero &= zero_i;
    }

    Ok(sign)
}

#[cfg(test)]
mod test {
    use ark_bls12_381::{Fq, Fq2, Fq2Config, Fr};
    use ark_bw6_761::Fq3Config;
    use ark_ec::hashing::{
        curve_maps::{parity, swu::SWUMap, wb::WBConfig},
        map_to_curve_hasher::MapToCurve,
    };
    use ark_ff::{Fp2, Fp3, UniformRand};
    use ark_r1cs_std::{
        alloc::AllocVar,
        fields::{fp::FpVar, fp2::Fp2Var, fp3::Fp3Var, FieldVar},
        R1CSVar,
    };
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::One;
    use ark_std::Zero;
    use rand::thread_rng;

    use crate::hash::map_to_curve::{swu::SWUMapGadget, MapToCurveGadget};

    use super::parity_var;

    macro_rules! generate_parity_tests {
        ($test_name:ident, $field:ty, $field_var:ty) => {
            #[test]
            fn $test_name() {
                fn test_constant() {
                    let mut rng = thread_rng();

                    {
                        // test zero
                        let zero = <$field>::zero();
                        let zero_var = <$field_var>::constant(zero);
                        let parity_zero = parity(&zero);
                        let parity_zero_var = parity_var(&zero_var).unwrap();
                        assert_eq!(parity_zero_var.value().unwrap(), parity_zero);
                        assert!(parity_zero_var.is_constant());
                    }

                    {
                        // test one
                        let one = <$field>::one();
                        let one_var = <$field_var>::constant(one);
                        let parity_one = parity(&one);
                        let parity_one_var = parity_var(&one_var).unwrap();
                        assert_eq!(parity_one_var.value().unwrap(), parity_one);
                        assert!(parity_one_var.is_constant());
                    }

                    {
                        // test random element
                        let r = <$field>::rand(&mut rng);
                        let r_var = <$field_var>::constant(r);
                        let parity_r = parity(&r);
                        let parity_r_var = parity_var(&r_var).unwrap();
                        assert_eq!(parity_r_var.value().unwrap(), parity_r);
                    }
                }

                fn test_input() {
                    let mut rng = thread_rng();

                    {
                        // test zero
                        let cs = ConstraintSystem::new_ref();
                        let zero = <$field>::zero();
                        let zero_var = <$field_var>::new_input(cs.clone(), || Ok(zero)).unwrap();
                        let parity_zero = parity(&zero);
                        let parity_zero_var = parity_var(&zero_var).unwrap();
                        assert_eq!(parity_zero_var.value().unwrap(), parity_zero);
                        assert!(cs.is_satisfied().unwrap());
                    }

                    {
                        // test one
                        let cs = ConstraintSystem::new_ref();
                        let one = <$field>::one();
                        let one_var = <$field_var>::new_input(cs.clone(), || Ok(one)).unwrap();
                        let parity_one = parity(&one);
                        let parity_one_var = parity_var(&one_var).unwrap();
                        assert_eq!(parity_one_var.value().unwrap(), parity_one);
                        assert!(cs.is_satisfied().unwrap());
                    }

                    {
                        // test random element
                        let cs = ConstraintSystem::new_ref();
                        let r = <$field>::rand(&mut rng);
                        let r_var = <$field_var>::new_input(cs.clone(), || Ok(r)).unwrap();
                        let parity_r = parity(&r);
                        let parity_r_var = parity_var(&r_var).unwrap();
                        assert_eq!(parity_r_var.value().unwrap(), parity_r);
                        assert!(cs.is_satisfied().unwrap());
                    }
                }

                test_constant();
                test_input();
            }
        };
    }

    generate_parity_tests!(test_parity_fp, Fr, FpVar<Fr>);
    generate_parity_tests!(test_parity_fp2, Fp2<Fq2Config>, Fp2Var<Fq2Config>);
    generate_parity_tests!(test_parity_fp3, Fp3<Fq3Config>, Fp3Var<Fq3Config>);

    macro_rules! generate_swu_map_tests {
        ($test_name:ident, $field:ty, $field_var:ty, $curve:ty) => {
            #[test]
            fn $test_name() {
                fn test_constant() {
                    let mut rng = thread_rng();

                    {
                        // test zero
                        let zero = <$field>::zero();
                        let zero_var = <$field_var>::constant(zero);
                        let swu_zero = SWUMap::<$curve>::map_to_curve(zero).unwrap();
                        let swu_zero_var = SWUMapGadget::<$curve>::map_to_curve(zero_var).unwrap();
                        assert_eq!(swu_zero_var.value_unchecked().unwrap(), swu_zero);
                        assert!(swu_zero_var.x.is_constant());
                        assert!(swu_zero_var.y.is_constant());
                    }

                    {
                        // test one
                        let one = <$field>::one();
                        let one_var = <$field_var>::constant(one);
                        let swu_one = SWUMap::<$curve>::map_to_curve(one).unwrap();
                        let swu_one_var = SWUMapGadget::<$curve>::map_to_curve(one_var).unwrap();
                        assert_eq!(swu_one_var.value_unchecked().unwrap(), swu_one);
                        assert!(swu_one_var.x.is_constant());
                        assert!(swu_one_var.y.is_constant());
                    }

                    {
                        // test random element
                        let r = <$field>::rand(&mut rng);
                        let r_var = <$field_var>::constant(r);
                        let swu_r = SWUMap::<$curve>::map_to_curve(r).unwrap();
                        let swu_r_var = SWUMapGadget::<$curve>::map_to_curve(r_var).unwrap();
                        assert_eq!(swu_r_var.value_unchecked().unwrap(), swu_r);
                        assert!(swu_r_var.x.is_constant());
                        assert!(swu_r_var.y.is_constant());
                    }
                }

                fn test_input() {
                    let mut rng = thread_rng();

                    {
                        // test zero
                        let cs = ConstraintSystem::new_ref();
                        let zero = <$field>::zero();
                        let zero_var = <$field_var>::new_input(cs.clone(), || Ok(zero)).unwrap();
                        let swu_zero = SWUMap::<$curve>::map_to_curve(zero).unwrap();
                        let swu_zero_var = SWUMapGadget::<$curve>::map_to_curve(zero_var).unwrap();
                        assert_eq!(swu_zero_var.value_unchecked().unwrap(), swu_zero);
                        assert!(cs.is_satisfied().unwrap());
                    }

                    {
                        // test one
                        let cs = ConstraintSystem::new_ref();
                        let one = <$field>::one();
                        let one_var = <$field_var>::new_input(cs.clone(), || Ok(one)).unwrap();
                        let swu_one = SWUMap::<$curve>::map_to_curve(one).unwrap();
                        let swu_one_var = SWUMapGadget::<$curve>::map_to_curve(one_var).unwrap();
                        assert_eq!(swu_one_var.value_unchecked().unwrap(), swu_one);
                        assert!(cs.is_satisfied().unwrap());
                    }

                    {
                        // test random element
                        let cs = ConstraintSystem::new_ref();
                        let r = <$field>::rand(&mut rng);
                        let r_var = <$field_var>::new_input(cs.clone(), || Ok(r)).unwrap();
                        let swu_r = SWUMap::<$curve>::map_to_curve(r).unwrap();
                        let swu_r_var = SWUMapGadget::<$curve>::map_to_curve(r_var).unwrap();
                        assert_eq!(swu_r_var.value_unchecked().unwrap(), swu_r);
                        assert!(cs.is_satisfied().unwrap());
                    }
                }

                test_constant();
                test_input();
            }
        };
    }

    generate_swu_map_tests!(
        test_swu_map_fp,
        Fq,
        FpVar<Fq>,
        <ark_bls12_381::g1::Config as WBConfig>::IsogenousCurve
    );

    generate_swu_map_tests!(
        test_swu_map_fp2,
        Fq2,
        Fp2Var<Fq2Config>,
        <ark_bls12_381::g2::Config as WBConfig>::IsogenousCurve
    );
}
