/*
pub struct SWUMap<P: SWUConfig>(PhantomData<fn() -> P>);

impl<P: SWUConfig> MapToCurve<Projective<P>> for SWUMap<P> {
    /// Map an arbitrary base field element to a curve point.
    /// Based on
    /// <https://github.com/zcash/pasta_curves/blob/main/src/hashtocurve.rs>.
    fn map_to_curve(element: P::BaseField) -> Result<Affine<P>, HashToCurveError> {
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

        let zeta_u2 = P::ZETA * element.square();
        let ta = zeta_u2.square() + zeta_u2;
        let num_x1 = b * (ta + <P::BaseField as One>::one());
        let div = a * if ta.is_zero() { P::ZETA } else { -ta };

        let num2_x1 = num_x1.square();
        let div2 = div.square();
        let div3 = div2 * div;
        let num_gx1 = (num2_x1 + a * div2) * num_x1 + b * div3;

        // 5. x2 = Z * u^2 * x1
        let num_x2 = zeta_u2 * num_x1; // same div

        // 6. gx2 = x2^3 + A * x2 + B  [optimized out; see below]
        // 7. If is_square(gx1), set x = x1 and y = sqrt(gx1)
        // 8. Else set x = x2 and y = sqrt(gx2)
        let gx1_square;
        let gx1;

        debug_assert!(
            !div3.is_zero(),
            "we have checked that neither a or ZETA are zero. Q.E.D."
        );
        let y1: P::BaseField = {
            gx1 = num_gx1 / div3;
            if gx1.legendre().is_qr() {
                gx1_square = true;
                gx1.sqrt()
                    .expect("We have checked that gx1 is a quadratic residue. Q.E.D")
            } else {
                let zeta_gx1 = P::ZETA * gx1;
                gx1_square = false;
                zeta_gx1.sqrt().expect(
                    "ZETA * gx1 is a quadratic residue because legard is multiplicative. Q.E.D",
                )
            }
        };

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

        let y2 = zeta_u2 * element * y1;
        let num_x = if gx1_square { num_x1 } else { num_x2 };
        let y = if gx1_square { y1 } else { y2 };

        let x_affine = num_x / div;
        let y_affine = if parity(&y) != parity(&element) {
            -y
        } else {
            y
        };
        let point_on_curve = Affine::<P>::new_unchecked(x_affine, y_affine);
        debug_assert!(
            point_on_curve.is_on_curve(),
            "swu mapped to a point off the curve"
        );
        Ok(point_on_curve)
    }
}
*/

use std::marker::PhantomData;

use ark_ec::{
    hashing::curve_maps::swu::SWUConfig,
    short_weierstrass::{Projective, SWCurveConfig},
    CurveGroup,
};
use ark_ff::{Field, PrimeField};
use ark_r1cs_std::{
    eq::EqGadget,
    fields::{FieldOpsBounds, FieldVar},
    groups::curves::short_weierstrass::AffineVar,
    prelude::Boolean,
};
use ark_relations::r1cs::SynthesisError;

use super::MapToCurveGadget;

pub struct SWUMapGadget<P: SWUConfig>(PhantomData<fn() -> P>);

impl<P: SWUConfig, CF: PrimeField, FP: FieldVar<P::BaseField, CF>>
    MapToCurveGadget<Projective<P>, CF, FP> for SWUMapGadget<P>
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
        let ta = zeta_u2.square()? + zeta_u2;
        let num_x1 = (ta + FP::one()) * b;

        // let div = a * if ta.is_zero()? { P::ZETA } else { -ta };
        let div_f = FP::constant(P::ZETA);
        let div_s = ta.negate()?;
        let div = ta.is_zero()?.select(&div_f, &div_s)?;

        let num2_x1 = num_x1.square()?;
        let div2 = div.square()?;
        let div3 = div2 * div;
        let num_gx1 = (num2_x1 + div2 * a) * num_x1 + div3 * b;

        // 5. x2 = Z * u^2 * x1
        let num_x2 = zeta_u2 * num_x1; // same div

        // 6. gx2 = x2^3 + A * x2 + B  [optimized out; see below]
        // 7. If is_square(gx1), set x = x1 and y = sqrt(gx1)
        // 8. Else set x = x2 and y = sqrt(gx2)
        let gx1_square;
        // TODO: check soundness, see if we can use `mul_by_inverse_unchecked`
        let gx1 = num_gx1 * div3.inverse()?;

        // TODO: implement this in R1CS
        let y1 = if gx1.legendre().is_qr() {
            gx1_square = true;
            gx1.sqrt()
                .expect("We have checked that gx1 is a quadratic residue. Q.E.D")
        } else {
            let zeta_gx1 = P::ZETA * gx1;
            gx1_square = false;
            zeta_gx1
                .sqrt()
                .expect("ZETA * gx1 is a quadratic residue because legard is multiplicative. Q.E.D")
        };

        // TODO:
        // - Understand Sarkar's square root algo
        // - Z / h is a square since both Z and h are nonsquares?
        // -
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

        let y2 = zeta_u2 * point * y1;
        let num_x = if gx1_square { num_x1 } else { num_x2 };
        let y = if gx1_square { y1 } else { y2 };

        // TODO: check soundness, see if we can use `mul_by_inverse_unchecked`
        let x_affine = num_x * div.inverse()?;
        let parity_y = parity_var(&y)?;
        let parity_p = parity_var(&point)?;
        // let y_affine = if parity(&y) != parity(&point) { -y } else { y };
        let y_affine = parity_y.is_eq(&parity_p)?.select(&y, &y.negate()?)?;

        let point_on_curve = AffineVar::new(x_affine, y_affine, Boolean::constant(false));

        Ok(point_on_curve)
    }
}

// TODO: implement this parity func
pub fn parity_var<F: FieldVar<TF, CF>, TF: Field, CF: PrimeField>(
    element: &F,
) -> Result<Boolean<CF>, SynthesisError> {
    // Idea
    // - follow 4.1. The sgn0 Function of https://datatracker.ietf.org/doc/html/rfc9380

    // element
    // .to_base_prime_field_elements()
    // .find(|&x| !x.is_zero())
    // .map_or(false, |x| x.into_bigint().is_odd())

    todo!()
}
