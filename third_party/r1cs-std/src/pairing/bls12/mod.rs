use ark_relations::r1cs::SynthesisError;

use super::{FieldOpsBounds, PairingVar as PG};

use crate::{
    fields::{fp12::Fp12Var, fp2::Fp2Var, FieldVar},
    groups::bls12::{G1AffineVar, G1PreparedVar, G1Var, G2PreparedVar, G2Var},
};
use ark_ec::bls12::{Bls12, Bls12Config, TwistType};
use ark_ff::{BitIteratorBE, PrimeField};
use ark_std::marker::PhantomData;

/// Specifies the constraints for computing a pairing in a BLS12 bilinear group.
pub struct PairingVar<P: Bls12Config, F, CF>(PhantomData<P>, PhantomData<F>, PhantomData<CF>);

type Fp2V<P, F, CF> = Fp2Var<<P as Bls12Config>::Fp2Config, F, CF>;

impl<P: Bls12Config, F: FieldVar<P::Fp, CF>, CF: PrimeField> PairingVar<P, F, CF>
where
    for<'a> &'a F: FieldOpsBounds<'a, <P as Bls12Config>::Fp, F>,
{
    // Evaluate the line function at point p.
    #[tracing::instrument(target = "r1cs")]
    fn ell(
        f: &mut Fp12Var<P::Fp12Config, F, CF>,
        coeffs: &(Fp2V<P, F, CF>, Fp2V<P, F, CF>),
        p: &G1AffineVar<P, F, CF>,
    ) -> Result<(), SynthesisError> {
        let zero = F::zero();

        match P::TWIST_TYPE {
            TwistType::M => {
                let c0 = coeffs.0.clone();
                let mut c1 = coeffs.1.clone();
                let c2 = Fp2V::<P, F, CF>::new(p.y.clone(), zero);

                c1.c0 *= &p.x;
                c1.c1 *= &p.x;
                *f = f.mul_by_014(&c0, &c1, &c2)?;
                Ok(())
            },
            TwistType::D => {
                let c0 = Fp2V::<P, F, CF>::new(p.y.clone(), zero);
                let mut c1 = coeffs.0.clone();
                let c2 = coeffs.1.clone();

                c1.c0 *= &p.x;
                c1.c1 *= &p.x;
                *f = f.mul_by_034(&c0, &c1, &c2)?;
                Ok(())
            },
        }
    }

    #[tracing::instrument(target = "r1cs")]
    fn exp_by_x(
        f: &Fp12Var<P::Fp12Config, F, CF>,
    ) -> Result<Fp12Var<P::Fp12Config, F, CF>, SynthesisError> {
        let mut result = f.optimized_cyclotomic_exp(P::X)?;
        if P::X_IS_NEGATIVE {
            result = result.unitary_inverse()?;
        }
        Ok(result)
    }
}

impl<P: Bls12Config, F: FieldVar<P::Fp, CF>, CF: PrimeField> PG<Bls12<P>, CF>
    for PairingVar<P, F, CF>
where
    for<'a> &'a F: FieldOpsBounds<'a, <P as Bls12Config>::Fp, F>,
{
    type G1Var = G1Var<P, F, CF>;
    type G2Var = G2Var<P, F, CF>;
    type G1PreparedVar = G1PreparedVar<P, F, CF>;
    type G2PreparedVar = G2PreparedVar<P, F, CF>;
    type GTVar = Fp12Var<P::Fp12Config, F, CF>;

    #[tracing::instrument(target = "r1cs")]
    fn miller_loop(
        ps: &[Self::G1PreparedVar],
        qs: &[Self::G2PreparedVar],
    ) -> Result<Self::GTVar, SynthesisError> {
        let mut pairs = vec![];
        for (p, q) in ps.iter().zip(qs.iter()) {
            pairs.push((p, q.ell_coeffs.iter()));
        }
        let mut f = Self::GTVar::one();

        for i in BitIteratorBE::new(P::X).skip(1) {
            f.square_in_place()?;

            for &mut (p, ref mut coeffs) in pairs.iter_mut() {
                Self::ell(&mut f, coeffs.next().unwrap(), &p.0)?;
            }

            if i {
                for &mut (p, ref mut coeffs) in pairs.iter_mut() {
                    Self::ell(&mut f, &coeffs.next().unwrap(), &p.0)?;
                }
            }
        }

        if P::X_IS_NEGATIVE {
            f = f.unitary_inverse()?;
        }

        Ok(f)
    }

    #[tracing::instrument(target = "r1cs")]
    fn final_exponentiation(f: &Self::GTVar) -> Result<Self::GTVar, SynthesisError> {
        // Computing the final exponentation following
        // https://eprint.iacr.org/2016/130.pdf.
        // We don't use their "faster" formula because it is difficult to make
        // it work for curves with odd `P::X`.
        // Hence we implement the slower algorithm from Table 1 below.

        let f1 = f.unitary_inverse()?;

        f.inverse().and_then(|mut f2| {
            // f2 = f^(-1);
            // r = f^(p^6 - 1)
            let mut r = f1;
            r *= &f2;

            // f2 = f^(p^6 - 1)
            f2 = r.clone();
            // r = f^((p^6 - 1)(p^2))
            r.frobenius_map_in_place(2)?;

            // r = f^((p^6 - 1)(p^2) + (p^6 - 1))
            // r = f^((p^6 - 1)(p^2 + 1))
            r *= &f2;

            // Hard part of the final exponentation is below:
            // From https://eprint.iacr.org/2016/130.pdf, Table 1
            let mut y0 = r.cyclotomic_square()?;
            y0 = y0.unitary_inverse()?;

            let mut y5 = Self::exp_by_x(&r)?;

            let mut y1 = y5.cyclotomic_square()?;
            let mut y3 = y0 * &y5;
            y0 = Self::exp_by_x(&y3)?;
            let y2 = Self::exp_by_x(&y0)?;
            let mut y4 = Self::exp_by_x(&y2)?;
            y4 *= &y1;
            y1 = Self::exp_by_x(&y4)?;
            y3 = y3.unitary_inverse()?;
            y1 *= &y3;
            y1 *= &r;
            y3 = r.clone();
            y3 = y3.unitary_inverse()?;
            y0 *= &r;
            y0.frobenius_map_in_place(3)?;
            y4 *= &y3;
            y4.frobenius_map_in_place(1)?;
            y5 *= &y2;
            y5.frobenius_map_in_place(2)?;
            y5 *= &y0;
            y5 *= &y4;
            y5 *= &y1;
            Ok(y5)
        })
    }

    #[tracing::instrument(target = "r1cs")]
    fn prepare_g1(p: &Self::G1Var) -> Result<Self::G1PreparedVar, SynthesisError> {
        Self::G1PreparedVar::from_group_var(p)
    }

    #[tracing::instrument(target = "r1cs")]
    fn prepare_g2(q: &Self::G2Var) -> Result<Self::G2PreparedVar, SynthesisError> {
        Self::G2PreparedVar::from_group_var(q)
    }
}
