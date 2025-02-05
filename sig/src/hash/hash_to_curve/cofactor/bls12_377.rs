use ark_bls12_377::g2::G2Projective;
use ark_bls12_377::{Fq, Fq2, Fq2Config};
use ark_ec::bls12::Bls12Config;
use ark_ec::short_weierstrass::SWCurveConfig;
use ark_ec::CurveGroup;
use ark_ff::{
    AdditiveGroup, BigInteger, BigInteger64, Fp2ConfigWrapper, MontBackend, MontFp, PrimeField,
    QuadExtConfig, QuadExtField,
};
use ark_r1cs_std::groups::CurveVar;
use ark_r1cs_std::prelude::Boolean;
use ark_r1cs_std::R1CSVar;
use ark_r1cs_std::{
    fields::{quadratic_extension::QuadExtVar, FieldOpsBounds, FieldVar},
    groups::curves::short_weierstrass::ProjectiveVar,
};
use ark_relations::r1cs::SynthesisError;

use super::CofactorGadget;

type CurveConfig = ark_bls12_377::Config;

// PSI_X = u^((p-1)/3)
const P_POWER_ENDOMORPHISM_COEFF_0 : Fq2 = Fq2::new(
    MontFp!(
            "80949648264912719408558363140637477264845294720710499478137287262712535938301461879813459410946"
        ),
        Fq::ZERO,
    );

// PSI_Y = u^((p-1)/2)
const P_POWER_ENDOMORPHISM_COEFF_1: Fq2 = Fq2::new(
    MontFp!(
        "216465761340224619389371505802605247630151569547285782856803747159100223055385581585702401816380679166954762214499"),
        Fq::ZERO,
    );

// PSI_2_X = u^((p^2 - 1)/3)
const DOUBLE_P_POWER_ENDOMORPHISM_COEFF_0: Fq2 = Fq2::new(
        MontFp!("80949648264912719408558363140637477264845294720710499478137287262712535938301461879813459410945"),
        Fq::ZERO
    );

// psi(x,y) is the untwist-Frobenius-twist endomorhism on E'(Fq2)
// FP must be a var that operates on QuadExt field that G2 operates on
pub fn p_power_endomorphism_var<
    FP: FieldVar<<Fp2ConfigWrapper<Fq2Config> as QuadExtConfig>::BaseField, CF>,
    CF: PrimeField,
>(
    p: &ProjectiveVar<
        <G2Projective as CurveGroup>::Config,
        QuadExtVar<FP, Fp2ConfigWrapper<Fq2Config>, CF>,
        CF,
    >,
) -> Result<
    ProjectiveVar<
        <G2Projective as CurveGroup>::Config,
        QuadExtVar<FP, Fp2ConfigWrapper<Fq2Config>, CF>,
        CF,
    >,
    SynthesisError,
>
where
    for<'a> &'a FP: ark_r1cs_std::fields::FieldOpsBounds<
        'a,
        ark_ff::Fp<MontBackend<ark_bls12_377::FqConfig, 6>, 6>,
        FP,
    >,
{
    // The p-power endomorphism for G2 is defined as follows:
    // 1. Note that G2 is defined on curve E': y^2 = x^3 + 1/u.
    //    To map a point (x, y) in E' to (s, t) in E,
    //    one set s = x * (u ^ (1/3)), t = y * (u ^ (1/2)),
    //    because E: y^2 = x^3 + 1.
    // 2. Apply the Frobenius endomorphism (s, t) => (s', t'),
    //    another point on curve E, where s' = s^p, t' = t^p.
    // 3. Map the point from E back to E'; that is,
    //    one set x' = s' / ((u) ^ (1/3)), y' = t' / ((u) ^ (1/2)).
    //
    // To sum up, it maps
    // (x,y) -> (x^p * (u ^ ((p-1)/3)), y^p * (u ^ ((p-1)/2)))
    // as implemented in the code as follows.

    let mut res = p.to_affine_unchecked()?;
    res.x.frobenius_map_in_place(1)?;
    res.y.frobenius_map_in_place(1)?;

    res.x *= P_POWER_ENDOMORPHISM_COEFF_0;
    res.y *= P_POWER_ENDOMORPHISM_COEFF_1;

    // the result is infinity only when the input (aka `res`) is infinity
    // so we will select by `res.infinity`
    Ok(ProjectiveVar::<
        <G2Projective as CurveGroup>::Config,
        QuadExtVar<FP, Fp2ConfigWrapper<Fq2Config>, CF>,
        CF,
    >::new(
        res.x,
        res.y,
        res.infinity
            .select(&QuadExtVar::zero(), &QuadExtVar::one())?,
    ))
}

// For a p-power endomorphism psi(P), compute psi(psi(P))
pub fn double_p_power_endomorphism_var<
    FP: FieldVar<<G2Projective as CurveGroup>::BaseField, CF>,
    CF: PrimeField,
>(
    p: &ProjectiveVar<<G2Projective as CurveGroup>::Config, FP, CF>,
) -> Result<ProjectiveVar<<G2Projective as CurveGroup>::Config, FP, CF>, SynthesisError>
where
    for<'a> &'a FP:
        FieldOpsBounds<'a, QuadExtField<Fp2ConfigWrapper<ark_bls12_377::Fq2Config>>, FP>,
{
    // p_power_endomorphism(&p_power_endomorphism(&p.into_affine())).into()
    let mut res = p.clone();

    res.x *= DOUBLE_P_POWER_ENDOMORPHISM_COEFF_0;
    res.y = res.y.negate()?;

    Ok(res)
}

impl<
        FP: FieldVar<<Fp2ConfigWrapper<Fq2Config> as QuadExtConfig>::BaseField, CF>,
        CF: PrimeField,
    > CofactorGadget<QuadExtVar<FP, Fp2ConfigWrapper<Fq2Config>, CF>, CF> for G2Projective
where
    <Self as CurveGroup>::Config: SWCurveConfig,
    for<'b> &'b FP: FieldOpsBounds<'b, ark_ff::Fp<MontBackend<ark_bls12_377::FqConfig, 6>, 6>, FP>,
{
    #[tracing::instrument(skip_all)]
    fn clear_cofactor_var(
        p: &ProjectiveVar<Self::Config, QuadExtVar<FP, Fp2ConfigWrapper<Fq2Config>, CF>, CF>,
    ) -> Result<
        ProjectiveVar<Self::Config, QuadExtVar<FP, Fp2ConfigWrapper<Fq2Config>, CF>, CF>,
        SynthesisError,
    > {
        let cs = p.cs();
        tracing::info!(num_constraints = cs.num_constraints());

        // Based on Section 4.1 of https://eprint.iacr.org/2017/419.pdf
        // [h(ψ)]P = [x^2 − x − 1]P + [x − 1]ψ(P) + (ψ^2)(2P)

        // x = -15132376222941642752
        // When multiplying, use -c1 instead, and then negate the result. That's much
        // more efficient, since the scalar -c1 has less limbs and a much lower Hamming
        // weight.
        let x: &'static [u64] = <CurveConfig as Bls12Config>::X;
        let x = x
            .iter()
            .flat_map(|value| {
                BigInteger64::from(*value)
                    .to_bits_le()
                    .into_iter()
                    .map(Boolean::constant)
            })
            .collect::<Vec<_>>();
        // p is already projective, but we clone it here to mimic the original code
        // let p_projective = p.clone();

        // [x]P
        // let x_p = Config::mul_affine(p, &x).neg();
        let x_p = p.scalar_mul_le_unchecked(x.iter())?;

        // ψ(P)
        let psi_p = p_power_endomorphism_var(p)?;
        // (ψ^2)(2P)
        let mut psi2_p2 = double_p_power_endomorphism_var(&p.double()?)?;

        // tmp = [x]P + ψ(P)
        let mut tmp = x_p.clone();
        tmp = tmp.add_unchecked(&psi_p);

        // tmp2 = [x^2]P + [x]ψ(P)
        let mut tmp2 = tmp;
        tmp2 = tmp2.scalar_mul_le_unchecked(x.iter())?;

        // add up all the terms
        psi2_p2 = psi2_p2.add_unchecked(&tmp2);
        psi2_p2 = psi2_p2.add_unchecked(&x_p.negate()?);
        psi2_p2 = psi2_p2.add_unchecked(&psi_p.negate()?);
        let ret = Ok(psi2_p2.add_unchecked(&p.negate()?));

        tracing::info!(num_constraints = cs.num_constraints());

        ret
    }
}

#[cfg(test)]
mod test {
    use std::ops::Neg;

    use ark_bls12_377::{g2::Config, Fq, Fq2, Fq2Config};
    use ark_ec::{
        short_weierstrass::{Affine, Projective},
        AffineRepr,
    };
    use ark_ff::{AdditiveGroup, Field, Fp2ConfigWrapper, MontFp, UniformRand};
    use ark_r1cs_std::{
        fields::{fp::FpVar, quadratic_extension::QuadExtVar},
        groups::{curves::short_weierstrass::ProjectiveVar, CurveVar},
    };
    use rand::{thread_rng, Rng};

    use crate::hash::hash_to_curve::cofactor::bls12_377::{
        double_p_power_endomorphism_var, p_power_endomorphism_var,
    };

    // PSI_X = u^((p-1)/3)
    const P_POWER_ENDOMORPHISM_COEFF_0 : Fq2 = Fq2::new(
    MontFp!(
            "80949648264912719408558363140637477264845294720710499478137287262712535938301461879813459410946"
        ),
        Fq::ZERO,
    );

    // PSI_Y = u^((p-1)/2)
    const P_POWER_ENDOMORPHISM_COEFF_1: Fq2 = Fq2::new(
    MontFp!(
        "216465761340224619389371505802605247630151569547285782856803747159100223055385581585702401816380679166954762214499"),
        Fq::ZERO,
    );

    // PSI_2_X = u^((p^2 - 1)/3)
    const DOUBLE_P_POWER_ENDOMORPHISM_COEFF_0: Fq2 = Fq2::new(
        MontFp!("80949648264912719408558363140637477264845294720710499478137287262712535938301461879813459410945"),
        Fq::ZERO
    );

    /// psi(x,y) is the untwist-Frobenius-twist endomorhism on E'(Fq2)
    fn p_power_endomorphism(p: &Affine<Config>) -> Affine<Config> {
        // The p-power endomorphism for G2 is defined as follows:
        // 1. Note that G2 is defined on curve E': y^2 = x^3 + 1/u.
        //    To map a point (x, y) in E' to (s, t) in E,
        //    one set s = x * (u ^ (1/3)), t = y * (u ^ (1/2)),
        //    because E: y^2 = x^3 + 1.
        // 2. Apply the Frobenius endomorphism (s, t) => (s', t'),
        //    another point on curve E, where s' = s^p, t' = t^p.
        // 3. Map the point from E back to E'; that is,
        //    one set x' = s' / ((u) ^ (1/3)), y' = t' / ((u) ^ (1/2)).
        //
        // To sum up, it maps
        // (x,y) -> (x^p * (u ^ ((p-1)/3)), y^p * (u ^ ((p-1)/2)))
        // as implemented in the code as follows.

        let mut res = *p;
        res.x.frobenius_map_in_place(1);
        res.y.frobenius_map_in_place(1);

        res.x *= P_POWER_ENDOMORPHISM_COEFF_0;
        res.y *= P_POWER_ENDOMORPHISM_COEFF_1;

        res
    }

    /// For a p-power endomorphism psi(P), compute psi(psi(P))
    fn double_p_power_endomorphism(p: &Projective<Config>) -> Projective<Config> {
        // p_power_endomorphism(&p_power_endomorphism(&p.into_affine())).into()
        let mut res = *p;

        res.x *= DOUBLE_P_POWER_ENDOMORPHISM_COEFF_0;
        // u^((p^2 - 1)/2) == -1
        res.y = res.y.neg();

        res
    }

    fn sample_unchecked() -> Affine<Config> {
        let mut rng = thread_rng();

        loop {
            let x1 = Fq::rand(&mut rng);
            let x2 = Fq::rand(&mut rng);
            let greatest = rng.gen();
            let x = Fq2::new(x1, x2);

            if let Some(p) = Affine::get_point_from_x_unchecked(x, greatest) {
                return p;
            }
        }
    }

    #[test]
    fn test_psi() {
        let p = sample_unchecked();
        let p_var: ProjectiveVar<Config, QuadExtVar<FpVar<Fq>, Fp2ConfigWrapper<Fq2Config>, _>, _> =
            ProjectiveVar::constant(p.into_group());

        let psi_p = p_power_endomorphism(&p);
        let psi_p_var = p_power_endomorphism_var(&p_var)
            .unwrap()
            .to_affine_unchecked()
            .unwrap()
            .value_unchecked()
            .unwrap();

        assert_eq!(psi_p, psi_p_var);
    }

    #[test]
    fn test_psi_2() {
        let p = sample_unchecked();
        let p_var: ProjectiveVar<Config, QuadExtVar<FpVar<Fq>, Fp2ConfigWrapper<Fq2Config>, _>, _> =
            ProjectiveVar::constant(p.into_group());

        let psi_p = double_p_power_endomorphism(&p.into_group());
        let psi_p_var = double_p_power_endomorphism_var(&p_var)
            .unwrap()
            .to_affine_unchecked()
            .unwrap()
            .value_unchecked()
            .unwrap();

        assert_eq!(psi_p, psi_p_var);
    }
}
