use ark_ec::{bls12::Bls12Config, short_weierstrass::Projective, CurveConfig, CurveGroup};
use ark_r1cs_std::fields::fp2::Fp2Var;

pub type G1<SigCurveConfig> = Projective<<SigCurveConfig as Bls12Config>::G1Config>;
pub type G2<SigCurveConfig> = Projective<<SigCurveConfig as Bls12Config>::G2Config>;
pub type SecretKeyScalarField<SigCurveConfig> =
    <<SigCurveConfig as Bls12Config>::G1Config as CurveConfig>::ScalarField;

pub type HashCurveGroup<SigCurveConfig> = G2<SigCurveConfig>;
pub type HashCurveConfig<SigCurveConfig> = <HashCurveGroup<SigCurveConfig> as CurveGroup>::Config;

// R1CS
pub type HashCurveVar<SigCurveConfig, F, CF> =
    Fp2Var<<SigCurveConfig as Bls12Config>::Fp2Config, F, CF>;

pub type BlsSigField<SigCurveConfig> = <SigCurveConfig as Bls12Config>::Fp;
