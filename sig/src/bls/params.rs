use ark_ec::{bls12::Bls12Config, short_weierstrass::Projective, CurveGroup};
use ark_r1cs_std::fields::fp2::Fp2Var;

// which curve is underlying sig
pub type BLSSigCurveConfig = ark_bls12_381::Config;

// which type we run our SNARK on
// pub type BaseField = ark_bw6_761::Fr;

// which base prime field the curve is running on
pub type TargetField = <BLSSigCurveConfig as Bls12Config>::Fp;

// G1 and G2 curve group
pub type G1 = Projective<<BLSSigCurveConfig as Bls12Config>::G1Config>;
pub type G2 = Projective<<BLSSigCurveConfig as Bls12Config>::G2Config>;

// which curve and config that hash to curve operates on
pub type HashCurveGroup = G2;
pub type HashCurveConfig = <HashCurveGroup as CurveGroup>::Config;
pub type HashCurveVar<F, CF> = Fp2Var<<BLSSigCurveConfig as Bls12Config>::Fp2Config, F, CF>;

// For experimentation: checking whether R1CS circuit is satisfied
pub type BaseField = TargetField;
