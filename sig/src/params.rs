use ark_ec::{
    bls12::Bls12Config,
    pairing::Pairing,
    short_weierstrass::{Projective, SWCurveConfig},
    CurveConfig, CurveGroup,
};
use ark_r1cs_std::fields::fp2::Fp2Var;

/* ====================Signature Related==================== */
// we can easily switch between `ark_bls12_377` and `ark_bls12_381`
// all we need to do is to replace the following crate name accordingly

#[cfg(feature = "sig-12381-snark-12377")]
use ark_bls12_381::{Config, G1Affine, G2Affine};

#[cfg(feature = "sig-12377-snark-761")]
use ark_bls12_377::{Config, G1Affine, G2Affine};

// which curve the sig scheme runs on
pub type BLSSigCurveConfig = Config;

// which field the secret key uses
pub type SecretKeyScalarField =
    <<BLSSigCurveConfig as Bls12Config>::G1Config as CurveConfig>::ScalarField;

// which base prime field the curve uses
pub type BaseSigCurveField = <BLSSigCurveConfig as Bls12Config>::Fp;

// G1 and G2 curve group
pub type G1 = Projective<<BLSSigCurveConfig as Bls12Config>::G1Config>;
pub type G2 = Projective<<BLSSigCurveConfig as Bls12Config>::G2Config>;

// which curve and config that hash to curve runs on
pub type HashCurveGroup = G2;
pub type HashCurveConfig = <HashCurveGroup as CurveGroup>::Config;
pub type HashCurveVar<F, CF> = Fp2Var<<BLSSigCurveConfig as Bls12Config>::Fp2Config, F, CF>;

// curve generators
pub const G1_GENERATOR: G1Affine = <<Config as Bls12Config>::G1Config as SWCurveConfig>::GENERATOR;
pub const G2_GENERATOR: G2Affine = <<Config as Bls12Config>::G2Config as SWCurveConfig>::GENERATOR;
/* ====================Signature Related==================== */

/* ====================SNARK Related==================== */
#[cfg(feature = "sig-12381-snark-12377")]
pub type SNARKCurve = ark_bls12_377::Bls12_377;

#[cfg(feature = "sig-12377-snark-761")]
pub type SNARKCurve = ark_bw6_761::BW6_761;

// which scalar field we run our SNARK on
pub type BaseSNARKField = <SNARKCurve as Pairing>::ScalarField;
// pub type BaseSNARKField = BaseSigCurveField; // experimentation only

// which underlying FieldVar we use
#[cfg(feature = "sig-12381-snark-12377")]
#[macro_export]
macro_rules! fp_var {
    ($type_a:ty, $type_b:ty) => {
        ark_r1cs_std::fields::emulated_fp::EmulatedFpVar::<$type_a, $type_b>
    };
}

#[cfg(feature = "sig-12377-snark-761")]
#[macro_export]
macro_rules! fp_var {
    ($type_a:ty, $type_b:ty) => {
        ark_r1cs_std::fields::fp::FpVar::<$type_a>
    };
}
/* ====================SNARK Related==================== */
