use ark_ec::bls12::Bls12Config;

pub type BlsSigField<SigCurveConfig> = <SigCurveConfig as Bls12Config>::Fp;

pub type BlsSigConfig = ark_bls12_381::Config;
