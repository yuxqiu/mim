mod bls;
use ark_ec::{bls12::Bls12Config, hashing::curve_maps::wb::WBConfig};
pub use bls::*;

mod params;

mod r1cs;
pub use r1cs::*;

mod circuit;
pub use circuit::*;

use rand::thread_rng;

pub fn get_bls_instance<SigCurveConfig: Bls12Config>() -> (
    &'static str,
    Parameters<SigCurveConfig>,
    SecretKey<SigCurveConfig>,
    PublicKey<SigCurveConfig>,
    Signature<SigCurveConfig>,
)
where
    <SigCurveConfig as Bls12Config>::G2Config: WBConfig,
{
    let msg = "Hello World";
    let mut rng = thread_rng();

    let params = Parameters::setup();
    let sk = SecretKey::new(&mut rng);
    let pk = PublicKey::new(&sk, &params);

    let sig = Signature::sign(msg.as_bytes(), &sk, &params);

    (msg, params, sk, pk, sig)
}

pub fn get_aggregate_bls_instance<SigCurveConfig: Bls12Config>() -> (
    &'static str,
    Parameters<SigCurveConfig>,
    Vec<SecretKey<SigCurveConfig>>,
    Vec<PublicKey<SigCurveConfig>>,
    Signature<SigCurveConfig>,
)
where
    <SigCurveConfig as Bls12Config>::G2Config: WBConfig,
{
    const N: usize = 1000;

    let msg = "Hello World";
    let mut rng = thread_rng();

    let params = Parameters::setup();
    let secret_keys: Vec<_> = (0..N).map(|_| SecretKey::new(&mut rng)).collect();
    let public_keys: Vec<_> = secret_keys
        .iter()
        .map(|sk| PublicKey::new(sk, &params))
        .collect();

    let sig = Signature::aggregate_sign(msg.as_bytes(), &secret_keys, &params).unwrap();

    (msg, params, secret_keys, public_keys, sig)
}
