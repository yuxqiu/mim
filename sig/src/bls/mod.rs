mod bls;
mod params;
mod r1cs;
mod snark;

pub use bls::*;
pub use params::*;
pub use r1cs::*;
pub use snark::*;

use rand::thread_rng;

pub fn get_bls_instance() -> (&'static str, Parameters, SecretKey, PublicKey, Signature) {
    let msg = "Hello World";
    let mut rng = thread_rng();

    let params = Parameters::setup();
    let sk = SecretKey::new(&mut rng);
    let pk = PublicKey::new(&sk, &params);

    let sig = Signature::sign(msg.as_bytes(), &sk, &params);

    (msg, params, sk, pk, sig)
}

pub fn get_aggregate_bls_instance() -> (
    &'static str,
    Parameters,
    Vec<SecretKey>,
    Vec<PublicKey>,
    Signature,
) {
    const N: usize = 1000;

    let msg = "Hello World";
    let mut rng = thread_rng();

    let params = Parameters::setup();
    let secret_keys: Vec<SecretKey> = (0..N).map(|_| SecretKey::new(&mut rng)).collect();
    let public_keys: Vec<PublicKey> = secret_keys
        .iter()
        .map(|sk| PublicKey::new(sk, &params))
        .collect();

    let sig = Signature::aggregate_sign(msg.as_bytes(), &secret_keys, &params).unwrap();

    (msg, params, secret_keys, public_keys, sig)
}
