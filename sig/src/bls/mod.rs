mod bls;
pub use bls::*;

mod r1cs;
pub use r1cs::*;

cfg_if::cfg_if! {
    if #[cfg(any(feature = "snark-12377", feature = "snark-761"))] {
        // only enable circuit if it is not native field or it uses sig-12377 and snark-761
        cfg_if::cfg_if! {
            if #[cfg(all(not(feature = "emulated-field"), feature = "sig-12377", feature = "snark-761"))] {
                mod circuit;
                pub use circuit::*;
            } else if #[cfg(feature = "emulated-field")] {
                mod circuit;
                pub use circuit::*;
            }
        }
    }
}

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
