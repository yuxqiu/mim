use core::ops::Mul;

use ark_ec::{
    bls12::{self},
    hashing::{curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher, HashToCurve},
    pairing::{Pairing, PairingOutput},
};
use ark_ff::{field_hashers::DefaultFieldHasher, AdditiveGroup, UniformRand};
use blake2::Blake2s256;
use rand::Rng;

use crate::bls::{HashCurveConfig, HashCurveGroup};

use super::{BLSSigCurveConfig, SecretKeyScalarField, G1, G1_GENERATOR, G2, G2_GENERATOR};

#[derive(Clone)]
pub struct Parameters {
    pub g1_generator: G1,
    pub g2_generator: G2,
}

#[derive(Clone)]
pub struct PublicKey {
    pub pub_key: G1,
}

#[derive(Clone)]
pub struct SecretKey {
    pub secret_key: SecretKeyScalarField,
}

#[derive(Clone)]
pub struct Signature {
    pub signature: G2,
}

impl Parameters {
    #[must_use]
    pub fn setup() -> Self {
        Self {
            g1_generator: G1_GENERATOR.into(),
            g2_generator: G2_GENERATOR.into(),
        }
    }
}

impl PublicKey {
    #[must_use]
    pub fn new(secret_key: &SecretKey, params: &Parameters) -> Self {
        let pub_key = params.g1_generator.mul(secret_key.secret_key);
        Self { pub_key }
    }
}

impl SecretKey {
    pub fn new<R: Rng>(rng: &mut R) -> Self {
        let secret_key = SecretKeyScalarField::rand(rng);
        Self { secret_key }
    }
}

impl Signature {
    fn hash_to_curve(message: &[u8]) -> G2 {
        // safety
        type FieldHasher = DefaultFieldHasher<Blake2s256, 128>;
        type CurveMap = WBMap<HashCurveConfig>;
        let hasher: MapToCurveBasedHasher<HashCurveGroup, FieldHasher, CurveMap> =
            MapToCurveBasedHasher::new(&[]).unwrap();
        let hashed_message = hasher.hash(message).unwrap();

        hashed_message.into()
    }

    #[must_use]
    pub fn sign(message: &[u8], secret_key: &SecretKey, _: &Parameters) -> Self {
        let hashed_message = Self::hash_to_curve(message);
        let signature = hashed_message.mul(secret_key.secret_key);
        Self { signature }
    }

    #[must_use]
    pub fn aggregate_sign(
        message: &[u8],
        secret_keys: &[SecretKey],
        params: &Parameters,
    ) -> Option<Self> {
        // we can theoretically do the following, but to mimic the real-world scenario,
        // let's sign them one by one and then add all sigs together

        /*
        if secret_keys.is_empty() {
            return None;
        }

        let sk = secret_keys
            .iter()
            .skip(1)
            .fold(secret_keys[0].clone(), |acc, new_sk| SecretKey {
                secret_key: acc.secret_key + new_sk.secret_key,
            });

        Some(Signature::sign(message, &sk, params))
        */

        let mut sigs = secret_keys.iter().map(|sk| Self::sign(message, sk, params));
        let first_sig = sigs.next()?;

        Some(sigs.fold(first_sig, |acc, new_sig| Self {
            signature: acc.signature + new_sig.signature,
        }))
    }

    #[must_use]
    pub fn verify_slow(
        message: &[u8],
        signature: &Self,
        public_key: &PublicKey,
        params: &Parameters,
    ) -> bool {
        let hashed_message = Self::hash_to_curve(message);

        // a naive way to check pairing equation: e(g1, sig) == e(pk, H(msg))
        let pairing_1 =
            bls12::Bls12::<BLSSigCurveConfig>::pairing(params.g1_generator, signature.signature);
        let pairing_2 =
            ark_ec::bls12::Bls12::<BLSSigCurveConfig>::pairing(public_key.pub_key, hashed_message);

        pairing_1 == pairing_2
    }

    #[must_use]
    pub fn verify(
        message: &[u8],
        signature: &Self,
        public_key: &PublicKey,
        params: &Parameters,
    ) -> bool {
        let hashed_message = Self::hash_to_curve(message);

        // an optimized way to check pairing equation: e(g1, sig) == e(pk, H(msg))
        //
        // e'(g1, sig)^x == e'(pk, H(msg))^x (do miller loop for two sides without final exponentiation)
        // <=> check e'(g1, sig)^-x * e'(pk, H(msg))^x = 1
        // <=> check e'(-g1, sig)^x * e'(pk, H(msg))^x = 1
        let prod = ark_ec::bls12::Bls12::<BLSSigCurveConfig>::multi_pairing(
            [-params.g1_generator, public_key.pub_key],
            [signature.signature, hashed_message],
        );

        prod == PairingOutput::ZERO
    }

    #[must_use]
    pub fn aggregate_verify(
        message: &[u8],
        aggregate_signature: &Self,
        public_keys: &[PublicKey],
        params: &Parameters,
    ) -> Option<bool> {
        if public_keys.is_empty() {
            return None;
        }

        let pk = public_keys
            .iter()
            .skip(1)
            .fold(public_keys[0].clone(), |acc, new_pk| PublicKey {
                pub_key: acc.pub_key + new_pk.pub_key,
            });

        Some(Self::verify_slow(message, aggregate_signature, &pk, params))
    }
}
