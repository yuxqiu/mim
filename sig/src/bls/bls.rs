use std::ops::Mul;

use ark_bls12_381::{
    g1::{G1_GENERATOR_X, G1_GENERATOR_Y},
    g2::{G2_GENERATOR_X, G2_GENERATOR_Y},
    Fr, G1Affine, G1Projective, G2Affine, G2Projective,
};
use ark_ec::{
    bls12,
    hashing::{curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher, HashToCurve},
    pairing::Pairing,
};
use ark_ff::{field_hashers::DefaultFieldHasher, UniformRand};
use ark_std::rand::Rng;
use blake2::Blake2s256;

type G1 = G1Projective;
type G2 = G2Projective;

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
    pub secret_key: Fr,
}

#[derive(Clone)]
pub struct Signature {
    pub signature: G2,
}

impl Parameters {
    pub fn setup() -> Self {
        Parameters {
            g1_generator: G1Affine::new_unchecked(G1_GENERATOR_X, G1_GENERATOR_Y).into(),
            g2_generator: G2Affine::new_unchecked(G2_GENERATOR_X, G2_GENERATOR_Y).into(),
        }
    }
}

impl PublicKey {
    pub fn new(secret_key: &SecretKey, params: &Parameters) -> Self {
        let pub_key = params.g1_generator.mul(secret_key.secret_key).into();
        Self { pub_key }
    }
}

impl SecretKey {
    pub fn new<R: Rng>(rng: &mut R) -> Self {
        let secret_key = Fr::rand(rng);
        Self { secret_key }
    }
}

impl Signature {
    fn hash_to_curve(message: &[u8]) -> G2 {
        // safety
        type FieldHasher = DefaultFieldHasher<Blake2s256, 128>;
        type CurveMap = WBMap<ark_bls12_381::g2::Config>;
        let hasher: MapToCurveBasedHasher<G2Projective, FieldHasher, CurveMap> =
            MapToCurveBasedHasher::new(&[]).unwrap();
        let hashed_message: G2Affine = hasher.hash(message).unwrap();

        hashed_message.into()
    }

    pub fn sign(message: &[u8], secret_key: &SecretKey, _: &Parameters) -> Self {
        let hashed_message = Signature::hash_to_curve(message);
        let signature = hashed_message.mul(secret_key.secret_key);
        Self { signature }
    }

    pub fn aggregate_sign(
        message: &[u8],
        secret_keys: &[SecretKey],
        params: &Parameters,
    ) -> Option<Signature> {
        if secret_keys.is_empty() {
            return None;
        }

        let mut secret_key = secret_keys[0].clone();
        secret_keys
            .iter()
            .skip(1)
            .for_each(|sk| secret_key.secret_key += sk.secret_key);

        Some(Signature::sign(message, &secret_key, params))
    }

    pub fn verify(
        message: &[u8],
        signature: &Signature,
        public_key: &PublicKey,
        params: &Parameters,
    ) -> bool {
        let hashed_message = Signature::hash_to_curve(message);

        // Check pairing equation: e(g1, sig) == e(pk, H(msg))
        let pairing_1 = bls12::Bls12::<ark_bls12_381::Config>::pairing(
            params.g1_generator,
            signature.signature,
        );
        let pairing_2 = ark_ec::bls12::Bls12::<ark_bls12_381::Config>::pairing(
            public_key.pub_key,
            hashed_message,
        );

        pairing_1 == pairing_2
    }

    pub fn aggregate_verify(
        message: &[u8],
        aggregate_signature: &Signature,
        public_keys: &[PublicKey],
        params: &Parameters,
    ) -> Option<bool> {
        if public_keys.is_empty() {
            return None;
        }

        let mut public_key = public_keys[0].clone();
        public_keys
            .iter()
            .skip(1)
            .for_each(|pk| public_key.pub_key += pk.pub_key);

        Some(Signature::verify(
            message,
            aggregate_signature,
            &public_key,
            params,
        ))
    }
}
