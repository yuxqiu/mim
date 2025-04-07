use core::ops::Mul;

use ark_ec::{
    bls12::{self, Bls12Config},
    hashing::{
        curve_maps::wb::{WBConfig, WBMap},
        map_to_curve_hasher::MapToCurveBasedHasher,
        HashToCurve,
    },
    pairing::{Pairing, PairingOutput},
    short_weierstrass::SWCurveConfig,
};
use ark_ff::{field_hashers::DefaultFieldHasher, AdditiveGroup, UniformRand};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use blake2::Blake2s256;
use derivative::Derivative;
use derive_more::{AsRef, From, Into};
use gen_ops::gen_ops_ex;
use rand::Rng;

use crate::bls::params::{HashCurveConfig, HashCurveGroup};

use super::params::{SecretKeyScalarField, G1, G2};

#[derive(Derivative, CanonicalSerialize, CanonicalDeserialize)]
#[derivative(
    Clone(bound = ""),
    Copy(bound = ""),
    Debug(bound = ""),
    Default(bound = "")
)]
pub struct Parameters<SigCurveConfig: Bls12Config> {
    pub g1_generator: G1<SigCurveConfig>,
    pub g2_generator: G2<SigCurveConfig>,
}

#[derive(Derivative, CanonicalSerialize, CanonicalDeserialize, From, Into, AsRef)]
#[derivative(
    Clone(bound = ""),
    Copy(bound = ""),
    Debug(bound = ""),
    Default(bound = "")
)]
pub struct PublicKey<SigCurveConfig: Bls12Config> {
    pub_key: G1<SigCurveConfig>,
}

#[derive(Derivative, CanonicalSerialize, CanonicalDeserialize)]
#[derivative(
    Clone(bound = ""),
    Copy(bound = ""),
    Debug(bound = ""),
    Default(bound = "")
)]
pub struct SecretKey<SigCurveConfig: Bls12Config> {
    secret_key: SecretKeyScalarField<SigCurveConfig>,
}

#[derive(Derivative, CanonicalSerialize, CanonicalDeserialize, From, Into, AsRef)]
#[derivative(
    Clone(bound = ""),
    Copy(bound = ""),
    Debug(bound = ""),
    Default(bound = "")
)]
pub struct Signature<SigCurveConfig: Bls12Config> {
    signature: G2<SigCurveConfig>,
}

gen_ops_ex!(
    <SigCurveConfig>;
    types mut PublicKey<SigCurveConfig>, mut PublicKey<SigCurveConfig> => PublicKey<SigCurveConfig>;
    for + call |a: &PublicKey<SigCurveConfig>, b: &PublicKey<SigCurveConfig>| {
        (a.pub_key + b.pub_key).into()
    };
    where SigCurveConfig: Bls12Config
);

gen_ops_ex!(
    <SigCurveConfig>;
    types mut SecretKey<SigCurveConfig>, mut SecretKey<SigCurveConfig> => SecretKey<SigCurveConfig>;
    for + call |a: &SecretKey<SigCurveConfig>, b: &SecretKey<SigCurveConfig>| {
        SecretKey {
            secret_key: a.secret_key + b.secret_key,
        }
    };
    where SigCurveConfig: Bls12Config
);

gen_ops_ex!(
    <SigCurveConfig>;
    types mut Signature<SigCurveConfig>, mut Signature<SigCurveConfig> => Signature<SigCurveConfig>;
    for + call |a: &Signature<SigCurveConfig>, b: &Signature<SigCurveConfig>| {
        (a.signature + b.signature).into()
    };
    where SigCurveConfig: Bls12Config
);

impl<SigCurveConfig: Bls12Config> Parameters<SigCurveConfig> {
    #[must_use]
    pub fn setup() -> Self {
        Self {
            g1_generator: <<SigCurveConfig as Bls12Config>::G1Config as SWCurveConfig>::GENERATOR
                .into(),
            g2_generator: <<SigCurveConfig as Bls12Config>::G2Config as SWCurveConfig>::GENERATOR
                .into(),
        }
    }
}

impl<SigCurveConfig: Bls12Config> PublicKey<SigCurveConfig> {
    #[must_use]
    pub fn new(
        secret_key: &SecretKey<SigCurveConfig>,
        params: &Parameters<SigCurveConfig>,
    ) -> Self {
        let pub_key = params.g1_generator.mul(secret_key.secret_key);
        pub_key.into()
    }
}

impl<SigCurveConfig: Bls12Config> SecretKey<SigCurveConfig> {
    pub fn new<R: Rng>(rng: &mut R) -> Self {
        let secret_key = SecretKeyScalarField::<SigCurveConfig>::rand(rng);
        Self { secret_key }
    }
}

impl<SigCurveConfig: Bls12Config> Signature<SigCurveConfig>
where
    <SigCurveConfig as Bls12Config>::G2Config: WBConfig,
{
    fn hash_to_curve(message: &[u8]) -> G2<SigCurveConfig> {
        // safety
        type FieldHasher = DefaultFieldHasher<Blake2s256, 128>;
        type CurveMap<SigCurveConfig> = WBMap<HashCurveConfig<SigCurveConfig>>;
        let hasher: MapToCurveBasedHasher<
            HashCurveGroup<SigCurveConfig>,
            FieldHasher,
            CurveMap<SigCurveConfig>,
        > = MapToCurveBasedHasher::new(&[]).expect("BLS12 curve supports hash to curve");
        let hashed_message = hasher.hash(message).unwrap();

        hashed_message.into()
    }

    #[must_use]
    pub fn sign(
        message: &[u8],
        secret_key: &SecretKey<SigCurveConfig>,
        _: &Parameters<SigCurveConfig>,
    ) -> Self {
        let hashed_message = Self::hash_to_curve(message);
        let signature = hashed_message.mul(secret_key.secret_key);
        signature.into()
    }

    #[must_use]
    pub fn aggregate_sign(
        message: &[u8],
        secret_keys: &[SecretKey<SigCurveConfig>],
        params: &Parameters<SigCurveConfig>,
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

        Some(sigs.fold(first_sig, |acc, new_sig| acc + new_sig))
    }

    #[must_use]
    pub fn verify_slow(
        message: &[u8],
        signature: &Self,
        public_key: &PublicKey<SigCurveConfig>,
        params: &Parameters<SigCurveConfig>,
    ) -> bool {
        let hashed_message = Self::hash_to_curve(message);

        // a naive way to check pairing equation: e(g1, sig) == e(pk, H(msg))
        let pairing_1 =
            bls12::Bls12::<SigCurveConfig>::pairing(params.g1_generator, signature.signature);
        let pairing_2 =
            ark_ec::bls12::Bls12::<SigCurveConfig>::pairing(public_key.pub_key, hashed_message);

        pairing_1 == pairing_2
    }

    #[must_use]
    pub fn verify(
        message: &[u8],
        signature: &Self,
        public_key: &PublicKey<SigCurveConfig>,
        params: &Parameters<SigCurveConfig>,
    ) -> bool {
        let hashed_message = Self::hash_to_curve(message);

        // an optimized way to check pairing equation: e(g1, sig) == e(pk, H(msg))
        //
        // e'(g1, sig)^x == e'(pk, H(msg))^x (do miller loop for two sides without final exponentiation)
        // <=> check e'(g1, sig)^-x * e'(pk, H(msg))^x = 1
        // <=> check e'(-g1, sig)^x * e'(pk, H(msg))^x = 1
        let prod = ark_ec::bls12::Bls12::<SigCurveConfig>::multi_pairing(
            [-params.g1_generator, public_key.pub_key],
            [signature.signature, hashed_message],
        );

        prod == PairingOutput::ZERO
    }

    #[must_use]
    pub fn aggregate_verify(
        message: &[u8],
        aggregate_signature: &Self,
        public_keys: &[PublicKey<SigCurveConfig>],
        params: &Parameters<SigCurveConfig>,
    ) -> Option<bool> {
        if public_keys.is_empty() {
            return None;
        }

        let public_key_0 = *public_keys.first()?;
        let pk = public_keys
            .iter()
            .skip(1)
            .fold(public_key_0, |acc, new_pk| PublicKey {
                pub_key: acc.pub_key + new_pk.pub_key,
            });

        Some(Self::verify_slow(message, aggregate_signature, &pk, params))
    }
}

#[cfg(test)]
mod test {
    use crate::bls::{get_aggregate_bls_instance, get_bls_instance};

    use super::*;

    #[test]
    fn check_signature() {
        let (msg, params, _, pk, sig) = get_bls_instance::<ark_bls12_381::Config>();
        assert!(Signature::verify_slow(msg.as_bytes(), &sig, &pk, &params));
        assert!(Signature::verify(msg.as_bytes(), &sig, &pk, &params));
    }

    #[test]
    fn check_verify_failure() {
        let (msg, params, _, pk, sig) = get_bls_instance::<ark_bls12_381::Config>();
        assert!(!Signature::verify_slow(
            &[msg.as_bytes(), &[1]].concat(),
            &sig,
            &pk,
            &params
        ));
        assert!(!Signature::verify(
            &[msg.as_bytes(), &[1]].concat(),
            &sig,
            &pk,
            &params
        ));
    }

    #[test]
    fn check_aggregate_signature() {
        let (msg, params, _, public_keys, sig) =
            get_aggregate_bls_instance::<ark_bls12_381::Config>();
        assert!(Signature::aggregate_verify(msg.as_bytes(), &sig, &public_keys, &params).unwrap());
    }
}
