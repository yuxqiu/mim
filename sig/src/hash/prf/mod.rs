#![allow(clippy::upper_case_acronyms)]
use ark_crypto_primitives::Error;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{fmt::Debug, hash::Hash};

pub mod blake2s;
pub mod constraints;

pub trait PRF {
    type Input: CanonicalDeserialize + Default;
    type Output: CanonicalSerialize + Eq + Clone + Debug + Default + Hash;

    fn evaluate(input: &Self::Input) -> Result<Self::Output, Error>;
}
