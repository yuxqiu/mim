use std::marker::PhantomData;

use ark_crypto_primitives::sponge::Absorb;
use ark_ff::PrimeField;

pub mod constraints;
pub mod forest;
pub mod tree;

pub trait MerkleConfig {
    type BasePrimeField: PrimeField + Absorb;
}

pub struct Config<CF>(PhantomData<CF>);
impl<CF: PrimeField + Absorb> MerkleConfig for Config<CF> {
    type BasePrimeField = CF;
}
