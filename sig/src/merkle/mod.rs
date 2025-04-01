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

#[inline]
pub(crate) const fn is_left_node(index: usize) -> bool {
    index & 1 == 1
}

#[inline]
pub(crate) const fn parent(index: usize) -> usize {
    (index - 1) / 2
}

#[inline]
pub(crate) const fn left(index: usize) -> usize {
    2 * index + 1
}

#[inline]
pub(crate) const fn right(index: usize) -> usize {
    2 * index + 2
}
