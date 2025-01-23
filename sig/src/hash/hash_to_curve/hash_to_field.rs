use ark_ff::{Field, PrimeField};
use ark_r1cs_std::{fields::FieldVar, uint8::UInt8};

pub trait HashToFieldGadget<TF: Field, CF: PrimeField, FP: FieldVar<TF, CF>>: Sized {
    /// Initialises a new hash-to-field helper struct.
    ///
    /// # Arguments
    ///
    /// * `domain` - bytes that get concatenated with the `msg` during hashing, in order to separate potentially interfering instantiations of the hasher.
    fn new(domain: &[u8]) -> Self;

    /// Hash an arbitrary `msg` to `N` elements of the field `F`.
    fn hash_to_field<const N: usize>(&self, msg: &[UInt8<CF>]) -> [FP; N];
}
