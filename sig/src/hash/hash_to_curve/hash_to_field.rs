use std::marker::PhantomData;

use ark_crypto_primitives::prf::{PRFGadget, PRF};
use ark_ff::{Field, PrimeField};
use ark_r1cs_std::{fields::FieldVar, prelude::ToBytesGadget, uint8::UInt8};
use arrayvec::ArrayVec;
use std::ops::BitXor;

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

// From `ark-ff-0.5.0/src/fields/field_hashers/expander/mod.rs`
const MAX_DST_LENGTH: usize = 255;
const LONG_DST_PREFIX: &[u8; 17] = b"H2C-OVERSIZE-DST-";

pub struct DSTGadget<F: PrimeField>(ArrayVec<UInt8<F>, MAX_DST_LENGTH>);

impl<F: PrimeField> DSTGadget<F> {
    pub fn new_xmd<H: PRFGadget<P, F>, P: PRF>(dst: &[UInt8<F>]) -> Self {
        let array = if dst.len() > MAX_DST_LENGTH {
            let long_dst_prefix = LONG_DST_PREFIX.map(|value| UInt8::constant(value));
            let msg: Vec<UInt8<F>> = long_dst_prefix.iter().chain(dst.iter()).cloned().collect();
            let out = H::evaluate(&msg).unwrap().to_bytes_le().unwrap();
            ArrayVec::try_from(&out[..]).unwrap()
        } else {
            ArrayVec::try_from(dst).unwrap()
        };
        DSTGadget(array)
    }

    pub fn get_update(&self) -> ArrayVec<UInt8<F>, MAX_DST_LENGTH> {
        // I2OSP(len,1) https://www.rfc-editor.org/rfc/rfc8017.txt
        let mut val = self.0.clone();
        val.push(UInt8::constant(self.0.len() as u8));
        val
    }
}

// Implement expander as it is in corresponding implementation in expander::ExpanderXmd
struct ExpanderXmdGadget<H: PRFGadget<P, F>, P: PRF, F: PrimeField> {
    hasher: PhantomData<(H, P)>,
    dst: Vec<UInt8<F>>,
    block_size: usize,
}

impl<H: PRFGadget<P, F>, P: PRF, F: PrimeField> ExpanderXmdGadget<H, P, F> {
    fn expand(&self, msg: &[UInt8<F>], n: usize) -> Vec<UInt8<F>> {
        // output size of the hash function, e.g. 32 bytes = 256 bits for sha2::Sha256
        let b_len = H::OUTPUT_SIZE;
        let ell = (n + (b_len - 1)) / b_len;
        assert!(
            ell <= 255,
            "The ratio of desired output to the output size of hash function is too large!"
        );

        // Represent `len_in_bytes` as a 2-byte array.
        // As per I2OSP method outlined in https://tools.ietf.org/pdf/rfc8017.pdf,
        // The program should abort if integer that we're trying to convert is too large.
        assert!(n < (1 << 16), "Length should be smaller than 2^16");
        let lib_str: [u8; 2] = (n as u16).to_be_bytes();

        let dst_prime = DSTGadget::<F>::new_xmd::<H, P>(&self.dst);

        let msg_bytes: Vec<UInt8<F>> = [0u8; 256][0..self.block_size]
            .iter()
            .map(|b| UInt8::constant(*b))
            .chain(msg.iter().cloned())
            .chain(lib_str.iter().map(|b| UInt8::constant(*b)))
            .chain(std::iter::once(UInt8::constant(0u8)))
            .chain(dst_prime.get_update())
            .collect();
        let b0 = H::evaluate(&msg_bytes).unwrap();

        let msg_prime_bytes: Vec<UInt8<F>> = b0
            .to_bytes_le()
            .unwrap()
            .into_iter()
            .chain(std::iter::once(UInt8::constant(1u8)))
            .chain(dst_prime.get_update())
            .collect();
        let mut bi = H::evaluate(&msg_prime_bytes)
            .unwrap()
            .to_bytes_le()
            .unwrap();

        let b0 = b0.to_bytes_le().unwrap();
        let mut uniform_bytes: Vec<UInt8<F>> = Vec::with_capacity(n);
        uniform_bytes.extend_from_slice(&bi);
        for i in 2..=ell {
            // update the hasher with xor of b_0 and b_i elements
            let msg_prime_bytes: Vec<UInt8<F>> = b0
                .iter()
                .zip(bi.iter())
                .map(|(l, r)| l.bitxor(r))
                .chain(std::iter::once(UInt8::constant(i as u8)))
                .chain(dst_prime.get_update())
                .collect();
            bi = H::evaluate(&msg_prime_bytes)
                .unwrap()
                .to_bytes_le()
                .unwrap();
            uniform_bytes.extend_from_slice(&bi);
        }

        uniform_bytes.truncate(n);
        uniform_bytes
    }
}

/// This function computes the length in bytes that a hash function should output
/// for hashing an element of type `Field`.
/// See section 5.1 and 5.3 of the
/// [IETF hash standardization draft](https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/14/)]
///
/// Copied from `ark-ff-0.5.0/src/fields/field_hashers/mod.rs`
const fn get_len_per_elem<F: Field, const SEC_PARAM: usize>() -> usize {
    // ceil(log(p))
    let base_field_size_in_bits = F::BasePrimeField::MODULUS_BIT_SIZE as usize;
    // ceil(log(p)) + security_parameter
    let base_field_size_with_security_padding_in_bits = base_field_size_in_bits + SEC_PARAM;
    // ceil( (ceil(log(p)) + security_parameter) / 8)
    let bytes_per_base_field_elem =
        ((base_field_size_with_security_padding_in_bits + 7) / 8) as u64;
    bytes_per_base_field_elem as usize
}

// Work on CF => Follow `le_bits_to_fp` without `enforce_in_field_le` as we are doing mod arithmetic
// - In this process, construct EmulatedFpVar<TF::BasePrimeField, CF>
//
// How to construct EmulatedFpVar<TF, CF> from EmulatedFpVar<TF::BasePrimeField, CF> is a problem
// - Add a method to quadext and cubic ext to construct from base prime field variable
//
// struct DefaultFieldHasherGadget<P: PRF, TF: Field, CF: PrimeField, FP: FieldVar<TF, CF>> {
//     expander: ExpanderXmdGadget<PRFGadget<P, TF>>,
//     len_per_base_elem: usize,
// }

#[cfg(test)]
mod test {
    use std::marker::PhantomData;

    use ark_crypto_primitives::prf::{blake2s::constraints::Blake2sGadget, Blake2s};
    use ark_ff::field_hashers::{Expander, ExpanderXmd};
    use ark_r1cs_std::{uint8::UInt8, R1CSVar};
    use blake2::{digest::Update, Blake2s256, Digest};
    use rand::{thread_rng, Rng};

    use crate::hash::hash_to_curve::hash_to_field::{get_len_per_elem, ExpanderXmdGadget};

    // This function is to validate how blake2 hash works.
    // So, I can implement the corresponding R1CS version.
    #[test]
    fn test_blake_update() {
        let mut rng = thread_rng();
        let mut a: [u8; 6] = [0; 6];
        let mut b: [u8; 6] = [0; 6];
        rng.fill(&mut a[..]);
        rng.fill(&mut b[..]);
        let c: Vec<_> = a.iter().chain(b.iter()).copied().collect();

        let mut hasher = blake2::Blake2s256::default();
        Update::update(&mut hasher, &a);
        Update::update(&mut hasher, &b);
        let s1 = hasher.finalize();

        let mut hasher2 = blake2::Blake2s256::default();
        Update::update(&mut hasher2, &c);
        let s2 = hasher2.finalize();

        assert!(s1 == s2);
    }

    #[test]
    fn test_expander() {
        use ark_bls12_381::Fr as F;

        let mut rng = thread_rng();
        let mut msg: [u8; 64] = [0; 64];
        rng.fill(&mut msg[..]);
        let msg_var: Vec<UInt8<F>> = msg.iter().map(|byte| UInt8::constant(*byte)).collect();

        let len_per_base_elem = get_len_per_elem::<F, 128>();
        let dst: [u8; 16] = [0; 16];
        let len_in_bytes = 16usize;

        let expander: ExpanderXmd<Blake2s256> = ExpanderXmd {
            hasher: PhantomData,
            dst: dst.to_vec(),
            block_size: len_per_base_elem,
        };
        let s1 = expander.expand(&msg, len_in_bytes);

        let hasher: PhantomData<(Blake2sGadget, Blake2s)> = PhantomData;
        let expander = ExpanderXmdGadget {
            hasher: hasher,
            dst: dst
                .to_vec()
                .iter()
                .map(|value| UInt8::constant(*value))
                .collect(),
            block_size: len_per_base_elem,
        };
        let s2 = expander.expand(&msg_var, len_in_bytes);

        assert!(
            s1 == s2
                .iter()
                .map(|value| value.value().unwrap())
                .collect::<Vec<u8>>()
        );
    }
}
