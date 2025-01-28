use ark_crypto_primitives::prf::PRFGadget;
use ark_ff::{
    field_hashers::expander::{LONG_DST_PREFIX, MAX_DST_LENGTH, Z_PAD},
    PrimeField,
};
use ark_r1cs_std::{prelude::ToBytesGadget, uint8::UInt8};
use ark_relations::r1cs::SynthesisError;
use arrayvec::ArrayVec;
use core::{marker::PhantomData, ops::BitXor};

struct DSTGadget<F: PrimeField>(ArrayVec<UInt8<F>, MAX_DST_LENGTH>);

impl<F: PrimeField> DSTGadget<F> {
    pub fn new_xmd<H: PRFGadget<F> + Default>(dst: &[UInt8<F>]) -> Result<Self, SynthesisError> {
        let array = if dst.len() > MAX_DST_LENGTH {
            let mut hasher = H::default();
            let long_dst_prefix = LONG_DST_PREFIX.map(|value| UInt8::constant(value));
            hasher.update(&long_dst_prefix)?;
            hasher.update(dst)?;
            let out = hasher.finalize()?.to_bytes_le()?;
            ArrayVec::try_from(&*out).expect(
                "supplied hash function should produce an output with length smaller than 255",
            )
        } else {
            ArrayVec::try_from(dst).expect(
                "supplied hash function should produce an output with length smaller than 255",
            )
        };

        Ok(Self(array))
    }

    pub fn get_update(&self) -> ArrayVec<UInt8<F>, MAX_DST_LENGTH> {
        // I2OSP(len,1) https://www.rfc-editor.org/rfc/rfc8017.txt
        let mut val = self.0.clone();
        // self.0.len() is guaranteed to be smaller than MAX_DST_LENGTH (255)
        #[expect(clippy::cast_possible_truncation)]
        val.push(UInt8::constant(self.0.len() as u8));
        val
    }
}

// Implement expander as it is in corresponding implementation in expander::ExpanderXmd
pub struct ExpanderXmdGadget<H: PRFGadget<F> + Default, F: PrimeField> {
    pub hasher: PhantomData<H>,
    pub dst: Vec<UInt8<F>>,
    pub block_size: usize,
}

impl<H: PRFGadget<F> + Default, F: PrimeField> ExpanderXmdGadget<H, F> {
    pub fn expand(&self, msg: &[UInt8<F>], n: usize) -> Result<Vec<UInt8<F>>, SynthesisError> {
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
        #[expect(clippy::cast_possible_truncation)]
        let lib_str: [u8; 2] = (n as u16).to_be_bytes();

        let dst_prime_data = DSTGadget::<F>::new_xmd::<H>(&self.dst)?.get_update();

        let mut hasher = H::default();
        hasher.update(
            &Z_PAD[0..self.block_size]
                .iter()
                .map(|b| UInt8::constant(*b))
                .collect::<Vec<_>>(),
        )?;
        hasher.update(msg)?;
        hasher.update(
            &lib_str
                .iter()
                .map(|b| UInt8::constant(*b))
                .collect::<Vec<_>>(),
        )?;
        hasher.update(&[UInt8::constant(0u8)])?;
        hasher.update(&dst_prime_data)?;
        let b0 = hasher.finalize()?.to_bytes_le()?;

        let mut hasher = H::default();
        hasher.update(&b0)?;
        hasher.update(&[UInt8::constant(1u8)])?;
        hasher.update(&dst_prime_data)?;
        let mut bi = hasher.finalize()?.to_bytes_le()?;

        let mut uniform_bytes: Vec<UInt8<F>> = Vec::with_capacity(n);
        uniform_bytes.extend_from_slice(&bi);
        for i in 2..=ell {
            // update the hasher with xor of b_0 and b_i elements
            let mut hasher = H::default();
            hasher.update(
                &bi.iter()
                    .zip(&b0)
                    .map(|(l, r)| l.bitxor(r))
                    .collect::<Vec<_>>(),
            )?;
            // i < ell <= 255
            #[expect(clippy::cast_possible_truncation)]
            hasher.update(&[UInt8::constant(i as u8)])?;
            hasher.update(&dst_prime_data)?;
            bi = hasher.finalize()?.to_bytes_le()?;
            uniform_bytes.extend_from_slice(&bi);
        }

        uniform_bytes.truncate(n);
        Ok(uniform_bytes)
    }
}

#[cfg(test)]
mod test {
    use core::marker::PhantomData;

    use ark_crypto_primitives::prf::blake2s::constraints::Blake2sGadget;
    use ark_ff::field_hashers::{
        expander::{Expander, ExpanderXmd},
        get_len_per_elem,
    };
    use ark_r1cs_std::{alloc::AllocVar, uint8::UInt8, R1CSVar};
    use ark_relations::r1cs::ConstraintSystem;
    use blake2::{digest::Update, Blake2s256, Digest};
    use rand::{thread_rng, Rng};

    use super::ExpanderXmdGadget;

    // This function is to validate how blake2 hash works.
    // So, I can implement the corresponding R1CS version.
    #[test]
    fn test_blake_update() {
        let mut rng = thread_rng();
        let mut a: [u8; 6] = [0; 6];
        let mut b: [u8; 6] = [0; 6];
        rng.fill(&mut a);
        rng.fill(&mut b);
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
    fn test_expander_constant() {
        use ark_bls12_381::Fr as F;

        let mut rng = thread_rng();

        let len_per_base_elem = get_len_per_elem::<F, 128>();
        let dst: [u8; 16] = [0; 16];

        let expander: ExpanderXmd<Blake2s256> = ExpanderXmd {
            hasher: PhantomData,
            dst: dst.to_vec(),
            block_size: len_per_base_elem,
        };

        let hasher: PhantomData<Blake2sGadget<F>> = PhantomData;
        let expander_gadget = ExpanderXmdGadget {
            hasher,
            dst: dst
                .to_vec()
                .iter()
                .map(|value| UInt8::constant(*value))
                .collect(),
            block_size: len_per_base_elem,
        };

        let input_lens = (0..32).chain(32..256).filter(|a| a % 8 == 0);
        let expand_len = (1..256).filter(|a| a % 8 == 0);

        for input_len in input_lens {
            for len_in_bytes in expand_len.clone() {
                let mut msg = vec![0u8; input_len];
                rng.fill(&mut *msg);
                let msg_var: Vec<UInt8<F>> = msg.iter().copied().map(UInt8::constant).collect();

                let s1 = expander.expand(&msg, len_in_bytes);
                let s2 = expander_gadget.expand(&msg_var, len_in_bytes).unwrap();

                println!("{input_len} {len_in_bytes}");

                assert!(
                    s1 == s2
                        .iter()
                        .map(|value| value.value().unwrap())
                        .collect::<Vec<u8>>()
                );
            }
        }
    }

    #[test]
    fn test_expander() {
        use ark_bls12_381::Fr as F;

        let mut rng = thread_rng();

        let len_per_base_elem = get_len_per_elem::<F, 128>();
        let dst: [u8; 16] = [0; 16];

        let expander: ExpanderXmd<Blake2s256> = ExpanderXmd {
            hasher: PhantomData,
            dst: dst.to_vec(),
            block_size: len_per_base_elem,
        };

        let hasher: PhantomData<Blake2sGadget<F>> = PhantomData;
        let expander_gadget = ExpanderXmdGadget {
            hasher,
            dst: dst
                .to_vec()
                .iter()
                .map(|value| UInt8::constant(*value))
                .collect(),
            block_size: len_per_base_elem,
        };

        let input_lens = (0..32).chain(32..128).filter(|a| a % 16 == 0);
        let expand_len = (1..64).filter(|a| a % 16 == 0);

        for input_len in input_lens {
            for len_in_bytes in expand_len.clone() {
                let cs = ConstraintSystem::new_ref();
                let mut msg = vec![0u8; input_len];
                rng.fill(&mut *msg);
                let msg_var: Vec<UInt8<F>> = msg
                    .iter()
                    .copied()
                    .map(|value| UInt8::new_witness(cs.clone(), || Ok(value)).unwrap())
                    .collect();

                let s1 = expander.expand(&msg, len_in_bytes);
                let s2 = expander_gadget.expand(&msg_var, len_in_bytes).unwrap();

                println!("{input_len} {len_in_bytes}");

                assert!(cs.is_satisfied().unwrap());
                assert!(
                    s1 == s2
                        .iter()
                        .map(|value| value.value().unwrap())
                        .collect::<Vec<u8>>()
                );
            }
        }
    }
}
