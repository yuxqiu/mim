use core::marker::PhantomData;

use super::{
    expander::ExpanderXmdGadget, from_base_field::FromBaseFieldGadget,
    from_base_field::FromBitsGadget, HashToFieldGadget,
};
use ark_crypto_primitives::prf::PRFGadget;
use ark_ff::{field_hashers::get_len_per_elem, Field, PrimeField};
use ark_r1cs_std::{fields::FieldVar, prelude::ToBitsGadget, uint8::UInt8};
use ark_relations::r1cs::SynthesisError;

/// This struct implements R1CS equivalent of `DefaultFieldHasher`. It works as follow
/// - Use `ExpanderGadget` to derive a vector of uniform bytes
/// - Construct a vector of `FpVar` or `EmulatedFpVar` based on the type of `BasePrimeFieldVar`
///   (defined in `FromBaseFieldGadget` trait, and the method to construct them from bits is
///   defined in `FromBitsGadget` trait)
/// - Recursively construct target field element based on a vector of corresponding
///   `BasePrimeFieldVar` elements (the method to construct them from bits is defined in
///   `FromBaseFieldGadget` trait))
pub struct DefaultFieldHasherGadget<
    H: PRFGadget<CF> + Default,
    TF: Field,
    CF: PrimeField,
    FP: FieldVar<TF, CF>,
    const SEC_PARAM: usize = 128,
> {
    expander: ExpanderXmdGadget<H, CF>,
    len_per_base_elem: usize,
    _params: PhantomData<(TF, FP)>,
}

impl<
        H: PRFGadget<CF> + Default,
        TF: Field,
        CF: PrimeField,
        FP: FieldVar<TF, CF> + FromBaseFieldGadget<CF>,
        const SEC_PARAM: usize,
    > HashToFieldGadget<TF, CF, FP> for DefaultFieldHasherGadget<H, TF, CF, FP, SEC_PARAM>
{
    fn new(domain: &[UInt8<CF>]) -> Self {
        // The final output of `hash_to_field` will be an array of field
        // elements from F::BaseField, each of size `len_per_elem`.
        let len_per_base_elem = get_len_per_elem::<TF, SEC_PARAM>();

        let expander = ExpanderXmdGadget {
            hasher: PhantomData,
            dst: domain.to_vec(),
            block_size: len_per_base_elem,
        };

        Self {
            expander,
            len_per_base_elem,
            _params: PhantomData,
        }
    }

    fn hash_to_field<const N: usize>(&self, msg: &[UInt8<CF>]) -> Result<[FP; N], SynthesisError> {
        let m = usize::try_from(TF::extension_degree())
            .expect("extension degree should be able to store in usize");

        // The user requests `N` of elements of F_p^m to output per input msg,
        // each field element comprising `m` BasePrimeField elements.
        let len_in_bytes = N * m * self.len_per_base_elem;
        let uniform_bytes = self.expander.expand(msg, len_in_bytes)?;

        // collect this first to deal with the error
        let bits_iter: Vec<_> = uniform_bytes
            .chunks(self.len_per_base_elem)
            .map(|chunk| {
                let mut chunk = chunk.to_vec();
                chunk.reverse();
                chunk.to_bits_le()
            })
            .collect::<Result<_, _>>()?;

        let mut base_field_var_iter = bits_iter
            .into_iter()
            .map(|bits| FP::BasePrimeFieldVar::from_le_bits(&bits));

        // can replace this with `array::try_from` once it becomes stable
        let f = |_| FP::from_base_prime_field_var(&mut base_field_var_iter);
        array_util::try_from_fn::<Result<FP, SynthesisError>, N, _>(f)
    }
}

#[cfg(test)]
mod test {
    use ark_crypto_primitives::prf::blake2s::constraints::Blake2sGadget;
    use ark_ff::field_hashers::{DefaultFieldHasher, HashToField};
    use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, uint8::UInt8, R1CSVar};
    use ark_relations::r1cs::ConstraintSystem;
    use blake2::Blake2s256;
    use rand::{thread_rng, Rng};

    use crate::hash::hash_to_field::{default_hasher::DefaultFieldHasherGadget, HashToFieldGadget};

    #[test]
    fn test_hash_to_field_constant() {
        use ark_bls12_381::Fr as F;

        let mut rng = thread_rng();

        let dst: [u8; 16] = [0; 16];
        let dst_var: [UInt8<F>; 16] = dst.map(UInt8::constant);

        let hasher = <DefaultFieldHasher<Blake2s256, 128> as HashToField<F>>::new(&dst);
        let hasher_gadget =
            DefaultFieldHasherGadget::<Blake2sGadget<F>, F, F, FpVar<F>, 128>::new(&dst_var);

        let input_lens = (0..32).chain(32..256).filter(|a| a % 8 == 0);

        for input_len in input_lens {
            let mut msg = vec![0u8; input_len];
            rng.fill(&mut *msg);
            let msg_var: Vec<UInt8<F>> = msg.iter().map(|byte| UInt8::constant(*byte)).collect();

            let s1: [F; 2] = hasher.hash_to_field::<2>(&msg);
            let s2: [FpVar<F>; 2] = hasher_gadget.hash_to_field::<2>(&msg_var).unwrap();

            assert!(
                s1.to_vec()
                    == s2
                        .iter()
                        .map(|value| value.value().unwrap())
                        .collect::<Vec<F>>()
            );
        }
    }

    #[test]
    fn test_hash_to_field() {
        use ark_bls12_381::Fr as F;

        let mut rng = thread_rng();

        let dst: [u8; 16] = [0; 16];
        let dst_var: [UInt8<F>; 16] = dst.map(UInt8::constant);

        let hasher = <DefaultFieldHasher<Blake2s256, 128> as HashToField<F>>::new(&dst);
        let hasher_gadget =
            DefaultFieldHasherGadget::<Blake2sGadget<F>, F, F, FpVar<F>, 128>::new(&dst_var);

        let input_lens = (0..32).chain(32..128).filter(|a| a % 16 == 0);

        for input_len in input_lens {
            let cs = ConstraintSystem::new_ref();
            let mut msg = vec![0u8; input_len];
            rng.fill(&mut *msg);
            let msg_var: Vec<UInt8<F>> = msg
                .iter()
                .map(|byte| UInt8::new_witness(cs.clone(), || Ok(*byte)).unwrap())
                .collect();

            let s1: [F; 2] = hasher.hash_to_field::<2>(&msg);
            let s2: [FpVar<F>; 2] = hasher_gadget.hash_to_field::<2>(&msg_var).unwrap();

            assert!(
                s1.to_vec()
                    == s2
                        .iter()
                        .map(|value| value.value().unwrap())
                        .collect::<Vec<F>>()
            );
        }
    }
}
