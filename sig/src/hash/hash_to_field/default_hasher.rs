use std::marker::PhantomData;

use super::{expander::ExpanderXmdGadget, HashToFieldGadget};
use ark_crypto_primitives::prf::{PRFGadget, PRF};
use ark_ff::{field_hashers::get_len_per_elem, Field, PrimeField};
use ark_r1cs_std::{fields::FieldVar, uint8::UInt8};
use ark_relations::r1cs::SynthesisError;

// Work on CF => Follow `le_bits_to_fp` without `enforce_in_field_le` as we are doing mod arithmetic
// - In this process, construct EmulatedFpVar<TF::BasePrimeField, CF>
//
// How to construct EmulatedFpVar<TF, CF> from EmulatedFpVar<TF::BasePrimeField, CF> is a problem
// - Add a method to quadext and cubic ext to construct from base prime field variable
struct DefaultFieldHasherGadget<
    H: PRFGadget<P, CF> + Default,
    P: PRF,
    TF: Field,
    CF: PrimeField,
    FP: FieldVar<TF, CF>,
    const SEC_PARAM: usize = 128,
> {
    expander: ExpanderXmdGadget<H, P, CF>,
    len_per_base_elem: usize,
    _params: PhantomData<(TF, FP)>,
}

impl<
        H: PRFGadget<P, CF> + Default,
        P: PRF,
        TF: Field,
        CF: PrimeField,
        FP: FieldVar<TF, CF>,
        const SEC_PARAM: usize,
    > HashToFieldGadget<TF, CF, FP> for DefaultFieldHasherGadget<H, P, TF, CF, FP, SEC_PARAM>
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
        /*
        let m = F::extension_degree() as usize;

        // The user requests `N` of elements of F_p^m to output per input msg,
        // each field element comprising `m` BasePrimeField elements.
        let len_in_bytes = N * m * self.len_per_base_elem;
        let uniform_bytes = self.expander.expand(message, len_in_bytes);

        let cb = |i| {
            let base_prime_field_elem = |j| {
                let elm_offset = self.len_per_base_elem * (j + i * m);
                F::BasePrimeField::from_be_bytes_mod_order(
                    &uniform_bytes[elm_offset..][..self.len_per_base_elem],
                )
            };
            F::from_base_prime_field_elems((0..m).map(base_prime_field_elem)).unwrap()
        };
        ark_std::array::from_fn::<F, N, _>(cb)
        */
        let m = TF::extension_degree() as usize;

        // The user requests `N` of elements of F_p^m to output per input msg,
        // each field element comprising `m` BasePrimeField elements.
        let len_in_bytes = N * m * self.len_per_base_elem;
        let uniform_bytes = self.expander.expand(msg, len_in_bytes)?;

        // let mut result = [FP::zero(); N];

        // let cb = |i| {
        //     let base_prime_field_elem = |j| {
        //         let elm_offset = self.len_per_base_elem * (j + i * m);
        //         F::BasePrimeField::from_be_bytes_mod_order(
        //             &uniform_bytes[elm_offset..][..self.len_per_base_elem],
        //         )
        //     };
        //     F::from_base_prime_field_elems((0..m).map(base_prime_field_elem)).unwrap()
        // };

        // for i in 0..N {
        //     let mut base_prime_field_elems = Vec::with_capacity(m);
        //     for j in 0..m {
        //         let elm_offset = self.len_per_base_elem * (j + i * m);
        //         let bytes: Vec<_> = uniform_bytes[elm_offset..][..self.len_per_base_elem]
        //             .iter()
        //             .map(|byte| byte.value().unwrap())
        //             .collect();
        //         let base_prime_field_elem = TF::BasePrimeField::from_be_bytes_mod_order(&bytes);
        //         base_prime_field_elems
        //             .push(FP::BasePrimeFieldVar::new_constant(base_prime_field_elem)?);
        //     }
        //     // result[i] = FP::from_base_prime_field_elems(&base_prime_field_elems)?;
        // }

        // result

        todo!()
    }
}
