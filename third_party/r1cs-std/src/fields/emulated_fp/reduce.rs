use super::{overhead, params::get_params, AllocatedEmulatedFpVar};
use crate::{
    alloc::AllocVar,
    boolean::Boolean,
    eq::EqGadget,
    fields::{fp::FpVar, FieldVar},
    R1CSVar,
};
use ark_ff::{biginteger::BigInteger, BitIteratorBE, One, PrimeField, Zero};
use ark_relations::{
    ns,
    r1cs::{ConstraintSystemRef, Result as R1CSResult},
};
use ark_std::{cmp::min, marker::PhantomData, vec, vec::Vec};
use num_bigint::BigUint;
use num_integer::Integer;

pub fn limbs_to_bigint<BaseF: PrimeField>(bits_per_limb: usize, limbs: &[BaseF]) -> BigUint {
    let mut val = BigUint::zero();
    let mut big_cur = BigUint::one();
    let two = BigUint::from(2u32);
    for limb in limbs.iter().rev() {
        let limb_repr = limb.into_bigint().to_bits_le();
        let mut small_cur = big_cur.clone();
        for limb_bit in limb_repr.iter() {
            if *limb_bit {
                val += &small_cur;
            }
            small_cur *= 2u32;
        }
        big_cur *= two.pow(bits_per_limb as u32);
    }

    val
}

pub fn bigint_to_basefield<BaseF: PrimeField>(bigint: &BigUint) -> BaseF {
    let mut val = BaseF::zero();
    let mut cur = BaseF::one();
    let bytes = bigint.to_bytes_be();

    let basefield_256 = BaseF::from_bigint(<BaseF as PrimeField>::BigInt::from(256u64)).unwrap();

    for byte in bytes.iter().rev() {
        let bytes_basefield = BaseF::from(*byte as u128);
        val += cur * bytes_basefield;

        cur *= &basefield_256;
    }

    val
}

/// the collections of methods for reducing the presentations
pub struct Reducer<TargetF: PrimeField, BaseF: PrimeField> {
    pub target_phantom: PhantomData<TargetF>,
    pub base_phantom: PhantomData<BaseF>,
}

impl<TargetF: PrimeField, BaseF: PrimeField> Reducer<TargetF, BaseF> {
    /// convert limbs to bits (take at most `BaseF::MODULUS_BIT_SIZE as
    /// usize - 1` bits) This implementation would be more efficient than
    /// the original `to_bits` or `to_non_unique_bits` since we enforce that
    /// some bits are always zero.
    #[tracing::instrument(target = "r1cs")]
    pub fn limb_to_bits(limb: &FpVar<BaseF>, num_bits: usize) -> R1CSResult<Vec<Boolean<BaseF>>> {
        let cs = limb.cs();

        let num_bits = min(BaseF::MODULUS_BIT_SIZE as usize - 1, num_bits);
        let mut bits_considered = Vec::with_capacity(num_bits);
        let limb_value = limb.value().unwrap_or_default();

        let num_bits_to_shave = BaseF::BigInt::NUM_LIMBS * 64 - (BaseF::MODULUS_BIT_SIZE as usize);

        for b in BitIteratorBE::new(limb_value.into_bigint())
            .skip(num_bits_to_shave + (BaseF::MODULUS_BIT_SIZE as usize - num_bits))
        {
            bits_considered.push(b);
        }

        if cs == ConstraintSystemRef::None {
            let mut bits = vec![];
            for b in bits_considered {
                bits.push(Boolean::<BaseF>::Constant(b));
            }

            Ok(bits)
        } else {
            let mut bits = vec![];
            for b in bits_considered {
                bits.push(Boolean::<BaseF>::new_witness(
                    ark_relations::ns!(cs, "bit"),
                    || Ok(b),
                )?);
            }

            let mut bit_sum = FpVar::<BaseF>::zero();
            let mut coeff = BaseF::one();

            for bit in bits.iter().rev() {
                bit_sum += <FpVar<BaseF> as From<Boolean<BaseF>>>::from((*bit).clone()) * coeff;
                coeff.double_in_place();
            }

            bit_sum.enforce_equal(limb)?;

            Ok(bits)
        }
    }

    /// Reduction to the normal form
    #[tracing::instrument(target = "r1cs")]
    pub fn reduce(elem: &mut AllocatedEmulatedFpVar<TargetF, BaseF>) -> R1CSResult<()> {
        let new_elem = AllocatedEmulatedFpVar::new_witness(ns!(elem.cs(), "normal_form"), || {
            Ok(elem.value().unwrap_or_default())
        })?;
        elem.conditional_enforce_equal(&new_elem, &Boolean::TRUE)?;
        *elem = new_elem;

        Ok(())
    }

    /// Reduction to be enforced after additions
    #[tracing::instrument(target = "r1cs")]
    pub fn post_add_reduce(elem: &mut AllocatedEmulatedFpVar<TargetF, BaseF>) -> R1CSResult<()> {
        let params = get_params(
            TargetF::MODULUS_BIT_SIZE as usize,
            BaseF::MODULUS_BIT_SIZE as usize,
            elem.get_optimization_type(),
        );
        let surfeit = overhead!(elem.num_of_additions_over_normal_form + BaseF::one()) + 1;

        if BaseF::MODULUS_BIT_SIZE as usize > 2 * params.bits_per_limb + surfeit + 1 {
            Ok(())
        } else {
            Self::reduce(elem)
        }
    }

    /// Reduction used before multiplication to reduce the representations in a
    /// way that allows efficient multiplication
    #[tracing::instrument(target = "r1cs")]
    pub fn pre_mul_reduce(
        elem: &mut AllocatedEmulatedFpVar<TargetF, BaseF>,
        elem_other: &mut AllocatedEmulatedFpVar<TargetF, BaseF>,
    ) -> R1CSResult<()> {
        assert_eq!(
            elem.get_optimization_type(),
            elem_other.get_optimization_type()
        );

        let params = get_params(
            TargetF::MODULUS_BIT_SIZE as usize,
            BaseF::MODULUS_BIT_SIZE as usize,
            elem.get_optimization_type(),
        );

        // `smallest_mul_bit_size` needs to be `<= BaseF::MODULUS_BIT_SIZE as usize - 4`
        // - see `group_and_check_equality` for more details
        if 2 * params.bits_per_limb + ark_std::log2(params.num_limbs + 1) as usize
            >= BaseF::MODULUS_BIT_SIZE as usize - 3
        {
            panic!("The current limb parameters do not support multiplication.");
        }

        loop {
            // this needs to be adjusted if we modify `prod_of_num_of_additions` of MulResult
            let prod_of_num_of_additions = (elem.num_of_additions_over_normal_form + BaseF::one())
                * (elem_other.num_of_additions_over_normal_form + BaseF::one());
            let overhead_limb = overhead!(
                BaseF::one()
                    + prod_of_num_of_additions.mul(
                        &BaseF::from_bigint(<BaseF as PrimeField>::BigInt::from(
                            (params.num_limbs) as u64
                        ))
                        .unwrap()
                    )
            );

            let bits_per_mulresult_limb = 2 * params.bits_per_limb + overhead_limb;

            // because we want bits_per_mulresult_limb <= MODULUS_BIT_SIZE - 4
            // - this is the max bit it can have in our configuration right now
            // - see `group_and_check_equality` for more details
            if bits_per_mulresult_limb < (BaseF::MODULUS_BIT_SIZE - 3) as usize {
                break;
            }

            if elem.num_of_additions_over_normal_form
                >= elem_other.num_of_additions_over_normal_form
            {
                Self::reduce(elem)?;
            } else {
                Self::reduce(elem_other)?;
            }
        }

        Ok(())
    }

    /// Reduction to the normal form
    #[tracing::instrument(target = "r1cs")]
    pub fn pre_eq_reduce(elem: &mut AllocatedEmulatedFpVar<TargetF, BaseF>) -> R1CSResult<()> {
        if elem.is_in_the_normal_form {
            return Ok(());
        }

        Self::reduce(elem)
    }

    /// Group and check equality
    #[tracing::instrument(target = "r1cs")]
    pub fn group_and_check_equality(
        surfeit: usize,
        bits_per_limb: usize,
        shift_per_limb: usize,
        left: &[FpVar<BaseF>],
        right: &[FpVar<BaseF>],
    ) -> R1CSResult<()> {
        let cs = left.cs().or(right.cs());
        let zero = FpVar::<BaseF>::zero();

        let mut limb_pairs = Vec::<(FpVar<BaseF>, FpVar<BaseF>)>::new();

        // this size is closely related to the grouped limb size, padding size, premul_reduce and post_add_reduce
        //
        // it should be carefully chosen so that 1) no overflow can happen in this function and 2) num_limb_in_a_group
        // is always >=1.
        //
        // 1. for this function
        // - pad_limb has bit size BaseF::MODULUS_BIT_SIZE - 1
        // - left/right_total_limb has bit size BaseF::MODULUS_BIT_SIZE - 3
        // - carry has even smaller size
        // - so, their sum has bit size at most BaseF::MODULUS_BIT_SIZE - 1
        //
        // 2. for premul_reduce
        // - it enforces `2 * bits_per_limb + surfeit <= BaseF::MODULUS_BIT_SIZE - 4`
        //   - 2 * bits_per_limb in that function == 2 * (bits_per_limb - shift_per_limb) == shift_per_limb
        // - so, num_limb_in_a_group is at least 1 for mul
        //
        // 3. for postadd_reduce
        // - need to check `sub_without_reduce` for its surfeit guarantee
        // - but, it should work as this function is not modified
        //
        // 4. use add after mul_without_reduce
        // - currently, no reduce is applied when adding over MulResult.
        let num_limb_in_a_group = (BaseF::MODULUS_BIT_SIZE as usize
            - 1
            - surfeit
            - 1
            - 1
            - 1
            - (bits_per_limb - shift_per_limb))
            / shift_per_limb;

        // let _left_values: Vec<_> = left.iter().map(|fv| fv.value().unwrap()).collect();
        // let _right_values: Vec<_> = right.iter().map(|fv| fv.value().unwrap()).collect();
        // dbg!(surfeit);
        // dbg!(BaseF::MODULUS_BIT_SIZE);
        // dbg!(
        //     num_limb_in_a_group,
        //     bits_per_limb,
        //     num_limb_in_a_group * shift_per_limb + (bits_per_limb - shift_per_limb) + surfeit
        // );
        // dbg!(&left_values, &right_values);

        // let left_value = AllocatedEmulatedFpVar::<TargetF, BaseF>::limbs_to_value(
        //     left_values,
        //     match cs.optimization_goal() {
        //         ark_relations::r1cs::OptimizationGoal::None => {
        //             crate::fields::emulated_fp::params::OptimizationType::Constraints
        //         },
        //         ark_relations::r1cs::OptimizationGoal::Constraints => {
        //             crate::fields::emulated_fp::params::OptimizationType::Constraints
        //         },
        //         ark_relations::r1cs::OptimizationGoal::Weight => {
        //             crate::fields::emulated_fp::params::OptimizationType::Weight
        //         },
        //     },
        // );
        // let right_value = AllocatedEmulatedFpVar::<TargetF, BaseF>::limbs_to_value(
        //     right_values,
        //     match cs.optimization_goal() {
        //         ark_relations::r1cs::OptimizationGoal::None => {
        //             crate::fields::emulated_fp::params::OptimizationType::Constraints
        //         },
        //         ark_relations::r1cs::OptimizationGoal::Constraints => {
        //             crate::fields::emulated_fp::params::OptimizationType::Constraints
        //         },
        //         ark_relations::r1cs::OptimizationGoal::Weight => {
        //             crate::fields::emulated_fp::params::OptimizationType::Weight
        //         },
        //     },
        // );
        // dbg!(left_value, right_value);

        let shift_array = {
            let mut array = Vec::new();
            let mut cur = BaseF::one().into_bigint();
            for _ in 0..num_limb_in_a_group {
                array.push(BaseF::from_bigint(cur).unwrap());
                cur <<= shift_per_limb as u32;
            }

            array
        };

        for (left_limb, right_limb) in left.iter().zip(right.iter()).rev() {
            // note: the `rev` operation is here, so that the first limb (and the first
            // groupped limb) will be the least significant limb.
            limb_pairs.push((left_limb.clone(), right_limb.clone()));
        }

        let mut groupped_limb_pairs = Vec::<(FpVar<BaseF>, FpVar<BaseF>, usize)>::new();

        for limb_pairs_in_a_group in limb_pairs.chunks(num_limb_in_a_group) {
            // bit = num_limb_in_a_group * shift_per_limb + bits_per_limb + true surfeit + 1
            //     = BaseF::MODULUS_BIT_SIZE - 3
            //
            // How is this derived? Calculate the sum of the total limbs. You will find it's a geometric series.
            let mut left_total_limb = zero.clone();
            let mut right_total_limb = zero.clone();

            for ((left_limb, right_limb), shift) in
                limb_pairs_in_a_group.iter().zip(shift_array.iter())
            {
                left_total_limb += &(left_limb * *shift);
                right_total_limb += &(right_limb * *shift);
            }

            groupped_limb_pairs.push((
                left_total_limb,
                right_total_limb,
                limb_pairs_in_a_group.len(),
            ));
        }

        // This part we mostly use the techniques in bellman-bignat
        // The following code is adapted from https://github.com/alex-ozdemir/bellman-bignat/blob/master/src/mp/bignat.rs#L567
        let mut carry_in = zero;
        let mut carry_in_value = BaseF::zero();
        let mut accumulated_extra = BigUint::zero();
        for (group_id, (left_total_limb, right_total_limb, num_limb_in_this_group)) in
            groupped_limb_pairs.iter().enumerate()
        {
            let mut pad_limb_repr = BaseF::ONE.into_bigint();

            // calculate max_word
            //
            // Problem
            // - I observed that sometimes eqn_left wraps around, which should not happen
            //
            // Reasoning
            // - we should keep the size <= MODULUS_SIZE - 1
            // - pad_limb_repr len is BaseF::MODULUS_BIT_SIZE - 1 (expand shift_per_limb * num_limb_in_this_group)
            //   - if it is greater than left/right values, adding left_total_limb_value + carry_in_value + pad_limb shouldn't cause
            //     any problem
            //   - however, then I observed a more serious problem, pad_limb_repr is not guaranteed to be larger than left/right.
            //     this might cause serious problem when left is smaller than right as then it's possible that
            //     `left_total_limb_value + carry_in_value + pad_limb - right_total_limb_value` is negative and then wrap around.
            //
            // Then, I suspect that it's because `surfeit` is not calculated correctly. As only in that case, the highest word will
            // have a value large than the pad_limb (surfeit is a upper bound for every word - see below).
            // - Why only this will happen when `surfeit` is not calculated correct is addressed below.
            // - Currently, for mul, `surfeit = ceil(log(prod of add_over_normal (without the num_limbs) + 1)) + 1 + 1`
            //
            // Before diving into my calculation, I want to explain what surfeit is for:
            // - We can treat it as an estimation of the maximum bits of all words - bits_per_limb.
            // - In other word, it is max(max(word in bit, ignore leading 0) for word in words) - bits_per_limb.
            //
            // Then, we can derive, given `x`` and `y`` that has `a` and `b` as `add_over_norm`. Let z = xy. We know we can bound
            // the value of all words by (a+1)*2^{bits_per_limb} * (b+1)*2^{bits_per_limb} * m
            // - m comes from the fact that m pairs of multiplication of 2 words will be added together at most
            //
            // So, we know the total bit size <= 2*bits_per_limb + log(ab+a+b+1) + log(m). Then, by definition,
            // surfeit will be log(ab+a+b+1) + log(m) (because `bits_per_limb` of this func is 2*bits_per_limb).
            // With the correct surfeit, we can have padding that satisfies the constraint.
            //
            // With the above knowledge. We can also deduce why we need such a `num_limb_in_a_group` variable, we know
            // final length of the number will be upper bounded by:
            // - num_limb_in_a_group * shift_per_limb + (bits_per_limb - shift_per_limb) + true_surfeit + 1
            //   - why is this? See analysis of `left_total_limb` and `right_total_limb` above.
            // - This provides another perspective about why it's crucial to have a correct surfeit, or otherwise,
            //   when you expand the above formula, it will potentially be >= pad_limb's bit size.

            // bit = BaseF::MODULUS_BIT_SIZE - 1 (left shift by BaseF::MODULUS_BIT_SIZE - 2)
            pad_limb_repr <<= (surfeit
                + (bits_per_limb - shift_per_limb)
                + shift_per_limb * num_limb_in_this_group
                + 1
                + 1) as u32;
            let pad_limb = BaseF::from_bigint(pad_limb_repr).unwrap();

            let left_total_limb_value = left_total_limb.value().unwrap_or_default();
            let right_total_limb_value = right_total_limb.value().unwrap_or_default();

            let mut carry_value =
                left_total_limb_value + carry_in_value + pad_limb - right_total_limb_value;

            let carry_repr =
                carry_value.into_bigint() >> (shift_per_limb * num_limb_in_this_group) as u32;

            carry_value = BaseF::from_bigint(carry_repr).unwrap();

            let carry = FpVar::new_witness(cs.clone(), || Ok(carry_value))?;

            accumulated_extra += limbs_to_bigint(bits_per_limb, &[pad_limb]);

            let (new_accumulated_extra, remainder) = accumulated_extra.div_rem(
                &BigUint::from(2u64).pow((shift_per_limb * num_limb_in_this_group) as u32),
            );
            let remainder_limb = bigint_to_basefield::<BaseF>(&remainder);

            // println!("");
            // dbg!(accumulated_extra);
            // dbg!(shift_per_limb * num_limb_in_this_group);
            // dbg!(left_total_limb_value < pad_limb);
            // dbg!(carry_in_value < pad_limb);
            // dbg!(left_total_limb_value + carry_in_value + pad_limb < left_total_limb_value);
            // dbg!(left_total_limb_value + carry_in_value + pad_limb < carry_in_value);
            // dbg!(left_total_limb_value + carry_in_value + pad_limb < pad_limb);
            // dbg!(left_total_limb_value + carry_in_value + pad_limb < right_total_limb_value);
            // dbg!(right_total_limb_value);
            // dbg!(&new_accumulated_extra, remainder_limb);

            // Now check
            //      left_total_limb + pad_limb + carry_in - right_total_limb
            //   =  carry shift by (shift_per_limb * num_limb_in_this_group) + remainder
            //
            // ---
            //
            // My Note:
            //
            // cur_left - cur_right + carry_in + pad (to accommodate possible overflow for subtraction)
            // = carry_out (of the above computation) + remainder (of accumulated padding)
            //
            // this is sound because it proves the remainder of the subtraction is 0 all the time.

            let eqn_left = left_total_limb + pad_limb + &carry_in - right_total_limb;

            let eqn_right = &carry
                * BaseF::from(2u64).pow(&[(shift_per_limb * num_limb_in_this_group) as u64])
                + remainder_limb;

            eqn_left.conditional_enforce_equal(&eqn_right, &Boolean::<BaseF>::TRUE)?;

            accumulated_extra = new_accumulated_extra;
            carry_in = carry.clone();
            carry_in_value = carry_value;

            if group_id == groupped_limb_pairs.len() - 1 {
                carry.enforce_equal(&FpVar::<BaseF>::Constant(bigint_to_basefield(
                    &accumulated_extra,
                )))?;
            } else {
                // enforce carry's bits length
                Reducer::<TargetF, BaseF>::limb_to_bits(&carry, surfeit + bits_per_limb)?;
            }
        }

        Ok(())
    }
}
