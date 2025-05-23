use crate::{
    boolean::Boolean,
    convert::ToBitsGadget,
    fields::{fp::FpVar, FieldVar},
    prelude::*,
};
use ark_ff::PrimeField;
use ark_relations::r1cs::SynthesisError;
use core::cmp::Ordering;

impl<F: PrimeField> FpVar<F> {
    /// This function enforces the ordering between `self` and `other`. The
    /// constraint system will not be satisfied otherwise. If `self` should
    /// also be checked for equality, e.g. `self <= other` instead of `self <
    /// other`, set `should_also_check_quality` to `true`. This variant
    /// verifies `self` and `other` are `<= (p-1)/2`.
    #[tracing::instrument(target = "r1cs")]
    pub fn enforce_cmp(
        &self,
        other: &FpVar<F>,
        ordering: Ordering,
        should_also_check_equality: bool,
    ) -> Result<(), SynthesisError> {
        let (left, right) = self.process_cmp_inputs(other, ordering, should_also_check_equality)?;
        left.enforce_smaller_than(&right)
    }

    /// This function enforces the ordering between `self` and `other`. The
    /// constraint system will not be satisfied otherwise. If `self` should
    /// also be checked for equality, e.g. `self <= other` instead of `self <
    /// other`, set `should_also_check_quality` to `true`. This variant
    /// assumes `self` and `other` are `<= (p-1)/2` and does not generate
    /// constraints to verify that.
    #[tracing::instrument(target = "r1cs")]
    pub fn enforce_cmp_unchecked(
        &self,
        other: &FpVar<F>,
        ordering: Ordering,
        should_also_check_equality: bool,
    ) -> Result<(), SynthesisError> {
        let (left, right) = self.process_cmp_inputs(other, ordering, should_also_check_equality)?;
        left.enforce_smaller_than_unchecked(&right)
    }

    /// This function checks the ordering between `self` and `other`. It outputs
    /// self `Boolean` that contains the result - `1` if true, `0`
    /// otherwise. The constraint system will be satisfied in any case. If
    /// `self` should also be checked for equality, e.g. `self <= other`
    /// instead of `self < other`, set `should_also_check_quality` to
    /// `true`. This variant verifies `self` and `other` are `<= (p-1)/2`.
    #[tracing::instrument(target = "r1cs")]
    pub fn is_cmp(
        &self,
        other: &FpVar<F>,
        ordering: Ordering,
        should_also_check_equality: bool,
    ) -> Result<Boolean<F>, SynthesisError> {
        let (left, right) = self.process_cmp_inputs(other, ordering, should_also_check_equality)?;
        left.is_smaller_than(&right)
    }

    /// This function checks the ordering between `self` and `other`. It outputs
    /// a `Boolean` that contains the result - `1` if true, `0` otherwise.
    /// The constraint system will be satisfied in any case. If `self`
    /// should also be checked for equality, e.g. `self <= other` instead of
    /// `self < other`, set `should_also_check_quality` to `true`. This
    /// variant assumes `self` and `other` are `<= (p-1)/2` and does not
    /// generate constraints to verify that.
    #[tracing::instrument(target = "r1cs")]
    pub fn is_cmp_unchecked(
        &self,
        other: &FpVar<F>,
        ordering: Ordering,
        should_also_check_equality: bool,
    ) -> Result<Boolean<F>, SynthesisError> {
        let (left, right) = self.process_cmp_inputs(other, ordering, should_also_check_equality)?;
        left.is_smaller_than_unchecked(&right)
    }

    fn process_cmp_inputs(
        &self,
        other: &Self,
        ordering: Ordering,
        should_also_check_equality: bool,
    ) -> Result<(Self, Self), SynthesisError> {
        let (left, right) = match ordering {
            Ordering::Less => (self, other),
            Ordering::Greater => (other, self),
            Ordering::Equal => return Err(SynthesisError::Unsatisfiable),
        };
        let right_for_check = if should_also_check_equality {
            right + F::one()
        } else {
            right.clone()
        };

        Ok((left.clone(), right_for_check))
    }

    /// Helper function to enforce that `self <= (p-1)/2`.
    #[tracing::instrument(target = "r1cs")]
    pub fn enforce_smaller_or_equal_than_mod_minus_one_div_two(
        &self,
    ) -> Result<(), SynthesisError> {
        // It's okay to use `to_non_unique_bits` bits here because we're enforcing
        // self <= (p-1)/2, which implies self < p.
        let _ = Boolean::enforce_smaller_or_equal_than_le(
            &self.to_non_unique_bits_le()?,
            F::MODULUS_MINUS_ONE_DIV_TWO,
        )?;
        Ok(())
    }

    /// Helper function to check `self < other` and output a result bit. This
    /// function verifies `self` and `other` are `<= (p-1)/2`.
    fn is_smaller_than(&self, other: &FpVar<F>) -> Result<Boolean<F>, SynthesisError> {
        self.enforce_smaller_or_equal_than_mod_minus_one_div_two()?;
        other.enforce_smaller_or_equal_than_mod_minus_one_div_two()?;
        self.is_smaller_than_unchecked(other)
    }

    /// Helper function to check `self < other` and output a result bit. This
    /// function assumes `self` and `other` are `<= (p-1)/2` and does not
    /// generate constraints to verify that.
    ///
    /// This is quite clever as if `self < other`, this underflows, results in a number, when doubled,
    /// greater than p. Then, as p is a prime, this number, when modulo p, results in an odd number.
    /// Whereas, when self > other, `double`  results in a number smaller than p, and is therefore even.
    fn is_smaller_than_unchecked(&self, other: &FpVar<F>) -> Result<Boolean<F>, SynthesisError> {
        Ok((self - other)
            .double()?
            .to_bits_le()?
            .first()
            .unwrap()
            .clone())
    }

    /// Helper function to enforce `self < other`. This function verifies `self`
    /// and `other` are `<= (p-1)/2`.
    fn enforce_smaller_than(&self, other: &FpVar<F>) -> Result<(), SynthesisError> {
        self.enforce_smaller_or_equal_than_mod_minus_one_div_two()?;
        other.enforce_smaller_or_equal_than_mod_minus_one_div_two()?;
        self.enforce_smaller_than_unchecked(other)
    }

    /// Helper function to enforce `self < other`. This function assumes `self`
    /// and `other` are `<= (p-1)/2` and does not generate constraints to
    /// verify that.
    fn enforce_smaller_than_unchecked(&self, other: &FpVar<F>) -> Result<(), SynthesisError> {
        let is_smaller_than = self.is_smaller_than_unchecked(other)?;
        is_smaller_than.enforce_equal(&Boolean::TRUE)
    }
}

#[cfg(test)]
mod test {
    use ark_std::{cmp::Ordering, rand::Rng};

    use crate::{alloc::AllocVar, fields::fp::FpVar};
    use ark_ff::{PrimeField, UniformRand};
    use ark_relations::r1cs::ConstraintSystem;
    use ark_test_curves::bls12_381::Fr;

    #[test]
    fn test_cmp() {
        let mut rng = ark_std::test_rng();
        fn rand_in_range<R: Rng>(rng: &mut R) -> Fr {
            let pminusonedivtwo: Fr = Fr::MODULUS_MINUS_ONE_DIV_TWO.into();
            let mut r;
            loop {
                r = Fr::rand(rng);
                if r <= pminusonedivtwo {
                    break;
                }
            }
            r
        }
        for i in 0..10 {
            let cs = ConstraintSystem::<Fr>::new_ref();
            let a = rand_in_range(&mut rng);
            let a_var = FpVar::<Fr>::new_witness(cs.clone(), || Ok(a)).unwrap();
            let b = rand_in_range(&mut rng);
            let b_var = FpVar::<Fr>::new_witness(cs.clone(), || Ok(b)).unwrap();

            match a.cmp(&b) {
                Ordering::Less => {
                    a_var.enforce_cmp(&b_var, Ordering::Less, false).unwrap();
                    a_var.enforce_cmp(&b_var, Ordering::Less, true).unwrap();
                },
                Ordering::Greater => {
                    a_var.enforce_cmp(&b_var, Ordering::Greater, false).unwrap();
                    a_var.enforce_cmp(&b_var, Ordering::Greater, true).unwrap();
                },
                _ => {},
            }

            if i == 0 {
                println!("number of constraints: {}", cs.num_constraints());
            }
            assert!(cs.is_satisfied().unwrap());
        }
        println!("Finished with satisfaction tests");

        for _i in 0..10 {
            let cs = ConstraintSystem::<Fr>::new_ref();
            let a = rand_in_range(&mut rng);
            let a_var = FpVar::<Fr>::new_witness(cs.clone(), || Ok(a)).unwrap();
            let b = rand_in_range(&mut rng);
            let b_var = FpVar::<Fr>::new_witness(cs.clone(), || Ok(b)).unwrap();

            match b.cmp(&a) {
                Ordering::Less => {
                    a_var.enforce_cmp(&b_var, Ordering::Less, false).unwrap();
                    a_var.enforce_cmp(&b_var, Ordering::Less, true).unwrap();
                },
                Ordering::Greater => {
                    a_var.enforce_cmp(&b_var, Ordering::Greater, false).unwrap();
                    a_var.enforce_cmp(&b_var, Ordering::Greater, true).unwrap();
                },
                _ => {},
            }

            assert!(!cs.is_satisfied().unwrap());
        }

        for _i in 0..10 {
            let cs = ConstraintSystem::<Fr>::new_ref();
            let a = rand_in_range(&mut rng);
            let a_var = FpVar::<Fr>::new_witness(cs.clone(), || Ok(a)).unwrap();
            a_var.enforce_cmp(&a_var, Ordering::Less, false).unwrap();

            assert!(!cs.is_satisfied().unwrap());
        }

        for _i in 0..10 {
            let cs = ConstraintSystem::<Fr>::new_ref();
            let a = rand_in_range(&mut rng);
            let a_var = FpVar::<Fr>::new_witness(cs.clone(), || Ok(a)).unwrap();
            a_var.enforce_cmp(&a_var, Ordering::Less, true).unwrap();
            assert!(cs.is_satisfied().unwrap());
        }
    }
}
