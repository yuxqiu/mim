use ark_ff::QuadExtConfig;
use ark_ff::{CubicExtConfig, CubicExtField, Field, PrimeField, QuadExtField, Zero};
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::cubic_extension::{CubicExtVar, CubicExtVarConfig};
use ark_r1cs_std::fields::emulated_fp::EmulatedFpVar;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::quadratic_extension::{QuadExtVar, QuadExtVarConfig};
use ark_r1cs_std::fields::FieldOpsBounds;
use ark_r1cs_std::R1CSVar;
use ark_r1cs_std::{fields::FieldVar, prelude::Boolean};
use ark_relations::r1cs::SynthesisError;

use crate::hash::map_to_curve::norm::NormGadget;

pub trait SqrtGadget<F: Field, CF: PrimeField>: Sized + FieldVar<F, CF> {
    fn legendre(&self) -> Result<Boolean<CF>, SynthesisError>;

    /// compute the square root of the FieldVar
    /// return (true, sqrt) iff the var is a quadratic residue
    /// otherwise, return (false, 0)
    /// - return 0 allows us to merge legendre == 0 and legendre == -1 cases
    fn sqrt(&self) -> Result<(Boolean<CF>, Self), SynthesisError>;
}

impl<F: PrimeField> SqrtGadget<F, F> for FpVar<F> {
    fn sqrt(&self) -> Result<(Boolean<F>, Self), SynthesisError> {
        let cs = self.cs();
        let should_construct_value = (!cs.is_in_setup_mode()) || self.is_constant();

        if should_construct_value {
            let value = self.value()?;
            Ok((
                Boolean::constant(value.legendre().is_qr()),
                Self::constant(value.sqrt().unwrap_or(F::zero())),
            ))
        } else {
            let legendre = self.legendre()?;

            let sqrt = self.value()?.sqrt().unwrap_or(F::zero());
            let sqrt_var = FpVar::new_witness(self.cs(), || Ok(sqrt))?;
            let sqrt_square = sqrt_var.square()?;

            sqrt_square.conditional_enforce_equal(self, &legendre)?;
            sqrt_var.conditional_enforce_equal(&FpVar::zero(), &!legendre.clone())?;

            Ok((legendre, sqrt_var))
        }
    }

    fn legendre(&self) -> Result<Boolean<F>, SynthesisError> {
        self.pow_by_constant(F::MODULUS_MINUS_ONE_DIV_TWO)?.is_one()
    }
}

impl<F: PrimeField, CF: PrimeField> SqrtGadget<F, CF> for EmulatedFpVar<F, CF> {
    fn sqrt(&self) -> Result<(Boolean<CF>, Self), SynthesisError> {
        let cs = self.cs();
        let should_construct_value = (!cs.is_in_setup_mode()) || self.is_constant();

        if should_construct_value {
            let value = self.value()?;
            Ok((
                Boolean::constant(value.legendre().is_qr()),
                Self::constant(value.sqrt().unwrap_or(F::zero())),
            ))
        } else {
            let legendre = self.legendre()?;

            let sqrt = self.value()?.sqrt().unwrap_or(F::zero());
            let sqrt_var = EmulatedFpVar::new_witness(self.cs(), || Ok(sqrt))?;
            let sqrt_square = sqrt_var.square()?;

            sqrt_square.conditional_enforce_equal(self, &legendre)?;
            sqrt_var.conditional_enforce_equal(&EmulatedFpVar::zero(), &!legendre.clone())?;

            Ok((legendre, sqrt_var))
        }
    }

    fn legendre(&self) -> Result<Boolean<CF>, SynthesisError> {
        self.pow_by_constant(F::MODULUS_MINUS_ONE_DIV_TWO)?.is_one()
    }
}

impl<
        BF: FieldVar<P::BaseField, CF> + SqrtGadget<P::BaseField, CF>,
        P: QuadExtVarConfig<BF, CF>,
        CF: PrimeField,
    > SqrtGadget<QuadExtField<P>, CF> for QuadExtVar<BF, P, CF>
where
    for<'a> &'a BF: FieldOpsBounds<'a, <P as QuadExtConfig>::BaseField, BF>,
{
    fn sqrt(&self) -> Result<(Boolean<CF>, Self), SynthesisError> {
        let cs = self.cs();
        let should_construct_value = (!cs.is_in_setup_mode()) || self.is_constant();

        if should_construct_value {
            let value = self.value()?;
            Ok((
                Boolean::constant(value.legendre().is_qr()),
                Self::constant(value.sqrt().unwrap_or(QuadExtField::zero())),
            ))
        } else {
            let legendre = self.legendre()?;

            let sqrt = self.value()?.sqrt().unwrap_or(QuadExtField::<P>::zero());
            let sqrt_var = QuadExtVar::new_witness(self.cs(), || Ok(sqrt))?;
            let sqrt_square = sqrt_var.square()?;

            sqrt_square.conditional_enforce_equal(self, &legendre)?;
            sqrt_var.conditional_enforce_equal(&QuadExtVar::zero(), &!legendre.clone())?;

            Ok((legendre, sqrt_var))
        }
    }

    fn legendre(&self) -> Result<Boolean<CF>, SynthesisError> {
        self.norm()?.legendre()
    }
}

impl<
        BF: FieldVar<P::BaseField, CF> + SqrtGadget<P::BaseField, CF>,
        P: CubicExtVarConfig<BF, CF>,
        CF: PrimeField,
    > SqrtGadget<CubicExtField<P>, CF> for CubicExtVar<BF, P, CF>
where
    for<'a> &'a BF: FieldOpsBounds<'a, <P as CubicExtConfig>::BaseField, BF>,
{
    fn sqrt(&self) -> Result<(Boolean<CF>, Self), SynthesisError> {
        let cs = self.cs();
        let should_construct_value = (!cs.is_in_setup_mode()) || self.is_constant();

        if should_construct_value {
            let value = self.value()?;
            Ok((
                Boolean::constant(value.legendre().is_qr()),
                Self::constant(value.sqrt().unwrap_or(CubicExtField::zero())),
            ))
        } else {
            let legendre = self.legendre()?;

            let sqrt = self.value()?.sqrt().unwrap_or(CubicExtField::<P>::zero());
            let sqrt_var = CubicExtVar::new_witness(self.cs(), || Ok(sqrt))?;
            let sqrt_square = sqrt_var.square()?;

            sqrt_square.conditional_enforce_equal(self, &legendre)?;
            sqrt_var.conditional_enforce_equal(&CubicExtVar::zero(), &!legendre.clone())?;

            Ok((legendre, sqrt_var))
        }
    }

    fn legendre(&self) -> Result<Boolean<CF>, SynthesisError> {
        self.norm()?.legendre()
    }
}

#[cfg(test)]
mod test {
    use ark_bls12_381::{Fq2Config, Fr};
    use ark_bw6_761::Fq3Config;
    use ark_ff::{Field, Fp2, Fp3, UniformRand};
    use ark_r1cs_std::{
        alloc::AllocVar,
        fields::{fp::FpVar, fp2::Fp2Var, fp3::Fp3Var, FieldVar},
        R1CSVar,
    };
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::One;
    use ark_std::Zero;
    use rand::thread_rng;

    use super::SqrtGadget;

    macro_rules! generate_parity_tests {
        ($test_name:ident, $field:ty, $field_var:ty) => {
            #[test]
            fn $test_name() {
                fn test_constant() {
                    let mut rng = thread_rng();

                    {
                        // test zero
                        let zero = <$field>::zero();
                        let zero_var = <$field_var>::constant(zero);
                        let legendre = zero.legendre().is_qr();
                        let sqrt_zero = zero.sqrt().unwrap_or(<$field>::zero());
                        let (legendre_var, sqrt_zero_var) = zero_var.sqrt().unwrap();
                        assert_eq!(legendre_var.value().unwrap(), legendre);
                        assert!(legendre_var.is_constant());
                        assert_eq!(sqrt_zero_var.value().unwrap(), sqrt_zero);
                        assert!(sqrt_zero_var.is_constant());
                    }

                    {
                        // test one
                        let one = <$field>::one();
                        let one_var = <$field_var>::constant(one);
                        let legendre = one.legendre().is_qr();
                        let sqrt_one = one.sqrt().unwrap_or(<$field>::zero());
                        let (legendre_var, sqrt_one_var) = one_var.sqrt().unwrap();
                        assert_eq!(legendre_var.value().unwrap(), legendre);
                        assert!(legendre_var.is_constant());
                        assert_eq!(sqrt_one_var.value().unwrap(), sqrt_one);
                        assert!(sqrt_one_var.is_constant());
                    }

                    {
                        // test random element
                        let r = <$field>::rand(&mut rng);
                        let r_var = <$field_var>::constant(r);
                        let legendre = r.legendre().is_qr();
                        let sqrt_one = r.sqrt().unwrap_or(<$field>::zero());
                        let (legendre_var, sqrt_one_var) = r_var.sqrt().unwrap();
                        assert_eq!(legendre_var.value().unwrap(), legendre);
                        assert!(legendre_var.is_constant());
                        assert_eq!(sqrt_one_var.value().unwrap(), sqrt_one);
                        assert!(sqrt_one_var.is_constant());
                    }
                }

                test_constant();

                fn test_input() {
                    let mut rng = thread_rng();

                    {
                        // test zero
                        let cs = ConstraintSystem::new_ref();
                        let zero = <$field>::zero();
                        let zero_var = <$field_var>::new_input(cs.clone(), || Ok(zero)).unwrap();
                        let legendre = zero.legendre().is_qr();
                        let sqrt_zero = zero.sqrt().unwrap_or(<$field>::zero());
                        let (legendre_var, sqrt_zero_var) = zero_var.sqrt().unwrap();
                        assert_eq!(legendre_var.value().unwrap(), legendre);
                        assert_eq!(sqrt_zero_var.value().unwrap(), sqrt_zero);
                        assert!(cs.is_satisfied().unwrap());
                    }

                    {
                        // test one
                        let cs = ConstraintSystem::new_ref();
                        let one = <$field>::one();
                        let one_var = <$field_var>::new_input(cs.clone(), || Ok(one)).unwrap();
                        let legendre = one.legendre().is_qr();
                        let sqrt_one = one.sqrt().unwrap_or(<$field>::zero());
                        let (legendre_var, sqrt_one_var) = one_var.sqrt().unwrap();
                        assert_eq!(legendre_var.value().unwrap(), legendre);
                        assert_eq!(sqrt_one_var.value().unwrap(), sqrt_one);
                        assert!(cs.is_satisfied().unwrap());
                    }

                    {
                        // test random element
                        let cs = ConstraintSystem::new_ref();
                        let r = <$field>::rand(&mut rng);
                        let r_var = <$field_var>::new_input(cs.clone(), || Ok(r)).unwrap();
                        let legendre = r.legendre().is_qr();
                        let sqrt_one = r.sqrt().unwrap_or(<$field>::zero());
                        let (legendre_var, sqrt_one_var) = r_var.sqrt().unwrap();
                        assert_eq!(legendre_var.value().unwrap(), legendre);
                        assert_eq!(sqrt_one_var.value().unwrap(), sqrt_one);
                        assert!(cs.is_satisfied().unwrap());
                    }
                }

                test_input();
            }
        };
    }

    generate_parity_tests!(test_parity_fp, Fr, FpVar<Fr>);
    generate_parity_tests!(test_parity_fp2, Fp2<Fq2Config>, Fp2Var<Fq2Config>);
    generate_parity_tests!(test_parity_fp3, Fp3<Fq3Config>, Fp3Var<Fq3Config>);
}
