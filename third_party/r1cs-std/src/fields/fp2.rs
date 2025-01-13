use crate::fields::quadratic_extension::*;
use ark_ff::{
    fields::{Fp2Config, Fp2ConfigWrapper, QuadExtConfig},
    PrimeField,
};

use super::{fp::FpVar, FieldOpsBounds, FieldVar};

/// A quadratic extension field constructed over a prime field.
/// This is the R1CS equivalent of `ark_ff::Fp2<P>`.
///
/// TODO: remove default, which is used to ensure groups/pairing other than bls can be compiled successfully
pub type Fp2Var<P, F = FpVar<<P as Fp2Config>::Fp>, CF = <P as Fp2Config>::Fp> =
    QuadExtVar<F, Fp2ConfigWrapper<P>, CF>;

impl<
        P: Fp2Config,
        F: FieldVar<<Fp2ConfigWrapper<P> as QuadExtConfig>::BaseField, CF>,
        CF: PrimeField,
    > QuadExtVarConfig<F, CF> for Fp2ConfigWrapper<P>
where
    for<'a> &'a F: FieldOpsBounds<'a, <P as Fp2Config>::Fp, F>,
{
    fn mul_base_field_var_by_frob_coeff(fe: &mut F, power: usize) {
        *fe *= Self::FROBENIUS_COEFF_C1[power % Self::DEGREE_OVER_BASE_PRIME_FIELD];
    }
}
