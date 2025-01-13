use crate::fields::cubic_extension::*;
use ark_ff::{
    fields::{CubicExtConfig, Fp3ConfigWrapper},
    Fp3Config, PrimeField,
};

use super::{fp::FpVar, FieldOpsBounds, FieldVar};

/// A cubic extension field constructed over a prime field.
/// This is the R1CS equivalent of `ark_ff::Fp3<P>`.
///
/// TODO: remove default, which is used to ensure groups/pairing other than bls can be compiled successfully
pub type Fp3Var<P, F = FpVar<<P as Fp3Config>::Fp>, CF = <P as Fp3Config>::Fp> =
    CubicExtVar<F, Fp3ConfigWrapper<P>, CF>;

impl<
        P: Fp3Config,
        F: FieldVar<<Fp3ConfigWrapper<P> as CubicExtConfig>::BaseField, CF>,
        CF: PrimeField,
    > CubicExtVarConfig<F, CF> for Fp3ConfigWrapper<P>
where
    for<'a> &'a F: FieldOpsBounds<'a, <P as Fp3Config>::Fp, F>,
{
    fn mul_base_field_vars_by_frob_coeff(c1: &mut F, c2: &mut F, power: usize) {
        *c1 *= Self::FROBENIUS_COEFF_C1[power % Self::DEGREE_OVER_BASE_PRIME_FIELD];
        *c2 *= Self::FROBENIUS_COEFF_C2[power % Self::DEGREE_OVER_BASE_PRIME_FIELD];
    }
}
