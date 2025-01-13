use crate::fields::{fp2::Fp2Var, quadratic_extension::*};
use ark_ff::{
    fields::{Fp4ConfigWrapper, QuadExtConfig},
    Fp2Config, Fp4Config, PrimeField,
};

use super::{fp::FpVar, FieldOpsBounds, FieldVar};

/// A quartic extension field constructed as the tower of a
/// quadratic extension over a quadratic extension field.
/// This is the R1CS equivalent of `ark_ff::Fp4<P>`.
///
/// TODO: remove default, which is used to ensure groups/pairing other than bls can be compiled successfully
pub type Fp4Var<
    P,
    F = FpVar<<<P as Fp4Config>::Fp2Config as Fp2Config>::Fp>,
    CF = <<P as Fp4Config>::Fp2Config as Fp2Config>::Fp,
> = QuadExtVar<Fp2Var<<P as Fp4Config>::Fp2Config, F, CF>, Fp4ConfigWrapper<P>, CF>;

impl<
        P: Fp4Config,
        F: FieldVar<<<P as Fp4Config>::Fp2Config as ark_ff::Fp2Config>::Fp, CF>,
        CF: PrimeField,
    > QuadExtVarConfig<Fp2Var<P::Fp2Config, F, CF>, CF> for Fp4ConfigWrapper<P>
where
    for<'b> &'b F: FieldOpsBounds<'b, <<P as Fp4Config>::Fp2Config as ark_ff::Fp2Config>::Fp, F>,
{
    fn mul_base_field_var_by_frob_coeff(fe: &mut Fp2Var<P::Fp2Config, F, CF>, power: usize) {
        fe.c0 *= Self::FROBENIUS_COEFF_C1[power % Self::DEGREE_OVER_BASE_PRIME_FIELD];
        fe.c1 *= Self::FROBENIUS_COEFF_C1[power % Self::DEGREE_OVER_BASE_PRIME_FIELD];
    }
}
