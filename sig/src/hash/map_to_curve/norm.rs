use ark_ff::{CubicExtConfig, Field, PrimeField, QuadExtConfig};
use ark_r1cs_std::fields::{
    cubic_extension::{CubicExtVar, CubicExtVarConfig},
    quadratic_extension::{QuadExtVar, QuadExtVarConfig},
    FieldOpsBounds, FieldVar,
};
use ark_relations::r1cs::SynthesisError;

// TODO: what is a norm?
// - return a norm in field F

/// Trait for calculating `norm` for `FieldVar<F: Field, CF: PrimeField>`.
pub trait NormGadget<FV: FieldVar<F, CF>, F: Field, CF: PrimeField>: Sized {
    fn norm(&self) -> Result<FV, SynthesisError>;
}

// TODO: why this?
impl<BF: FieldVar<P::BaseField, CF>, P: QuadExtVarConfig<BF, CF>, CF: PrimeField>
    NormGadget<BF, P::BaseField, CF> for QuadExtVar<BF, P, CF>
where
    for<'a> &'a BF: FieldOpsBounds<'a, <P as QuadExtConfig>::BaseField, BF>,
{
    // Copied from `third_party/ark-ff/src/fields/models/quadratic_extension.rs`
    fn norm(&self) -> Result<BF, SynthesisError> {
        let mut result = self.c1.square()?;
        // t1 = c0.square() - P::NON_RESIDUE * c1^2
        result = self.c0.square()? - result * P::NONRESIDUE;

        Ok(result)
    }
}

// TODO: frobenius map
impl<BF: FieldVar<P::BaseField, CF>, P: CubicExtVarConfig<BF, CF>, CF: PrimeField>
    NormGadget<BF, P::BaseField, CF> for CubicExtVar<BF, P, CF>
where
    for<'a> &'a BF: FieldOpsBounds<'a, <P as CubicExtConfig>::BaseField, BF>,
{
    // Copied from `third_party/ark-ff/src/fields/models/cubic_extension.rs`
    fn norm(&self) -> Result<BF, SynthesisError> {
        // w.r.t to BaseField, we need the 0th, 1st & 2nd powers of `q`
        // Since Frobenius coefficients on the towered extensions are
        // indexed w.r.t. to BasePrimeField, we need to calculate the correct index.
        let index_multiplier = usize::try_from(P::BaseField::extension_degree())
            .expect("extension degree should be able to store in usize");
        let mut self_to_p = self.clone();
        self_to_p.frobenius_map_in_place(index_multiplier)?;
        let mut self_to_p2 = self.clone();
        self_to_p2.frobenius_map_in_place(2 * index_multiplier)?;
        self_to_p *= &(self_to_p2 * self);

        Ok(self_to_p.c0)
    }
}
