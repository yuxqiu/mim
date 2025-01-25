use crate::prf::PRF;
use ark_ff::Field;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::SynthesisError;
use ark_std::fmt::Debug;
#[cfg(not(feature = "std"))]
use ark_std::vec::Vec;

pub trait PRFGadget<P: PRF, F: Field> {
    type OutputVar: EqGadget<F>
        + ToBytesGadget<F>
        + AllocVar<P::Output, F>
        + R1CSVar<F, Value = P::Output>
        + Clone
        + Debug;

    // total output size in
    const OUTPUT_SIZE: usize;

    fn evaluate(input: &[UInt8<F>]) -> Result<Self::OutputVar, SynthesisError>;
}
