use ark_ff::Field;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::SynthesisError;
use ark_std::fmt::Debug;
#[cfg(not(feature = "std"))]
use ark_std::vec::Vec;

pub trait PRFGadget<F: Field> {
    type OutputVar: EqGadget<F> + ToBytesGadget<F> + Clone + Debug;

    // output size of the hash function in bytes
    const OUTPUT_SIZE: usize;

    fn update(&mut self, input: &[UInt8<F>]) -> Result<(), SynthesisError>;

    fn finalize(self) -> Result<Self::OutputVar, SynthesisError>;
}
