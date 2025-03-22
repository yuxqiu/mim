use ark_ff::PrimeField;
use ark_r1cs_std::{prelude::ToBytesGadget, uint8::UInt8};
use ark_relations::r1cs::SynthesisError;

#[cfg(target_pointer_width = "32")]
pub struct USize<F: PrimeField>(pub ark_r1cs_std::uint32::UInt32<F>);

#[cfg(target_pointer_width = "64")]
pub struct USize<F: PrimeField>(pub ark_r1cs_std::uint64::UInt64<F>);

impl<F: PrimeField> USize<F> {
    #[cfg(target_pointer_width = "32")]
    pub fn constant(value: u32) -> USize<F> {
        use ark_r1cs_std::uint32::UInt32;
        USize(UInt32::constant(value))
    }

    #[cfg(target_pointer_width = "64")]
    pub fn constant(value: u64) -> Self {
        use ark_r1cs_std::uint64::UInt64;
        Self(UInt64::constant(value))
    }

    delegate::delegate! {
        to &self.0 {
            #[through(ToBytesGadget::<F>)]
            pub fn to_bytes_le(&self) -> Result<Vec<UInt8<F>>, SynthesisError>;
        }
    }
}
