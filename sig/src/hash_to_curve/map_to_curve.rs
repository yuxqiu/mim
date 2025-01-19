use ark_ec::{hashing::HashToCurveError, CurveGroup};
use ark_ff::PrimeField;
use ark_r1cs_std::fields::FieldVar;

/// Trait for mapping a random field element to a random curve point.
pub trait MapToCurveGadget<T: CurveGroup, CF: PrimeField, FP: FieldVar<T::BaseField, CF>>:
    Sized
{
    /// Checks whether supplied parameters represent a valid map.
    fn check_parameters() -> Result<(), HashToCurveError>;

    /// Map an arbitrary field element to a corresponding curve point.
    fn map_to_curve(point: T::BaseField) -> Result<T::Affine, HashToCurveError>;
}
