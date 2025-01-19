use ark_ec::{hashing::HashToCurveError, CurveGroup};
use ark_ff::{field_hashers::HashToField, PrimeField};
use ark_r1cs_std::fields::FieldVar;
use ark_std::marker::PhantomData;

use super::{HashToFieldGadget, MapToCurveGadget};

/// Helper struct that can be used to construct elements on the elliptic curve
/// from arbitrary messages, by first hashing the message onto a field element
/// and then mapping it to the elliptic curve defined over that field.
pub struct MapToCurveBasedHasher<T, H2F, M2C, CF, FP>
where
    T: CurveGroup,
    H2F: HashToFieldGadget<T::BaseField, CF, FP>,
    M2C: MapToCurveGadget<T, CF, FP>,
    CF: PrimeField,
    FP: FieldVar<T::BaseField, CF>,
{
    field_hasher: H2F,
    _phantom: PhantomData<(T, M2C, CF, FP)>,
}

// impl<T, H2F, M2C, CF, FP> MapToCurveBasedHasher<T, H2F, M2C, CF, FP>
// where
//     T: CurveGroup,
//     H2F: HashToFieldGadget<T::BaseField, CF, FP>,
//     M2C: MapToCurveGadget<T>,
//     CF: PrimeField,
//     FP: FieldVar<T::BaseField, CF>,
// {
//     fn new(domain: &[u8]) -> Result<Self, HashToCurveError> {
//         #[cfg(test)]
//         M2C::check_parameters()?;
//         Ok(MapToCurveBasedHasher {
//             field_hasher: H2F::new(domain),
//             _phantom: PhantomData,
//         })
//     }

//     /// Produce a hash of the message, using the hash to field and map to curve
//     /// traits. This uses the IETF hash to curve's specification for Random
//     /// oracle encoding (hash_to_curve) defined by combining these components.
//     /// See <https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-09#section-3>
//     fn hash(&self, msg: &[u8]) -> Result<T::Affine, HashToCurveError> {
//         // IETF spec of hash_to_curve, from hash_to_field and map_to_curve
//         // sub-components
//         // 1. u = hash_to_field(msg, 2)
//         // 2. Q0 = map_to_curve(u[0])
//         // 3. Q1 = map_to_curve(u[1])
//         // 4. R = Q0 + Q1              # Point addition
//         // 5. P = clear_cofactor(R)
//         // 6. return P

//         let rand_field_elems = self.field_hasher.hash_to_field::<2>(msg);

//         let rand_curve_elem_0 = M2C::map_to_curve(rand_field_elems[0])?;
//         let rand_curve_elem_1 = M2C::map_to_curve(rand_field_elems[1])?;

//         let rand_curve_elem = (rand_curve_elem_0 + rand_curve_elem_1).into();
//         let rand_subgroup_elem = rand_curve_elem.clear_cofactor();

//         Ok(rand_subgroup_elem)
//     }
// }
