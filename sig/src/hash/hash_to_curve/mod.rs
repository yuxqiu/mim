mod cofactor;

use ark_ec::{short_weierstrass::SWCurveConfig, CurveGroup};
use ark_ff::PrimeField;
use ark_r1cs_std::{
    fields::{FieldOpsBounds, FieldVar},
    groups::curves::short_weierstrass::ProjectiveVar,
    uint8::UInt8,
};
use ark_relations::r1cs::SynthesisError;
use ark_std::marker::PhantomData;

use super::{hash_to_field::HashToFieldGadget, map_to_curve::MapToCurveGadget};
use cofactor::CofactorGadget;

/// Helper struct that can be used to construct elements on the elliptic curve
/// from arbitrary messages, by first hashing the message onto a field element
/// and then mapping it to the elliptic curve defined over that field.
pub struct MapToCurveBasedHasherGadget<T, H2F, M2C, CF, FP>
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

impl<T, H2F, M2C, CF, FP> MapToCurveBasedHasherGadget<T, H2F, M2C, CF, FP>
where
    T: CurveGroup + CofactorGadget<FP, CF>,
    H2F: HashToFieldGadget<T::BaseField, CF, FP>,
    M2C: MapToCurveGadget<T, CF, FP>,
    CF: PrimeField,
    FP: FieldVar<T::BaseField, CF>,
    for<'a> &'a FP: FieldOpsBounds<'a, <T as CurveGroup>::BaseField, FP>,
    <T as CurveGroup>::Config: SWCurveConfig,
{
    #[must_use] pub fn new(domain: &[UInt8<CF>]) -> Self {
        Self {
            field_hasher: H2F::new(domain),
            _phantom: PhantomData,
        }
    }

    /// Produce a hash of the message, using the hash to field and map to curve
    /// traits. This uses the IETF hash to curve's specification for Random
    /// oracle encoding (hash_to_curve) defined by combining these components.
    /// See <https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-09#section-3>
    pub fn hash(
        &self,
        msg: &[UInt8<CF>],
    ) -> Result<ProjectiveVar<T::Config, FP, CF>, SynthesisError>
    where
        <T as CurveGroup>::Config: SWCurveConfig,
        for<'a> &'a FP: FieldOpsBounds<'a, <T as CurveGroup>::BaseField, FP>,
    {
        // IETF spec of hash_to_curve, from hash_to_field and map_to_curve
        // sub-components
        // 1. u = hash_to_field(msg, 2)
        // 2. Q0 = map_to_curve(u[0])
        // 3. Q1 = map_to_curve(u[1])
        // 4. R = Q0 + Q1              # Point addition
        // 5. P = clear_cofactor(R)
        // 6. return P

        let rand_field_elems = self.field_hasher.hash_to_field::<2>(msg)?;

        let rand_curve_elem_0 = M2C::map_to_curve(rand_field_elems[0].clone())?;
        let rand_curve_elem_1 = M2C::map_to_curve(rand_field_elems[1].clone())?;

        let rand_curve_elem_0 = ProjectiveVar::new(
            rand_curve_elem_0.x,
            rand_curve_elem_0.y,
            // z = 0 encodes infinity
            rand_curve_elem_0.infinity.select(&FP::zero(), &FP::one())?,
        );

        let rand_curve_elem_1 = ProjectiveVar::new(
            rand_curve_elem_1.x,
            rand_curve_elem_1.y,
            // z = 0 encodes infinity
            rand_curve_elem_1.infinity.select(&FP::zero(), &FP::one())?,
        );

        // cannot simply use `+` here as it internally checks that the point is is_in_correct_subgroup_assuming_on_curve
        // let rand_subgroup_elem = rand_curve_elem_0 + rand_curve_elem_1;
        let rand_curve_elem = rand_curve_elem_0.add_unchecked(&rand_curve_elem_1);

        // The corresponding cofactor clearing method is different from simply multiplying by cofactor.
        // It's based on endomorphism, which still clears the cofactor but yields a different element in the curve group.
        //
        // That's why the assertion is not failing after I commented off the `clear_cofactor` function
        // `ark-bls12-381-0.5.0/src/curves/g2.rs`.
        //
        // rand_subgroup_elem.clear_cofactor()
        T::clear_cofactor_var(&rand_curve_elem)
    }
}

#[cfg(test)]
mod test {
    use ark_crypto_primitives::prf::blake2s::constraints::Blake2sGadget;
    use ark_ec::{
        hashing::{curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher, HashToCurve},
        CurveConfig, CurveGroup,
    };
    use ark_ff::{field_hashers::DefaultFieldHasher, Field};
    use ark_r1cs_std::{alloc::AllocVar, fields::fp2::Fp2Var, uint8::UInt8, R1CSVar};
    use ark_relations::r1cs::ConstraintSystem;
    use blake2::Blake2s256;
    use rand::{thread_rng, RngCore};

    use crate::hash::{
        hash_to_curve::MapToCurveBasedHasherGadget,
        hash_to_field::default_hasher::DefaultFieldHasherGadget, map_to_curve::wb::WBMapGadget,
    };

    macro_rules! generate_hash_to_curve_tests {
        ($test_name:ident, $field_var:ty, $curve:ty) => {
            #[test]
            fn $test_name() {
                type BaseField = <<$curve as CurveGroup>::Config as CurveConfig>::BaseField;
                type BasePrimeField = <BaseField as Field>::BasePrimeField;

                type FieldHasher = DefaultFieldHasher<Blake2s256, 128>;
                type CurveMap = WBMap<<$curve as CurveGroup>::Config>;
                type Hasher = MapToCurveBasedHasher<$curve, FieldHasher, CurveMap>;

                type FieldHasherGadget = DefaultFieldHasherGadget<
                    Blake2sGadget<BasePrimeField>,
                    BaseField,
                    BasePrimeField,
                    $field_var,
                    128,
                >;
                type CurveMapGadget = WBMapGadget<<$curve as CurveGroup>::Config>;
                type HasherGadget = MapToCurveBasedHasherGadget<
                    $curve,
                    FieldHasherGadget,
                    CurveMapGadget,
                    BasePrimeField,
                    $field_var,
                >;

                fn test_constant() {
                    let mut rng = thread_rng();

                    {
                        // test zero
                        let hasher = Hasher::new(&[]).unwrap();
                        let hasher_gadget = HasherGadget::new(&[]);

                        let zero = [0u8];
                        let zero_var = zero.map(UInt8::constant);
                        let htc_zero = hasher.hash(&zero).unwrap();
                        let htc_zero_var = hasher_gadget.hash(&zero_var).unwrap();

                        assert_eq!(htc_zero_var.value().unwrap(), htc_zero);
                        assert!(htc_zero_var.x.is_constant());
                        assert!(htc_zero_var.y.is_constant());
                    }

                    {
                        // test one
                        let hasher = Hasher::new(&[]).unwrap();
                        let hasher_gadget = HasherGadget::new(&[]);

                        let one = [1u8];
                        let one_var = one.map(UInt8::constant);
                        let htc_one = hasher.hash(&one).unwrap();
                        let htc_one_var = hasher_gadget.hash(&one_var).unwrap();

                        assert_eq!(htc_one_var.value().unwrap(), htc_one);
                        assert!(htc_one_var.x.is_constant());
                        assert!(htc_one_var.y.is_constant());
                    }

                    {
                        // test random
                        let hasher = Hasher::new(&[]).unwrap();
                        let hasher_gadget = HasherGadget::new(&[]);

                        let rand_len = rng.next_u32() as u16;
                        let mut r = vec![0; rand_len as usize];
                        rng.fill_bytes(&mut r);
                        let r_var: Vec<_> = r.iter().copied().map(UInt8::constant).collect();
                        let htc_one = hasher.hash(&r).unwrap();
                        let htc_one_var = hasher_gadget.hash(&r_var).unwrap();

                        assert_eq!(htc_one_var.value().unwrap(), htc_one);
                        assert!(htc_one_var.x.is_constant());
                        assert!(htc_one_var.y.is_constant());
                    }
                }

                fn test_input() {
                    let mut rng = thread_rng();

                    {
                        // test zero
                        let hasher = Hasher::new(&[]).unwrap();
                        let hasher_gadget = HasherGadget::new(&[]);
                        let cs = ConstraintSystem::new_ref();

                        let zero = [0u8];
                        let zero_var =
                            zero.map(|value| UInt8::new_input(cs.clone(), || Ok(value)).unwrap());
                        let htc_zero = hasher.hash(&zero).unwrap();
                        let htc_zero_var = hasher_gadget.hash(&zero_var).unwrap();

                        assert_eq!(htc_zero_var.value().unwrap(), htc_zero);
                        assert!(cs.is_satisfied().unwrap());
                    }

                    {
                        // test one
                        let hasher = Hasher::new(&[]).unwrap();
                        let hasher_gadget = HasherGadget::new(&[]);
                        let cs = ConstraintSystem::new_ref();

                        let one = [1u8];
                        let one_var =
                            one.map(|value| UInt8::new_input(cs.clone(), || Ok(value)).unwrap());
                        let htc_one = hasher.hash(&one).unwrap();
                        let htc_one_var = hasher_gadget.hash(&one_var).unwrap();

                        assert_eq!(htc_one_var.value().unwrap(), htc_one);
                        assert!(cs.is_satisfied().unwrap());
                    }

                    {
                        // test random
                        let hasher = Hasher::new(&[]).unwrap();
                        let hasher_gadget = HasherGadget::new(&[]);
                        let cs = ConstraintSystem::new_ref();

                        // rand_len has to be small to allow this to run on consumer machine
                        let rand_len = rng.next_u32() as u8;
                        let mut r = vec![0; rand_len as usize];
                        rng.fill_bytes(&mut r);
                        let r_var: Vec<_> = r
                            .iter()
                            .copied()
                            .map(|value| UInt8::new_input(cs.clone(), || Ok(value)).unwrap())
                            .collect();
                        let htc_one = hasher.hash(&r).unwrap();
                        let htc_one_var = hasher_gadget.hash(&r_var).unwrap();

                        assert_eq!(htc_one_var.value().unwrap(), htc_one);
                        assert!(cs.is_satisfied().unwrap());
                    }
                }

                test_constant();
                test_input();
            }
        };
    }

    generate_hash_to_curve_tests!(
        test_hash_to_curve_bls12_381_g2,
        Fp2Var<ark_bls12_381::Fq2Config>,
        ark_bls12_381::G2Projective
    );

    generate_hash_to_curve_tests!(
        test_hash_to_curve_bls12_377_g2,
        Fp2Var<ark_bls12_377::Fq2Config>,
        ark_bls12_377::G2Projective
    );
}
