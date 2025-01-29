use ark_ec::{short_weierstrass::SWCurveConfig, CurveConfig, CurveGroup};
use ark_ff::{BigInteger, BigInteger64, PrimeField};
use ark_r1cs_std::{
    fields::{FieldOpsBounds, FieldVar},
    groups::{
        curves::short_weierstrass::{AffineVar, ProjectiveVar},
        CurveVar,
    },
    prelude::Boolean,
    uint8::UInt8,
};
use ark_relations::r1cs::SynthesisError;
use ark_std::marker::PhantomData;

use super::{hash_to_field::HashToFieldGadget, map_to_curve::MapToCurveGadget};

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
    T: CurveGroup,
    H2F: HashToFieldGadget<T::BaseField, CF, FP>,
    M2C: MapToCurveGadget<T, CF, FP>,
    CF: PrimeField,
    FP: FieldVar<T::BaseField, CF>,
{
    fn new(domain: &[UInt8<CF>]) -> Self {
        Self {
            field_hasher: H2F::new(&domain),
            _phantom: PhantomData,
        }
    }

    /// Produce a hash of the message, using the hash to field and map to curve
    /// traits. This uses the IETF hash to curve's specification for Random
    /// oracle encoding (hash_to_curve) defined by combining these components.
    /// See <https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-09#section-3>
    fn hash(&self, msg: &[UInt8<CF>]) -> Result<AffineVar<T::Config, FP, CF>, SynthesisError>
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

        // rand_subgroup_elem.clear_cofactor()
        let cofactor_bits: Vec<_> = T::Config::COFACTOR
            .iter()
            .flat_map(|value| {
                BigInteger64::from(*value)
                    .to_bits_le()
                    .into_iter()
                    .map(Boolean::constant)
            })
            .collect();

        // It's even wrong when I switched to a generic implementation. I tested `double_in_place`, it should be correct.
        // At the same time, `+` should also be correct as the above rand_curve_elem is correctly calculated.
        // - I should probably test cofactor_bits.
        // - log every step of the calculation
        //
        // TODO: uncomment SWAffine check
        let rand_subgroup_elem = rand_curve_elem.scalar_mul_le(cofactor_bits.iter())?;
        println!("rse-0: {:?}", rand_subgroup_elem.to_affine_unchecked());

        rand_subgroup_elem.to_affine()
    }
}

#[cfg(test)]
mod test {
    use ark_bls12_381::{Fq, G2Projective};
    use ark_crypto_primitives::prf::blake2s::constraints::Blake2sGadget;
    use ark_ec::{
        hashing::{curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher, HashToCurve},
        CurveConfig,
    };
    use ark_ff::{field_hashers::DefaultFieldHasher, Field};
    use ark_r1cs_std::{fields::fp2::Fp2Var, uint8::UInt8, R1CSVar};
    use blake2::Blake2s256;
    use rand::{thread_rng, RngCore};

    use crate::hash::{
        hash_to_curve::MapToCurveBasedHasherGadget,
        hash_to_field::default_hasher::DefaultFieldHasherGadget, map_to_curve::wb::WBMapGadget,
    };

    #[test]
    fn test_hash_to_curve_constant() {
        type BaseField = <ark_bls12_381::g2::Config as CurveConfig>::BaseField;
        type BasePrimeField = <BaseField as Field>::BasePrimeField;

        type FieldHasher = DefaultFieldHasher<Blake2s256, 128>;
        type CurveMap = WBMap<ark_bls12_381::g2::Config>;
        type Hasher = MapToCurveBasedHasher<G2Projective, FieldHasher, CurveMap>;

        type FieldHasherGadget = DefaultFieldHasherGadget<
            Blake2sGadget<Fq>,
            BaseField,
            BasePrimeField,
            Fp2Var<ark_bls12_381::Fq2Config>,
            128,
        >;
        type CurveMapGadget = WBMapGadget<ark_bls12_381::g2::Config>;
        type HasherGadget = MapToCurveBasedHasherGadget<
            G2Projective,
            FieldHasherGadget,
            CurveMapGadget,
            BasePrimeField,
            Fp2Var<ark_bls12_381::Fq2Config>,
        >;

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
            // test one
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
}
