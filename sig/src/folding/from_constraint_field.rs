use ark_ff::PrimeField;
use ark_r1cs_std::{
    fields::{
        emulated_fp::{
            params::{get_params, OptimizationType},
            AllocatedEmulatedFpVar, EmulatedFpVar,
        },
        fp::FpVar,
    },
    groups::bls12::G1Var,
    uint64::UInt64,
    R1CSVar,
};
use ark_relations::r1cs::SynthesisError;

use crate::{
    bc::params::MAX_COMMITTEE_SIZE,
    bls::PublicKeyVar,
    params::{BlsSigConfig, BlsSigField},
};

use super::bc::{CommitteeVar, SignerVar};

/// Specifies how to convert from `Vec<FpVar<ConstraintF>>` to `Self`
///
/// It should be able to interrop with `ToConstraintFieldGadget` trait to support serialization and deserialization for any variable.
pub trait FromConstraintFieldGadget<CF: PrimeField>: Sized {
    fn num_constraint_var_needed() -> usize;

    /// Converts from `Vec<FpVar<ConstraintF>>` to `Self`.
    fn from_constraint_field(iter: impl Iterator<Item = FpVar<CF>>)
        -> Result<Self, SynthesisError>;
}

impl<CF: PrimeField> FromConstraintFieldGadget<CF> for UInt64<CF> {
    fn from_constraint_field(
        mut iter: impl Iterator<Item = FpVar<CF>>,
    ) -> Result<Self, SynthesisError> {
        let (num, _) = Self::from_fp(&iter.next().ok_or(SynthesisError::Unsatisfiable)?)?;
        Ok(num)
    }

    fn num_constraint_var_needed() -> usize {
        1
    }
}

impl<CF: PrimeField> FromConstraintFieldGadget<CF>
    for EmulatedFpVar<BlsSigField<BlsSigConfig>, CF>
{
    fn from_constraint_field(
        iter: impl Iterator<Item = FpVar<CF>>,
    ) -> Result<Self, SynthesisError> {
        // `OptimizationType::Weight` is used because it results in fewer constraint field elements
        let params = get_params(
            <BlsSigField<BlsSigConfig> as PrimeField>::MODULUS_BIT_SIZE as usize,
            CF::MODULUS_BIT_SIZE as usize,
            OptimizationType::Weight,
        );

        let limbs = Vec::from_iter(iter.take(params.num_limbs));

        // `to_constraint_field` promises to give a normal repr of EmulatedFpVar
        Ok(Self::Var(AllocatedEmulatedFpVar {
            cs: limbs.cs(),
            limbs,
            num_of_additions_over_normal_form: CF::zero(),
            is_in_the_normal_form: true,
            target_phantom: std::marker::PhantomData,
        }))
    }

    fn num_constraint_var_needed() -> usize {
        let params = get_params(
            <BlsSigField<BlsSigConfig> as PrimeField>::MODULUS_BIT_SIZE as usize,
            CF::MODULUS_BIT_SIZE as usize,
            OptimizationType::Weight,
        );
        params.num_limbs
    }
}

impl<CF: PrimeField> FromConstraintFieldGadget<CF>
    for PublicKeyVar<BlsSigConfig, EmulatedFpVar<BlsSigField<BlsSigConfig>, CF>, CF>
{
    fn from_constraint_field(
        mut iter: impl Iterator<Item = FpVar<CF>>,
    ) -> Result<Self, SynthesisError> {
        // There are no checks to ensure this point is on the curve and the prime order subgroup.
        // This is safe because all the reconstructed `PublicKeyVar` are either public input or
        // signed by some committee. Since the committee is the trusted base of the safety of the circuit,
        // we don't need to perform additional check here.
        Ok(Self {
            pub_key: G1Var::<BlsSigConfig, EmulatedFpVar<BlsSigField<BlsSigConfig>, CF>, CF>::new(
                EmulatedFpVar::from_constraint_field(iter.by_ref())?,
                EmulatedFpVar::from_constraint_field(iter.by_ref())?,
                EmulatedFpVar::from_constraint_field(iter.by_ref())?,
            ),
        })
    }

    fn num_constraint_var_needed() -> usize {
        3 * EmulatedFpVar::<BlsSigField<BlsSigConfig>, CF>::num_constraint_var_needed()
    }
}

// Failed Attempt. The following adds slightly more constraints in total.
//
// impl<CF: PrimeField> FromConstraintFieldGadget<CF> for Boolean<CF> {
//     fn from_constraint_field(
//         mut iter: impl Iterator<Item = FpVar<CF>>,
//     ) -> Result<Self, SynthesisError> {
//         let fp = iter.next().ok_or(SynthesisError::Unsatisfiable)?;
//         // safety: `unwrap` is safe to call because FpVar is composed of one or more bits
//         //
//         // Here, it seems that we trade off state size vs. num of constraints.
//         // But, reducing state sizes can greatly help reduce the num of constraints as folding scheme (Nova)
//         // needs to compute commitment on the witnesses (states).
//         Ok(fp.to_non_unique_bits_le()?.into_iter().next().unwrap())
//     }

//     fn num_constraint_var_needed() -> usize {
//         1
//     }
// }

impl<CF: PrimeField> FromConstraintFieldGadget<CF> for SignerVar<CF> {
    fn from_constraint_field(
        mut iter: impl Iterator<Item = FpVar<CF>>,
    ) -> Result<Self, SynthesisError> {
        Ok(Self {
            pk: PublicKeyVar::from_constraint_field(iter.by_ref())?,
            weight: UInt64::from_constraint_field(iter.by_ref())?,
        })
    }

    fn num_constraint_var_needed() -> usize {
        PublicKeyVar::<BlsSigConfig, EmulatedFpVar<BlsSigField<BlsSigConfig>, CF>, CF>::num_constraint_var_needed() + UInt64::<CF>::num_constraint_var_needed()
    }
}

impl<CF: PrimeField> FromConstraintFieldGadget<CF> for CommitteeVar<CF> {
    fn from_constraint_field(
        mut iter: impl Iterator<Item = FpVar<CF>>,
    ) -> Result<Self, SynthesisError> {
        let mut committee = Vec::new();
        committee.reserve_exact(MAX_COMMITTEE_SIZE);

        for _ in 0..MAX_COMMITTEE_SIZE {
            let signer = SignerVar::from_constraint_field(iter.by_ref())?;
            committee.push(signer);
        }

        Ok(Self { committee })
    }

    fn num_constraint_var_needed() -> usize {
        SignerVar::<CF>::num_constraint_var_needed() * MAX_COMMITTEE_SIZE
    }
}
