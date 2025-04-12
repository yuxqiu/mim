use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::AllocVar, fields::emulated_fp::EmulatedFpVar, prelude::Boolean, uint64::UInt64,
    uint8::UInt8,
};
use ark_relations::r1cs::SynthesisError;
use derivative::Derivative;

use crate::{
    bc::{
        block::{Block, Committee, QuorumSignature},
        params::HASH_OUTPUT_SIZE,
    },
    bls::{PublicKey, PublicKeyVar, SignatureVar},
    params::{BlsSigConfig, BlsSigField},
};

#[derive(Derivative)]
#[derivative(Clone(bound = ""), Debug(bound = ""))]
pub struct SignerVar<CF: PrimeField> {
    /// This field was originally used with on curve check and on prime order subgroup check enabled.
    /// Because of the excessive number of constraints generated, it now disables on these checks.
    /// But it is still safe, and you can see the safety argument in `BlockVar` and `from_constraint_field`
    /// function of `PublicKeyVar`.
    pub pk: PublicKeyVar<BlsSigConfig, EmulatedFpVar<BlsSigField<BlsSigConfig>, CF>, CF>,
    pub weight: UInt64<CF>,
}

#[derive(Derivative)]
#[derivative(Clone(bound = ""), Debug(bound = ""))]
pub struct CommitteeVar<CF: PrimeField, const MAX_COMMITTEE_SIZE: usize> {
    pub committee: Vec<SignerVar<CF>>,
}

#[derive(Derivative)]
#[derivative(Clone(bound = ""), Debug(bound = ""))]
pub struct QuorumSignatureVar<CF: PrimeField> {
    pub sig: SignatureVar<BlsSigConfig, EmulatedFpVar<BlsSigField<BlsSigConfig>, CF>, CF>,
    pub signers: Vec<Boolean<CF>>,
}

/// Copied from `sig/src/bc/block.rs`
#[derive(Derivative)]
#[derivative(Clone(bound = ""), Debug(bound = ""))]
pub struct BlockVar<CF: PrimeField, const MAX_COMMITTEE_SIZE: usize> {
    pub epoch: UInt64<CF>,
    pub prev_digest: [UInt8<CF>; HASH_OUTPUT_SIZE],
    pub sig: QuorumSignatureVar<CF>,

    /// This field was originally used with on curve check and on prime order subgroup check enabled
    /// for every committee member, which significantly grows the number of constraints
    /// (70 million / 90 million constraints for 25 committee member). Right now, `SignerVar` disables
    /// all the checks because the committee/blockchain consensus is responsible for ensuring the security
    /// (pks reside on the curve and the prime order subgroup) of the first committee and new blocks signed
    /// by the majority of the committee.
    pub committee: CommitteeVar<CF, MAX_COMMITTEE_SIZE>,
}

impl<CF: PrimeField> AllocVar<(PublicKey<BlsSigConfig>, u64), CF> for SignerVar<CF> {
    fn new_variable<T: std::borrow::Borrow<(PublicKey<BlsSigConfig>, u64)>>(
        cs: impl Into<ark_relations::r1cs::Namespace<CF>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: ark_r1cs_std::prelude::AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into();
        let signer = f();

        Ok(Self {
            // safety: see above
            pk: PublicKeyVar::new_variable_omit_on_curve_check(
                cs.clone(),
                || {
                    signer
                        .as_ref()
                        .map(|signer| signer.borrow().0)
                        .map_err(SynthesisError::clone)
                },
                mode,
            )?,
            weight: UInt64::new_variable(
                cs,
                || {
                    signer
                        .as_ref()
                        .map(|signer| signer.borrow().1)
                        .map_err(SynthesisError::clone)
                },
                mode,
            )?,
        })
    }
}

impl<CF: PrimeField, const MAX_COMMITTEE_SIZE: usize> AllocVar<Committee<MAX_COMMITTEE_SIZE>, CF>
    for CommitteeVar<CF, MAX_COMMITTEE_SIZE>
{
    fn new_variable<T: std::borrow::Borrow<Committee<MAX_COMMITTEE_SIZE>>>(
        cs: impl Into<ark_relations::r1cs::Namespace<CF>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: ark_r1cs_std::prelude::AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into();

        let committee = f();

        let committee_var = Vec::<SignerVar<CF>>::new_variable(
            cs,
            || {
                committee
                    .as_ref()
                    .map(|value| value.borrow().clone().signers)
                    .map_err(SynthesisError::clone)
            },
            mode,
        )?;

        assert_eq!(
            committee_var.len(),
            MAX_COMMITTEE_SIZE,
            "committee_var must have len == MAX_COMMITTEE_SIZE"
        );

        // similar to `QuorumSignatureVar`, we need to fill committee_var
        //
        // safety: committee_var.len() <= MAX_COMMITTEE_SIZE
        // committee_var.extend(
        //     std::iter::repeat(SignerVar::new_variable(
        //         cs,
        //         // it's ok to use default values as they will not be used
        //         || Ok((PublicKey::default(), u64::default())),
        //         mode,
        //     )?)
        //     .take(MAX_COMMITTEE_SIZE - committee_var.len()),
        // );
        //
        // Update: It's not correct to extend it here. Rather, we need to enforce all the state outside the circuit has
        // fixed size. Otherwise, the hash of those states will never match their circuit counterpart.

        Ok(Self {
            committee: committee_var,
        })
    }
}

impl<CF: PrimeField, const MAX_COMMITTEE_SIZE: usize>
    AllocVar<QuorumSignature<MAX_COMMITTEE_SIZE>, CF> for QuorumSignatureVar<CF>
{
    fn new_variable<T: std::borrow::Borrow<QuorumSignature<MAX_COMMITTEE_SIZE>>>(
        cs: impl Into<ark_relations::r1cs::Namespace<CF>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: ark_r1cs_std::prelude::AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into();

        let quorum_signature = f();

        let sig = SignatureVar::new_variable(
            cs.clone(),
            || {
                quorum_signature
                    .as_ref()
                    .map(|qsig| qsig.borrow().sig)
                    .map_err(SynthesisError::clone)
            },
            mode,
        )?;

        let signers = Vec::<Boolean<CF>>::new_variable(
            cs,
            || {
                quorum_signature
                    .as_ref()
                    .map(|qsig| qsig.borrow().signers)
                    .map_err(SynthesisError::clone)
            },
            mode,
        )?;

        assert_eq!(
            signers.len(),
            MAX_COMMITTEE_SIZE,
            "signers must have len == MAX_COMMITTEE_SIZE"
        );

        // needs to fill it to `MAX_COMMITTEE_SIZE` as the number of constraints needed should be fixed,
        // irrespective of which state it is currently in.
        // - otherwise nova `preprocess` will fail
        //
        // safety: signers.len() <= MAX_COMMITTEE_SIZE
        // signers.extend(
        //     std::iter::repeat(Boolean::new_variable(cs, || Ok(false), mode)?)
        //         .take(MAX_COMMITTEE_SIZE - signers.len()),
        // );
        //
        // Update: It's not correct to extend it here. Rather, we need to enforce all the state outside the circuit has
        // fixed size. Otherwise, the hash of those states will never match their circuit counterpart.

        Ok(Self { sig, signers })
    }
}

impl<CF: PrimeField, const MAX_COMMITTEE_SIZE: usize> AllocVar<Block<MAX_COMMITTEE_SIZE>, CF>
    for BlockVar<CF, MAX_COMMITTEE_SIZE>
{
    fn new_variable<T: std::borrow::Borrow<Block<MAX_COMMITTEE_SIZE>>>(
        cs: impl Into<ark_relations::r1cs::Namespace<CF>>,
        f: impl FnOnce() -> Result<T, ark_relations::r1cs::SynthesisError>,
        mode: ark_r1cs_std::prelude::AllocationMode,
    ) -> Result<Self, ark_relations::r1cs::SynthesisError> {
        let cs = cs.into();

        let block = f();

        let epoch = UInt64::new_variable(
            cs.clone(),
            || {
                block
                    .as_ref()
                    .map(|block| block.borrow().epoch)
                    .map_err(SynthesisError::clone)
            },
            mode,
        )?;

        let prev_digest = AllocVar::<[u8; HASH_OUTPUT_SIZE], CF>::new_variable(
            cs.clone(),
            || {
                block
                    .as_ref()
                    .map(|block| block.borrow().prev_digest)
                    .map_err(SynthesisError::clone)
            },
            mode,
        )?;

        let sig = QuorumSignatureVar::new_variable(
            cs.clone(),
            || {
                block
                    .as_ref()
                    .map(|block| block.borrow().sig.clone())
                    .map_err(SynthesisError::clone)
            },
            mode,
        )?;

        let committee = CommitteeVar::new_variable(
            cs,
            || {
                block
                    .as_ref()
                    .map(|block| {
                        let block = block.borrow();
                        block.committee.clone()
                    })
                    .map_err(SynthesisError::clone)
            },
            mode,
        )?;

        Ok(Self {
            epoch,
            prev_digest,
            sig,
            committee,
        })
    }
}
