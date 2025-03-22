use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::AllocVar, fields::emulated_fp::EmulatedFpVar, prelude::Boolean, uint64::UInt64,
    uint8::UInt8,
};
use ark_relations::r1cs::SynthesisError;
use derivative::Derivative;

use crate::{
    bc::{
        checkpoints::{CheckPoint, QuorumSignature},
        params::{Committee, HASH_OUTPUT_SIZE},
    },
    bls::{PublicKey, PublicKeyVar, SignatureVar},
    params::{BlsSigConfig, BlsSigField},
};

#[derive(Derivative)]
#[derivative(Clone(bound = ""), Debug(bound = ""))]
pub struct SignerVar<CF: PrimeField> {
    pub pk: PublicKeyVar<BlsSigConfig, EmulatedFpVar<BlsSigField<BlsSigConfig>, CF>, CF>,
    pub weight: UInt64<CF>,
}

#[derive(Derivative)]
#[derivative(Clone(bound = ""), Debug(bound = ""))]
pub struct CommitteeVar<CF: PrimeField> {
    pub committee: Vec<SignerVar<CF>>,
}

#[derive(Derivative)]
#[derivative(Clone(bound = ""), Debug(bound = ""))]
pub struct QuorumSignatureVar<CF: PrimeField> {
    pub sig: SignatureVar<BlsSigConfig, EmulatedFpVar<BlsSigField<BlsSigConfig>, CF>, CF>,
    pub signers: Vec<Boolean<CF>>,
}

#[derive(Derivative)]
#[derivative(Clone(bound = ""), Debug(bound = ""))]
pub struct CheckPointVar<CF: PrimeField> {
    pub epoch: UInt64<CF>,

    /// hash to the previous checkpoint
    pub prev_digest: [UInt8<CF>; HASH_OUTPUT_SIZE],

    pub sig: QuorumSignatureVar<CF>,

    /// Present only on the final checkpoint of the epoch.
    pub committee: CommitteeVar<CF>,
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
            pk: PublicKeyVar::new_variable(
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

impl<CF: PrimeField> AllocVar<Committee, CF> for CommitteeVar<CF> {
    fn new_variable<T: std::borrow::Borrow<Committee>>(
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
                    .map(|value| value.borrow().clone())
                    .map_err(SynthesisError::clone)
            },
            mode,
        )?;

        Ok(Self {
            committee: committee_var,
        })
    }
}

impl<CF: PrimeField> AllocVar<QuorumSignature, CF> for QuorumSignatureVar<CF> {
    fn new_variable<T: std::borrow::Borrow<QuorumSignature>>(
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
                    .map(|qsig| qsig.borrow().signers.clone())
                    .map_err(SynthesisError::clone)
            },
            mode,
        )?;

        Ok(Self { sig, signers })
    }
}

impl<CF: PrimeField> AllocVar<CheckPoint, CF> for CheckPointVar<CF> {
    fn new_variable<T: std::borrow::Borrow<CheckPoint>>(
        cs: impl Into<ark_relations::r1cs::Namespace<CF>>,
        f: impl FnOnce() -> Result<T, ark_relations::r1cs::SynthesisError>,
        mode: ark_r1cs_std::prelude::AllocationMode,
    ) -> Result<Self, ark_relations::r1cs::SynthesisError> {
        let cs = cs.into();

        let cp = f();

        let epoch = UInt64::new_variable(
            cs.clone(),
            || {
                cp.as_ref()
                    .map(|cp| cp.borrow().epoch)
                    .map_err(SynthesisError::clone)
            },
            mode,
        )?;

        let prev_digest = AllocVar::<[u8; HASH_OUTPUT_SIZE], CF>::new_variable(
            cs.clone(),
            || {
                cp.as_ref()
                    .map(|cp| cp.borrow().prev_digest)
                    .map_err(SynthesisError::clone)
            },
            mode,
        )?;

        let sig = QuorumSignatureVar::new_variable(
            cs.clone(),
            || {
                cp.as_ref()
                    .map(|cp| cp.borrow().sig.clone())
                    .map_err(SynthesisError::clone)
            },
            mode,
        )?;

        let committee = CommitteeVar::new_variable(
            cs,
            || {
                cp.as_ref()
                    .map(|cp| {
                        let cp = cp.borrow();
                        cp.committee.clone()
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
