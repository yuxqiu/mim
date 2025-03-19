use ark_r1cs_std::{
    alloc::AllocVar, fields::fp::FpVar, groups::bls12::G1Var, prelude::Boolean, uint8::UInt8,
};
use ark_relations::r1cs::SynthesisError;

use crate::{
    bc::{
        checkpoints::{CheckPoint, QuorumSignature},
        params::{Committee, HASH_OUTPUT_SIZE, MAX_COMMITTEE_SIZE},
    },
    bls::{PublicKey, PublicKeyVar, SignatureVar},
    hash::hash_to_field::from_base_field::FromBaseFieldGadget,
    params::{BLSSigCurveConfig, BaseSigCurveField},
};

#[derive(Clone, Debug)]
pub struct SignerVar {
    pub pk: PublicKeyVar<FpVar<BaseSigCurveField>, BaseSigCurveField>,
    // for easy deserialization, we treat weight as FpVar
    pub weight: FpVar<BaseSigCurveField>,
}

#[derive(Clone, Debug)]
pub struct CommitteeVar {
    // for easy deserialization, we treat epoch as FpVar
    pub epoch: FpVar<BaseSigCurveField>,
    pub committee: Vec<SignerVar>,
}

impl FromBaseFieldGadget<BaseSigCurveField>
    for G1Var<BLSSigCurveConfig, FpVar<BaseSigCurveField>, BaseSigCurveField>
{
    type BasePrimeFieldVar = FpVar<BaseSigCurveField>;

    fn num_base_prime_field_var_needed() -> usize {
        FpVar::<BaseSigCurveField>::num_base_prime_field_var_needed() * 3
    }

    fn from_base_prime_field_var(
        mut iter: impl Iterator<Item = Self::BasePrimeFieldVar>,
    ) -> Result<Self, ark_relations::r1cs::SynthesisError> {
        Ok(G1Var::<
            BLSSigCurveConfig,
            FpVar<BaseSigCurveField>,
            BaseSigCurveField,
        >::new(
            FpVar::from_base_prime_field_var(iter.by_ref())?,
            FpVar::from_base_prime_field_var(iter.by_ref())?,
            FpVar::from_base_prime_field_var(iter.by_ref())?,
        ))
    }
}

/// Reconstruct PublicKeyVar from BaseFieldVar
impl FromBaseFieldGadget<BaseSigCurveField>
    for PublicKeyVar<FpVar<BaseSigCurveField>, BaseSigCurveField>
{
    type BasePrimeFieldVar = FpVar<BaseSigCurveField>;

    fn from_base_prime_field_var(
        iter: impl Iterator<Item = Self::BasePrimeFieldVar>,
    ) -> Result<Self, ark_relations::r1cs::SynthesisError> {
        Ok(PublicKeyVar {
            pub_key: G1Var::<BLSSigCurveConfig, FpVar<BaseSigCurveField>, BaseSigCurveField>::from_base_prime_field_var(iter)?,
        })
    }

    fn num_base_prime_field_var_needed() -> usize {
        G1Var::<BLSSigCurveConfig, FpVar<BaseSigCurveField>, BaseSigCurveField>::num_base_prime_field_var_needed()
    }
}

impl FromBaseFieldGadget<BaseSigCurveField> for SignerVar {
    type BasePrimeFieldVar = FpVar<BaseSigCurveField>;

    fn num_base_prime_field_var_needed() -> usize {
        PublicKeyVar::num_base_prime_field_var_needed()
            + FpVar::<BaseSigCurveField>::num_base_prime_field_var_needed()
    }

    fn from_base_prime_field_var(
        mut iter: impl Iterator<Item = Self::BasePrimeFieldVar>,
    ) -> Result<Self, SynthesisError> {
        Ok(SignerVar {
            pk: PublicKeyVar::from_base_prime_field_var(iter.by_ref())?,
            weight: FpVar::from_base_prime_field_var(iter.by_ref())?,
        })
    }
}

impl FromBaseFieldGadget<BaseSigCurveField> for CommitteeVar {
    type BasePrimeFieldVar = FpVar<BaseSigCurveField>;

    fn from_base_prime_field_var(
        mut iter: impl Iterator<Item = Self::BasePrimeFieldVar>,
    ) -> Result<Self, ark_relations::r1cs::SynthesisError> {
        let mut num_consumed = 0;

        let epoch = iter.next().ok_or(SynthesisError::AssignmentMissing)?;

        let mut committee = Vec::new();
        committee.reserve_exact(MAX_COMMITTEE_SIZE as usize);

        let mut iter = iter.peekable();
        while iter.peek().is_some() {
            let signer = SignerVar::from_base_prime_field_var(iter.by_ref())?;
            num_consumed += SignerVar::num_base_prime_field_var_needed();
            committee.push(signer);
        }

        if num_consumed != Self::num_base_prime_field_var_needed() {
            return Err(ark_relations::r1cs::SynthesisError::AssignmentMissing);
        }
        Ok(CommitteeVar { epoch, committee })
    }

    fn num_base_prime_field_var_needed() -> usize {
        (PublicKeyVar::num_base_prime_field_var_needed() + 1) * MAX_COMMITTEE_SIZE as usize
    }
}

impl AllocVar<(PublicKey, u64), BaseSigCurveField> for SignerVar {
    fn new_variable<T: std::borrow::Borrow<(PublicKey, u64)>>(
        cs: impl Into<ark_relations::r1cs::Namespace<BaseSigCurveField>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: ark_r1cs_std::prelude::AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into();
        let signer = f();

        Ok(SignerVar {
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
            weight: FpVar::new_variable(
                cs.clone(),
                || {
                    signer
                        .as_ref()
                        .map(|signer| BaseSigCurveField::from(signer.borrow().1))
                        .map_err(SynthesisError::clone)
                },
                mode,
            )?,
        })
    }
}

impl AllocVar<(u64, Committee), BaseSigCurveField> for CommitteeVar {
    fn new_variable<T: std::borrow::Borrow<(u64, Committee)>>(
        cs: impl Into<ark_relations::r1cs::Namespace<BaseSigCurveField>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: ark_r1cs_std::prelude::AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into();

        let committee = f();

        let epoch = FpVar::new_variable(
            cs.clone(),
            || {
                committee
                    .as_ref()
                    .map(|value| BaseSigCurveField::from(value.borrow().0))
                    .map_err(SynthesisError::clone)
            },
            mode,
        )?;
        let committee_var = Vec::<SignerVar>::new_variable(
            cs.clone(),
            || {
                committee
                    .as_ref()
                    .map(|value| value.borrow().1.clone())
                    .map_err(SynthesisError::clone)
            },
            mode,
        )?;

        Ok(CommitteeVar {
            epoch,
            committee: committee_var,
        })
    }
}

// ToBytesGadget and ToBaseFieldGadget

#[derive(Clone, Debug)]
pub struct QuorumSignatureVar {
    pub sig: SignatureVar<FpVar<BaseSigCurveField>, BaseSigCurveField>,
    pub signers: Vec<Boolean<BaseSigCurveField>>,
}

impl AllocVar<QuorumSignature, BaseSigCurveField> for QuorumSignatureVar {
    fn new_variable<T: std::borrow::Borrow<QuorumSignature>>(
        cs: impl Into<ark_relations::r1cs::Namespace<BaseSigCurveField>>,
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
        let signers = Vec::<Boolean<BaseSigCurveField>>::new_variable(
            cs.clone(),
            || {
                quorum_signature
                    .as_ref()
                    .map(|qsig| qsig.borrow().signers.clone())
                    .map_err(SynthesisError::clone)
            },
            mode,
        )?;

        Ok(QuorumSignatureVar { sig, signers })
    }
}

#[derive(Clone, Debug)]
pub struct CheckPointVar {
    // copy checkpoint struct
    pub epoch: FpVar<BaseSigCurveField>,

    /// hash to the previous checkpoint
    pub prev_digest: [UInt8<BaseSigCurveField>; HASH_OUTPUT_SIZE],

    pub sig: QuorumSignatureVar,

    /// Present only on the final checkpoint of the epoch.
    pub committee: CommitteeVar,
}

impl AllocVar<CheckPoint, BaseSigCurveField> for CheckPointVar {
    fn new_variable<T: std::borrow::Borrow<CheckPoint>>(
        cs: impl Into<ark_relations::r1cs::Namespace<BaseSigCurveField>>,
        f: impl FnOnce() -> Result<T, ark_relations::r1cs::SynthesisError>,
        mode: ark_r1cs_std::prelude::AllocationMode,
    ) -> Result<Self, ark_relations::r1cs::SynthesisError> {
        let cs = cs.into();

        let cp = f();

        let epoch = FpVar::new_variable(
            cs.clone(),
            || {
                cp.as_ref()
                    .map(|cp| BaseSigCurveField::from(cp.borrow().epoch))
                    .map_err(SynthesisError::clone)
            },
            mode,
        )?;

        let prev_digest = AllocVar::<[u8; HASH_OUTPUT_SIZE], BaseSigCurveField>::new_variable(
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
            cs.clone(),
            || {
                cp.as_ref()
                    .map(|cp| {
                        let cp = cp.borrow();
                        (cp.epoch, cp.committee.clone())
                    })
                    .map_err(SynthesisError::clone)
            },
            mode,
        )?;

        Ok(CheckPointVar {
            epoch,
            prev_digest,
            sig,
            committee,
        })
    }
}
