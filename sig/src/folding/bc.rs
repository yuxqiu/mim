use ark_r1cs_std::{
    alloc::AllocVar, convert::ToConstraintFieldGadget, fields::fp::FpVar, groups::bls12::G1Var,
    prelude::Boolean, uint64::UInt64, uint8::UInt8,
};
use ark_relations::r1cs::SynthesisError;

use crate::{
    bc::{
        checkpoints::{CheckPoint, QuorumSignature},
        params::{Committee, HASH_OUTPUT_SIZE, MAX_COMMITTEE_SIZE},
    },
    bls::{PublicKey, PublicKeyVar, SignatureVar},
    hash::{
        hash_to_field::from_base_field::FromBaseFieldVarGadget,
        map_to_curve::to_base_field::ToBaseFieldVarGadget,
    },
    params::{BLSSigCurveConfig, BaseSigCurveField},
};

#[derive(Clone, Debug)]
pub struct SignerVar {
    pub pk: PublicKeyVar<FpVar<BaseSigCurveField>, BaseSigCurveField>,
    pub weight: UInt64<BaseSigCurveField>,
}

#[derive(Clone, Debug)]
pub struct CommitteeVar {
    pub committee: Vec<SignerVar>,
}

impl FromBaseFieldVarGadget<BaseSigCurveField> for UInt64<BaseSigCurveField> {
    type BasePrimeFieldVar = FpVar<BaseSigCurveField>;

    fn from_base_field_var(
        mut iter: impl Iterator<Item = Self::BasePrimeFieldVar>,
    ) -> Result<Self, SynthesisError> {
        let next = iter.next().ok_or(SynthesisError::Unsatisfiable)?;
        UInt64::from_fp(&next).map(|value| value.0)
    }

    const NUM_BASE_FIELD_VAR_NEEDED: usize = 1;
}

impl FromBaseFieldVarGadget<BaseSigCurveField>
    for G1Var<BLSSigCurveConfig, FpVar<BaseSigCurveField>, BaseSigCurveField>
{
    type BasePrimeFieldVar = FpVar<BaseSigCurveField>;

    fn from_base_field_var(
        mut iter: impl Iterator<Item = Self::BasePrimeFieldVar>,
    ) -> Result<Self, ark_relations::r1cs::SynthesisError> {
        Ok(G1Var::<
            BLSSigCurveConfig,
            FpVar<BaseSigCurveField>,
            BaseSigCurveField,
        >::new(
            FpVar::from_base_field_var(iter.by_ref())?,
            FpVar::from_base_field_var(iter.by_ref())?,
            FpVar::from_base_field_var(iter.by_ref())?,
        ))
    }

    const NUM_BASE_FIELD_VAR_NEEDED: usize =
        FpVar::<BaseSigCurveField>::NUM_BASE_FIELD_VAR_NEEDED * 3;
}

/// Reconstruct PublicKeyVar from BaseFieldVar
impl FromBaseFieldVarGadget<BaseSigCurveField>
    for PublicKeyVar<FpVar<BaseSigCurveField>, BaseSigCurveField>
{
    type BasePrimeFieldVar = FpVar<BaseSigCurveField>;

    fn from_base_field_var(
        iter: impl Iterator<Item = Self::BasePrimeFieldVar>,
    ) -> Result<Self, ark_relations::r1cs::SynthesisError> {
        Ok(PublicKeyVar {
            pub_key: G1Var::<BLSSigCurveConfig, FpVar<BaseSigCurveField>, BaseSigCurveField>::from_base_field_var(iter)?,
        })
    }

    const NUM_BASE_FIELD_VAR_NEEDED: usize = G1Var::<
        BLSSigCurveConfig,
        FpVar<BaseSigCurveField>,
        BaseSigCurveField,
    >::NUM_BASE_FIELD_VAR_NEEDED;
}

impl FromBaseFieldVarGadget<BaseSigCurveField> for SignerVar {
    type BasePrimeFieldVar = FpVar<BaseSigCurveField>;

    fn from_base_field_var(
        mut iter: impl Iterator<Item = Self::BasePrimeFieldVar>,
    ) -> Result<Self, SynthesisError> {
        Ok(SignerVar {
            pk: PublicKeyVar::from_base_field_var(iter.by_ref())?,
            weight: UInt64::from_base_field_var(iter.by_ref())?,
        })
    }

    const NUM_BASE_FIELD_VAR_NEEDED: usize = PublicKeyVar::NUM_BASE_FIELD_VAR_NEEDED
        + FpVar::<BaseSigCurveField>::NUM_BASE_FIELD_VAR_NEEDED;
}

impl FromBaseFieldVarGadget<BaseSigCurveField> for CommitteeVar {
    type BasePrimeFieldVar = FpVar<BaseSigCurveField>;

    fn from_base_field_var(
        iter: impl Iterator<Item = Self::BasePrimeFieldVar>,
    ) -> Result<Self, ark_relations::r1cs::SynthesisError> {
        let mut num_consumed = 0;

        let mut committee = Vec::new();
        committee.reserve_exact(MAX_COMMITTEE_SIZE as usize);

        let mut iter = iter.peekable();
        while iter.peek().is_some() && num_consumed < Self::NUM_BASE_FIELD_VAR_NEEDED {
            let signer = SignerVar::from_base_field_var(iter.by_ref())?;
            num_consumed += SignerVar::NUM_BASE_FIELD_VAR_NEEDED;
            committee.push(signer);
        }

        if num_consumed != Self::NUM_BASE_FIELD_VAR_NEEDED {
            return Err(ark_relations::r1cs::SynthesisError::Unsatisfiable);
        }
        Ok(CommitteeVar { committee })
    }

    const NUM_BASE_FIELD_VAR_NEEDED: usize =
        SignerVar::NUM_BASE_FIELD_VAR_NEEDED * MAX_COMMITTEE_SIZE as usize;
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
            weight: UInt64::new_variable(
                cs.clone(),
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

impl AllocVar<Committee, BaseSigCurveField> for CommitteeVar {
    fn new_variable<T: std::borrow::Borrow<Committee>>(
        cs: impl Into<ark_relations::r1cs::Namespace<BaseSigCurveField>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: ark_r1cs_std::prelude::AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into();

        let committee = f();

        let committee_var = Vec::<SignerVar>::new_variable(
            cs.clone(),
            || {
                committee
                    .as_ref()
                    .map(|value| value.borrow().clone())
                    .map_err(SynthesisError::clone)
            },
            mode,
        )?;

        Ok(CommitteeVar {
            committee: committee_var,
        })
    }
}

impl ToBaseFieldVarGadget<BaseSigCurveField, BaseSigCurveField>
    for PublicKeyVar<FpVar<BaseSigCurveField>, BaseSigCurveField>
{
    type BasePrimeFieldVar = FpVar<BaseSigCurveField>;

    fn to_base_field_vars(&self) -> Result<Vec<Self::BasePrimeFieldVar>, SynthesisError> {
        // as we are on native field, we can directly reuse existing trait
        self.pub_key.to_constraint_field()
    }
}

impl ToBaseFieldVarGadget<BaseSigCurveField, BaseSigCurveField> for SignerVar {
    type BasePrimeFieldVar = FpVar<BaseSigCurveField>;

    fn to_base_field_vars(&self) -> Result<Vec<Self::BasePrimeFieldVar>, SynthesisError> {
        let mut pk = self.pk.to_base_field_vars()?;
        let weight = self.weight.to_fp()?;
        pk.push(weight);
        Ok(pk)
    }
}

impl ToBaseFieldVarGadget<BaseSigCurveField, BaseSigCurveField> for CommitteeVar {
    type BasePrimeFieldVar = FpVar<BaseSigCurveField>;

    fn to_base_field_vars(&self) -> Result<Vec<Self::BasePrimeFieldVar>, SynthesisError> {
        let mut committee = Vec::new();

        for signer in &self.committee {
            committee.extend(signer.to_base_field_vars()?);
        }

        Ok(committee)
    }
}

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
    pub epoch: UInt64<BaseSigCurveField>,

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

        let epoch = UInt64::new_variable(
            cs.clone(),
            || {
                cp.as_ref()
                    .map(|cp| cp.borrow().epoch)
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
                        cp.committee.clone()
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
