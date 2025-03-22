use ark_ff::PrimeField;
use ark_r1cs_std::{
    fields::emulated_fp::EmulatedFpVar,
    prelude::{Boolean, ToBytesGadget},
    uint64::UInt64,
    uint8::UInt8,
};
use ark_relations::r1cs::SynthesisError;

use crate::{
    bls::{PublicKeyVar, SignatureVar},
    params::{BlsSigConfig, BlsSigField},
};

use super::{
    bc::{CheckPointVar, CommitteeVar, QuorumSignatureVar, SignerVar},
    params::USize,
};

/// Serialize a R1CS variable to a canonical byte representation
/// Implementation should match the result of `bincode::serialize`.
pub trait SerializeGadget<F: PrimeField> {
    fn serialize(&self) -> Result<Vec<UInt8<F>>, SynthesisError>;
}

impl<CF: PrimeField> SerializeGadget<CF> for UInt8<CF> {
    fn serialize(&self) -> Result<Vec<UInt8<CF>>, SynthesisError> {
        self.to_bytes_le()
    }
}

impl<CF: PrimeField> SerializeGadget<CF> for USize<CF> {
    fn serialize(&self) -> Result<Vec<UInt8<CF>>, SynthesisError> {
        self.to_bytes_le()
    }
}

impl<CF: PrimeField> SerializeGadget<CF> for UInt64<CF> {
    fn serialize(&self) -> Result<Vec<UInt8<CF>>, SynthesisError> {
        self.to_bytes_le()
    }
}

/// We cannot implement the following three gadgets as a generic over `T: SerializeGadget<F>` because
/// what's right for boolean is not right for others.
impl<CF: PrimeField> SerializeGadget<CF> for [Boolean<CF>] {
    fn serialize(&self) -> Result<Vec<UInt8<CF>>, SynthesisError> {
        self.to_bytes_le()
    }
}

impl<CF: PrimeField> SerializeGadget<CF> for [UInt8<CF>] {
    fn serialize(&self) -> Result<Vec<UInt8<CF>>, SynthesisError> {
        self.to_bytes_le()
    }
}

impl<CF: PrimeField> SerializeGadget<CF>
    for SignatureVar<BlsSigConfig, EmulatedFpVar<BlsSigField<BlsSigConfig>, CF>, CF>
{
    fn serialize(&self) -> Result<Vec<UInt8<CF>>, SynthesisError> {
        self.signature.to_bytes_le()
    }
}

impl<CF: PrimeField> SerializeGadget<CF>
    for PublicKeyVar<BlsSigConfig, EmulatedFpVar<BlsSigField<BlsSigConfig>, CF>, CF>
{
    fn serialize(&self) -> Result<Vec<UInt8<CF>>, SynthesisError> {
        self.pub_key.to_bytes_le()
    }
}

/*
`.to_bytes_le()` should not exist after this line
*/

impl<CF: PrimeField> SerializeGadget<CF> for SignerVar<CF> {
    fn serialize(&self) -> Result<Vec<UInt8<CF>>, SynthesisError> {
        let mut pk = self.pk.serialize()?;
        let weight = self.weight.serialize()?;
        pk.extend(weight);
        Ok(pk)
    }
}

impl<CF: PrimeField> SerializeGadget<CF> for [SignerVar<CF>] {
    fn serialize(&self) -> Result<Vec<UInt8<CF>>, SynthesisError> {
        self.iter()
            .map(|v| v.serialize())
            .collect::<Result<Vec<_>, _>>()
            .map(|vecs| vecs.into_iter().flatten().collect::<Vec<_>>())
    }
}

impl<CF: PrimeField> SerializeGadget<CF> for QuorumSignatureVar<CF> {
    fn serialize(&self) -> Result<Vec<UInt8<CF>>, SynthesisError> {
        let mut sig = self.sig.serialize()?;
        let signers_len = USize::constant(
            self.signers
                .len()
                .try_into()
                .map_err(|_| SynthesisError::Unsatisfiable)?,
        )
        .serialize()?;
        let signers = self.signers.serialize()?;

        sig.extend(signers_len);
        sig.extend(signers);
        Ok(sig)
    }
}

impl<CF: PrimeField> SerializeGadget<CF> for CommitteeVar<CF> {
    fn serialize(&self) -> Result<Vec<UInt8<CF>>, SynthesisError> {
        let mut committee_len = USize::constant(
            self.committee
                .len()
                .try_into()
                .map_err(|_| SynthesisError::Unsatisfiable)?,
        )
        .serialize()?;
        let committee = self.committee.serialize()?;

        committee_len.extend(committee);
        Ok(committee_len)
    }
}

impl<CF: PrimeField> SerializeGadget<CF> for CheckPointVar<CF> {
    fn serialize(&self) -> Result<Vec<UInt8<CF>>, SynthesisError> {
        let mut epoch = self.epoch.serialize()?;
        let prev_digest = self.prev_digest.serialize()?;
        let sig = self.sig.serialize()?;
        let committee = self.committee.serialize()?;

        epoch.extend(prev_digest);
        epoch.extend(sig);
        epoch.extend(committee);

        Ok(epoch)
    }
}

#[cfg(test)]
mod test {
    use ark_r1cs_std::{alloc::AllocVar, uint8::UInt8, R1CSVar};
    use ark_relations::r1cs::ConstraintSystem;

    use crate::{
        bc::{
            checkpoints::{CheckPoint, QuorumSignature},
            params::Committee,
        },
        bls::{Parameters, PublicKey, SecretKey, Signature, SignatureVar},
        folding::{
            bc::{CheckPointVar, CommitteeVar, QuorumSignatureVar, SignerVar},
            params::USize,
        },
        params::{BlsSigConfig, BlsSigField},
    };

    use super::SerializeGadget;

    type CF = BlsSigField<BlsSigConfig>;

    #[test]
    fn u64_ser() {
        let x: usize = 42;
        let xv: USize<CF> = USize::constant(x.try_into().unwrap());

        let xs = bincode::serialize(&x).unwrap();
        let xvs: Vec<u8> = xv
            .serialize()
            .unwrap()
            .iter()
            .map(|v| v.value().unwrap())
            .collect();

        assert_eq!(xs, xvs);
    }

    #[test]
    fn u8_array_ser() {
        let cs = ConstraintSystem::new_ref();

        let x: [u8; 20] = [42; 20];
        let xv: Vec<UInt8<CF>> = Vec::new_constant(cs.clone(), x).unwrap();

        let xs = bincode::serialize(&x).unwrap();
        let xvs: Vec<u8> = xv
            .serialize()
            .unwrap()
            .iter()
            .map(|v| v.value().unwrap())
            .collect();

        assert_eq!(xs, xvs);
    }

    #[test]
    fn sig_ser() {
        let cs = ConstraintSystem::<CF>::new_ref();

        let x = Signature::default();
        let xv = SignatureVar::new_constant(cs, x).unwrap();

        let xs = bincode::serialize(&x).unwrap();
        let xvs: Vec<u8> = xv
            .serialize()
            .unwrap()
            .iter()
            .map(|v| v.value().unwrap())
            .collect();

        assert_eq!(xs, xvs);
    }

    #[test]
    fn quorum_sig_ser() {
        let cs = ConstraintSystem::<CF>::new_ref();

        let x = QuorumSignature::default();
        let xv = QuorumSignatureVar::new_constant(cs, x.clone()).unwrap();

        let xs = bincode::serialize(&x).unwrap();
        let xvs: Vec<u8> = xv
            .serialize()
            .unwrap()
            .iter()
            .map(|v| v.value().unwrap())
            .collect();

        assert_eq!(xs, xvs);
    }

    #[test]
    fn signer_ser() {
        let cs = ConstraintSystem::<CF>::new_ref();

        let x = (
            PublicKey::new(&SecretKey::default(), &Parameters::setup()),
            42,
        );
        let xv = SignerVar::new_constant(cs, x.clone()).unwrap();

        let xs = bincode::serialize(&x).unwrap();
        let xvs: Vec<u8> = xv
            .serialize()
            .unwrap()
            .iter()
            .map(|v| v.value().unwrap())
            .collect();

        assert_eq!(xs, xvs);
    }

    #[test]
    fn committee_ser() {
        let cs = ConstraintSystem::<CF>::new_ref();

        let x = Committee::default();
        let xv = CommitteeVar::new_constant(cs, x.clone()).unwrap();

        let xs = bincode::serialize(&x).unwrap();
        let xvs: Vec<u8> = xv
            .serialize()
            .unwrap()
            .iter()
            .map(|v| v.value().unwrap())
            .collect();

        assert_eq!(xs, xvs);
    }

    #[test]
    fn checkpoint_ser() {
        let cs = ConstraintSystem::<CF>::new_ref();

        let x = CheckPoint::default();
        let xv = CheckPointVar::new_constant(cs, x.clone()).unwrap();

        let xs = bincode::serialize(&x).unwrap();
        let xvs: Vec<u8> = xv
            .serialize()
            .unwrap()
            .iter()
            .map(|v| v.value().unwrap())
            .collect();

        assert_eq!(xs, xvs);
    }
}
