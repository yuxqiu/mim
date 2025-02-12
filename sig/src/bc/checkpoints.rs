use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use blake2::Digest;
use delegate::delegate;
use rand::{thread_rng, Rng};
use roaring::RoaringBitmap;
use serde::{Deserialize, Serialize};

use crate::{
    bc::params::AuthoritySecretKey,
    bls::{Parameters, Signature},
};

use super::params::{
    AuthorityAggregatedSignature, AuthorityPublicKey, AuthoritySigParams, Committee, HashFunc,
    Signers, HASH_OUTPUT_SIZE, STRONG_THRESHOLD, TOTAL_VOTING_POWER,
};

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct QuorumSignature {
    sig: AuthorityAggregatedSignature,
    signers: RoaringBitmap,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CheckPoint {
    epoch: u64,

    /// hash to the previous checkpoint
    prev_digest: [u8; HASH_OUTPUT_SIZE],

    seq_number: u64,

    sig: QuorumSignature,

    /// Present only on the final checkpoint of the epoch.
    end_of_epoch_data: Option<EndOfEpochData>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EndOfEpochData {
    committee: Committee,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Blockchain {
    checkpoints: Vec<CheckPoint>,
    params: AuthoritySigParams,
}

/// A thin ser/des layer on top of ark-serialize
/// - see <https://github.com/arkworks-rs/algebra/issues/178>
macro_rules! impl_serde {
    ($type:ty) => {
        impl Serialize for $type {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                let mut bytes = vec![];
                self.serialize_with_mode(&mut bytes, Compress::Yes)
                    .map_err(serde::ser::Error::custom)?;
                serializer.serialize_bytes(&bytes)
            }
        }

        impl<'de> Deserialize<'de> for $type {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let s: Vec<u8> = serde::de::Deserialize::deserialize(deserializer)?;
                let a = Self::deserialize_with_mode(s.as_slice(), Compress::Yes, Validate::Yes);
                a.map_err(serde::de::Error::custom)
            }
        }
    };
}

impl_serde!(AuthorityPublicKey);
impl_serde!(AuthorityAggregatedSignature);
impl_serde!(AuthoritySigParams);

impl CheckPoint {
    pub fn genesis(data: EndOfEpochData) -> Self {
        Self {
            epoch: 0,
            prev_digest: Default::default(),
            seq_number: 0,
            sig: Default::default(),
            end_of_epoch_data: Some(data),
        }
    }

    fn new_internal(
        prev: &CheckPoint,
        data: Option<EndOfEpochData>,
        signers: &Signers,
        bitmap: &RoaringBitmap,
        params: &AuthoritySigParams,
        increase_epoch: bool,
    ) -> Result<Self, Box<bincode::Error>> {
        assert!(!bitmap.is_empty(), "checkpoint must be signed");

        let mut cp = Self {
            epoch: prev.epoch + increase_epoch as u64,
            prev_digest: compute_digest(prev),
            seq_number: prev.seq_number + 1,
            sig: Default::default(),
            end_of_epoch_data: data,
        };

        let mut hasher = HashFunc::new();
        hasher.update(bincode::serialize(&cp)?);
        let sig = AuthorityAggregatedSignature::aggregate_sign(
            &Into::<[u8; HASH_OUTPUT_SIZE]>::into(hasher.finalize()),
            &signers
                .iter()
                .enumerate()
                .filter(|(i, _)| bitmap.contains(*i as u32))
                .map(|(_, sec)| sec)
                .cloned()
                .collect::<Vec<_>>(),
            params,
        );

        cp.sig = QuorumSignature {
            sig: sig.unwrap(),
            signers: bitmap.clone(),
        };

        Ok(cp)
    }

    pub fn new(
        prev: &CheckPoint,
        signers: &Signers,
        bitmap: &RoaringBitmap,
        params: &AuthoritySigParams,
        increase_epoch: bool,
    ) -> Result<Self, Box<bincode::Error>> {
        Self::new_internal(prev, None, signers, bitmap, params, increase_epoch)
    }

    pub fn new_with_data(
        prev: &CheckPoint,
        data: EndOfEpochData,
        signers: &Signers,
        bitmap: &RoaringBitmap,
        params: &AuthoritySigParams,
    ) -> Result<Self, Box<bincode::Error>> {
        Self::new_internal(prev, Some(data), signers, bitmap, params, false)
    }

    pub fn verify(&self, committee: &Committee, epoch: u64, params: &Parameters) -> bool {
        assert!(
            self.epoch == epoch + 1,
            "epoch mismatches: expect {} but get {}",
            self.epoch,
            epoch
        );

        let aggregate_signer_info = committee
            .iter()
            .enumerate()
            .filter(|(i, _)| self.sig.signers.contains(*i as u32))
            .map(|(_, signer_info)| signer_info)
            .cloned()
            .reduce(|acc, e| {
                (
                    AuthorityPublicKey {
                        pub_key: acc.0.pub_key + e.0.pub_key,
                    },
                    acc.1 + e.1,
                )
            });

        // prepare the msg used in signing
        let mut self_clone = self.clone();
        self_clone.sig = QuorumSignature::default();
        let msg = bincode::serialize(&self_clone).expect("serialization should succeed");

        if let Some((aggregate_pk, weights)) = aggregate_signer_info {
            if weights < STRONG_THRESHOLD {
                return false;
            }
            let mut hasher = HashFunc::new();
            hasher.update(msg);
            return Signature::verify(&hasher.finalize(), &self.sig.sig, &aggregate_pk, params);
        }

        // weights == 0 => no quorum signs this checkpoint
        return false;
    }
}

impl Blockchain {
    pub fn new(params: AuthoritySigParams) -> Self {
        Self {
            checkpoints: vec![],
            params: params,
        }
    }

    delegate! {
        to self.checkpoints {
            pub fn is_empty(&self) -> bool;

            #[call(push)]
            pub fn add_checkpoint(&mut self, value: CheckPoint);

            pub fn len(&self) -> usize;

            fn reserve(&mut self, size: usize);

            fn last(&self) -> Option<&CheckPoint>;
        }
    }

    pub fn verify(&self) -> bool {
        if self.is_empty() {
            return true;
        }

        let mut committee = &self.checkpoints[0]
            .end_of_epoch_data
            .as_ref()
            .unwrap()
            .committee;
        let mut prev_digest = compute_digest(&self.checkpoints[0]);
        let mut committee_epoch = self.checkpoints[0].epoch;

        for cp in self.checkpoints.iter().skip(1) {
            if cp.prev_digest != prev_digest || !cp.verify(committee, committee_epoch, &self.params)
            {
                return false;
            }
            prev_digest = compute_digest(cp);
            if let Some(new_commitee) = &cp.end_of_epoch_data {
                committee = &new_commitee.committee;
                committee_epoch = cp.epoch;
            }
        }

        return true;
    }
}

fn compute_digest(cp: &CheckPoint) -> [u8; HASH_OUTPUT_SIZE] {
    let bytes = bincode::serialize(&cp).unwrap();
    let mut hasher = HashFunc::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

fn generate_committee(committee_size: usize, params: &AuthoritySigParams) -> (Signers, Committee) {
    let mut rng = thread_rng();

    let mut weights = Vec::new();
    let mut remaining_weight = TOTAL_VOTING_POWER;
    for _ in 0..committee_size - 1 {
        let weight = rng.gen_range(0..=remaining_weight);
        weights.push(weight);
        remaining_weight -= weight;
    }
    weights.push(remaining_weight);

    let csk = (0..committee_size)
        .map(|_| AuthoritySecretKey::new(&mut rng))
        .collect::<Vec<_>>();
    let committee = csk
        .iter()
        .zip(weights)
        .map(|(sk, weight)| (AuthorityPublicKey::new(sk, &params), weight))
        .collect::<Vec<_>>();

    (csk, committee)
}

fn select_strong_committee(committee: &Committee) -> RoaringBitmap {
    let mut rng = thread_rng();
    let mut selected_indices = RoaringBitmap::new();
    let mut total_weight: u64 = 0;

    while total_weight <= STRONG_THRESHOLD {
        let index = rng.gen_range(0..committee.len());
        if !selected_indices.contains(index as u32) {
            selected_indices.insert(index as u32);
            total_weight += committee[index].1;
        }
    }

    selected_indices
}

pub fn gen_blockchain_with_params(
    num_epochs: usize,
    num_checkpoints_per_epoch: usize,
    committee_size: usize,
) -> Blockchain {
    assert!(num_epochs > 0, "num_epochs should > 0");
    assert!(
        num_checkpoints_per_epoch > 0,
        "num_checkpoints_per_epoch should > 0"
    );
    assert!(committee_size > 0, "committee_size should > 0");

    // generate param
    let params = AuthoritySigParams::setup();

    let mut bc = Blockchain::new(params.clone());
    bc.reserve(num_epochs * num_checkpoints_per_epoch);

    // generate genesis block (the only cp in 0th epoch)
    let (signers, committee) = generate_committee(committee_size, &params);
    let genesis_cp = CheckPoint::genesis(EndOfEpochData {
        committee: committee.clone(),
    });
    bc.add_checkpoint(genesis_cp);

    let mut prev_signers = signers.clone();
    let mut prev_committee = committee;
    let mut prev_cp = &bc.checkpoints[0];

    // generate checkpoints for other epochs
    for _ in 1..num_epochs {
        for i in 0..num_checkpoints_per_epoch - 1 {
            let bitmap = select_strong_committee(&prev_committee);
            let cp = CheckPoint::new(prev_cp, &prev_signers, &bitmap, &params, i == 0).unwrap();
            bc.add_checkpoint(cp);
            prev_cp = bc.last().unwrap();
        }

        let bitmap = select_strong_committee(&prev_committee);
        let (signers, committee) = generate_committee(committee_size, &params);

        let cp = CheckPoint::new_with_data(
            prev_cp,
            EndOfEpochData {
                committee: committee.clone(),
            },
            &prev_signers,
            &bitmap,
            &params,
        )
        .unwrap();
        bc.add_checkpoint(cp);
        prev_cp = bc.last().unwrap();

        prev_committee = committee;
        prev_signers = signers;
    }

    assert_eq!(bc.len(), (num_epochs - 1) * num_checkpoints_per_epoch + 1);
    assert!(bc.verify());

    bc
}

#[cfg(test)]
mod test {
    use super::gen_blockchain_with_params;

    #[test]
    fn test_gen_blockchain() {
        gen_blockchain_with_params(10, 10, 10);
    }
}
