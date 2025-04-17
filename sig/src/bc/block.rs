use ark_ec::{
    short_weierstrass::{Affine, Projective, SWCurveConfig},
    CurveGroup,
};
use ark_serialize::CanonicalSerialize;
use blake2::Digest;
use delegate::delegate;
use rand::Rng;
use serde::{ser::SerializeTuple, Serialize, Serializer};
use serde_with::serde_as;

use crate::{bc::params::AuthoritySecretKey, bls::Signature};

use super::params::{
    AuthorityAggregatedSignature, AuthorityPublicKey, AuthoritySigParams, HashFunc, Signers,
    Weight, HASH_OUTPUT_SIZE, STRONG_THRESHOLD, TOTAL_VOTING_POWER,
};

// const MAX_COMMITTEE_SIZE: usize = 1;

#[serde_as]
#[derive(Serialize, Debug, Clone)]
pub struct QuorumSignature<const MAX_COMMITTEE_SIZE: usize> {
    pub sig: AuthorityAggregatedSignature,
    // a roaring bitmap is a better alternative, but for easy impl of R1CS circuit, we use Vec<bool>
    #[serde_as(as = "[_; MAX_COMMITTEE_SIZE]")]
    pub signers: [bool; MAX_COMMITTEE_SIZE],
}

impl<const MAX_COMMITTEE_SIZE: usize> Default for QuorumSignature<MAX_COMMITTEE_SIZE> {
    fn default() -> Self {
        Self {
            sig: Default::default(),
            signers: [bool::default(); MAX_COMMITTEE_SIZE],
        }
    }
}

#[serde_as]
#[derive(Serialize, Debug, Clone)]
pub struct Committee<const MAX_COMMITTEE_SIZE: usize> {
    #[serde_as(as = "[_; MAX_COMMITTEE_SIZE]")]
    pub signers: [(AuthorityPublicKey, Weight); MAX_COMMITTEE_SIZE],
}

impl<const MAX_COMMITTEE_SIZE: usize> Default for Committee<MAX_COMMITTEE_SIZE> {
    fn default() -> Self {
        Self {
            signers: [(AuthorityPublicKey::default(), Weight::default()); MAX_COMMITTEE_SIZE],
        }
    }
}

#[derive(Serialize, Debug, Default, Clone)]
pub struct Block<const MAX_COMMITTEE_SIZE: usize> {
    pub epoch: u64,

    /// hash to the previous block
    pub prev_digest: [u8; HASH_OUTPUT_SIZE],

    pub sig: QuorumSignature<MAX_COMMITTEE_SIZE>,

    /// This is a simplification. Usually, committee is only stored at the last node of an epoch
    /// as `Committee`.
    pub committee: Committee<MAX_COMMITTEE_SIZE>,
}

#[derive(Debug)]
pub struct Blockchain<const MAX_COMMITTEE_SIZE: usize> {
    blocks: Vec<Block<MAX_COMMITTEE_SIZE>>,
    params: AuthoritySigParams,
}

fn serialize_curve_point<Config: SWCurveConfig, S: Serializer>(
    affine: Affine<Config>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    let mut bytes = vec![];
    affine
        .x
        .serialize_uncompressed(&mut bytes)
        .map_err(serde::ser::Error::custom)?;
    affine
        .y
        .serialize_uncompressed(&mut bytes)
        .map_err(serde::ser::Error::custom)?;
    affine
        .infinity
        .serialize_uncompressed(&mut bytes)
        .map_err(serde::ser::Error::custom)?;

    // The length of the struct is static, so it's safe to use this
    let mut seq = serializer.serialize_tuple(bytes.len())?;
    for b in bytes {
        seq.serialize_element(&b)?;
    }
    seq.end()
}

/// Serialize is implemented manually because it's easy to match it with `SerializeGadget` implementation
impl Serialize for AuthorityAggregatedSignature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let affine = Into::<Projective<_>>::into(*self).into_affine();
        serialize_curve_point(affine, serializer)
    }
}

/// Serialize is implemented manually because it's easy to match it with `SerializeGadget` implementation
impl Serialize for AuthorityPublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let affine = Into::<Projective<_>>::into(*self).into_affine();
        serialize_curve_point(affine, serializer)
    }
}

impl<const MAX_COMMITTEE_SIZE: usize> Block<MAX_COMMITTEE_SIZE> {
    #[must_use]
    pub fn genesis(data: Committee<MAX_COMMITTEE_SIZE>) -> Self {
        Self {
            epoch: 0,
            prev_digest: Default::default(),
            sig: Default::default(),
            committee: data,
        }
    }

    fn new(
        prev: &Self,
        data: Committee<MAX_COMMITTEE_SIZE>,
        signers: &Signers,
        bitmap: &[bool],
        params: &AuthoritySigParams,
    ) -> Result<Self, Box<bincode::Error>> {
        assert!(!bitmap.is_empty(), "block must be signed");

        let mut block = Self {
            epoch: prev.epoch + 1_u64,
            prev_digest: compute_digest(prev),
            sig: Default::default(),
            committee: data,
        };

        let sig = AuthorityAggregatedSignature::aggregate_sign(
            &bincode::serialize(&block)?,
            &signers
                .iter()
                .enumerate()
                .filter(|(i, _)| *bitmap.get(*i).unwrap_or(&false))
                .map(|(_, sec)| sec)
                .copied()
                .collect::<Vec<_>>(),
            params,
        );

        block.sig = QuorumSignature {
            sig: sig.expect("at least one secret key is provided"),
            signers: bitmap
                .try_into()
                .expect("bitmap should match the size of the committee"),
        };

        Ok(block)
    }

    #[must_use]
    pub fn verify(
        &self,
        committee: &Committee<MAX_COMMITTEE_SIZE>,
        epoch: u64,
        params: &AuthoritySigParams,
    ) -> bool {
        assert!(
            self.epoch == epoch + 1,
            "epoch mismatches: expect {} but get {}",
            self.epoch,
            epoch
        );

        let aggregate_signer_info = committee
            .signers
            .iter()
            .enumerate()
            .filter(|(i, _)| self.sig.signers[*i])
            .map(|(_, signer_info)| signer_info)
            .copied()
            .reduce(|acc, e| (acc.0 + e.0, acc.1 + e.1));

        // prepare the msg used in signing
        let mut self_clone = self.clone();
        self_clone.sig = QuorumSignature::default();
        let msg = bincode::serialize(&self_clone).expect("serialization should succeed");

        if let Some((aggregate_pk, weights)) = aggregate_signer_info {
            if weights < STRONG_THRESHOLD {
                return false;
            }
            return Signature::verify(&msg, &self.sig.sig, &aggregate_pk, params);
        }

        // weights == 0 => no quorum signs this block
        false
    }
}

/// A committee rotation chain, where each node is a block that stores a committee.
/// This is a simplification of common light client protocols that rely on committee.
impl<const MAX_COMMITTEE_SIZE: usize> Blockchain<MAX_COMMITTEE_SIZE> {
    #[must_use]
    pub const fn new(params: AuthoritySigParams) -> Self {
        Self {
            blocks: vec![],
            params,
        }
    }

    delegate! {
        to self.blocks {
            #[must_use] pub fn is_empty(&self) -> bool;

            #[call(push)]
            pub fn add_block(&mut self, value: Block<MAX_COMMITTEE_SIZE>);

            #[must_use] pub fn len(&self) -> usize;

            fn reserve(&mut self, size: usize);

            fn last(&self) -> Option<&Block<MAX_COMMITTEE_SIZE>>;

            pub fn get(&self, i: usize) -> Option<&Block<MAX_COMMITTEE_SIZE>>;

            #[call(into_iter)]
            pub fn into_blocks(self) -> <Vec<Block<MAX_COMMITTEE_SIZE>> as IntoIterator>::IntoIter;
        }
    }

    #[must_use]
    pub fn verify(&self) -> bool {
        if self.is_empty() {
            return true;
        }

        let mut committee = &self.blocks[0].committee;
        let mut prev_digest = compute_digest(&self.blocks[0]);
        let mut committee_epoch = self.blocks[0].epoch;

        for block in self.blocks.iter().skip(1) {
            if block.prev_digest != prev_digest
                || !block.verify(committee, committee_epoch, &self.params)
            {
                return false;
            }
            prev_digest = compute_digest(block);
            committee = &block.committee;
            committee_epoch = block.epoch;
        }

        true
    }
}

fn compute_digest<const MAX_COMMITTEE_SIZE: usize>(
    block: &Block<MAX_COMMITTEE_SIZE>,
) -> [u8; HASH_OUTPUT_SIZE] {
    let bytes = bincode::serialize(&block).unwrap();
    let mut hasher = HashFunc::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

fn generate_committee<R: Rng, const MAX_COMMITTEE_SIZE: usize>(
    committee_size: usize,
    params: &AuthoritySigParams,
    rng: &mut R,
) -> (Signers, Committee<MAX_COMMITTEE_SIZE>) {
    let mut weights = Vec::new();
    let mut remaining_weight = TOTAL_VOTING_POWER;
    for _ in 0..committee_size - 1 {
        let weight = rng.gen_range(0..=remaining_weight);
        weights.push(weight);
        remaining_weight -= weight;
    }
    weights.push(remaining_weight);

    // fill to `MAX_COMMITTEE_SIZE`
    weights.extend(std::iter::repeat(0).take(MAX_COMMITTEE_SIZE - committee_size));

    let csk = (0..MAX_COMMITTEE_SIZE)
        .map(|_| AuthoritySecretKey::new(rng))
        .collect::<Vec<_>>();
    let committee = csk
        .iter()
        .zip(weights)
        .map(|(sk, weight)| (AuthorityPublicKey::new(sk, params), weight))
        .collect::<Vec<_>>();

    (
        csk,
        Committee {
            signers: committee
                .try_into()
                .expect("committee size is guaranteed to == MAX_COMMITTEE_SIZE"),
        },
    )
}

fn select_strong_committee<R: Rng, const MAX_COMMITTEE_SIZE: usize>(
    committee: &Committee<MAX_COMMITTEE_SIZE>,
    effective_committee_size: usize,
    rng: &mut R,
) -> Vec<bool> {
    let mut selected_indices = vec![false; effective_committee_size];
    let mut total_weight: u64 = 0;
    let signers = &committee.signers[0..effective_committee_size];

    while total_weight < STRONG_THRESHOLD {
        let index = rng.gen_range(0..signers.len());
        if !selected_indices[index] {
            selected_indices[index] = true;
            total_weight += signers[index].1;
        }
    }

    // fill to `MAX_COMMITTEE_SIZE`
    selected_indices
        .extend(std::iter::repeat(false).take(MAX_COMMITTEE_SIZE - effective_committee_size));

    selected_indices
}

/// Generate a blockchain with effective committee size `committee_size`.
///
/// By effective, it means in the returned blockchain, every block has a committee size of `MAX_COMMITTEE_SIZE`,
/// but only `committee_size` of them has non-zero weights.
#[must_use]
pub fn gen_blockchain_with_params<R: Rng, const MAX_COMMITTEE_SIZE: usize>(
    num_epochs: usize,
    effective_committee_size: usize,
    rng: &mut R,
) -> Blockchain<MAX_COMMITTEE_SIZE> {
    assert!(num_epochs > 0, "num_epochs should > 0");
    assert!(
        effective_committee_size > 0,
        "effective_committee_size should > 0"
    );
    assert!(
        effective_committee_size <= MAX_COMMITTEE_SIZE,
        "effective_committee_size should <= MAX_COMMITTEE_SIZE {}",
        MAX_COMMITTEE_SIZE
    );

    // generate param
    let params = AuthoritySigParams::setup();

    let mut bc = Blockchain::new(params);
    bc.reserve(num_epochs);

    // generate genesis block
    let (signers, committee) = generate_committee(effective_committee_size, &params, rng);

    assert_eq!(
        committee.signers.len(),
        MAX_COMMITTEE_SIZE,
        "committee must have len == MAX_COMMITTEE_SIZE"
    );

    let genesis_block = Block::genesis(committee.clone());
    bc.add_block(genesis_block);

    let mut prev_signers = signers;
    let mut prev_committee = committee;
    let mut prev_block = &bc.blocks[0];

    // generate blocks for other epochs
    for _ in 1..num_epochs {
        let bitmap = select_strong_committee(&prev_committee, effective_committee_size, rng);

        assert_eq!(
            bitmap.len(),
            MAX_COMMITTEE_SIZE,
            "bitmap must have len == MAX_COMMITTEE_SIZE"
        );

        let (signers, committee) = generate_committee(effective_committee_size, &params, rng);

        let block = Block::new(
            prev_block,
            committee.clone(),
            &prev_signers,
            &bitmap,
            &params,
        )
        .unwrap();
        bc.add_block(block);
        prev_block = bc.last().unwrap();

        prev_committee = committee;
        prev_signers = signers;
    }

    assert_eq!(bc.len(), num_epochs);
    assert!(bc.verify());

    bc
}

#[cfg(test)]
mod test {
    use rand::thread_rng;

    use super::gen_blockchain_with_params;

    const MAX_COMMITTEE_SIZE: usize = 25;

    #[test]
    fn test_gen_blockchain() {
        let _ = gen_blockchain_with_params::<_, MAX_COMMITTEE_SIZE>(100, 10, &mut thread_rng());
    }
}
