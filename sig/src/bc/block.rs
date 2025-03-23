use ark_ec::{
    short_weierstrass::{Affine, SWCurveConfig},
    CurveGroup,
};
use ark_serialize::CanonicalSerialize;
use blake2::Digest;
use delegate::delegate;
use rand::{thread_rng, Rng};
use serde::{ser::SerializeTuple, Serialize, Serializer};

use crate::{
    bc::params::{AuthoritySecretKey, MAX_COMMITTEE_SIZE},
    bls::Signature,
};

use super::params::{
    AuthorityAggregatedSignature, AuthorityPublicKey, AuthoritySigParams, HashFunc, Signers,
    Weight, HASH_OUTPUT_SIZE, STRONG_THRESHOLD, TOTAL_VOTING_POWER,
};

#[derive(Serialize, Debug, Clone)]
pub struct QuorumSignature {
    pub sig: AuthorityAggregatedSignature,
    // a roaring bitmap is a better alternative, but for easy impl of R1CS circuit, we use Vec<bool>
    pub signers: Vec<bool>,
}

#[derive(Serialize, Debug, Clone)]
pub struct Committee {
    pub signers: Vec<(AuthorityPublicKey, Weight)>,
}

#[derive(Serialize, Debug, Default, Clone)]
pub struct Block {
    pub epoch: u64,

    /// hash to the previous block
    pub prev_digest: [u8; HASH_OUTPUT_SIZE],

    pub sig: QuorumSignature,

    /// This is a simplification. Usually, committee is only stored at the last node of an epoch
    /// as `Committee`.
    pub committee: Committee,
}

#[derive(Debug)]
pub struct Blockchain {
    blocks: Vec<Block>,
    params: AuthoritySigParams,
}

impl Default for QuorumSignature {
    // a default quorum signature contains `MAX_COMMITTEE_SIZE` signers
    fn default() -> Self {
        Self {
            sig: Default::default(),
            signers: vec![bool::default(); MAX_COMMITTEE_SIZE],
        }
    }
}

impl Default for Committee {
    // a default committee contains `MAX_COMMITTEE_SIZE` signers
    fn default() -> Self {
        Self {
            signers: vec![(AuthorityPublicKey::default(), Weight::default()); MAX_COMMITTEE_SIZE],
        }
    }
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
        let affine = self.signature.into_affine();
        serialize_curve_point(affine, serializer)
    }
}

/// Serialize is implemented manually because it's easy to match it with `SerializeGadget` implementation
impl Serialize for AuthorityPublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let affine = self.pub_key.into_affine();
        serialize_curve_point(affine, serializer)
    }
}

impl Block {
    #[must_use]
    pub fn genesis(data: Committee) -> Self {
        Self {
            epoch: 0,
            prev_digest: Default::default(),
            sig: Default::default(),
            committee: data,
        }
    }

    fn new(
        prev: &Self,
        data: Committee,
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

        let mut hasher = HashFunc::new();
        hasher.update(bincode::serialize(&block)?);
        let sig = AuthorityAggregatedSignature::aggregate_sign(
            &Into::<[u8; HASH_OUTPUT_SIZE]>::into(hasher.finalize()),
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
            signers: bitmap.to_owned(),
        };

        Ok(block)
    }

    #[must_use]
    pub fn verify(&self, committee: &Committee, epoch: u64, params: &AuthoritySigParams) -> bool {
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

        // weights == 0 => no quorum signs this block
        false
    }
}

/// A committee rotation chain, where each node is a block that stores a committee.
/// This is a simplification of common light client protocols that rely on committee.
impl Blockchain {
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
            pub fn add_block(&mut self, value: Block);

            #[must_use] pub fn len(&self) -> usize;

            fn reserve(&mut self, size: usize);

            fn last(&self) -> Option<&Block>;

            pub fn get(&self, i: usize) -> Option<&Block>;

            #[call(into_iter)]
            pub fn into_blocks(self) -> <Vec<Block> as IntoIterator>::IntoIter;
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

fn compute_digest(block: &Block) -> [u8; HASH_OUTPUT_SIZE] {
    let bytes = bincode::serialize(&block).unwrap();
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

    // fill to `MAX_COMMITTEE_SIZE`
    weights.extend(std::iter::repeat(0).take(MAX_COMMITTEE_SIZE - committee_size));

    let csk = (0..MAX_COMMITTEE_SIZE)
        .map(|_| AuthoritySecretKey::new(&mut rng))
        .collect::<Vec<_>>();
    let committee = csk
        .iter()
        .zip(weights)
        .map(|(sk, weight)| (AuthorityPublicKey::new(sk, params), weight))
        .collect::<Vec<_>>();

    (csk, Committee { signers: committee })
}

fn select_strong_committee(committee: &Committee, effective_committee_size: usize) -> Vec<bool> {
    let mut rng = thread_rng();
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
/// By effective, it means in the returned blockchain, every block has a committee size of `MAX_COMMITTEE_SIZE`,
/// but only `committee_size` of them has non-zero weights.
#[must_use]
pub fn gen_blockchain_with_params(
    num_epochs: usize,
    effective_committee_size: usize,
) -> Blockchain {
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
    let (signers, committee) = generate_committee(effective_committee_size, &params);

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
        let bitmap = select_strong_committee(&prev_committee, effective_committee_size);

        assert_eq!(
            bitmap.len(),
            MAX_COMMITTEE_SIZE,
            "bitmap must have len == MAX_COMMITTEE_SIZE"
        );

        let (signers, committee) = generate_committee(effective_committee_size, &params);

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
    use super::gen_blockchain_with_params;

    #[test]
    fn test_gen_blockchain() {
        let _ = gen_blockchain_with_params(100, 10);
    }
}
