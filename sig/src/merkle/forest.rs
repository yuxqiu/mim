use std::collections::HashMap;

use ark_crypto_primitives::{
    crh::{poseidon::CRH as Poseidon, CRHScheme},
    sponge::poseidon::PoseidonConfig,
};
use derivative::Derivative;
use either::{for_both, Either};
use thiserror::Error;

use super::{
    tree::{MerkleTree, MerkleTreeError},
    MerkleConfig,
};

#[derive(Derivative)]
#[derivative(Debug(bound = ""))]
pub struct LeveledMerkleForest<'a, P: MerkleConfig> {
    trees: Vec<MerkleTree<'a, P>>,
    states: Vec<HashMap<usize, MerkleTree<'a, P>>>,
    size: usize,
}

#[derive(Error, Debug)]
pub enum MerkleForestError {
    #[error("num_tree should >= 1")]
    InvalidNumTree,

    #[error("Leaf index out of bound")]
    IndexOutOfBound,

    #[error("Merkle forest is full")]
    ForestIsFull,

    #[error("Merkle tree error occurred: {0}")]
    MerkleTreeError(#[from] MerkleTreeError),
}

#[derive(Derivative)]
#[derivative(Debug(bound = ""))]
pub struct MerkleForestProof<P: MerkleConfig> {
    pub siblings: Vec<P::BasePrimeField>,
    pub leaf_index: usize,
    pub num_leaves_per_tree: usize,
}

#[derive(Derivative)]
#[derivative(Debug(bound = ""))]
pub struct MerkleForestVariableLengthProof<P: MerkleConfig> {
    pub siblings: Vec<P::BasePrimeField>,
    pub leaf_index: usize,
    pub num_leaves_per_tree: usize,
}

impl<'a, P: MerkleConfig> LeveledMerkleForest<'a, P> {
    pub fn new_optimal(
        n: usize,
        params: &'a PoseidonConfig<P::BasePrimeField>,
    ) -> Result<Self, MerkleForestError> {
        let (capacity_per_tree, num_tree) = optimal_forest_params(n);
        Self::new(capacity_per_tree, num_tree, params)
    }

    // the `Construct-Fast` algorithm in the thesis
    pub fn new_with_data(
        data: either::Either<
            &[P::BasePrimeField],
            &[&<Poseidon<P::BasePrimeField> as CRHScheme>::Input],
        >,
        params: &'a PoseidonConfig<P::BasePrimeField>,
    ) -> Result<Self, MerkleForestError> {
        let len = for_both!(data, data => data.len());
        let mut s = Self::new_optimal(len, params)?;
        s.size = len;

        let mut data = match data {
            either::Either::Left(v) => v.to_owned(),
            either::Either::Right(v) => {
                let mut data = Vec::new();
                data.reserve_exact(v.len());
                for d in v {
                    data.push(
                        Poseidon::evaluate(params, *d).map_err(|_| MerkleTreeError::CRHError)?,
                    );
                }
                data
            }
        };

        for i in 0..s.num_trees() as usize {
            let mut new_data = Vec::new();
            for (j, data_per_tree) in data
                .chunks(s.num_leaves_per_tree() as usize)
                .by_ref()
                .enumerate()
            {
                // guard against the last chunk
                let mut data_per_tree = data_per_tree.to_owned();
                if j == 0 {
                    data_per_tree.extend(
                        std::iter::repeat(P::BasePrimeField::default())
                            .take(s.num_leaves_per_tree() as usize - data_per_tree.len()),
                    );
                } else {
                    // extend with previous tree's remaining data to match incremental update
                    data_per_tree.extend_from_slice(
                        &data[(j - 1) * s.num_leaves_per_tree() as usize + data_per_tree.len()
                            ..j * s.num_leaves_per_tree() as usize],
                    );
                }

                let merkle_tree = MerkleTree::new_with_data(either::Left(&data_per_tree), params)?;
                let root = merkle_tree.root();
                s.states[i].insert(j, merkle_tree);
                new_data.push(root);
            }
            s.trees[i] = s.states[i]
                .get(&(new_data.len() - 1))
                .expect("state exists because leaf index is in bound")
                .clone();
            data = new_data;
        }

        Ok(s)
    }

    // TODO: add an `update` method that allows arbitrary position update
    // - 1. We can get rid of `s` entirely
    // - 2. During the update, we need to update each level's tree

    pub fn prove(&self, leaf_index: usize) -> Result<MerkleForestProof<P>, MerkleForestError> {
        if leaf_index >= self.size {
            return Err(MerkleForestError::IndexOutOfBound);
        }

        let mut forest_proof = vec![];
        let mut idx = leaf_index;

        let num_leaves_per_tree = self.num_leaves_per_tree() as usize;
        for i in 0..self.trees.len() {
            let idx_within_tree = idx % num_leaves_per_tree;
            idx /= num_leaves_per_tree;
            let s = self.states[i]
                .get(&idx)
                .expect("state exists because leaf index is in bound");
            let (siblings, _) = s.prove(idx_within_tree)?;
            forest_proof.extend(siblings);
        }

        Ok(MerkleForestProof {
            siblings: forest_proof,
            leaf_index,
            num_leaves_per_tree,
        })
    }

    pub fn verify(
        params: &PoseidonConfig<P::BasePrimeField>,
        root: P::BasePrimeField,
        leaf: Either<&P::BasePrimeField, &<Poseidon<P::BasePrimeField> as CRHScheme>::Input>,
        proof: MerkleForestProof<P>,
    ) -> Result<bool, MerkleForestError> {
        let mut index = proof.leaf_index;
        let leaf_start = proof.num_leaves_per_tree - 1;
        let tree_height = proof.num_leaves_per_tree.ilog2();

        let mut hash = match leaf {
            Either::Left(v) => *v,
            Either::Right(v) => {
                Poseidon::evaluate(params, v).map_err(|_| MerkleTreeError::CRHError)?
            }
        };

        // chunk by tree_height to get siblings for each tree
        for siblings in proof.siblings.chunks(tree_height as usize) {
            // We need to offset the idx by `leaf_start` to be able to use MerkleTree's `hash_path` algorithm.
            let idx_within_tree = leaf_start + index % proof.num_leaves_per_tree;
            hash = MerkleTree::<P>::hash_path(params, hash, idx_within_tree, siblings)?;
            index /= proof.num_leaves_per_tree;
        }

        Ok(hash == root)
    }

    pub fn prove_variable(
        &self,
        leaf_index: usize,
    ) -> Result<MerkleForestVariableLengthProof<P>, MerkleForestError> {
        if leaf_index >= self.size {
            return Err(MerkleForestError::IndexOutOfBound);
        }

        let num_leaves_per_tree = self.num_leaves_per_tree() as usize;
        let n = next_power_of_q(self.size, num_leaves_per_tree);
        let diff = n - leaf_index - 1;
        let diff = std::cmp::max(diff, 1); // handle the special case that leaf_index == n-1
        let state_idx = diff.ilog(num_leaves_per_tree);

        let mut forest_proof = vec![];
        let mut idx = leaf_index;

        // only need to generate proof for state with index < state_idx
        for i in 0..(state_idx as usize) {
            let idx_within_tree = idx % num_leaves_per_tree;
            idx /= num_leaves_per_tree;
            let s = self.states[i]
                .get(&idx)
                .expect("state exists because leaf index is in bound");
            let (siblings, _) = s.prove(idx_within_tree)?;
            forest_proof.extend(siblings);
        }

        Ok(MerkleForestVariableLengthProof {
            siblings: forest_proof,
            leaf_index,
            num_leaves_per_tree,
        })
    }

    pub fn verify_variable(
        params: &PoseidonConfig<P::BasePrimeField>,
        states: &[MerkleTree<P>],
        n: usize,
        num_leaves: u32,
        leaf: Either<&P::BasePrimeField, &<Poseidon<P::BasePrimeField> as CRHScheme>::Input>,
        proof: MerkleForestVariableLengthProof<P>,
    ) -> Result<bool, MerkleForestError> {
        let (root, adjusted_index) = {
            let n = next_power_of_q(n, num_leaves as usize);
            let diff = n - proof.leaf_index - 1;
            let diff = std::cmp::max(diff, 1); // handle the special case that leaf_index == n-1
            let state_idx = diff.ilog(num_leaves as usize);
            let idx_within_tree = {
                // calculate the position of the leaf at the (state_idx)-th level (indexed from 0)
                proof.leaf_index / num_leaves.pow(state_idx) as usize % num_leaves as usize
            };

            (
                states[state_idx as usize].leaves()[idx_within_tree],
                proof.leaf_index,
            )
        };

        Self::verify(
            params,
            root,
            leaf,
            MerkleForestProof {
                siblings: proof.siblings,
                leaf_index: adjusted_index,
                num_leaves_per_tree: proof.num_leaves_per_tree,
            },
        )
    }

    pub fn root(&self) -> P::BasePrimeField {
        self.trees
            .last()
            .expect("forest should not be empty")
            .root()
    }

    pub fn states(&self) -> &[MerkleTree<P>] {
        &self.trees
    }

    #[inline]
    pub fn max_leaves(&self) -> usize {
        // safe conversion as trees.len() is limited to be <= 2^32 - 1
        #[allow(clippy::cast_possible_truncation)]
        (self.num_leaves_per_tree() as usize).pow(self.trees.len() as u32)
    }

    #[inline]
    pub fn num_leaves_per_tree(&self) -> u32 {
        self.trees[0].num_leaves() as u32
    }

    #[inline]
    pub fn num_trees(&self) -> u32 {
        self.trees.len() as u32
    }

    #[inline]
    pub fn capacity_per_tree(&self) -> u32 {
        self.trees[0].capacity() as u32
    }

    #[inline]
    pub fn size(&self) -> usize {
        self.size
    }

    // for the `Construct-Naive` algorithm in the thesis
    fn seqadd(
        &mut self,
        val: &<Poseidon<P::BasePrimeField> as CRHScheme>::Input,
    ) -> Result<(), MerkleForestError> {
        if self.size == self.max_leaves() {
            return Err(MerkleForestError::ForestIsFull);
        }

        // update Merkle trees
        let num_leaves_per_tree = self.num_leaves_per_tree() as usize;
        self.trees[0].update(self.size % num_leaves_per_tree, val)?;
        let mut node = self.trees[0].root();
        let mut idx = self.size / num_leaves_per_tree;
        for i in 1..self.trees.len() {
            self.trees[i].update_with_hash(idx % num_leaves_per_tree, node)?;
            node = self.trees[i].root();
            idx = idx / num_leaves_per_tree;
        }

        // update states
        let mut idx = self.size / num_leaves_per_tree;
        for i in 0..self.trees.len() {
            self.states[i].insert(idx, self.trees[i].clone());
            idx /= num_leaves_per_tree;
        }

        self.size += 1;
        Ok(())
    }

    fn new(
        capacity_per_tree: u32,
        num_tree: u32,
        params: &'a PoseidonConfig<P::BasePrimeField>,
    ) -> Result<Self, MerkleForestError> {
        if num_tree == 0 {
            return Err(MerkleForestError::InvalidNumTree);
        }

        let trees = vec![MerkleTree::new(capacity_per_tree as usize, params)?; num_tree as usize];
        let states = vec![HashMap::new(); num_tree as usize];

        Ok(Self {
            trees,
            states,
            size: 0,
        })
    }

    // the `Construct-Naive` algorithm in the thesis
    #[allow(dead_code)]
    fn new_with_data_naive(
        data: &[&<Poseidon<P::BasePrimeField> as CRHScheme>::Input],
        params: &'a PoseidonConfig<P::BasePrimeField>,
    ) -> Result<Self, MerkleForestError> {
        let mut s = Self::new_optimal(data.len(), params)?;

        for d in data {
            s.seqadd(d)?;
        }

        Ok(s)
    }
}

#[allow(clippy::cast_precision_loss)]
#[allow(clippy::cast_sign_loss)]
pub fn forest_stats(capacity_per_tree: u32, num_tree: u32) -> (u64, u64, u128) {
    // reserve space for mul
    let capacity_per_tree = u64::from(capacity_per_tree);
    let num_tree = u64::from(num_tree);

    assert!(
        (capacity_per_tree + 1).is_power_of_two(),
        "capacity + 1 must be a power of 2"
    );
    assert!(capacity_per_tree >= 3, "capacity must be >= 3");

    let proof_size = u64::from(((capacity_per_tree + 1) / 2).ilog2()) * num_tree;
    let forest_state_size = capacity_per_tree * num_tree;

    #[allow(clippy::cast_possible_truncation)]
    let n = ((capacity_per_tree + 1) / 2).pow(num_tree as u32);

    // The following is upper bounded when setting `r = 2 / capacity_per_tree`
    // safety: capacity_per_tree + 1 <= 2^32
    let r = 2. / (capacity_per_tree + 1) as f64;
    #[allow(clippy::cast_possible_truncation)]
    let max_permanent_state_size = f64::from(capacity_per_tree as u32)
        * n as f64
        * ((1. - r.powi(i32::try_from(num_tree).expect("num_tree is too large for i32") + 1))
            / (1. - r)
            - 1.);

    println!(
        "proof size: {}",
        u64::from(((capacity_per_tree + 1) / 2).ilog2()) * num_tree
    );
    println!("forest state size: {}", forest_state_size);
    println!("max permanent state size: {}", max_permanent_state_size);
    println!("plain merkle tree size: {}", 2 * n - 1);

    let max_permanent_state_size = max_permanent_state_size.ceil();
    #[allow(clippy::cast_possible_truncation)]
    let max_permanent_state_size_r = max_permanent_state_size.ceil() as u128;
    assert_eq!(
        max_permanent_state_size_r as f64, max_permanent_state_size,
        "max_permanent_state_size is too large for u128"
    );

    (proof_size, forest_state_size, max_permanent_state_size_r)
}

/// Find the optimal forest parameters for a given `n` with respect to the forest state size
pub fn optimal_forest_params(n: usize) -> (u32, u32) {
    let n = int_to_safe_float(n as u64);

    // minimize log2(N)/log2(q/2)*q with respect to q
    let q = 2. * std::f64::consts::E;
    // safe: as q = 2e
    #[allow(clippy::cast_possible_truncation)]
    #[allow(clippy::cast_sign_loss)]
    let q = (q.ceil() as u32).next_power_of_two() - 1;

    // safe: as n (float) >= n (uint)
    #[allow(clippy::cast_precision_loss)]
    let k = n.log(f64::from(q) / 2.);

    let k = k.ceil();
    #[allow(clippy::cast_possible_truncation)]
    #[allow(clippy::cast_sign_loss)]
    let kr = k as u32;
    assert_eq!(f64::from(kr), k, "k is too large for u32");

    // guard against when n = 1
    let kr = std::cmp::max(1, kr);

    (q, kr)
}

fn int_to_safe_float(x: u64) -> f64 {
    let f = x as f64;
    let back = f as u64;

    if back < x {
        // Float rounded down — nudge up to ensure it's at least x
        f.next_up()
    } else {
        // Either exact or rounded up
        f
    }
}

const fn next_power_of_q(n: usize, q: usize) -> usize {
    debug_assert!(q.is_power_of_two() && q > 1);

    // start at 1, keep multiplying by q until we reach >= n
    // - this does not guard against possible overflows
    let mut p = 1;
    while p < n {
        p *= q;
    }
    p
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fr;
    use ark_ff::UniformRand;
    use folding_schemes::transcript::poseidon::poseidon_canonical_config;
    use rand::thread_rng;
    use rayon::iter::{IntoParallelIterator, ParallelIterator};

    struct TestConfig;
    impl MerkleConfig for TestConfig {
        type BasePrimeField = Fr;
    }

    fn poseidon_params() -> PoseidonConfig<Fr> {
        poseidon_canonical_config::<Fr>()
    }

    #[test]
    fn test_merkles_forest_creation_single_tree() {
        let params = poseidon_params(); // Use any appropriate field
        let capacity_per_tree = 8 - 1;
        let num_tree = 1;

        let forest = LeveledMerkleForest::<TestConfig>::new(capacity_per_tree, num_tree, &params);
        assert!(forest.is_ok());
        let forest = forest.unwrap();
        assert_eq!(forest.trees.len(), num_tree as usize);
        assert_eq!(forest.num_leaves_per_tree(), 4);
    }

    #[test]
    fn test_merkles_forest_creation_multiple_trees() {
        let params = poseidon_params();
        let capacity_per_tree = 8 - 1;
        let num_tree = 3;

        let forest = LeveledMerkleForest::<TestConfig>::new(capacity_per_tree, num_tree, &params);
        assert!(forest.is_ok());
        let forest = forest.unwrap();
        assert_eq!(forest.trees.len(), num_tree as usize);
    }

    #[test]
    fn test_seqadd_single_element() {
        let params = poseidon_params();
        let capacity_per_tree = 8 - 1;
        let num_tree = 3;
        let mut forest =
            LeveledMerkleForest::<TestConfig>::new(capacity_per_tree, num_tree, &params).unwrap();

        let val = {
            let mut rng = thread_rng();
            Fr::rand(&mut rng)
        };
        let add_result = forest.seqadd(&[val]);
        assert!(add_result.is_ok());
        assert_eq!(forest.size, 1);
    }

    #[test]
    fn test_seqadd_multiple_elements() {
        let params = poseidon_params();
        let capacity_per_tree = 8 - 1;
        let num_tree = 3;
        let mut forest =
            LeveledMerkleForest::<TestConfig>::new(capacity_per_tree, num_tree, &params).unwrap();

        for _ in 0..5 {
            let val = {
                let mut rng = thread_rng();
                Fr::rand(&mut rng)
            };
            let add_result = forest.seqadd(&[val]);
            assert!(add_result.is_ok());
        }
        assert_eq!(forest.size, 5);
    }

    #[test]
    fn test_seqadd_until_full() {
        let params = poseidon_params();
        let capacity_per_tree = 4 - 1; // Small capacity for testing full condition
        let num_tree = 3;
        let mut forest =
            LeveledMerkleForest::<TestConfig>::new(capacity_per_tree, num_tree, &params).unwrap();

        // Fill up the forest completely
        for _ in 0..8 {
            let val = {
                let mut rng = thread_rng();
                Fr::rand(&mut rng)
            };
            let add_result = forest.seqadd(&[val]);
            assert!(add_result.is_ok());
        }

        // After adding 8 elements, the size should be 8, and trees should reset appropriately
        assert_eq!(forest.size, 8);
    }

    #[test]
    fn test_prove_and_verify_large_capacity() {
        let params = poseidon_params();
        let capacity_per_tree = 8 - 1;
        let num_tree = 3;
        let mut forest =
            LeveledMerkleForest::<TestConfig>::new(capacity_per_tree, num_tree, &params).unwrap();

        let mut values = vec![];
        for _ in 0..3 {
            let val = {
                let mut rng = thread_rng();
                Fr::rand(&mut rng)
            };
            values.push(val);
            let add_result = forest.seqadd(&[val]);
            assert!(add_result.is_ok());
        }

        let leaf_index = 2; // Index of the leaf we want to prove
        let proof_result = forest.prove(leaf_index);

        assert!(proof_result.is_ok());
        let proof = proof_result.unwrap();
        assert_eq!(proof.leaf_index, leaf_index);

        // Verify the proof
        let root = forest.root();
        let verify_result = LeveledMerkleForest::<TestConfig>::verify(
            &params,
            root,
            either::Right(&[values[leaf_index]]),
            proof,
        );
        assert!(verify_result.is_ok());
        assert_eq!(verify_result.unwrap(), true);
    }

    #[test]
    fn test_prove_and_verify_small_capacity() {
        let params = poseidon_params();
        let capacity_per_tree = 4 - 1;
        let num_tree = 3;
        let mut forest =
            LeveledMerkleForest::<TestConfig>::new(capacity_per_tree, num_tree, &params).unwrap();

        let mut values = vec![];
        for _ in 0..6 {
            let val = {
                let mut rng = thread_rng();
                Fr::rand(&mut rng)
            };
            values.push(val);
            let add_result = forest.seqadd(&[val]);
            assert!(add_result.is_ok());
        }

        let leaf_index = 5; // Index of the leaf we want to prove
        let proof_result = forest.prove(leaf_index);

        assert!(proof_result.is_ok());
        let proof = proof_result.unwrap();
        assert_eq!(proof.leaf_index, leaf_index);

        // Verify the proof
        let root = forest.root();
        let verify_result = LeveledMerkleForest::<TestConfig>::verify(
            &params,
            root,
            either::Right(&[values[leaf_index]]),
            proof,
        );
        assert!(verify_result.is_ok());
        assert_eq!(verify_result.unwrap(), true);
    }

    #[test]
    fn test_prove_and_verify_large_capacity_variable() {
        let params = poseidon_params();
        let capacity_per_tree = 8 - 1;
        let num_tree = 3;
        let mut forest =
            LeveledMerkleForest::<TestConfig>::new(capacity_per_tree, num_tree, &params).unwrap();

        let mut values = vec![];
        for _ in 0..forest.max_leaves() {
            let val = {
                let mut rng = thread_rng();
                Fr::rand(&mut rng)
            };
            values.push(val);
            let add_result = forest.seqadd(&[val]);
            assert!(add_result.is_ok());
        }

        let leaf_index = forest.max_leaves() - 1; // Index of the leaf we want to prove
        let proof_result = forest.prove_variable(leaf_index);

        assert!(proof_result.is_ok());
        let proof = proof_result.unwrap();
        assert_eq!(proof.leaf_index, leaf_index);

        // Verify the proof
        let verify_result = LeveledMerkleForest::<TestConfig>::verify_variable(
            &params,
            forest.states(),
            forest.size(),
            forest.num_leaves_per_tree(),
            either::Right(&[values[leaf_index]]),
            proof,
        );

        assert!(verify_result.is_ok());
        assert_eq!(verify_result.unwrap(), true);
    }

    #[test]
    fn test_prove_and_verify_small_capacity_variable() {
        let params = poseidon_params();
        let capacity_per_tree = 4 - 1;
        let num_tree = 3;
        let mut forest =
            LeveledMerkleForest::<TestConfig>::new(capacity_per_tree, num_tree, &params).unwrap();

        let mut values = vec![];
        for _ in 0..forest.max_leaves() {
            let val = {
                let mut rng = thread_rng();
                Fr::rand(&mut rng)
            };
            values.push(val);
            let add_result = forest.seqadd(&[val]);
            assert!(add_result.is_ok());
        }

        let leaf_index = forest.max_leaves() - 1; // Index of the leaf we want to prove
        let proof_result = forest.prove_variable(leaf_index);

        assert!(proof_result.is_ok());
        let proof = proof_result.unwrap();
        assert_eq!(proof.leaf_index, leaf_index);

        // Verify the proof
        let verify_result = LeveledMerkleForest::<TestConfig>::verify_variable(
            &params,
            forest.states(),
            forest.size(),
            forest.num_leaves_per_tree(),
            either::Right(&[values[leaf_index]]),
            proof,
        );
        assert!(verify_result.is_ok());
        assert_eq!(verify_result.unwrap(), true);
    }

    #[test]
    fn test_prove_out_of_bound() {
        let params = poseidon_params();
        let capacity_per_tree = 8 - 1;
        let num_tree = 3;
        let mut forest =
            LeveledMerkleForest::<TestConfig>::new(capacity_per_tree, num_tree, &params).unwrap();

        for _ in 0..3 {
            let val = {
                let mut rng = thread_rng();
                Fr::rand(&mut rng)
            };
            let add_result = forest.seqadd(&[val]);
            assert!(add_result.is_ok());
        }

        let leaf_index = 4; // Out of bound index (we only have 3 elements)
        let proof_result = forest.prove(leaf_index);
        assert!(matches!(
            proof_result,
            Err(MerkleForestError::IndexOutOfBound)
        ));
    }

    #[test]
    fn test_invalid_num_tree() {
        let params = poseidon_params();
        let capacity_per_tree = 8 - 1;
        let num_tree = 0; // Invalid number of trees

        let forest = LeveledMerkleForest::<TestConfig>::new(capacity_per_tree, num_tree, &params);
        assert!(matches!(forest, Err(MerkleForestError::InvalidNumTree)));
    }

    #[test]
    fn test_forest_stats() {
        let params = poseidon_params();
        let capacity_per_tree = 8 - 1;
        let num_tree = 3; // Invalid number of trees

        let mut forest =
            LeveledMerkleForest::<TestConfig>::new(capacity_per_tree, num_tree, &params).unwrap();
        forest.seqadd(&[Fr::default()]).unwrap();

        let (proof_size, _, max_permanent_state_size) = forest_stats(capacity_per_tree, num_tree);

        let proof = forest.prove(0).unwrap();
        assert_eq!(proof_size as usize, proof.siblings.len());

        // populate the forest
        for _ in 0..((capacity_per_tree + 1) / 2).pow(num_tree as u32) - 1 {
            forest.seqadd(&[Fr::default()]).unwrap();
        }

        // count permanent state size
        let mut actual_permanent_state_size = 0;
        for i in 0..num_tree as usize {
            actual_permanent_state_size += forest.states[i].len() * capacity_per_tree as usize;
        }

        assert_eq!(
            max_permanent_state_size as usize,
            actual_permanent_state_size
        );
    }

    fn test_new_with_data_helper(data_size: usize) {
        let params = poseidon_params();
        let mut values = Vec::new();
        for _ in 0..data_size {
            let val = {
                let mut rng = thread_rng();
                Fr::rand(&mut rng)
            };
            values.push(val);
        }

        let forest =
            LeveledMerkleForest::<TestConfig>::new_with_data(either::Left(&values), &params)
                .unwrap();

        fn is_power_of_q(x: usize, q: usize) -> bool {
            let i = x.ilog(q);
            if q.pow(i) as usize == x {
                return true;
            }
            false
        }

        for i in 0..values.len() {
            let proof = forest.prove(i).unwrap();
            let valid = LeveledMerkleForest::verify(
                &params,
                forest.root(),
                either::Left(&values[i]),
                proof,
            )
            .unwrap();
            assert!(valid);

            let proof = forest.prove_variable(i).unwrap();

            // enforce variable length proof property
            let n = next_power_of_q(values.len(), forest.num_leaves_per_tree() as usize);
            let diff = n - i;
            if is_power_of_q(diff, forest.num_leaves_per_tree() as usize) && diff != 1 {
                assert_eq!(
                    proof.siblings.len(),
                    forest.num_leaves_per_tree().ilog2() as usize
                        * diff
                            .ilog(forest.num_leaves_per_tree() as usize)
                            .saturating_sub(1) as usize
                )
            }

            let valid = LeveledMerkleForest::<TestConfig>::verify_variable(
                &params,
                forest.states(),
                forest.size(),
                forest.num_leaves_per_tree(),
                either::Left(&values[i]),
                proof,
            )
            .unwrap();
            assert!(valid);
        }
    }

    #[test]
    fn test_new_with_data() {
        (1..=128).into_par_iter().for_each(|i| {
            test_new_with_data_helper(i);
        });
    }

    #[test]
    fn play_with_optimal_params() {
        let (capacity_per_tree, num_tree) = optimal_forest_params(1 << 25);
        println!("capacity_per_tree: {}", capacity_per_tree);
        println!("num_tree: {}", num_tree);
        forest_stats(capacity_per_tree, num_tree);
    }
}
