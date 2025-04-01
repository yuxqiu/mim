use std::{cmp::max, collections::HashMap};

use ark_crypto_primitives::{
    crh::{
        poseidon::{TwoToOneCRH as PoseidonTwoToOne, CRH as Poseidon},
        CRHScheme, TwoToOneCRHScheme,
    },
    sponge::poseidon::PoseidonConfig,
};
use derivative::Derivative;
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

impl<'a, P: MerkleConfig> LeveledMerkleForest<'a, P> {
    #[inline]
    fn num_leaves_per_tree(&self) -> usize {
        self.trees[0].num_leaves()
    }

    #[inline]
    fn max_leaves(&self) -> usize {
        self.num_leaves_per_tree().pow(self.trees.len() as u32)
    }

    #[inline]
    fn is_left_node(index: usize) -> bool {
        index & 1 == 0
    }

    pub fn new(
        capacity_per_tree: usize,
        num_tree: usize,
        params: &'a PoseidonConfig<P::BasePrimeField>,
    ) -> Result<Self, MerkleForestError> {
        if num_tree == 0 {
            return Err(MerkleForestError::InvalidNumTree);
        }

        let trees = vec![MerkleTree::new(capacity_per_tree, params)?; num_tree];
        let states = vec![HashMap::new(); num_tree];

        Ok(Self {
            trees,
            states,
            size: 0,
        })
    }

    pub fn add(
        &mut self,
        val: &<Poseidon<P::BasePrimeField> as CRHScheme>::Input,
    ) -> Result<(), MerkleForestError> {
        if self.size == self.max_leaves() {
            return Err(MerkleForestError::ForestIsFull);
        }

        let mut is_prev_tree_full = self.trees[0].is_full();
        if is_prev_tree_full {
            self.trees[0].reset_size();
        }
        self.trees[0].add(val)?;

        // update Merkle trees
        let mut node = self.trees[0].root();
        for i in 1..self.trees.len() {
            let is_cur_tree_full = self.trees[i].is_full();
            if is_cur_tree_full {
                self.trees[i].reset_size();
            }
            if is_prev_tree_full || self.trees[i].is_empty() {
                self.trees[i].add_with_hash(node)?;
            } else {
                let idx = self.trees[i].last_idx();
                self.trees[i].update_with_hash(idx, node)?;
            }
            node = self.trees[i].root();
            is_prev_tree_full = is_cur_tree_full;
        }

        // update states
        let num_leaves_per_tree = self.num_leaves_per_tree();
        let mut idx = self.size / num_leaves_per_tree;
        for i in 0..self.trees.len() {
            self.states[i].insert(idx, self.trees[i].clone());
            idx /= num_leaves_per_tree;
        }

        self.size += 1;
        Ok(())
    }

    pub fn prove(&self, leaf_index: usize) -> Result<MerkleForestProof<P>, MerkleForestError> {
        if leaf_index >= self.size {
            return Err(MerkleForestError::IndexOutOfBound);
        }

        let mut forest_proof = vec![];
        let mut idx = leaf_index;

        let num_leaves_per_tree = self.num_leaves_per_tree();
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
            leaf_index: leaf_index,
            num_leaves_per_tree: num_leaves_per_tree,
        })
    }

    pub fn verify(
        params: &PoseidonConfig<P::BasePrimeField>,
        root: P::BasePrimeField,
        leaf: &<Poseidon<P::BasePrimeField> as CRHScheme>::Input,
        proof: MerkleForestProof<P>,
    ) -> Result<bool, MerkleForestError> {
        let mut hash = Poseidon::evaluate(&params, leaf).map_err(|_| MerkleTreeError::CRHError)?;

        let mut index = proof.leaf_index;

        for sibling in proof.siblings {
            let idx_within_tree = index % proof.num_leaves_per_tree;
            if Self::is_left_node(idx_within_tree) {
                hash = PoseidonTwoToOne::evaluate(&params, hash, sibling)
                    .map_err(|_| MerkleTreeError::CRHError)?;
            } else {
                hash = PoseidonTwoToOne::evaluate(&params, sibling, hash)
                    .map_err(|_| MerkleTreeError::CRHError)?;
            }
            index /= proof.num_leaves_per_tree;
        }

        Ok(hash == root)
    }

    pub fn root(&self) -> P::BasePrimeField {
        self.trees
            .last()
            .expect("forest should not be empty")
            .root()
    }
}

pub fn forest_stats(capacity_per_tree: usize, num_tree: usize) -> (usize, usize, usize) {
    assert!(
        (capacity_per_tree + 1).is_power_of_two(),
        "capacity + 1 must be a power of 2"
    );
    assert!(capacity_per_tree >= 3, "capacity must be >= 3");

    let proof_size = ((capacity_per_tree + 1) / 2).ilog2() as usize * num_tree;
    let forest_state_size = capacity_per_tree * num_tree;

    let n = ((capacity_per_tree + 1) / 2).pow(num_tree as u32);

    // the following is upper bounded when setting `r = 2 / capacity_per_tree`
    let r = 2. / (capacity_per_tree + 1) as f64;
    let max_permanent_state_size =
        capacity_per_tree as f64 * n as f64 * ((1. - r.powi(num_tree as i32 + 1)) / (1. - r) - 1.);

    println!(
        "proof size: {}",
        ((capacity_per_tree + 1) / 2).ilog2() as usize * num_tree
    );
    println!("forest state size: {}", forest_state_size);
    println!("max permanent state size: {}", max_permanent_state_size);
    println!("plain merkle tree size: {}", 2 * n - 1);

    (
        proof_size,
        forest_state_size,
        max_permanent_state_size.ceil() as usize,
    )
}

/// Find the optimal forest parameters for a given `n` with respect to the forest state size
pub fn optimal_forest_params(n: usize) -> (usize, usize) {
    // round n to the next power of 2
    let n = n.next_power_of_two();

    // minimize log2(2N/q)/log2(q/2)*q with respect to q
    let a = n.ilog2() as f64;
    let q = 2_f64.powf((2. + a - (a * a - 4. * a / std::f64::consts::LN_2).sqrt()) / 2.);
    let q = (q.ceil() as usize).next_power_of_two() - 1;
    let q = max(q, 3);
    let k = ((2. * n as f64) / q as f64).log2() / (q as f64 / 2.).log2();
    (q, k.ceil() as usize)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fr;
    use ark_ff::UniformRand;
    use folding_schemes::transcript::poseidon::poseidon_canonical_config;
    use rand::thread_rng;

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
        assert_eq!(forest.trees.len(), num_tree);
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
        assert_eq!(forest.trees.len(), num_tree);
    }

    #[test]
    fn test_add_single_element() {
        let params = poseidon_params();
        let capacity_per_tree = 8 - 1;
        let num_tree = 3;
        let mut forest =
            LeveledMerkleForest::<TestConfig>::new(capacity_per_tree, num_tree, &params).unwrap();

        let val = {
            let mut rng = thread_rng();
            Fr::rand(&mut rng)
        };
        let add_result = forest.add(&[val]);
        assert!(add_result.is_ok());
        assert_eq!(forest.size, 1);
    }

    #[test]
    fn test_add_multiple_elements() {
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
            let add_result = forest.add(&[val]);
            assert!(add_result.is_ok());
        }
        assert_eq!(forest.size, 5);
    }

    #[test]
    fn test_add_until_full() {
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
            let add_result = forest.add(&[val]);
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
            let add_result = forest.add(&[val]);
            assert!(add_result.is_ok());
        }

        let leaf_index = 2; // Index of the leaf we want to prove
        let proof_result = forest.prove(leaf_index);

        assert!(proof_result.is_ok());
        let proof = proof_result.unwrap();
        assert_eq!(proof.leaf_index, leaf_index);

        // Verify the proof
        let root = forest.root();
        let verify_result =
            LeveledMerkleForest::<TestConfig>::verify(&params, root, &[values[leaf_index]], proof);
        assert!(verify_result.is_ok());
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
            let add_result = forest.add(&[val]);
            assert!(add_result.is_ok());
        }

        let leaf_index = 5; // Index of the leaf we want to prove
        let proof_result = forest.prove(leaf_index);

        assert!(proof_result.is_ok());
        let proof = proof_result.unwrap();
        assert_eq!(proof.leaf_index, leaf_index);

        // Verify the proof
        let root = forest.root();
        let verify_result =
            LeveledMerkleForest::<TestConfig>::verify(&params, root, &[values[leaf_index]], proof);
        assert!(verify_result.is_ok());
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
            let add_result = forest.add(&[val]);
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
        forest.add(&[Fr::default()]).unwrap();

        let (proof_size, _, max_permanent_state_size) = forest_stats(capacity_per_tree, num_tree);

        let proof = forest.prove(0).unwrap();
        assert_eq!(proof_size, proof.siblings.len());

        // populate the forest
        for _ in 0..((capacity_per_tree + 1) / 2).pow(num_tree as u32) - 1 {
            forest.add(&[Fr::default()]).unwrap();
        }

        // count permanent state size
        let mut actual_permanent_state_size = 0;
        for i in 0..num_tree {
            actual_permanent_state_size += forest.states[i].len() * capacity_per_tree;
        }

        assert_eq!(max_permanent_state_size, actual_permanent_state_size);
    }

    #[test]
    fn play_with_optimal_params() {
        let (capacity_per_tree, num_tree) = optimal_forest_params(1 << 30);
        println!("capacity_per_tree: {}", capacity_per_tree);
        forest_stats(capacity_per_tree, num_tree);
    }
}
