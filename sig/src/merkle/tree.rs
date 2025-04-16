use ark_crypto_primitives::{
    crh::{
        poseidon::{TwoToOneCRH as PoseidonTwoToOne, CRH as Poseidon},
        CRHScheme, TwoToOneCRHScheme,
    },
    sponge::poseidon::PoseidonConfig,
};
use derivative::Derivative;
use either::{for_both, Either};
use thiserror::Error;

use super::{is_left_node, left, parent, right, MerkleConfig};

#[derive(Derivative)]
#[derivative(Debug(bound = ""))]
pub struct MerkleTree<'a, P: MerkleConfig> {
    states: Vec<P::BasePrimeField>,

    #[derivative(Debug = "ignore")]
    params: &'a PoseidonConfig<P::BasePrimeField>,
}

impl<'a, P: MerkleConfig> Clone for MerkleTree<'a, P> {
    fn clone(&self) -> Self {
        Self {
            states: self.states.clone(),
            params: self.params,
        }
    }
}

#[derive(Error, Debug)]
pub enum MerkleTreeError {
    #[error("Merkle tree is full")]
    TreeIsFull,

    #[error("Leaf index out of bound")]
    IndexOutOfBound,

    #[error("Path length mismatches")]
    PathLenMismatch,

    #[error("capacity != 2^k - 1 for k >= 2")]
    InvalidCapacity,

    #[error("Poseidon CRH evaluation failed")]
    CRHError,
}

pub type MerkleProof<P> = (Vec<<P as MerkleConfig>::BasePrimeField>, usize);

impl<'a, P: MerkleConfig> MerkleTree<'a, P> {
    pub fn new(
        capacity: usize,
        params: &'a PoseidonConfig<P::BasePrimeField>,
    ) -> Result<Self, MerkleTreeError> {
        let mut s = Self::new_with_empty(capacity, params)?;

        // ensure the constructed merkle tree is valid
        for i in (0..s.leaf_start()).rev() {
            s.update_state(i)?;
        }

        Ok(s)
    }

    pub fn new_with_data(
        data: Either<&[P::BasePrimeField], &[&<Poseidon<P::BasePrimeField> as CRHScheme>::Input]>,
        params: &'a PoseidonConfig<P::BasePrimeField>,
    ) -> Result<Self, MerkleTreeError> {
        let len = for_both!(data, data => data.len());
        let capacity = len * 2 - 1;
        let mut s = Self::new_with_empty(capacity, params)?;

        let data = match data {
            Either::Left(v) => v.to_owned(),
            Either::Right(v) => {
                let mut data = Vec::new();
                data.reserve_exact(v.len());
                for d in v {
                    data.push(
                        Poseidon::evaluate(s.params, *d).map_err(|_| MerkleTreeError::CRHError)?,
                    );
                }
                data
            }
        };

        let leaf_start = s.leaf_start();
        for (h, v) in s.states[leaf_start..].iter_mut().zip(data) {
            *h = v;
        }

        // O(N) construction
        for i in (0..leaf_start).rev() {
            s.update_state(i)?;
        }

        Ok(s)
    }

    pub fn prove(&self, leaf_index: usize) -> Result<MerkleProof<P>, MerkleTreeError> {
        if leaf_index >= self.num_leaves() {
            return Err(MerkleTreeError::IndexOutOfBound);
        }

        let mut proof = Vec::new();
        let mut index = self.leaf_start() + leaf_index;
        while index > 0 {
            let sibling = Self::sibling(index);
            proof.push(self.states[sibling]);
            index = parent(index);
        }
        Ok((proof, self.leaf_start() + leaf_index))
    }

    pub fn update(
        &mut self,
        leaf_index: usize,
        val: &<Poseidon<P::BasePrimeField> as CRHScheme>::Input,
    ) -> Result<(), MerkleTreeError> {
        if leaf_index >= self.num_leaves() {
            return Err(MerkleTreeError::IndexOutOfBound);
        }

        self.update_with_hash(
            leaf_index,
            Poseidon::evaluate(self.params, val).map_err(|_| MerkleTreeError::CRHError)?,
        )
    }

    #[inline]
    pub fn root(&self) -> P::BasePrimeField {
        self.states[0]
    }

    pub fn verify(
        params: &PoseidonConfig<P::BasePrimeField>,
        root: P::BasePrimeField,
        leaf: Either<&P::BasePrimeField, &<Poseidon<P::BasePrimeField> as CRHScheme>::Input>,
        proof: MerkleProof<P>,
    ) -> Result<bool, MerkleTreeError> {
        let (siblings, leaf_index) = proof;
        if (leaf_index + 1).ilog2() as usize != siblings.len() {
            return Err(MerkleTreeError::PathLenMismatch);
        }

        let hash = match leaf {
            Either::Left(v) => *v,
            Either::Right(v) => {
                Poseidon::evaluate(params, v).map_err(|_| MerkleTreeError::CRHError)?
            }
        };
        let hash = Self::hash_path(params, hash, leaf_index, &siblings)?;
        Ok(hash == root)
    }

    #[inline]
    pub fn capacity(&self) -> usize {
        self.states.len()
    }

    #[inline]
    pub fn num_leaves(&self) -> usize {
        (self.capacity() + 1) / 2
    }

    pub(crate) fn hash_path(
        params: &PoseidonConfig<P::BasePrimeField>,
        mut hash: P::BasePrimeField,
        mut index: usize,
        siblings: &[P::BasePrimeField],
    ) -> Result<P::BasePrimeField, MerkleTreeError> {
        for sibling in siblings {
            if is_left_node(index) {
                hash = PoseidonTwoToOne::evaluate(params, hash, *sibling)
                    .map_err(|_| MerkleTreeError::CRHError)?;
            } else {
                hash = PoseidonTwoToOne::evaluate(params, sibling, &hash)
                    .map_err(|_| MerkleTreeError::CRHError)?;
            }
            index = parent(index);
        }
        Ok(hash)
    }

    pub(crate) fn update_with_hash(
        &mut self,
        leaf_index: usize,
        val: P::BasePrimeField,
    ) -> Result<(), MerkleTreeError> {
        if leaf_index >= (self.capacity() + 1) / 2 {
            return Err(MerkleTreeError::IndexOutOfBound);
        }

        let mut index = self.leaf_start() + leaf_index;
        self.states[index] = val;
        while index > 0 {
            index = parent(index);
            self.update_state(index)?;
        }

        Ok(())
    }

    const fn sibling(index: usize) -> usize {
        if index % 2 == 0 {
            index - 1
        } else {
            index + 1
        }
    }

    #[inline]
    fn new_with_empty(
        capacity: usize,
        params: &'a PoseidonConfig<P::BasePrimeField>,
    ) -> Result<Self, MerkleTreeError> {
        if capacity < 3 || !(capacity + 1).is_power_of_two() {
            return Err(MerkleTreeError::InvalidCapacity);
        }

        let s = Self {
            states: vec![P::BasePrimeField::default(); capacity],
            params,
        };

        Ok(s)
    }

    #[inline]
    fn leaf_start(&self) -> usize {
        (self.capacity() + 1) / 2 - 1
    }

    fn update_state(&mut self, index: usize) -> Result<(), MerkleTreeError> {
        let left = left(index);
        let right = right(index);
        self.states[index] =
            PoseidonTwoToOne::evaluate(self.params, self.states[left], self.states[right])
                .map_err(|_| MerkleTreeError::CRHError)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fr;
    use ark_ff::UniformRand;
    use folding_schemes::transcript::poseidon::poseidon_canonical_config;
    use rand::{rngs::StdRng, thread_rng, SeedableRng};

    struct TestConfig;
    impl MerkleConfig for TestConfig {
        type BasePrimeField = Fr;
    }

    fn poseidon_params() -> PoseidonConfig<Fr> {
        poseidon_canonical_config::<Fr>()
    }

    fn test_tree_with_capacity(capacity: usize) {
        let params = poseidon_params();

        // Test tree creation
        let tree = MerkleTree::<TestConfig>::new(capacity, &params);
        if capacity < 3 || !(capacity + 1).is_power_of_two() {
            assert!(matches!(tree, Err(MerkleTreeError::InvalidCapacity)));
            return;
        }

        let mut tree = tree.unwrap();

        let mut rng = thread_rng();
        let leaf = Fr::rand(&mut rng);

        // Test adding a leaf
        assert!(tree.update(0, &[leaf]).is_ok());

        // Test updating a leaf
        let new_leaf = Fr::rand(&mut rng);
        assert!(tree.update(0, &[new_leaf]).is_ok());

        // Test proof generation
        let proof = tree.prove(0);
        assert!(proof.is_ok());

        // Test proof verification
        let proof = proof.unwrap();
        let root = tree.root();
        let valid =
            MerkleTree::<TestConfig>::verify(&params, root, either::Right(&[new_leaf]), proof);
        assert!(matches!(valid, Ok(true)));
    }

    #[test]
    fn test_merkle_tree_varied_capacities() {
        for capacity in [1, 2, 3, 4, 8, 16] {
            test_tree_with_capacity(capacity);
        }
    }

    fn test_large_tree_operations(capacity: usize) {
        let params = poseidon_params();

        // Create a tree with a large capacity
        let mut tree = MerkleTree::<TestConfig>::new(capacity, &params).unwrap();

        let mut rng = thread_rng();
        let leaf_max_index = (capacity + 1) / 2;

        // Perform multiple add operations
        let mut leaves = Vec::new();
        for i in 0..leaf_max_index {
            let leaf = Fr::rand(&mut rng);
            leaves.push(leaf);
            assert!(tree.update(i, &[leaf]).is_ok());
        }

        for i in 0..leaf_max_index {
            let proof = tree.prove(i).unwrap();
            let root = tree.root();

            // Verify the proof of each updated leaf
            let valid =
                MerkleTree::<TestConfig>::verify(&params, root, either::Right(&[leaves[i]]), proof);
            assert!(matches!(valid, Ok(true)));
        }

        // Perform multiple update operations
        let mut leaves = Vec::new();
        for i in 0..leaf_max_index {
            let new_leaf = Fr::rand(&mut rng);
            leaves.push(new_leaf);
            assert!(tree.update(i, &[new_leaf]).is_ok());
        }

        // Verify the updates
        for i in 0..leaf_max_index {
            let proof = tree.prove(i).unwrap();
            let root = tree.root();

            // Verify the proof of each updated leaf
            let valid =
                MerkleTree::<TestConfig>::verify(&params, root, either::Right(&[leaves[i]]), proof);
            assert!(matches!(valid, Ok(true)));
        }
    }

    #[test]
    fn test_large_tree_operations_varied_capacities() {
        for capacity in [4 - 1, 32 - 1, 64 - 1, 128 - 1] {
            test_large_tree_operations(capacity);
        }
    }

    #[test]
    fn test_new_with_data() {
        let mut rng = StdRng::from_seed([42; 32]);
        let leaf_max_index = 128;
        let params = poseidon_params();

        let mut leaves = Vec::new();
        for _ in 0..leaf_max_index {
            leaves.push(Fr::rand(&mut rng));
        }

        let merkle =
            MerkleTree::<TestConfig>::new_with_data(either::Left(&leaves), &params).unwrap();
        for i in 0..leaf_max_index {
            let p = merkle.prove(i).unwrap();
            let valid = MerkleTree::<TestConfig>::verify(
                &params,
                merkle.root(),
                either::Left(&leaves[i]),
                p,
            )
            .unwrap();
            assert!(valid);
        }
    }
}
