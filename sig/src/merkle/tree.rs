use ark_crypto_primitives::{
    crh::{
        poseidon::{TwoToOneCRH as PoseidonTwoToOne, CRH as Poseidon},
        CRHScheme, TwoToOneCRHScheme,
    },
    sponge::{poseidon::PoseidonConfig, Absorb},
};
use ark_ff::PrimeField;
use derivative::Derivative;
use thiserror::Error;

pub trait MerkleConfig {
    type BasePrimeField: PrimeField + Absorb;
}

#[derive(Derivative)]
#[derivative(Debug(bound = ""))]
pub struct MerkleTree<'a, P: MerkleConfig> {
    states: Vec<P::BasePrimeField>,
    size: usize,

    #[derivative(Debug = "ignore")]
    params: &'a PoseidonConfig<P::BasePrimeField>,
}

impl<'a, P: MerkleConfig> Clone for MerkleTree<'a, P> {
    fn clone(&self) -> Self {
        Self {
            states: self.states.clone(),
            size: self.size.clone(),
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
        if capacity < 3 || !(capacity + 1).is_power_of_two() {
            return Err(MerkleTreeError::InvalidCapacity);
        }

        let mut s = Self {
            states: vec![P::BasePrimeField::default(); capacity],
            size: 0,
            params: &params,
        };

        // ensure the constructed merkle tree is valid
        for i in (0..s.leaf_start()).rev() {
            s.update_state(i)?;
        }

        Ok(s)
    }

    pub fn prove(&self, leaf_index: usize) -> Result<MerkleProof<P>, MerkleTreeError> {
        if leaf_index >= self.size {
            return Err(MerkleTreeError::IndexOutOfBound);
        }

        let mut proof = Vec::new();
        let mut index = self.leaf_start() + leaf_index;
        while index > 0 {
            let sibling = Self::sibling(index);
            proof.push(self.states[sibling]);
            index = Self::parent(index);
        }
        Ok((proof, self.leaf_start() + leaf_index))
    }

    pub fn update(
        &mut self,
        leaf_index: usize,
        val: &<Poseidon<P::BasePrimeField> as CRHScheme>::Input,
    ) -> Result<(), MerkleTreeError> {
        if leaf_index >= (self.capacity() + 1) / 2 {
            return Err(MerkleTreeError::IndexOutOfBound);
        }

        self.update_with_hash(
            leaf_index,
            Poseidon::evaluate(&self.params, val).map_err(|_| MerkleTreeError::CRHError)?,
        )
    }

    pub fn add(
        &mut self,
        val: &<Poseidon<P::BasePrimeField> as CRHScheme>::Input,
    ) -> Result<(), MerkleTreeError> {
        if self.size == (self.capacity() + 1) / 2 {
            return Err(MerkleTreeError::TreeIsFull);
        }

        self.update(self.size, val)?;
        self.size += 1;
        Ok(())
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.size == 0
    }

    #[inline]
    pub fn is_full(&self) -> bool {
        self.size == (self.capacity() + 1) / 2
    }

    #[inline]
    pub fn root(&self) -> P::BasePrimeField {
        self.states[0]
    }

    pub fn verify(
        params: &PoseidonConfig<P::BasePrimeField>,
        root: P::BasePrimeField,
        leaf: &<Poseidon<P::BasePrimeField> as CRHScheme>::Input,
        proof: MerkleProof<P>,
    ) -> Result<bool, MerkleTreeError> {
        let (siblings, leaf_index) = proof;
        if (leaf_index + 1).ilog2() as usize != siblings.len() {
            return Err(MerkleTreeError::PathLenMismatch);
        }

        let mut hash = Poseidon::evaluate(&params, leaf).map_err(|_| MerkleTreeError::CRHError)?;

        let mut index = leaf_index;
        for sibling in siblings {
            if Self::is_left_node(index) {
                hash = PoseidonTwoToOne::evaluate(&params, hash, sibling)
                    .map_err(|_| MerkleTreeError::CRHError)?;
            } else {
                hash = PoseidonTwoToOne::evaluate(&params, sibling, hash)
                    .map_err(|_| MerkleTreeError::CRHError)?;
            }
            index = Self::parent(index);
        }

        Ok(hash == root)
    }

    fn sibling(index: usize) -> usize {
        if index % 2 == 0 {
            index - 1
        } else {
            index + 1
        }
    }

    #[inline]
    fn parent(index: usize) -> usize {
        (index - 1) / 2
    }

    #[inline]
    fn left(index: usize) -> usize {
        2 * index + 1
    }

    #[inline]
    fn right(index: usize) -> usize {
        2 * index + 2
    }

    #[inline]
    fn leaf_start(&self) -> usize {
        (self.capacity() + 1) / 2 - 1
    }

    #[inline]
    fn is_left_node(index: usize) -> bool {
        index & 1 == 1
    }

    #[inline]
    fn capacity(&self) -> usize {
        self.states.len()
    }

    fn update_state(&mut self, index: usize) -> Result<(), MerkleTreeError> {
        let left = Self::left(index);
        let right = Self::right(index);
        self.states[index] =
            PoseidonTwoToOne::evaluate(&self.params, self.states[left], self.states[right])
                .map_err(|_| MerkleTreeError::CRHError)?;
        Ok(())
    }

    #[inline]
    pub(crate) fn num_leaves(&self) -> usize {
        (self.capacity() + 1) / 2
    }

    #[inline]
    pub(crate) fn last_idx(&self) -> usize {
        self.size - 1
    }

    pub(crate) fn reset_size(&mut self) {
        self.size = 0;
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
            index = Self::parent(index);
            self.update_state(index)?;
        }

        Ok(())
    }

    pub(crate) fn add_with_hash(&mut self, val: P::BasePrimeField) -> Result<(), MerkleTreeError> {
        if self.size == (self.capacity() + 1) / 2 {
            return Err(MerkleTreeError::TreeIsFull);
        }

        self.update_with_hash(self.size, val)?;
        self.size += 1;
        Ok(())
    }
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

    fn test_tree_with_capacity(capacity: usize) {
        let params = poseidon_params();

        // Test tree creation
        let tree = MerkleTree::<TestConfig>::new(capacity, &params);
        if capacity < 3 || !(capacity + 1).is_power_of_two() {
            assert!(matches!(tree, Err(MerkleTreeError::InvalidCapacity)));
            return;
        }

        let mut tree = tree.unwrap();
        assert_eq!(tree.size, 0);

        let mut rng = thread_rng();
        let leaf = Fr::rand(&mut rng);

        // Test adding a leaf
        assert!(tree.add(&[leaf]).is_ok());
        assert_eq!(tree.size, 1);

        // Test updating a leaf
        let new_leaf = Fr::rand(&mut rng);
        assert!(tree.update(0, &[new_leaf]).is_ok());

        // Test proof generation
        let proof = tree.prove(0);
        assert!(proof.is_ok());

        // Test proof verification
        let proof = proof.unwrap();
        let root = tree.root();
        let valid = MerkleTree::<TestConfig>::verify(&params, root, &[new_leaf], proof);
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
        assert_eq!(tree.size, 0);

        let mut rng = thread_rng();
        let leaf_max_index = (capacity + 1) / 2;

        // Perform multiple add operations
        let mut leaves = Vec::new();
        for _ in 0..leaf_max_index {
            let leaf = Fr::rand(&mut rng);
            leaves.push(leaf);
            assert!(tree.add(&[leaf]).is_ok());
        }
        assert_eq!(tree.size, leaf_max_index);

        for i in 0..leaf_max_index {
            let proof = tree.prove(i).unwrap();
            let root = tree.root();

            // Verify the proof of each updated leaf
            let valid = MerkleTree::<TestConfig>::verify(&params, root, &[leaves[i]], proof);
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
            let valid = MerkleTree::<TestConfig>::verify(&params, root, &[leaves[i]], proof);
            assert!(matches!(valid, Ok(true)));
        }
    }

    #[test]
    fn test_large_tree_operations_varied_capacities() {
        for capacity in [4 - 1, 32 - 1, 64 - 1, 128 - 1] {
            test_large_tree_operations(capacity);
        }
    }
}
