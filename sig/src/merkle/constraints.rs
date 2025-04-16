use std::marker::PhantomData;

use ark_crypto_primitives::crh::{
    poseidon::constraints::{
        CRHGadget as Poseidon, CRHParametersVar as PoseidonParams,
        TwoToOneCRHGadget as PoseidonTwoToOne,
    },
    CRHSchemeGadget, TwoToOneCRHSchemeGadget,
};
use ark_ff::{BigInteger, PrimeField};
use ark_r1cs_std::{
    alloc::AllocVar, convert::ToConstraintFieldGadget, eq::EqGadget, fields::fp::FpVar, R1CSVar,
};
use ark_relations::r1cs::SynthesisError;

use super::{
    forest::{optimal_forest_params, MerkleForestError},
    left, right,
    tree::MerkleTreeError,
    MerkleConfig,
};

pub struct MerkleTreeVar<'a, P: MerkleConfig> {
    nodes: Vec<FpVar<P::BasePrimeField>>,
    hash_params: &'a PoseidonParams<P::BasePrimeField>,
}

impl<'a, P: MerkleConfig> MerkleTreeVar<'a, P> {
    pub fn new(
        capacity: usize,
        params: &'a PoseidonParams<P::BasePrimeField>,
    ) -> Result<Self, MerkleTreeError> {
        if !(capacity + 1).is_power_of_two() {
            return Err(MerkleTreeError::InvalidCapacity);
        }

        let mut s = Self {
            nodes: vec![FpVar::Constant(P::BasePrimeField::default()); capacity],
            hash_params: params,
        };

        // Recompute the internal nodes in a bottom-up fashion.
        // For every internal node (from leaves_start-1 down to 0),
        // compute the hash of its two children.
        for i in (0..s.num_leaves() - 1).rev() {
            s.update_state(i)
                .expect("state update should not fail for constant FpVar");
        }

        Ok(s)
    }

    /// Update the Merkle tree with the `new_leaf` at `index`.
    ///
    /// Note: caller of this method should ensure `index` is within the acceptable
    /// range of the Merkle tree.
    pub fn update(
        &mut self,
        index: FpVar<P::BasePrimeField>,
        new_leaf: &[FpVar<P::BasePrimeField>],
    ) -> Result<FpVar<P::BasePrimeField>, SynthesisError> {
        self.update_with_hash(index, Poseidon::evaluate(self.hash_params, new_leaf)?)
    }

    /// Update the Merkle tree with the `new_leaf` at `index`.
    ///
    /// Note: caller of this method should ensure `index` is within the acceptable
    /// range of the Merkle tree.
    pub fn update_with_hash(
        &mut self,
        index: FpVar<P::BasePrimeField>,
        new_leaf: FpVar<P::BasePrimeField>,
    ) -> Result<FpVar<P::BasePrimeField>, SynthesisError> {
        let num_leaves = self.num_leaves();
        let leaves_start = num_leaves - 1;

        // Create an updated leaves vector by iterating over each leaf.
        // For each leaf position i (a constant), compare i with the provided index.
        // If they are equal then select new_leaf; otherwise keep the original leaf.
        let mut updated_leaves = Vec::with_capacity(num_leaves);
        for i in 0..num_leaves {
            // Create a constant FpVar for the index value i.
            let i_const = FpVar::Constant(P::BasePrimeField::from(i as u64));
            // Enforce equality check: index == i_const.
            let eq = index.is_eq(&i_const)?;
            // Use the equality gadget to conditionally select new_leaf if eq holds.
            let leaf_val = eq.select(&new_leaf, &self.nodes[leaves_start + i])?;
            updated_leaves.push(leaf_val);
        }

        // Replace the old leaves
        self.nodes.splice(leaves_start.., updated_leaves);

        // Recompute the internal nodes in a bottom-up fashion.
        // For every internal node (from leaves_start-1 down to 0),
        // compute the hash of its two children.
        for i in (0..leaves_start).rev() {
            self.update_state(i)?;
        }

        // Return the updated root).
        Ok(self.root())
    }

    pub fn root(&self) -> FpVar<P::BasePrimeField> {
        self.nodes[0].clone()
    }

    pub fn from_constraint_field(
        iter: impl Iterator<Item = FpVar<P::BasePrimeField>>,
        capacity: usize,
        params: &'a PoseidonParams<P::BasePrimeField>,
    ) -> Result<Self, SynthesisError> {
        let nodes: Vec<_> = iter.take(capacity).collect();
        if nodes.len() != capacity {
            return Err(SynthesisError::Unsatisfiable);
        }
        Ok(Self {
            nodes,
            hash_params: params,
        })
    }

    pub const fn num_constraint_var_needed(capacity: usize) -> usize {
        capacity
    }

    fn update_state(&mut self, index: usize) -> Result<(), SynthesisError> {
        let left_child = &self.nodes[left(index)];
        let right_child = &self.nodes[right(index)];
        // Note: I originally thought we can select between hash and the
        // old tree hash. But, in either case, we need to compute a hash.
        // So, to avoid waste constraints to select, we can just use the new hash to
        // as the new tree node.
        self.nodes[index] = PoseidonTwoToOne::evaluate(self.hash_params, left_child, right_child)?;
        Ok(())
    }

    #[inline]
    pub(crate) fn num_leaves(&self) -> usize {
        (self.nodes.len() + 1) / 2
    }
}

impl<'a, P: MerkleConfig> ToConstraintFieldGadget<P::BasePrimeField> for MerkleTreeVar<'a, P> {
    fn to_constraint_field(&self) -> Result<Vec<FpVar<P::BasePrimeField>>, SynthesisError> {
        Ok(self.nodes.clone())
    }
}

pub struct LeveledMerkleForestVar<'a, P: MerkleConfig> {
    trees: Vec<MerkleTreeVar<'a, P>>,
    _hash_params: PhantomData<&'a P>,
}

impl<'a, P: MerkleConfig> LeveledMerkleForestVar<'a, P> {
    pub fn new(
        capacity_per_tree: u32,
        num_tree: u32,
        params: &'a PoseidonParams<P::BasePrimeField>,
    ) -> Result<Self, MerkleForestError> {
        if num_tree == 0 {
            return Err(MerkleForestError::InvalidNumTree);
        }

        let mut trees = vec![];
        for _ in 0..num_tree {
            trees.push(MerkleTreeVar::new(capacity_per_tree as usize, params)?);
        }

        Ok(Self {
            trees,
            _hash_params: PhantomData,
        })
    }

    pub fn new_optimal(
        n: usize,
        params: &'a PoseidonParams<P::BasePrimeField>,
    ) -> Result<Self, MerkleForestError> {
        let (capacity_per_tree, num_tree) = optimal_forest_params(n);
        LeveledMerkleForestVar::new(capacity_per_tree, num_tree, params)
    }

    /// Update the Merkle forest with the `new_leaf` at `index`.
    ///
    /// Note: caller of this method should ensure `index` is within the acceptable
    /// range of the Merkle tree.
    pub fn update(
        &mut self,
        index: FpVar<P::BasePrimeField>,
        new_leaf: &[FpVar<P::BasePrimeField>],
    ) -> Result<FpVar<P::BasePrimeField>, SynthesisError> {
        let num_leaves_per_tree = self.num_leaves_per_tree();
        let (mut index, index_within_tree) = div_rem_power_of_2(index, num_leaves_per_tree)?;

        let mut new_root = self.trees[0].update(index_within_tree, new_leaf)?;

        for tree in self.trees.iter_mut().skip(1) {
            let (new_index, index_within_tree) = div_rem_power_of_2(index, num_leaves_per_tree)?;
            new_root = tree.update_with_hash(index_within_tree, new_root)?;
            index = new_index;
        }
        Ok(new_root)
    }

    pub fn from_constraint_field(
        mut iter: impl Iterator<Item = FpVar<P::BasePrimeField>>,
        capacity_per_tree: u32,
        num_tree: u32,
        params: &'a PoseidonParams<P::BasePrimeField>,
    ) -> Result<Self, SynthesisError> {
        let capacity_per_tree = capacity_per_tree as usize;
        let trees = (0..num_tree)
            .map(|_| MerkleTreeVar::from_constraint_field(iter.by_ref(), capacity_per_tree, params))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            trees,
            _hash_params: PhantomData,
        })
    }

    pub const fn num_constraint_var_needed(capacity_per_tree: u32, num_tree: u32) -> usize {
        num_tree as usize
            * MerkleTreeVar::<P>::num_constraint_var_needed(capacity_per_tree as usize)
    }

    pub fn root(&self) -> FpVar<P::BasePrimeField> {
        self.trees.last().expect("there is at least 1 tree").root()
    }

    #[inline]
    pub fn max_leaves(&self) -> usize {
        // safe conversion as trees.len() is limited to be <= 2^32 - 1
        #[allow(clippy::cast_possible_truncation)]
        self.num_leaves_per_tree().pow(self.trees.len() as u32)
    }

    #[inline]
    fn num_leaves_per_tree(&self) -> usize {
        self.trees[0].num_leaves()
    }
}

impl<'a, P: MerkleConfig> ToConstraintFieldGadget<P::BasePrimeField>
    for LeveledMerkleForestVar<'a, P>
{
    fn to_constraint_field(&self) -> Result<Vec<FpVar<P::BasePrimeField>>, SynthesisError> {
        self.trees
            .iter()
            .map(|tree| tree.to_constraint_field())
            .collect::<Result<Vec<_>, _>>()
            .map(|vecs| vecs.into_iter().flatten().collect::<Vec<_>>())
    }
}

fn div_rem_power_of_2<F: PrimeField>(
    v: FpVar<F>,
    p2: usize,
) -> Result<(FpVar<F>, FpVar<F>), SynthesisError> {
    let cs = v.cs();
    let div = FpVar::new_witness(cs, || {
        v.value().map(|v| {
            let mut v = v.into_bigint();
            for _ in 0..p2.ilog2() {
                v.div2();
            }
            F::from(v)
        })
    })?;
    let rem = v - &div * FpVar::Constant(F::from(p2 as u64));
    rem.enforce_cmp(
        &FpVar::Constant(F::from(p2 as u64)),
        std::cmp::Ordering::Less,
        false,
    )?;
    Ok((div, rem))
}

impl<'a, P: MerkleConfig> R1CSVar<P::BasePrimeField> for MerkleTreeVar<'a, P> {
    type Value = Vec<<FpVar<P::BasePrimeField> as R1CSVar<P::BasePrimeField>>::Value>;

    fn cs(&self) -> ark_relations::r1cs::ConstraintSystemRef<P::BasePrimeField> {
        self.nodes.cs()
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        self.nodes.value()
    }
}

impl<'a, P: MerkleConfig> R1CSVar<P::BasePrimeField> for LeveledMerkleForestVar<'a, P> {
    type Value = Vec<Vec<<FpVar<P::BasePrimeField> as R1CSVar<P::BasePrimeField>>::Value>>;

    fn cs(&self) -> ark_relations::r1cs::ConstraintSystemRef<P::BasePrimeField> {
        self.trees.cs()
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        self.trees.value()
    }
}

#[cfg(test)]
mod test {
    use crate::merkle::{forest::LeveledMerkleForest, tree::MerkleTree};

    use super::*;
    use ark_bls12_381::Fr;
    use ark_ff::UniformRand;
    use ark_r1cs_std::{alloc::AllocVar, R1CSVar};
    use ark_relations::r1cs::ConstraintSystem;
    use folding_schemes::transcript::poseidon::poseidon_canonical_config;
    use rand::{rngs::StdRng, thread_rng, SeedableRng};

    struct TestConfig;
    impl MerkleConfig for TestConfig {
        type BasePrimeField = Fr;
    }

    fn poseidon_params() -> PoseidonParams<Fr> {
        PoseidonParams {
            parameters: poseidon_canonical_config::<Fr>(),
        }
    }

    #[test]
    fn test_r1cs_merkle_tree_gadget() {
        use ark_r1cs_std::fields::fp::FpVar;
        use ark_relations::r1cs::ConstraintSystem;

        let mut rng = thread_rng();
        let params = poseidon_params();
        let cs = ConstraintSystem::<Fr>::new_ref();

        let leaves = vec![Fr::rand(&mut rng), Fr::rand(&mut rng)];
        let leaves_var: Vec<_> = leaves
            .iter()
            .map(|leaf| FpVar::new_input(cs.clone(), || Ok(leaf)).unwrap())
            .collect();

        let mut tree = MerkleTree::<TestConfig>::new(3, &params.parameters).unwrap();
        tree.update_with_hash(0, leaves[0]).unwrap();
        tree.update_with_hash(1, leaves[1]).unwrap();
        let root = tree.root();

        let mut gadget_tree = MerkleTreeVar::<TestConfig>::new(3, &params).unwrap();
        let index = FpVar::new_input(cs.clone(), || Ok(Fr::from(0))).unwrap();
        let _ = gadget_tree
            .update_with_hash(index, leaves_var[0].clone())
            .unwrap();
        let index = FpVar::new_input(cs.clone(), || Ok(Fr::from(1))).unwrap();
        let root_var = gadget_tree
            .update_with_hash(index, leaves_var[1].clone())
            .unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(root_var.value().unwrap(), root);
    }

    fn test_r1cs_merkle_forest_gadget_helper(values: Vec<Fr>) {
        let params = poseidon_params();
        let cs = ConstraintSystem::new_ref();

        let values_ref = values.iter().map(|v| [*v]).collect::<Vec<_>>();
        let values_ref = values_ref.iter().map(|v| &v[..]).collect::<Vec<_>>();
        let forest = LeveledMerkleForest::<TestConfig>::new_with_data(
            either::Right(&values_ref),
            &params.parameters,
        )
        .unwrap();
        let mut forest_var =
            LeveledMerkleForestVar::<TestConfig>::new_optimal(values.len(), &params).unwrap();

        for (i, val) in values.iter().enumerate() {
            let add_result = forest_var.update(
                FpVar::new_witness(cs.clone(), || Ok(Fr::from(i as u32))).unwrap(),
                &[FpVar::new_witness(cs.clone(), || Ok(val)).unwrap()],
            );
            assert!(add_result.is_ok());
        }

        dbg!(forest_var.value().unwrap());
        dbg!(&forest);

        let new_root = forest_var.root();
        assert_eq!(new_root.value().unwrap(), forest.root());
        assert!(cs.is_satisfied().unwrap());

        println!("{}", cs.num_constraints());
    }

    #[test]
    fn test_r1cs_merkle_forest_gadget() {
        let mut rng = StdRng::from_seed([42; 32]);

        for i in [1, 2, 3, 4, 8, 16] {
            let mut values = vec![];
            for _ in 0..i {
                let val = { Fr::rand(&mut rng) };
                values.push(val);
            }
            test_r1cs_merkle_forest_gadget_helper(values);
        }
    }
}
