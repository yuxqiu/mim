use std::{cmp::Ordering, marker::PhantomData};

use ark_crypto_primitives::{crh::poseidon::constraints::CRHParametersVar, sponge::Absorb};
use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::AllocVar,
    convert::ToConstraintFieldGadget,
    eq::EqGadget,
    fields::{emulated_fp::EmulatedFpVar, fp::FpVar, FieldVar},
    groups::{bls12::G1Var, CurveVar},
    prelude::Boolean,
    uint64::UInt64,
};
use ark_relations::r1cs::{ConstraintSystemRef, OptimizationGoal, SynthesisError};
use derivative::Derivative;
use folding_schemes::{frontend::FCircuit, transcript::poseidon::poseidon_canonical_config, Error};

use crate::{
    bc::{
        block::{Block, QuorumSignature},
        params::STRONG_THRESHOLD,
    },
    bls::{BLSAggregateSignatureVerifyGadget, Parameters, ParametersVar},
    folding::bc::{CommitteeVar, QuorumSignatureVar},
    merkle::{constraints::LeveledMerkleForestVar, forest::optimal_forest_params, Config},
    params::BlsSigConfig,
};

use super::{
    bc::BlockVar, from_constraint_field::FromConstraintFieldGadget, serialize::SerializeGadget,
};

#[derive(Clone, Copy, Debug)]
pub struct BCCircuitNoMerkle<CF: PrimeField, const MAX_COMMITTEE_SIZE: usize> {
    sig_params: Parameters<BlsSigConfig>,
    _cf: PhantomData<CF>,
}

#[derive(Clone, Derivative)]
#[derivative(Debug)]
pub struct BCCircuitMerkleForest<CF: PrimeField + Absorb, const MAX_COMMITTEE_SIZE: usize> {
    sig_params: Parameters<BlsSigConfig>,

    // Merkle Forest params
    capacity_per_tree: u32,
    num_tree: u32,

    #[derivative(Debug = "ignore")]
    hash_params: CRHParametersVar<CF>,

    _cf: PhantomData<CF>,
}

impl<CF: PrimeField, const MAX_COMMITTEE_SIZE: usize> FCircuit<CF>
    for BCCircuitNoMerkle<CF, MAX_COMMITTEE_SIZE>
{
    type Params = Parameters<BlsSigConfig>;
    type ExternalInputs = Block<MAX_COMMITTEE_SIZE>;
    type ExternalInputsVar = BlockVar<CF, MAX_COMMITTEE_SIZE>;

    fn new(params: Self::Params) -> Result<Self, Error> {
        Ok(Self {
            sig_params: params,
            _cf: PhantomData,
        })
    }

    fn state_len(&self) -> usize {
        CommitteeVar::<CF, MAX_COMMITTEE_SIZE>::num_constraint_var_needed(
            OptimizationGoal::Constraints,
        ) + UInt64::<CF>::num_constraint_var_needed(OptimizationGoal::Constraints)
    }

    /// generates the constraints for the step of F for the given z_i
    #[tracing::instrument(skip_all)]
    fn generate_step_constraints(
        &self,
        cs: ConstraintSystemRef<CF>,
        _: usize,
        z_i: Vec<FpVar<CF>>,
        external_inputs: Self::ExternalInputsVar,
    ) -> Result<Vec<FpVar<CF>>, SynthesisError> {
        tracing::info!("start reconstructing committee and epoch");

        let optim = cs.optimization_goal();

        // 1. Reconstruct epoch and committee from z_i
        let mut iter = z_i.into_iter();
        let committee = CommitteeVar::from_constraint_field(iter.by_ref(), optim)?;
        let epoch = UInt64::from_constraint_field(iter.by_ref(), optim)?;

        tracing::info!(num_constraints = cs.num_constraints());

        // 2. Enforce constraints
        bc_generate_constraints(
            cs.clone(),
            &external_inputs,
            epoch,
            committee,
            self.sig_params,
        )?;

        // 3. Return the new state
        tracing::info!("start returning the new state");

        let mut committee = external_inputs.committee.to_constraint_field()?;
        let epoch = external_inputs.epoch.to_fp()?;
        committee.push(epoch);

        tracing::info!(num_constraints = cs.num_constraints());

        Ok(committee)
    }
}

impl<CF: PrimeField + Absorb, const MAX_COMMITTEE_SIZE: usize> FCircuit<CF>
    for BCCircuitMerkleForest<CF, MAX_COMMITTEE_SIZE>
{
    type Params = (Parameters<BlsSigConfig>, usize);
    type ExternalInputs = Block<MAX_COMMITTEE_SIZE>;
    type ExternalInputsVar = BlockVar<CF, MAX_COMMITTEE_SIZE>;

    fn new(params: Self::Params) -> Result<Self, Error> {
        let (capacity_per_tree, num_tree) = optimal_forest_params(params.1);

        Ok(Self {
            sig_params: params.0,
            capacity_per_tree,
            num_tree,
            hash_params: CRHParametersVar {
                parameters: poseidon_canonical_config::<CF>(),
            },
            _cf: PhantomData,
        })
    }

    fn state_len(&self) -> usize {
        CommitteeVar::<CF, MAX_COMMITTEE_SIZE>::num_constraint_var_needed(
            OptimizationGoal::Constraints,
        ) + UInt64::<CF>::num_constraint_var_needed(OptimizationGoal::Constraints)
            + LeveledMerkleForestVar::<Config<CF>>::num_constraint_var_needed(
                self.capacity_per_tree,
                self.num_tree,
            )
    }

    /// generates the constraints for the step of F for the given z_i
    #[tracing::instrument(skip_all)]
    fn generate_step_constraints(
        &self,
        cs: ConstraintSystemRef<CF>,
        _: usize,
        z_i: Vec<FpVar<CF>>,
        external_inputs: Self::ExternalInputsVar,
    ) -> Result<Vec<FpVar<CF>>, SynthesisError> {
        tracing::info!("start reconstructing committee and epoch");

        let optim = cs.optimization_goal();

        // 1. Reconstruct epoch and committee from z_i
        let mut iter = z_i.into_iter();
        let committee = CommitteeVar::from_constraint_field(iter.by_ref(), optim)?;
        let epoch = UInt64::from_constraint_field(iter.by_ref(), optim)?;
        let mut forest = LeveledMerkleForestVar::<Config<CF>>::from_constraint_field(
            iter.by_ref(),
            self.capacity_per_tree,
            self.num_tree,
            &self.hash_params,
        )?;

        tracing::info!(num_constraints = cs.num_constraints());

        // 2. Enforce constraints
        bc_generate_constraints(
            cs.clone(),
            &external_inputs,
            epoch,
            committee,
            self.sig_params,
        )?;

        // 2.1 Prove forest Update
        // - the forest stores the hash of the committee
        tracing::info!("start proving forest update");
        let _ = forest.update(
            external_inputs.epoch.to_fp()?,
            &external_inputs.committee.to_constraint_field()?,
        )?;

        // 2.2 Ensure the new epoch is < max # of leaves the tree can store
        let epoch = external_inputs.epoch.to_fp()?;
        epoch.enforce_cmp(
            &FpVar::Constant((forest.max_leaves() as u64).into()),
            Ordering::Less,
            false,
        )?;

        // 3. Return the new state
        tracing::info!("start returning the new state");

        let mut committee = external_inputs.committee.to_constraint_field()?;
        committee.push(epoch);
        committee.extend(forest.to_constraint_field()?);

        tracing::info!(num_constraints = cs.num_constraints());

        Ok(committee)
    }
}

#[tracing::instrument(skip_all)]
fn bc_generate_constraints<CF: PrimeField, const MAX_COMMITTEE_SIZE: usize>(
    cs: ConstraintSystemRef<CF>,
    external_inputs: &BlockVar<CF, MAX_COMMITTEE_SIZE>,
    epoch: UInt64<CF>,
    committee: CommitteeVar<CF, MAX_COMMITTEE_SIZE>,
    sig_params: Parameters<BlsSigConfig>,
) -> Result<(), SynthesisError> {
    // 1. enforce epoch of new committee = epoch of old committee + 1
    tracing::info!("start enforcing epoch of new committee = epoch of old committee + 1");

    external_inputs
        .epoch
        .is_eq(&(epoch.wrapping_add(&UInt64::constant(1))))?
        .enforce_equal(&Boolean::TRUE)?;

    tracing::info!(num_constraints = cs.num_constraints());

    // 2. enforce the signature matches
    tracing::info!("start enforcing signature matches");
    let sig = &external_inputs.sig.sig;
    let signers = &external_inputs.sig.signers;

    // 2.1 aggregate public keys
    tracing::info!("start aggregating public keys");

    let mut weight = UInt64::constant(0);
    let mut aggregate_pk = G1Var::<BlsSigConfig, EmulatedFpVar<_, CF>, CF>::zero();
    for (signed, signer) in signers.iter().zip(committee.committee) {
        let pk = signed.select(
            &(signer.pk.into()),
            &G1Var::<BlsSigConfig, EmulatedFpVar<_, CF>, CF>::zero(),
        )?;
        let w = signed.select(&(signer.weight), &UInt64::constant(0))?;
        aggregate_pk += pk;
        weight.wrapping_add_in_place(&w);
    }
    let aggregate_pk = aggregate_pk.into();

    tracing::info!(num_constraints = cs.num_constraints());

    // 2.2 check signature
    tracing::info!("start checking signatures");

    let params = ParametersVar::new_constant(cs.clone(), sig_params)?;
    let mut external_inputs_without_sig = external_inputs.clone();
    external_inputs_without_sig.sig = QuorumSignatureVar::new_constant(
        cs.clone(),
        QuorumSignature::<MAX_COMMITTEE_SIZE>::default(),
    )?;
    BLSAggregateSignatureVerifyGadget::verify(
        &params,
        &aggregate_pk,
        &external_inputs_without_sig.serialize()?,
        sig,
    )?;

    tracing::info!(num_constraints = cs.num_constraints());

    // 2.3 check weight > threshold
    tracing::info!("start checking weight > threshold");

    weight.to_fp()?.enforce_cmp(
        &FpVar::constant(STRONG_THRESHOLD.into()),
        Ordering::Greater,
        true,
    )?;

    tracing::info!(num_constraints = cs.num_constraints());

    Ok(())
}

#[cfg(test)]
mod test {
    use ark_crypto_primitives::crh::poseidon::constraints::CRHParametersVar;
    use ark_r1cs_std::{alloc::AllocVar, convert::ToConstraintFieldGadget, uint64::UInt64};
    use ark_relations::r1cs::ConstraintSystem;
    use folding_schemes::{frontend::FCircuit, transcript::poseidon::poseidon_canonical_config};
    use rand::{rngs::StdRng, SeedableRng};

    use crate::{
        bc::block::{gen_blockchain_with_params, Blockchain},
        bls::Parameters,
        folding::{
            bc::{BlockVar, CommitteeVar},
            circuit::BCCircuitMerkleForest,
        },
        merkle::{constraints::LeveledMerkleForestVar, Config},
    };

    use super::BCCircuitNoMerkle;
    use ark_bls12_381::Fr;

    const COMMITTEE_SIZE: usize = 25;

    #[test]
    #[ignore = "folding circuit generates ~2^26 constraints"]
    fn test_bc_no_merkle() {
        let mut rng = StdRng::from_seed([42; 32]);
        let bc: Blockchain<COMMITTEE_SIZE> =
            gen_blockchain_with_params(2, COMMITTEE_SIZE, &mut rng);
        let cs = ConstraintSystem::new_ref();

        let f_circuit: BCCircuitNoMerkle<Fr, COMMITTEE_SIZE> =
            BCCircuitNoMerkle::new(Parameters::setup()).unwrap();
        let z_0: Vec<_> = {
            let cs = ConstraintSystem::<Fr>::new_ref();
            CommitteeVar::new_constant(cs.clone(), bc.get(0).unwrap().committee.clone())
                .unwrap()
                .to_constraint_field()
                .unwrap()
                .into_iter()
                .chain(std::iter::once(
                    UInt64::constant(bc.get(0).unwrap().epoch).to_fp().unwrap(),
                ))
                .collect()
        };
        assert_eq!(
            z_0.len(),
            f_circuit.state_len(),
            "state length should match"
        );

        f_circuit
            .generate_step_constraints(
                cs.clone(),
                0,
                z_0,
                BlockVar::new_witness(cs.clone(), || Ok(bc.get(1).unwrap())).unwrap(),
            )
            .unwrap();

        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    #[ignore = "folding circuit generates ~2^26 constraints"]
    fn test_bc_merkle() {
        const STATE_SIZE: usize = 1024;

        let mut rng = StdRng::from_seed([42; 32]);
        let bc: Blockchain<COMMITTEE_SIZE> =
            gen_blockchain_with_params(2, COMMITTEE_SIZE, &mut rng);
        let cs = ConstraintSystem::new_ref();

        let f_circuit: BCCircuitMerkleForest<Fr, COMMITTEE_SIZE> =
            BCCircuitMerkleForest::new((Parameters::setup(), STATE_SIZE)).unwrap();
        let z_0: Vec<_> = {
            let cs = ConstraintSystem::<Fr>::new_ref();
            let poseidon_config = poseidon_canonical_config();

            CommitteeVar::new_constant(cs.clone(), bc.get(0).unwrap().committee.clone())
                .unwrap()
                .to_constraint_field()
                .unwrap()
                .into_iter()
                .chain(std::iter::once(
                    UInt64::constant(bc.get(0).unwrap().epoch).to_fp().unwrap(),
                ))
                .chain(
                    LeveledMerkleForestVar::<Config<Fr>>::new_optimal(
                        STATE_SIZE,
                        &CRHParametersVar {
                            parameters: poseidon_config,
                        },
                    )
                    .expect("LMS should be constructed successfully")
                    .to_constraint_field()
                    .unwrap()
                    .into_iter(),
                )
                .collect()
        };
        assert_eq!(
            z_0.len(),
            f_circuit.state_len(),
            "state length should match"
        );

        f_circuit
            .generate_step_constraints(
                cs.clone(),
                0,
                z_0,
                BlockVar::new_witness(cs.clone(), || Ok(bc.get(1).unwrap())).unwrap(),
            )
            .unwrap();

        assert!(cs.is_satisfied().unwrap());
    }
}
