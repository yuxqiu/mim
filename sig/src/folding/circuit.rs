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
    bls::{BLSAggregateSignatureVerifyGadget, Parameters, ParametersVar, PublicKeyVar},
    folding::bc::{CommitteeVar, QuorumSignatureVar},
    merkle::{constraints::LeveledMerkleForestVar, forest::optimal_forest_params, Config},
    params::BlsSigConfig,
};

use super::{
    bc::BlockVar, from_constraint_field::FromConstraintFieldGadget, serialize::SerializeGadget,
};

#[derive(Clone, Copy, Debug)]
pub struct BCCircuitNoMerkle<CF: PrimeField> {
    sig_params: Parameters<BlsSigConfig>,
    _cf: PhantomData<CF>,
}

#[derive(Clone, Derivative)]
#[derivative(Debug)]
pub struct BCCircuitMerkleForest<CF: PrimeField + Absorb> {
    sig_params: Parameters<BlsSigConfig>,

    // Merkle Forest params
    capacity_per_tree: u32,
    num_tree: u32,

    #[derivative(Debug = "ignore")]
    hash_params: CRHParametersVar<CF>,

    _cf: PhantomData<CF>,
}

impl<CF: PrimeField> FCircuit<CF> for BCCircuitNoMerkle<CF> {
    type Params = Parameters<BlsSigConfig>;
    type ExternalInputs = Block;
    type ExternalInputsVar = BlockVar<CF>;

    fn new(params: Self::Params) -> Result<Self, Error> {
        Ok(Self {
            sig_params: params,
            _cf: PhantomData,
        })
    }

    fn state_len(&self) -> usize {
        CommitteeVar::<CF>::num_constraint_var_needed(OptimizationGoal::Constraints)
            + UInt64::<CF>::num_constraint_var_needed(OptimizationGoal::Constraints)
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

impl<CF: PrimeField + Absorb> FCircuit<CF> for BCCircuitMerkleForest<CF> {
    type Params = (Parameters<BlsSigConfig>, usize);
    type ExternalInputs = Block;
    type ExternalInputsVar = BlockVar<CF>;

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
        CommitteeVar::<CF>::num_constraint_var_needed(OptimizationGoal::Constraints)
            + UInt64::<CF>::num_constraint_var_needed(OptimizationGoal::Constraints)
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
        let _ = forest.update(
            external_inputs.epoch.to_fp()?,
            &external_inputs.committee.to_constraint_field()?,
        )?;

        // 3. Return the new state
        tracing::info!("start returning the new state");

        let mut committee = external_inputs.committee.to_constraint_field()?;
        let epoch = external_inputs.epoch.to_fp()?;
        committee.push(epoch);
        committee.extend(forest.to_constraint_field()?);

        tracing::info!(num_constraints = cs.num_constraints());

        Ok(committee)
    }
}

#[tracing::instrument(skip_all)]
fn bc_generate_constraints<CF: PrimeField>(
    cs: ConstraintSystemRef<CF>,
    external_inputs: &BlockVar<CF>,
    epoch: UInt64<CF>,
    committee: CommitteeVar<CF>,
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
            &(signer.pk.pub_key),
            &G1Var::<BlsSigConfig, EmulatedFpVar<_, CF>, CF>::zero(),
        )?;
        let w = signed.select(&(signer.weight), &UInt64::constant(0))?;
        aggregate_pk += pk;
        weight.wrapping_add_in_place(&w);
    }
    let aggregate_pk = PublicKeyVar {
        pub_key: aggregate_pk,
    };

    tracing::info!(num_constraints = cs.num_constraints());

    // 2.2 check signature
    tracing::info!("start checking signatures");

    let params = ParametersVar::new_constant(cs.clone(), sig_params)?;
    let mut external_inputs_without_sig = external_inputs.clone();
    external_inputs_without_sig.sig =
        QuorumSignatureVar::new_constant(cs.clone(), QuorumSignature::default())?;
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
