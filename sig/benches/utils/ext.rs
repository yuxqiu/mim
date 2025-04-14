use std::{
    fs::File,
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use ark_crypto_primitives::sponge::Absorb;
use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::AllocVar,
    eq::EqGadget,
    fields::{emulated_fp::EmulatedFpVar, fp::FpVar},
    prelude::Boolean,
    uint64::UInt64,
    uint8::UInt8,
};
use ark_relations::r1cs::{
    ConstraintSystem, ConstraintSystemRef, OptimizationGoal, SynthesisError,
};
use derivative::Derivative;
use folding_schemes::{frontend::FCircuit, Error};
use rand::{rngs::StdRng, SeedableRng};
use serde::{Deserialize, Serialize};
use sig::{
    bc::{
        block::{gen_blockchain_with_params, Block, QuorumSignature},
        params::HASH_OUTPUT_SIZE,
    },
    bls::{Parameters as BlsParameters, SignatureVar},
    folding::{
        bc::{BlockVar, CommitteeVar},
        from_constraint_field::FromConstraintFieldGadget,
    },
    merkle::{constraints::LeveledMerkleForestVar, forest::optimal_forest_params, Config},
    params::BlsSigConfig,
};
use std::ops::Mul;
use tikv_jemalloc_ctl::{epoch, stats::resident};

#[allow(dead_code)]
pub struct Timer(Instant);

impl Timer {
    #[allow(dead_code)]
    pub fn start() -> Timer {
        Timer(Instant::now())
    }

    #[allow(dead_code)]
    pub fn end(self) -> f64 {
        self.0.elapsed().as_secs_f64()
    }
}

#[allow(dead_code)]
pub struct MemRecorder {
    stop_flag: Arc<AtomicBool>,
    handle: Option<JoinHandle<usize>>,
}

impl MemRecorder {
    #[allow(dead_code)]
    pub fn start() -> MemRecorder {
        let stop_flag = Arc::new(AtomicBool::new(false));
        let flag_clone = Arc::clone(&stop_flag);

        let e = epoch::mib().unwrap();
        let resident_mib = resident::mib().unwrap();

        let handle = thread::spawn(move || {
            let mut peak = 0;
            while !flag_clone.load(Ordering::Relaxed) {
                e.advance().ok(); // Refresh stats
                if let Ok(mem) = resident_mib.read() {
                    peak = peak.max(mem);
                }
                thread::sleep(Duration::from_millis(5));
            }
            peak
        });

        MemRecorder {
            stop_flag,
            handle: Some(handle),
        }
    }

    #[allow(dead_code)]
    pub fn end(mut self) -> usize {
        self.stop_flag.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            match handle.join() {
                Ok(peak) => peak,
                Err(_) => 0, // In case the thread panicked
            }
        } else {
            0
        }
    }
}

#[derive(Clone, Debug)]
struct DummyQuorumSignatureVar;

#[derive(Clone, Debug)]
pub struct DummyBlockVar;

impl<CF: PrimeField, const MAX_COMMITTEE_SIZE: usize>
    AllocVar<QuorumSignature<MAX_COMMITTEE_SIZE>, CF> for DummyQuorumSignatureVar
{
    fn new_variable<T: std::borrow::Borrow<QuorumSignature<MAX_COMMITTEE_SIZE>>>(
        cs: impl Into<ark_relations::r1cs::Namespace<CF>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: ark_r1cs_std::prelude::AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into();

        let quorum_signature = f();

        let _ =
            SignatureVar::<BlsSigConfig, EmulatedFpVar<_, _>, _>::new_variable_omit_on_curve_check(
                cs.clone(),
                || {
                    quorum_signature
                        .as_ref()
                        .map(|qsig| qsig.borrow().sig)
                        .map_err(SynthesisError::clone)
                },
                mode,
            )?;

        let _ = Vec::<Boolean<CF>>::new_variable(
            cs,
            || {
                quorum_signature
                    .as_ref()
                    .map(|qsig| qsig.borrow().signers)
                    .map_err(SynthesisError::clone)
            },
            mode,
        )?;

        Ok(Self)
    }
}

impl<CF: PrimeField, const MAX_COMMITTEE_SIZE: usize> AllocVar<Block<MAX_COMMITTEE_SIZE>, CF>
    for DummyBlockVar
{
    fn new_variable<T: std::borrow::Borrow<Block<MAX_COMMITTEE_SIZE>>>(
        cs: impl Into<ark_relations::r1cs::Namespace<CF>>,
        f: impl FnOnce() -> Result<T, ark_relations::r1cs::SynthesisError>,
        mode: ark_r1cs_std::prelude::AllocationMode,
    ) -> Result<Self, ark_relations::r1cs::SynthesisError> {
        let cs = cs.into();

        let block = f();

        let _ = UInt64::new_variable(
            cs.clone(),
            || {
                block
                    .as_ref()
                    .map(|block| block.borrow().epoch)
                    .map_err(SynthesisError::clone)
            },
            mode,
        )?;

        let _ =
            <[UInt8<CF>; HASH_OUTPUT_SIZE] as AllocVar<[u8; HASH_OUTPUT_SIZE], CF>>::new_variable(
                cs.clone(),
                || {
                    block
                        .as_ref()
                        .map(|block| block.borrow().prev_digest)
                        .map_err(SynthesisError::clone)
                },
                mode,
            )?;

        let _ = DummyQuorumSignatureVar::new_variable(
            cs.clone(),
            || {
                block
                    .as_ref()
                    .map(|block| block.borrow().sig.clone())
                    .map_err(SynthesisError::clone)
            },
            mode,
        )?;

        let _ = CommitteeVar::new_variable(
            cs,
            || {
                block
                    .as_ref()
                    .map(|block| {
                        let block = block.borrow();
                        block.committee.clone()
                    })
                    .map_err(SynthesisError::clone)
            },
            mode,
        )?;

        Ok(Self)
    }
}

#[derive(Clone, Derivative)]
#[derivative(Debug)]
pub struct MockBCCircuitNoMerkle<CF: ark_ff::PrimeField, const MAX_COMMITTEE_SIZE: usize> {
    target_constraints: usize,
    _cf: std::marker::PhantomData<CF>,
}

impl<CF: ark_ff::PrimeField, const MAX_COMMITTEE_SIZE: usize>
    MockBCCircuitNoMerkle<CF, MAX_COMMITTEE_SIZE>
{
    #[allow(dead_code)]
    pub fn new(target_constraints: usize) -> Result<Self, Error> {
        Ok(Self {
            target_constraints,
            _cf: std::marker::PhantomData,
        })
    }
}

impl<CF: ark_ff::PrimeField, const MAX_COMMITTEE_SIZE: usize> FCircuit<CF>
    for MockBCCircuitNoMerkle<CF, MAX_COMMITTEE_SIZE>
{
    type Params = BlsParameters<BlsSigConfig>;
    type ExternalInputs = Block<MAX_COMMITTEE_SIZE>;
    type ExternalInputsVar = DummyBlockVar;

    fn new(_: Self::Params) -> Result<Self, Error> {
        unimplemented!("this method should not be used")
    }

    fn state_len(&self) -> usize {
        // Same state length as BCCircuitNoMerkle
        CommitteeVar::<CF, MAX_COMMITTEE_SIZE>::num_constraint_var_needed(
            OptimizationGoal::Constraints,
        ) + UInt64::<CF>::num_constraint_var_needed(OptimizationGoal::Constraints)
    }

    fn generate_step_constraints(
        &self,
        cs: ConstraintSystemRef<CF>,
        _: usize,
        z: Vec<FpVar<CF>>,
        _: Self::ExternalInputsVar,
    ) -> Result<Vec<FpVar<CF>>, SynthesisError> {
        // Generate dummy constraints to reach target_constraints
        let current_constraints = cs.num_constraints();
        let constraints_to_add = self.target_constraints.saturating_sub(current_constraints);

        // Add arithmetic constraints: e.g., x * y = z
        for j in 0..constraints_to_add {
            let x = FpVar::new_witness(cs.clone(), || Ok(CF::from((j + 1) as u64)))?;
            let y = FpVar::new_witness(cs.clone(), || Ok(CF::from((j + 2) as u64)))?;
            let z =
                FpVar::new_witness(cs.clone(), || Ok(CF::from((j + 1) as u64 * (j + 2) as u64)))?;
            x.mul(&y).enforce_equal(&z)?;
        }

        // Return new state (same as BCCircuit)
        Ok(z)
    }
}

#[derive(Clone, Derivative)]
#[derivative(Debug)]
pub struct MockBCCircuitMerkleForest<CF: ark_ff::PrimeField, const MAX_COMMITTEE_SIZE: usize> {
    target_constraints: usize,
    capacity_per_tree: u32,
    num_tree: u32,
    _cf: std::marker::PhantomData<CF>,
}

impl<CF: ark_ff::PrimeField, const MAX_COMMITTEE_SIZE: usize>
    MockBCCircuitMerkleForest<CF, MAX_COMMITTEE_SIZE>
{
    #[allow(dead_code)]
    pub fn new(params: usize, target_constraints: usize) -> Result<Self, Error> {
        let (capacity_per_tree, num_tree) = optimal_forest_params(params);

        Ok(Self {
            target_constraints,
            capacity_per_tree,
            num_tree,
            _cf: std::marker::PhantomData,
        })
    }
}

impl<CF: ark_ff::PrimeField + Absorb, const MAX_COMMITTEE_SIZE: usize> FCircuit<CF>
    for MockBCCircuitMerkleForest<CF, MAX_COMMITTEE_SIZE>
{
    type Params = (BlsParameters<BlsSigConfig>, usize);
    type ExternalInputs = Block<MAX_COMMITTEE_SIZE>;
    type ExternalInputsVar = DummyBlockVar;

    fn new(_: Self::Params) -> Result<Self, Error> {
        unimplemented!("this method should not be used");
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

    fn generate_step_constraints(
        &self,
        cs: ConstraintSystemRef<CF>,
        _: usize,
        z: Vec<FpVar<CF>>,
        _: Self::ExternalInputsVar,
    ) -> Result<Vec<FpVar<CF>>, SynthesisError> {
        // Generate dummy constraints to reach target_constraints
        let current_constraints = cs.num_constraints();
        let constraints_to_add = self.target_constraints.saturating_sub(current_constraints);

        // Add arithmetic constraints: e.g., x * y = z
        for j in 0..constraints_to_add {
            let x = FpVar::new_witness(cs.clone(), || Ok(CF::from((j + 1) as u64)))?;
            let y = FpVar::new_witness(cs.clone(), || Ok(CF::from((j + 2) as u64)))?;
            let z =
                FpVar::new_witness(cs.clone(), || Ok(CF::from((j + 1) as u64 * (j + 2) as u64)))?;
            x.mul(&y).enforce_equal(&z)?;
        }

        // Return new state (same as BCCircuit)
        Ok(z)
    }
}

// Configuration to store BCCircuit constraints
#[derive(Serialize, Deserialize)]
pub struct ExperimentConfig {
    bc_circuit_constraints: usize,
}

// Measure BCCircuitNoMerkle constraints
#[allow(dead_code)]
pub fn measure_bc_circuit_constraints<
    const MAX_COMMITTEE_SIZE: usize,
    Fr: PrimeField,
    BCCircuit: FCircuit<Fr, ExternalInputsVar = BlockVar<Fr, MAX_COMMITTEE_SIZE>>,
>(
    config_path: &Path,
    params: BCCircuit::Params,
) -> Result<usize, Error> {
    let f_circuit = BCCircuit::new(params)?;

    // Try to load existing config
    if let Ok(file) = File::open(&config_path) {
        let config: ExperimentConfig =
            serde_json::from_reader(file).expect("serde_json should deserialize correctly");
        println!(
            "Loaded BCCircuit constraints: {}",
            config.bc_circuit_constraints
        );
        return Ok(config.bc_circuit_constraints);
    }

    // Measure constraints
    let mut rng = StdRng::from_seed([42; 32]);
    let cs = ConstraintSystem::<Fr>::new_ref();

    let bc = gen_blockchain_with_params(2, MAX_COMMITTEE_SIZE, &mut rng);
    let block = bc.get(1).expect("there are 2 blocks");
    let block_var = BlockVar::new_witness(cs.clone(), || Ok(block))?;

    // as long as length matches, it is fine
    let z_0: Vec<_> = std::iter::repeat(FpVar::new_witness(cs.clone(), || Ok(Fr::default()))?)
        .take(f_circuit.state_len())
        .collect();

    f_circuit.generate_step_constraints(cs.clone(), 0, z_0, block_var)?;

    let constraints = cs.num_constraints();
    println!("Measured BCCircuit constraints: {}", constraints);

    // Save to config
    let config = ExperimentConfig {
        bc_circuit_constraints: constraints,
    };
    let mut file = File::create(&config_path)?;
    serde_json::to_writer(&mut file, &config).expect("serde_json should serialize correctly");
    Ok(constraints)
}
