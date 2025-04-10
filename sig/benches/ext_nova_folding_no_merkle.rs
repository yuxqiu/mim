/// Adapted experiment to benchmark and extrapolate timing for BCCircuitNoMerkle
/// - Measures actual BCCircuitNoMerkle constraints and saves to config
/// - Uses a mock circuit with configurable constraints to collect timing data
/// - Stores and prints results for extrapolation
mod utils;

use ark_groth16::Groth16;
use ark_mnt4_753::{Fr, G1Projective as G1, MNT4_753 as MNT4};
use ark_mnt6_753::{G1Projective as G2, MNT6_753 as MNT6};
use ark_r1cs_std::convert::ToConstraintFieldGadget;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::R1CSVar;
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, uint64::UInt64};
use ark_relations::r1cs::{
    ConstraintSystem, ConstraintSystemRef, OptimizationGoal, SynthesisError,
};
use derivative::Derivative;
use folding_schemes::{
    commitment::kzg::KZG,
    folding::{
        nova::{decider::Decider as NovaDecider, Nova, PreprocessorParam},
        traits::CommittedInstanceOps,
    },
    frontend::FCircuit,
    transcript::poseidon::poseidon_canonical_config,
    Decider, Error, FoldingScheme,
};
use rand::rngs::StdRng;
use rand::SeedableRng;
use serde::{Deserialize, Serialize};
use sig::bc::params::MAX_COMMITTEE_SIZE;
use sig::folding::bc::BlockVar;
use sig::folding::from_constraint_field::FromConstraintFieldGadget;
use sig::params::BlsSigConfig;
use sig::{
    bc::block::{gen_blockchain_with_params, Block},
    bls::Parameters as BlsParameters,
    folding::{bc::CommitteeVar, circuit::BCCircuitNoMerkle},
};
use std::fs::{self, File};
use std::ops::Mul;
use std::path::Path;

// Configuration to store BCCircuit constraints
#[derive(Serialize, Deserialize)]
struct ExperimentConfig {
    bc_circuit_constraints: usize,
}

// Timing results for each experiment
#[derive(Serialize, Deserialize, Clone)]
struct ExperimentResult {
    constraint_count: usize,
    nova_param_gen_time: f64,     // seconds
    nova_init_time: f64,          // seconds
    snark_param_gen_time: f64,    // seconds
    folding_step_times: Vec<f64>, // seconds
    snark_prove_time: f64,        // seconds
    snark_verify_time: f64,       // seconds,
}

#[derive(Clone, Derivative)]
#[derivative(Debug)]
struct MockBCCircuit<CF: ark_ff::PrimeField> {
    params: BlsParameters<BlsSigConfig>,
    target_constraints: usize,
    _cf: std::marker::PhantomData<CF>,
}

impl<CF: ark_ff::PrimeField> MockBCCircuit<CF> {
    fn new(params: BlsParameters<BlsSigConfig>, target_constraints: usize) -> Result<Self, Error> {
        Ok(Self {
            params,
            target_constraints,
            _cf: std::marker::PhantomData,
        })
    }
}

impl<CF: ark_ff::PrimeField> FCircuit<CF> for MockBCCircuit<CF> {
    type Params = BlsParameters<BlsSigConfig>;
    type ExternalInputs = Block;
    type ExternalInputsVar = BlockVar<CF>;

    fn new(params: Self::Params) -> Result<Self, Error> {
        Ok(Self {
            params,
            target_constraints: 10000, // default, overridden in experiments
            _cf: std::marker::PhantomData,
        })
    }

    fn state_len(&self) -> usize {
        // Same state length as BCCircuitNoMerkle
        CommitteeVar::<CF>::num_constraint_var_needed(OptimizationGoal::Constraints)
            + UInt64::<CF>::num_constraint_var_needed(OptimizationGoal::Constraints)
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

// Measure BCCircuitNoMerkle constraints
fn measure_bc_circuit_constraints(data_path: &Path) -> Result<usize, Error> {
    let config_path = data_path.join("experiment_config.json");
    let f_circuit = BCCircuitNoMerkle::<Fr>::new(BlsParameters::setup())?;

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
    let z_0: Vec<_> = CommitteeVar::new_witness(cs.clone(), || Ok(block.committee.clone()))?
        .to_constraint_field()?
        .into_iter()
        .chain(std::iter::once(
            UInt64::constant(bc.get(0).unwrap().epoch).to_fp()?,
        ))
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

fn main() -> Result<(), Error> {
    let data_path = Path::new("../exp/nova-no-merkle");
    fs::create_dir_all(data_path)?;

    let poseidon_config = poseidon_canonical_config::<Fr>();
    let mut rng = StdRng::from_seed([42; 32]);

    // Measure BCCircuit constraints
    let bc_constraints = measure_bc_circuit_constraints(data_path)?;

    // Define experiment parameters
    let constraint_points = vec![1 << 13, 1 << 15, 1 << 17, 1 << 19, 1 << 21, 1 << 23];
    const N_STEPS_TO_PROVE: usize = 3;
    let results_path = data_path.join("experiment_results.json");

    // Load existing results
    let mut results: Vec<ExperimentResult> = if let Ok(file) = File::open(&results_path) {
        serde_json::from_reader(file).unwrap_or_default()
    } else {
        vec![]
    };

    for target_constraints in constraint_points {
        // Skip if already run
        if results
            .iter()
            .any(|r| r.constraint_count == target_constraints)
        {
            println!(
                "Skipping constraint count {} (already run)",
                target_constraints
            );
            continue;
        }

        println!(
            "\nRunning experiment with {} constraints",
            target_constraints
        );

        // Use MockBCCircuit
        type FC = MockBCCircuit<Fr>;
        type N = Nova<G1, G2, FC, KZG<'static, MNT4>, KZG<'static, MNT6>, false>;
        type D = NovaDecider<
            G1,
            G2,
            FC,
            KZG<'static, MNT4>,
            KZG<'static, MNT6>,
            Groth16<MNT4>,
            Groth16<MNT6>,
            N,
        >;

        let f_circuit = MockBCCircuit::<Fr>::new(BlsParameters::setup(), target_constraints)?;

        // Generate Nova parameters
        println!("Generating Nova parameters");
        let nova_preprocess_params =
            PreprocessorParam::new(poseidon_config.clone(), f_circuit.clone());
        let nova_param_start = std::time::Instant::now();
        let nova_params = N::preprocess(&mut rng, &nova_preprocess_params)?;
        let nova_param_time = nova_param_start.elapsed().as_secs_f64();

        // Initialize blockchain
        let bc = gen_blockchain_with_params(N_STEPS_TO_PROVE + 1, MAX_COMMITTEE_SIZE, &mut rng);

        // Prepare data to init Nova
        let cs = ConstraintSystem::new_ref();
        let z_0: Vec<_> =
            CommitteeVar::new_constant(cs.clone(), bc.get(0).unwrap().committee.clone())?
                .to_constraint_field()?
                .iter()
                .map(|fpvar| fpvar.value().unwrap())
                .chain(std::iter::once(
                    UInt64::constant(bc.get(0).unwrap().epoch)
                        .to_fp()?
                        .value()
                        .unwrap(),
                ))
                .collect();

        // Initialize Nova
        println!("Nova init");
        let nova_init_start = std::time::Instant::now();
        let mut nova = N::init(&nova_params, f_circuit.clone(), z_0)?;
        let nova_init_time = nova_init_start.elapsed().as_secs_f64();

        // Run folding steps
        println!("Running folding steps");
        let mut folding_step_times = vec![];
        for (_, block) in (0..N_STEPS_TO_PROVE).zip(bc.into_blocks().skip(1)) {
            let folding_start = std::time::Instant::now();
            nova.prove_step(&mut rng, block, None)?;
            let folding_step_time = folding_start.elapsed().as_secs_f64();
            folding_step_times.push(folding_step_time);
        }

        // Generate Decider parameters
        println!("Generating Decider parameters");
        let snark_start = std::time::Instant::now();
        let (decider_pp, decider_vp) =
            D::preprocess(&mut rng, (nova_params.clone(), f_circuit.state_len()))?;
        let snark_param_time = snark_start.elapsed().as_secs_f64();

        // Generate SNARK proof
        println!("Generating SNARK proof");
        let prove_start = std::time::Instant::now();
        let proof = D::prove(&mut rng, decider_pp, nova.clone())?;
        let snark_prove_time = prove_start.elapsed().as_secs_f64();

        // Verify SNARK proof
        println!("Verifying SNARK proof");
        let verify_start = std::time::Instant::now();
        let verified = D::verify(
            decider_vp,
            nova.i,
            nova.z_0.clone(),
            nova.z_i.clone(),
            &nova.U_i.get_commitments(),
            &nova.u_i.get_commitments(),
            &proof,
        )?;
        let snark_verify_time = verify_start.elapsed().as_secs_f64();
        assert!(verified);

        // Record results
        let result = ExperimentResult {
            constraint_count: target_constraints,
            nova_param_gen_time: nova_param_time,
            nova_init_time: nova_init_time,
            snark_param_gen_time: snark_param_time,
            folding_step_times,
            snark_prove_time,
            snark_verify_time,
        };
        results.push(result.clone());

        // Save results
        let mut file = File::create(&results_path)?;
        serde_json::to_writer_pretty(&mut file, &results)
            .expect("serde_json pretty print should succeed");

        // Print results
        println!("\nResults for {} constraints:", target_constraints);
        println!(
            "- Nova parameter generation time: {:.2}s",
            result.nova_param_gen_time
        );
        println!("- Nova init time: {:.2}s", result.nova_init_time);
        print!("- Folding step times: ",);
        for (i, num) in result.folding_step_times.iter().enumerate() {
            if i > 0 {
                print!(", ");
            }
            print!("{:.2}s", num);
        }
        println!();
        println!(
            "- SNARK parameter generation time: {:.2}s",
            result.snark_param_gen_time
        );
        println!("- SNARK prove time: {:.2}s", result.snark_prove_time);
        println!("- SNARK verify time: {:.2}s", result.snark_verify_time);
    }

    // Print all results for extrapolation
    println!("\nAll Experiment Results:");
    println!("BCCircuitNoMerkle constraints: {}", bc_constraints);
    println!(
        "{:>15} | {:>15} | {:>15} | {:>15} | {:>15}",
        "Constraints", "Param Gen (s)", "Fold Step (s)", "SNARK Prove (s)", "SNARK Verify (s)"
    );
    println!("{}", "-".repeat(85));
    for result in &results {
        println!(
            "{:>15} | {:>15.2} | {:>15.2} | {:>15.2} | {:>15.2} | {:>15.2} | {:>15.2}",
            result.constraint_count,
            result.nova_param_gen_time,
            result.nova_init_time,
            result.folding_step_times.iter().sum::<f64>() / result.folding_step_times.len() as f64,
            result.snark_param_gen_time,
            result.snark_prove_time,
            result.snark_verify_time
        );
    }

    // Suggest extrapolation
    println!("\nTo extrapolate for {} constraints:", bc_constraints);
    println!("- Use linear or polynomial regression on the above data points.");
    println!(
        "- Fit models for each metric (param gen, folding, prove, verify) vs. constraint count."
    );
    println!(
        "- Apply the model to predict times at {} constraints.",
        bc_constraints
    );

    Ok(())
}
