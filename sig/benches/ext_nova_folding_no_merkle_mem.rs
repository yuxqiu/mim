/// Adapted experiment to benchmark and extrapolate timing for BCCircuitNoMerkle
/// - Measures actual BCCircuitNoMerkle constraints and saves to config
/// - Uses a mock circuit with configurable constraints to collect timing data
/// - Stores and prints results for extrapolation
mod utils;

use ark_groth16::Groth16;
use ark_mnt4_753::{Fr, G1Projective as G1, MNT4_753 as MNT4};
use ark_mnt6_753::{G1Projective as G2, MNT6_753 as MNT6};
use ark_r1cs_std::convert::ToConstraintFieldGadget;
use ark_r1cs_std::R1CSVar;
use ark_r1cs_std::{alloc::AllocVar, uint64::UInt64};
use ark_relations::r1cs::ConstraintSystem;
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
use sig::folding::bc::BlockVar;
use sig::{
    bc::block::{gen_blockchain_with_params, Block},
    bls::Parameters as BlsParameters,
    folding::{bc::CommitteeVar, circuit::BCCircuitNoMerkle},
};
use std::fs::{self, File};
use std::path::Path;
use utils::{DummyBlockVar, MemRecorder, MockBCCircuit};

#[cfg(not(target_env = "msvc"))]
use tikv_jemallocator::Jemalloc;

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

// Configuration to store BCCircuit constraints
#[derive(Serialize, Deserialize)]
struct ExperimentConfig {
    bc_circuit_constraints: usize,
}

// Timing results for each experiment
#[derive(Serialize, Deserialize, Clone)]
struct ExperimentResult {
    constraint_count: usize,
    peak_mem: usize, // bytes
}

// Measure BCCircuitNoMerkle constraints
fn measure_bc_circuit_constraints<const MAX_COMMITTEE_SIZE: usize>(
    data_path: &Path,
) -> Result<usize, Error> {
    let config_path = data_path.join(format!("experiment_config_{}.json", MAX_COMMITTEE_SIZE));
    let f_circuit = BCCircuitNoMerkle::<Fr, MAX_COMMITTEE_SIZE>::new(BlsParameters::setup())?;

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

fn run_exp<const MAX_COMMITTEE_SIZE: usize>(data_path: &Path) -> Result<(), Error> {
    println!("Start exp with MAX_COMMITTEE_SIZE = {}", MAX_COMMITTEE_SIZE);

    let num_base_constraints = {
        let cs = ConstraintSystem::<Fr>::new_ref();
        DummyBlockVar::new_witness(cs.clone(), || Ok(Block::<MAX_COMMITTEE_SIZE>::default()))?;
        cs.num_constraints()
    };

    let poseidon_config = poseidon_canonical_config::<Fr>();
    let mut rng = StdRng::from_seed([42; 32]);

    // Measure BCCircuit constraints
    let bc_constraints = measure_bc_circuit_constraints::<MAX_COMMITTEE_SIZE>(data_path)?;

    // Define experiment parameters
    // - capped at 1 << 23 as it already requires roughly 900 GB memory
    let constraint_points = vec![
        1 << 16,
        1 << 17,
        1 << 18,
        1 << 19,
        1 << 20,
        1 << 21,
        1 << 22,
        1 << 23,
    ];
    let constraint_points: Vec<_> = constraint_points
        .into_iter()
        .filter(|v| *v >= num_base_constraints)
        // tale 5 data points
        .take(5)
        .collect();

    const N_STEPS_TO_PROVE: usize = 3;
    let results_path = data_path.join(format!(
        "experiment_results_mem_{}.json",
        MAX_COMMITTEE_SIZE
    ));

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
        type FC<const MAX_COMMITTEE_SIZE: usize> = MockBCCircuit<Fr, MAX_COMMITTEE_SIZE>;
        type N<const MAX_COMMITTEE_SIZE: usize> =
            Nova<G1, G2, FC<MAX_COMMITTEE_SIZE>, KZG<'static, MNT4>, KZG<'static, MNT6>, false>;
        type D<const MAX_COMMITTEE_SIZE: usize> = NovaDecider<
            G1,
            G2,
            FC<MAX_COMMITTEE_SIZE>,
            KZG<'static, MNT4>,
            KZG<'static, MNT6>,
            Groth16<MNT4>,
            Groth16<MNT6>,
            N<MAX_COMMITTEE_SIZE>,
        >;

        let mem = MemRecorder::start();

        let f_circuit = MockBCCircuit::<Fr, MAX_COMMITTEE_SIZE>::new(
            BlsParameters::setup(),
            target_constraints,
        )?;

        // Generate Nova parameters
        println!("Generating Nova parameters");
        let nova_preprocess_params =
            PreprocessorParam::new(poseidon_config.clone(), f_circuit.clone());
        let nova_params = N::preprocess(&mut rng, &nova_preprocess_params)?;

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
        let mut nova = N::init(&nova_params, f_circuit.clone(), z_0)?;

        // Run folding steps
        println!("Running folding steps");
        for (_, block) in (0..N_STEPS_TO_PROVE).zip(bc.into_blocks().skip(1)) {
            nova.prove_step(&mut rng, block, None)?;
        }

        // Generate Decider parameters
        println!("Generating Decider parameters");
        let (decider_pp, decider_vp) = D::<MAX_COMMITTEE_SIZE>::preprocess(
            &mut rng,
            (nova_params.clone(), f_circuit.state_len()),
        )?;

        // Generate SNARK proof
        println!("Generating SNARK proof");
        let proof = D::<MAX_COMMITTEE_SIZE>::prove(&mut rng, decider_pp, nova.clone())?;

        let peak_mem = mem.end();

        // Verify SNARK proof
        println!("Verifying SNARK proof");
        let verified = D::<MAX_COMMITTEE_SIZE>::verify(
            decider_vp,
            nova.i,
            nova.z_0.clone(),
            nova.z_i.clone(),
            &nova.U_i.get_commitments(),
            &nova.u_i.get_commitments(),
            &proof,
        )?;
        assert!(verified);

        // Record results
        let result = ExperimentResult {
            constraint_count: target_constraints,
            peak_mem,
        };
        results.push(result.clone());

        // Save results
        let mut file = File::create(&results_path)?;
        serde_json::to_writer_pretty(&mut file, &results)
            .expect("serde_json pretty print should succeed");

        // Print results
        println!("\nResults for {} constraints:", target_constraints);
        println!("- Peak mem usage: {} bytes", result.peak_mem);
    }

    // Print all results for extrapolation
    println!("\nAll Experiment Results:");
    println!("BCCircuitNoMerkle constraints: {}", bc_constraints);
    println!("{:>15} | {:>15}", "Constraints", "Peak mem usage (bytes)");
    println!("{}", "-".repeat(85));
    for result in &results {
        println!(
            "{:>15} | {:>15.2}",
            result.constraint_count, result.peak_mem
        );
    }

    // Suggest extrapolation
    println!("\nTo extrapolate for {} constraints:", bc_constraints);
    println!("- Use linear or polynomial regression on the above data points.");
    println!("- Fit models for peak mem usage vs. constraint count.");
    println!(
        "- Apply the model to predict peak mem usage at {} constraints.",
        bc_constraints
    );

    Ok(())
}

fn main() -> Result<(), Error> {
    let data_path = Path::new("../exp/nova-no-merkle");
    fs::create_dir_all(data_path)?;

    run_exp::<128>(data_path)?;
    run_exp::<256>(data_path)?;
    run_exp::<512>(data_path)?;
    run_exp::<1024>(data_path)?;

    Ok(())
}
