/// Adapted experiment to benchmark and extrapolate timing for BCCircuitMerkleForest
/// - Measures actual BCCircuitMerkleForest constraints and saves to config
/// - Uses a mock circuit with configurable constraints to collect timing data
/// - Stores and prints results for extrapolation
mod utils;

use ark_mnt4_753::{Fr, G1Projective as G1, MNT4_753 as MNT4};
use ark_mnt6_753::{G1Projective as G2, MNT6_753 as MNT6};
use ark_r1cs_std::convert::ToConstraintFieldGadget;
use ark_r1cs_std::R1CSVar;
use ark_r1cs_std::{alloc::AllocVar, uint64::UInt64};
use ark_relations::r1cs::ConstraintSystem;
use folding_schemes::FoldingScheme;
use folding_schemes::{
    commitment::kzg::KZG,
    folding::nova::{Nova, PreprocessorParam},
    frontend::FCircuit,
    transcript::poseidon::poseidon_canonical_config,
    Error,
};
use rand::rngs::StdRng;
use rand::SeedableRng;
use serde::{Deserialize, Serialize};
use sig::folding::circuit::BCCircuitNoMerkle;
use sig::{
    bc::block::gen_blockchain_with_params, bls::Parameters as BlsParameters,
    folding::bc::CommitteeVar,
};
use std::fs::{self, File};
use std::path::Path;
use utils::ext::Timer;

#[cfg(not(target_env = "msvc"))]
use tikv_jemallocator::Jemalloc;

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

// Timing results for each experiment
#[derive(Serialize, Deserialize, Clone)]
struct ExperimentResult {
    committee_size: usize,
    nova_param_gen_time: f64,     // seconds
    nova_init_time: f64,          // seconds
    folding_step_times: Vec<f64>, // seconds
}

fn run_exp<const MAX_COMMITTEE_SIZE: usize>(data_path: &Path) -> Result<(), Error> {
    println!("Start exp with MAX_COMMITTEE_SIZE = {}", MAX_COMMITTEE_SIZE);

    let poseidon_config = poseidon_canonical_config::<Fr>();
    let mut rng = StdRng::from_seed([42; 32]);

    const N_STEPS_TO_PROVE: usize = 3;
    let results_path = data_path.join(format!(
        "experiment_folding_results_time_{}.json",
        MAX_COMMITTEE_SIZE
    ));

    // Load existing results
    let mut results: Vec<ExperimentResult> = if let Ok(file) = File::open(&results_path) {
        serde_json::from_reader(file).unwrap_or_default()
    } else {
        vec![]
    };

    // Skip if already run
    if results
        .iter()
        .any(|r| r.committee_size == MAX_COMMITTEE_SIZE)
    {
        println!(
            "Skipping committee size {} (already run)",
            MAX_COMMITTEE_SIZE
        );
        return Ok(());
    }

    println!(
        "\nRunning experiment committee size = {}",
        MAX_COMMITTEE_SIZE
    );

    // Use MockBCCircuitMerkleForest
    type FC<const MAX_COMMITTEE_SIZE: usize> = BCCircuitNoMerkle<Fr, MAX_COMMITTEE_SIZE>;
    type N<const MAX_COMMITTEE_SIZE: usize> =
        Nova<G1, G2, FC<MAX_COMMITTEE_SIZE>, KZG<'static, MNT4>, KZG<'static, MNT6>, false>;

    let f_circuit = FC::<MAX_COMMITTEE_SIZE>::new(BlsParameters::setup())?;

    // Generate Nova parameters
    println!("Generating Nova parameters");
    let nova_preprocess_params = PreprocessorParam::new(poseidon_config.clone(), f_circuit.clone());
    let nova_param_start = Timer::start();
    let nova_params = N::preprocess(&mut rng, &nova_preprocess_params)?;
    let nova_param_time = nova_param_start.end();

    // Initialize blockchain
    let bc = gen_blockchain_with_params(N_STEPS_TO_PROVE + 1, MAX_COMMITTEE_SIZE, &mut rng);

    // Prepare data to init Nova
    let cs = ConstraintSystem::new_ref();
    let z_0: Vec<_> = CommitteeVar::new_constant(cs.clone(), bc.get(0).unwrap().committee.clone())?
        .to_constraint_field()?
        .into_iter()
        .chain(std::iter::once(
            UInt64::constant(bc.get(0).unwrap().epoch).to_fp()?,
        ))
        .map(|fpvar| fpvar.value().unwrap())
        .collect();
    assert_eq!(
        z_0.len(),
        f_circuit.state_len(),
        "state length should match"
    );

    // Initialize Nova
    println!("Nova init");
    let nova_init_start = Timer::start();
    let mut nova = N::init(&nova_params, f_circuit.clone(), z_0)?;
    let nova_init_time = nova_init_start.end();

    // drop params to save memory
    drop(nova_params);

    // Run folding steps
    println!("Running folding steps");
    let mut folding_step_times = vec![];
    for (i, block) in (0..N_STEPS_TO_PROVE).zip(bc.into_blocks().skip(1)) {
        println!("start folding step {}", i);
        let folding_start = Timer::start();
        nova.prove_step(&mut rng, block, None)?;
        let folding_step_time = folding_start.end();
        folding_step_times.push(folding_step_time);
        println!("finish folding step {} with time {}", i, folding_step_time);
    }

    // Record results
    let result = ExperimentResult {
        committee_size: MAX_COMMITTEE_SIZE,
        nova_param_gen_time: nova_param_time,
        nova_init_time: nova_init_time,
        folding_step_times,
    };
    results.push(result.clone());

    // Save results
    let mut file = File::create(&results_path)?;
    serde_json::to_writer_pretty(&mut file, &results)
        .expect("serde_json pretty print should succeed");

    // Print results
    println!("\nResults for {} committee size:", MAX_COMMITTEE_SIZE);
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

    Ok(())
}

fn main() -> Result<(), Error> {
    let data_path = Path::new("../exp/nova-no-merkle");
    fs::create_dir_all(data_path)?;

    // all this should be able to fit in 756 GB memory
    run_exp::<128>(data_path)?;
    run_exp::<256>(data_path)?;
    run_exp::<512>(data_path)?;

    Ok(())
}
