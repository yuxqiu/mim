/// This example performs the full flow:
/// - define the circuit to be folded
/// - fold the circuit with Nova+CycleFold's IVC
/// - generate a `DeciderEthCircuit` final proof
///
/// It's adapted from `sonobe/examples/full_flow.rs`
mod utils;

use ark_crypto_primitives::crh::poseidon::constraints::CRHParametersVar;
use ark_mnt4_298::{Fr, G1Projective as G1, MNT4_298 as MNT4};
use ark_mnt6_298::{G1Projective as G2, MNT6_298 as MNT6};

use ark_r1cs_std::convert::ToConstraintFieldGadget;
use ark_r1cs_std::R1CSVar;
use ark_r1cs_std::{alloc::AllocVar, uint64::UInt64};
use ark_relations::r1cs::ConstraintSystem;
use rand::rngs::StdRng;
use rand::SeedableRng;
use serde::{Deserialize, Serialize};
use sig::merkle::constraints::LeveledMerkleForestVar;
use sig::merkle::Config;
use sig::{
    bc::block::gen_blockchain_with_params,
    bls::Parameters,
    folding::{bc::CommitteeVar, circuit::BCCircuitNoMerkle},
};

use folding_schemes::{
    commitment::kzg::KZG,
    folding::nova::{Nova, PreprocessorParam},
    frontend::FCircuit,
    transcript::poseidon::poseidon_canonical_config,
    Error, FoldingScheme,
};
use utils::ext::Timer;

use std::fs::{self, File};
use std::path::Path;

// Timing results for each experiment
#[derive(Serialize, Deserialize, Clone)]
struct ExperimentResult {
    folding_step_times: Vec<f64>, // seconds
}

const N_STEPS_TO_PROVE: usize = 3;
const STATE_SIZE: usize = 1024;

fn run_exp<const MAX_COMMITTEE_SIZE: usize>(data_path: &Path) -> Result<(), Error> {
    println!("Start exp with MAX_COMMITTEE_SIZE = {}", MAX_COMMITTEE_SIZE);

    let results_path = data_path.join(format!(
        "experiment_results_folding_time_{}.json",
        MAX_COMMITTEE_SIZE
    ));

    // if ran, can skip
    {
        let results: Vec<ExperimentResult> = if let Ok(file) = File::open(&results_path) {
            serde_json::from_reader(file).unwrap_or_default()
        } else {
            vec![]
        };
        if results.len() == N_STEPS_TO_PROVE {
            return Ok(());
        }
    }

    let f_circuit = BCCircuitNoMerkle::<Fr, MAX_COMMITTEE_SIZE>::new(Parameters::setup())?;

    type FC<const MAX_COMMITTEE_SIZE: usize> = BCCircuitNoMerkle<Fr, MAX_COMMITTEE_SIZE>;
    type N<const MAX_COMMITTEE_SIZE: usize> =
        Nova<G1, G2, FC<MAX_COMMITTEE_SIZE>, KZG<'static, MNT4>, KZG<'static, MNT6>, false>;

    let poseidon_config = poseidon_canonical_config::<Fr>();
    let mut rng = StdRng::from_seed([42; 32]); // deterministic seeding

    // prepare the Nova prover & verifier params
    // - can serialize this when the circuit is stable
    println!("nova folding preprocess");
    let nova_preprocess_params = PreprocessorParam::new(poseidon_config.clone(), f_circuit);
    let nova_params = N::preprocess(&mut rng, &nova_preprocess_params)?;

    // prepare num steps and blockchain
    println!("generate blockchain instance");

    let bc = gen_blockchain_with_params(N_STEPS_TO_PROVE + 1, MAX_COMMITTEE_SIZE, &mut rng);

    // initialize the folding scheme engine, in our case we use Nova
    println!("nova init");
    let cs = ConstraintSystem::new_ref();
    let z_0: Vec<_> = CommitteeVar::new_constant(cs.clone(), bc.get(0).unwrap().committee.clone())?
        .to_constraint_field()?
        .into_iter()
        .chain(std::iter::once(
            UInt64::constant(bc.get(0).unwrap().epoch).to_fp()?,
        ))
        .chain(
            LeveledMerkleForestVar::<Config<Fr>>::new_optimal(
                STATE_SIZE,
                &CRHParametersVar {
                    parameters: poseidon_config.clone(),
                },
            )
            .expect("LMS should be constructed successfully")
            .to_constraint_field()?
            .into_iter(),
        )
        .map(|fpvar| fpvar.value().unwrap())
        .collect();
    assert_eq!(
        z_0.len(),
        f_circuit.state_len(),
        "state length should match"
    );

    let mut nova = N::init(&nova_params, f_circuit, z_0)?;

    // run `N_STEPS_TO_PROVE` steps of the folding iteration
    let mut folding_step_times = Vec::new();
    println!("nova folding prove step");
    for (_, block) in (0..N_STEPS_TO_PROVE).zip(bc.into_blocks().skip(1)) {
        let timer = Timer::start();
        nova.prove_step(&mut rng, block, None)?;
        folding_step_times.push(timer.end());
    }

    let mut file = File::create(&results_path)?;
    serde_json::to_writer_pretty(&mut file, &ExperimentResult { folding_step_times })
        .expect("serde_json pretty print should succeed");

    Ok(())
}

fn main() -> Result<(), Error> {
    let data_path = Path::new("../exp/nova-merkle-forest");
    fs::create_dir_all(data_path)?;

    run_exp::<128>(data_path)?;
    run_exp::<256>(data_path)?;
    run_exp::<512>(data_path)?;

    Ok(())
}
