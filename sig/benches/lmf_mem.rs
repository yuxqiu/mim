mod utils;

use either::Either;
#[cfg(not(target_env = "msvc"))]
use tikv_jemallocator::Jemalloc;

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

use ark_bls12_381::Fr;
use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
use ark_ff::UniformRand;
use rand::thread_rng;
use serde::Serialize;
use sig::merkle::{forest::LeveledMerkleForest, tree::MerkleTree, Config};
use std::{
    fs::{self, File},
    path::Path,
};
use utils::ext::MemRecorder;

// Utility to get Poseidon parameters
fn poseidon_params() -> PoseidonConfig<Fr> {
    folding_schemes::transcript::poseidon::poseidon_canonical_config::<Fr>()
}

// Experiment struct to hold results
#[derive(Copy, Clone, Debug, Serialize)]
struct ExperimentResult {
    n: usize,
    peak_mem_merkle: usize, // bytes
    peak_mem_lmf: usize,    // bytes
}

// Function to run the experiment for a given n
fn run_experiment(n: usize) -> ExperimentResult {
    let params = poseidon_params();
    let mut rng = thread_rng();

    // Generate random leaves
    println!("generate random leaves");
    let mut leaves = Vec::new();
    for _ in 0..n {
        leaves.push(Fr::rand(&mut rng));
    }

    // --- Standard Merkle Tree ---
    println!("eval standard Merkle Tree");
    let peak_mem_merkle = {
        let mem = MemRecorder::start();
        let _merkle_tree = MerkleTree::<Config<Fr>>::new_with_data(Either::Left(&leaves), &params)
            .expect("Failed to create Merkle tree");
        mem.end()
    };

    // --- Leveled Merkle Forest ---
    println!("eval Leveled Merkle Forest");
    let peak_mem_lmf = {
        let mem = MemRecorder::start();
        let _lmf = LeveledMerkleForest::<Config<Fr>>::new_with_data(Either::Left(&leaves), &params)
            .expect("Failed to create LMF");
        mem.end()
    };

    // Return results
    ExperimentResult {
        n,
        peak_mem_merkle,
        peak_mem_lmf,
    }
}

// Main experiment runner
fn main() {
    // Vector sizes to test
    let sizes = vec![
        1 << 15, // 2^15
        1 << 16, // 2^16
        1 << 17, // 2^17
        1 << 18, // 2^18
        1 << 19, // 2^19
    ];
    let results_path = Path::new("../exp/lmf");
    fs::create_dir_all(results_path).unwrap();
    let results_path = results_path.join("experiment_results_mem.json");

    println!("Running Merkle Tree and LMF experiments...");
    println!(
        "{:<10} | {:<25} | {:<25}",
        "n", "Merkle Peak Memory (bytes)", "LMF Peak Memory (bytes)",
    );
    println!("{}", "-".repeat(70));

    let mut results = Vec::new();
    for n in sizes {
        let result = run_experiment(n);
        results.push(result);

        let mut file = File::create(&results_path).unwrap();
        serde_json::to_writer_pretty(&mut file, &results)
            .expect("serde_json pretty print should succeed");

        // Print results in a formatted table
        println!(
            "{:<10} | {:<25} | {:<25}",
            result.n, result.peak_mem_merkle, result.peak_mem_lmf
        );
    }
}
