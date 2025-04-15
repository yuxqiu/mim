mod utils;

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
        leaves.push([Fr::rand(&mut rng)]);
    }

    // --- Standard Merkle Tree ---
    println!("eval standard Merkle Tree");
    let peak_mem_merkle = {
        let mem = MemRecorder::start();
        let _merkle_tree = MerkleTree::<Config<Fr>>::new_with_data(
            &leaves.iter().map(|v| &v[..]).collect::<Vec<_>>(),
            &params,
        )
        .expect("Failed to create Merkle tree");
        mem.end()
    };

    // --- Leveled Merkle Forest ---
    println!("eval Leveled Merkle Forest");
    let peak_mem_lmf = {
        let mem = MemRecorder::start();
        let mut lmf = LeveledMerkleForest::<Config<Fr>>::new_optimal(n, &params)
            .expect("Failed to create LMF");

        // Add leaves to LMF
        for leaf in &leaves {
            lmf.add(leaf).expect("Failed to add leaf to LMF");
        }
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
        1 << 23, // 2^23
        1 << 24, // 2^24
        1 << 25, // 2^25
        1 << 26, // 2^26
        1 << 27, // 2^27
    ];
    let results_path = Path::new("../exp/lmf");
    fs::create_dir_all(results_path).unwrap();

    println!("Running Merkle Tree and LMF experiments...");
    println!(
        "{:<10} | {:<25} | {:<25}",
        "n", "Merkle Peak Memory (bytes)", "LMF Peak Memory (bytes)",
    );
    println!("{}", "-".repeat(70));

    let mut results = Vec::new();
    for n in sizes {
        let results_path = results_path.join("experiment_results_mem.json");
        let result = run_experiment(n);
        results.push(result);

        let mut file = File::create(&results_path).unwrap();
        serde_json::to_writer_pretty(&mut file, &result)
            .expect("serde_json pretty print should succeed");

        // Print results in a formatted table
        println!(
            "{:<10} | {:<25} | {:<25}",
            result.n, result.peak_mem_merkle, result.peak_mem_lmf
        );
    }
}
