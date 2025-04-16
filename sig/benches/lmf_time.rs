mod utils;

use ark_bls12_381::Fr;
use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
use ark_ff::UniformRand;
use either::Either;
use rand::{thread_rng, Rng};
use serde::Serialize;
use sig::merkle::{forest::LeveledMerkleForest, tree::MerkleTree, Config};
use std::{
    fs::{self, File},
    path::Path,
};
use utils::ext::Timer;

// Utility to get Poseidon parameters
fn poseidon_params() -> PoseidonConfig<Fr> {
    folding_schemes::transcript::poseidon::poseidon_canonical_config::<Fr>()
}

// Experiment struct to hold results
#[derive(Clone, Debug, Serialize)]
struct ExperimentResult {
    n: usize,
    merkle_construction_time: f64, // seconds
    merkle_proof_size: usize,
    merkle_proof_time: f64,     // seconds
    lmf_construction_time: f64, // seconds
    lmf_fixed_proof_size: usize,
    lmf_fixed_proof_time: f64, // seconds
}

// Function to run the experiment for a given n
fn run_experiment(n: usize, num_proofs: usize) -> ExperimentResult {
    let params = poseidon_params();
    let mut rng = thread_rng();

    // Generate random leaves
    println!("generate random leaves");
    let mut leaves = Vec::new();
    for _ in 0..n {
        leaves.push(Fr::rand(&mut rng));
    }

    // Select 10 random leaf indices for proof generation
    let proof_indices: Vec<usize> = (0..num_proofs).map(|_| rng.gen_range(0..n)).collect();

    // --- Standard Merkle Tree ---
    println!("eval standard Merkle Tree");
    let merkle_start = Timer::start();
    let merkle_tree = MerkleTree::<Config<Fr>>::new_with_data(Either::Left(&leaves), &params)
        .expect("Failed to create Merkle tree");
    let merkle_construction_time = merkle_start.end();

    // Generate proofs for Merkle tree
    let mut merkle_proof_size = 0;
    let mut merkle_proof_time = 0.;
    for &idx in &proof_indices {
        let proof_start = Timer::start();
        let proof = merkle_tree
            .prove(idx)
            .expect("Failed to generate Merkle proof");
        merkle_proof_time += proof_start.end();
        merkle_proof_size = proof.0.len();

        // ensure the proof is correct
        let valid = MerkleTree::<Config<Fr>>::verify(
            &params,
            merkle_tree.root(),
            Either::Left(&leaves[idx]),
            proof,
        )
        .unwrap();
        assert!(valid);
    }
    let merkle_proof_time = merkle_proof_time / (proof_indices.len() as f64);

    // --- Leveled Merkle Forest ---
    println!("eval Leveled Merkle Forest");
    let lmf_start = Timer::start();
    let lmf = LeveledMerkleForest::<Config<Fr>>::new_with_data(Either::Left(&leaves), &params)
        .expect("Failed to create LMF");
    let lmf_construction_time = lmf_start.end();

    // Generate fixed-size proofs for LMF
    let mut lmf_fixed_proof_size = 0;
    let mut lmf_fixed_proof_time = 0.;
    for &idx in &proof_indices {
        let proof_start = Timer::start();
        let proof = lmf
            .prove(idx)
            .expect("Failed to generate fixed-size LMF proof");
        lmf_fixed_proof_time += proof_start.end();
        lmf_fixed_proof_size = proof.siblings.len();

        // ensure the proof is correct
        let valid =
            LeveledMerkleForest::verify(&params, lmf.root(), Either::Left(&leaves[idx]), proof)
                .unwrap();
        assert!(valid);
    }
    let lmf_fixed_proof_time = lmf_fixed_proof_time / proof_indices.len() as f64;

    // Return results
    ExperimentResult {
        n,
        merkle_construction_time,
        merkle_proof_size,
        merkle_proof_time,
        lmf_construction_time,
        lmf_fixed_proof_size,
        lmf_fixed_proof_time,
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
    let num_proofs = 10;
    let results_path = Path::new("../exp/lmf");
    fs::create_dir_all(results_path).unwrap();
    let results_path = results_path.join("experiment_results_time.json");

    println!("Running Merkle Tree and LMF experiments...");
    println!(
        "{:<10} | {:<25} | {:<15} | {:<25} | {:<25} | {:<20} | {:<25}",
        "n",
        "Merkle Construct (ms)",
        "Merkle Proof Size",
        "Merkle Proof Time (ms)",
        "LMF Construct (ms)",
        "LMF Fixed Proof Size",
        "LMF Fixed Proof Time (ms)",
    );
    println!("{}", "-".repeat(200));

    let mut results = Vec::new();
    for n in sizes {
        let result = run_experiment(n, num_proofs);
        results.push(result.clone());

        let mut file = File::create(&results_path).unwrap();
        serde_json::to_writer_pretty(&mut file, &results)
            .expect("serde_json pretty print should succeed");

        // Print results in a formatted table
        println!(
            "{:<10} | {:<25.2} | {:<15} | {:<25.2} | {:<25.2} | {:<20} | {:<25.2}",
            result.n,
            result.merkle_construction_time * 1000.0,
            result.merkle_proof_size,
            result.merkle_proof_time * 1000.0,
            result.lmf_construction_time * 1000.0,
            result.lmf_fixed_proof_size,
            result.lmf_fixed_proof_time * 1000.0,
        );
    }
}
