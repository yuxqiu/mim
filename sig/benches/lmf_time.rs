use ark_bls12_381::Fr;
use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
use ark_ff::UniformRand;
use rand::{thread_rng, Rng};
use serde::Serialize;
use sig::merkle::{forest::LeveledMerkleForest, tree::MerkleTree, Config};
use std::{
    fs::{self, File},
    path::Path,
    time::{Duration, Instant},
};

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
    lmf_variable_proof_sizes: Vec<usize>,
    lmf_variable_proof_times: Vec<f64>, // seconds
}

// Function to run the experiment for a given n
fn run_experiment(n: usize, num_proofs: usize) -> ExperimentResult {
    let params = poseidon_params();
    let mut rng = thread_rng();

    // Generate random leaves
    let mut leaves = Vec::new();
    for _ in 0..n {
        leaves.push(Fr::rand(&mut rng));
    }

    // Select 10 random leaf indices for proof generation
    let proof_indices: Vec<usize> = (0..num_proofs).map(|_| rng.gen_range(0..n)).collect();

    // --- Standard Merkle Tree ---
    let merkle_capacity = n.next_power_of_two() * 2 - 1; // Ensure capacity is 2^k - 1
    let mut merkle_tree = MerkleTree::<Config<Fr>>::new(merkle_capacity, &params)
        .expect("Failed to create Merkle tree");

    // Add leaves to Merkle tree
    let merkle_start = Instant::now();
    for (i, leaf) in leaves.iter().enumerate() {
        merkle_tree
            .update(i, &[*leaf])
            .expect("Failed to add leaf to Merkle tree");
    }
    let merkle_construction_time = merkle_start.elapsed().as_secs_f64();

    // Generate proofs for Merkle tree
    let mut merkle_proof_size = 0;
    let mut merkle_proof_time = Duration::new(0, 0);
    for &idx in &proof_indices {
        let proof_start = Instant::now();
        let proof = merkle_tree
            .prove(idx)
            .expect("Failed to generate Merkle proof");
        merkle_proof_time += proof_start.elapsed();
        merkle_proof_size = proof.0.len();
    }
    let merkle_proof_time = merkle_proof_time.as_secs_f64() / (proof_indices.len() as f64);

    // --- Leveled Merkle Forest ---
    let mut lmf =
        LeveledMerkleForest::<Config<Fr>>::new_optimal(n, &params).expect("Failed to create LMF");

    // Add leaves to LMF
    let lmf_start = Instant::now();
    for leaf in &leaves {
        lmf.add(&[*leaf]).expect("Failed to add leaf to LMF");
    }
    let lmf_construction_time = lmf_start.elapsed().as_secs_f64();

    // Generate fixed-size proofs for LMF
    let mut lmf_fixed_proof_size = 0;
    let mut lmf_fixed_proof_time = Duration::new(0, 0);
    for &idx in &proof_indices {
        let proof_start = Instant::now();
        let proof = lmf
            .prove(idx)
            .expect("Failed to generate fixed-size LMF proof");
        lmf_fixed_proof_time += proof_start.elapsed();
        lmf_fixed_proof_size = proof.siblings.len();
    }
    let lmf_fixed_proof_time = lmf_fixed_proof_time.as_secs_f64() / proof_indices.len() as f64;

    // Generate variable-size proofs for LMF
    let proof_indices: Vec<usize> = (0..=n.ilog(lmf.num_leaves_per_tree() as usize))
        .map(|e| (lmf.num_leaves_per_tree() as usize).pow(e) - 1)
        .collect();
    let mut lmf_variable_proof_sizes = Vec::new();
    let mut lmf_variable_proof_times = Vec::new();
    for &idx in &proof_indices {
        let proof_start = Instant::now();
        let proof = lmf
            .prove_variable(idx)
            .expect("Failed to generate variable-size LMF proof");
        lmf_variable_proof_times.push(proof_start.elapsed().as_secs_f64());
        lmf_variable_proof_sizes.push(proof.siblings.len());
    }

    // Return results
    ExperimentResult {
        n,
        merkle_construction_time,
        merkle_proof_size,
        merkle_proof_time,
        lmf_construction_time,
        lmf_fixed_proof_size,
        lmf_fixed_proof_time,
        lmf_variable_proof_sizes,
        lmf_variable_proof_times,
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
    let num_proofs = 10;
    let results_path = Path::new("../exp/lmf");
    fs::create_dir_all(results_path).unwrap();
    let results_path = results_path.join("experiment_results_time.json");

    println!("Running Merkle Tree and LMF experiments...");
    println!(
        "{:<10} | {:<25} | {:<15} | {:<25} | {:<25} | {:<20} | {:<25} | {:<20} | {:<25}",
        "n",
        "Merkle Construct (ms)",
        "Merkle Proof Size",
        "Merkle Proof Time (ms)",
        "LMF Construct (ms)",
        "LMF Fixed Proof Size",
        "LMF Fixed Proof Time (ms)",
        "LMF Var Proof Size",
        "LMF Var Proof Time (ms)"
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
            "{:<10} | {:<25.2} | {:<15} | {:<25.2} | {:<25.2} | {:<20} | {:<25.2} | {:?} | {:?}",
            result.n,
            result.merkle_construction_time * 1000.0,
            result.merkle_proof_size,
            result.merkle_proof_time * 1000.0,
            result.lmf_construction_time * 1000.0,
            result.lmf_fixed_proof_size,
            result.lmf_fixed_proof_time * 1000.0,
            result.lmf_variable_proof_sizes,
            result.lmf_variable_proof_times
        );
    }
}
