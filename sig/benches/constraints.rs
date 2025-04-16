use std::env::temp_dir;

use sig::{
    bls::Parameters,
    folding::circuit::{BCCircuitMerkleForest, BCCircuitNoMerkle},
};
use utils::{ext::measure_bc_circuit_constraints, register_tracing};

mod utils;

fn main() {
    const MAX_COMMITTEE_SIZE: usize = 512;
    const MAX_CHAIN_SIZE: usize = 1024;
    use ark_mnt4_753::Fr;

    register_tracing();

    let mut dir = temp_dir();
    dir.push("tmp_config.json");

    measure_bc_circuit_constraints::<
        MAX_COMMITTEE_SIZE,
        Fr,
        BCCircuitNoMerkle<Fr, MAX_COMMITTEE_SIZE>,
    >(&dir, Parameters::setup())
    .unwrap();

    measure_bc_circuit_constraints::<
        MAX_COMMITTEE_SIZE,
        Fr,
        BCCircuitMerkleForest<Fr, MAX_COMMITTEE_SIZE>,
    >(&dir, (Parameters::setup(), MAX_CHAIN_SIZE))
    .unwrap();
}
