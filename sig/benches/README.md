## Usage

This folder contains some benchmark/experiments for evaluation.

## `bls_pairing`

This file benchmarks two ways to verify BLS signature.
- One is by directly comparing the results of two pairings
- The other is by running Miller's loop on both side and performing only one final exponentiation

## `groth16_single_step_native` and `groth16_single_step_emulation`

These file measures the time to generate public parameters and proofs and verify BLS signatures using Groth16.

The feature flags allow you to control which curve is used for BLS signatures and SNARK
- `sig-12381-snark-12377`: BLS signature runs on BLS12-381 and SNARK runs on BLS12-377. This setup uses field emulation.
- `sig-12377-snark-761`: BLS signature runs on BLS12-377, SNARK runs on BW6-761. This setup uses native field variables as the curves are two-chain curves.

As field emulation takes a long time, `groth16_single_step_emulation` is created separately to not use `Criterion` (which requires a sample size of at least 10) for benchmarking. Instead, it uses Rust's built-in `Duration` to measure the wall clock running time. It's recommended to use `groth16_single_step_emulation` when measuring time on `sig-12381-snark-12377`.

For example,

```sh
# benchmark using BLS12-381 and BLS12-377
cargo bench --bench groth16_single_step_emulation --no-default-features --features sig-12381-snark-12377

# benchmark using BLS12-377 and BW6-761
cargo bench --bench groth16_single_step_native --no-default-features --features sig-12377-snark-761
```