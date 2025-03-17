## Usage

This folder contains some benchmark/experiments for evaluation.

## `bls_pairing`

This file benchmarks two ways to verify BLS signature.
- One is by directly comparing the results of two pairings
- The other is by running Miller's loop on both side and performing only one final exponentiation

## `groth16_single_step`

This file measures the time to generate public parameters and proofs and verify BLS signatures using Groth16. The feature flags allow you to control which curve is used for BLS signatures and SNARK
- `sig-12381-snark-12377`: BLS signature runs on BLS12-381 and SNARK runs on BLS12-377. This setup uses field emulation.
- `sig-12377-snark-761`: BLS signature runs on BLS12-377, SNARK runs on BW6-761. This setup uses native field variables as the curves are two-chain curves.

For example,

```sh
# benchmark using BLS12-381 and BLS12-377
cargo bench --bench groth16_single_step --no-default-features --features sig-12381-snark-12377

# benchmark using BLS12-377 and BW6-761
cargo bench --bench groth16_single_step --no-default-features --features sig-12377-snark-761
```