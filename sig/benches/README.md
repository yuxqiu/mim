## 📊 Usage & Benchmark Overview

This directory contains benchmarking scripts and experimental evaluations used for analyzing the performance of folding-based SNARKs in the context of committee rotation.

The `archives/` folder includes experiments that are **not included** in the final version of the thesis but may still be useful for reference.

---

## 🧪 Benchmark Descriptions

### `ext_nova_folding_no_merkle_{mem,time}` and `ext_nova_folding_merkle_forest_{mem,time}`

These files estimate the **memory** (`_mem`) and **execution time** (`_time`) required for folding-based SNARK proof generation using Nova.
Due to the extremely high constraint count, **extrapolation** is used rather than full execution.
Benchmarks are conducted with and without **Leveled Merkle Forest (LMF)** optimizations.

---

### `lmf_time` and `lmf_mem`

- `lmf_time` measures:
  - The time to construct the LMF
  - Comparison with a traditional Merkle tree of equivalent size
  - Average time to generate 10 inclusion proofs for randomly selected leaves
  - Average proof length

- `lmf_mem` captures:
  - Peak memory usage during LMF construction
  - Memory comparison with a standard Merkle tree

---

### `constraints`

Measures the **number of R1CS constraints** contributed by each component within the folding circuit.

---

### `folding_no_merkle` and `folding_merkle_forest`

Benchmarks the time taken to perform **five folding steps**:
- `folding_no_merkle`: Without LMF optimization
- `folding_merkle_forest`: With LMF optimization

---

## 🗃️ Archived Experiments

These files contain older or exploratory benchmarks that were ultimately **excluded from the thesis** but may offer additional insight.

### `bls_pairing`

Compares two methods of verifying BLS signatures:
- Direct pairing comparison
- Running **Miller's loop** separately and performing one final exponentiation

---

### `groth16_single_step_native` and `groth16_single_step_emulation`

Benchmarks **Groth16 proof generation and verification** for BLS signatures:
- `groth16_single_step_native`: Using native field arithmetic
- `groth16_single_step_emulation`: Using field emulation (not benchmarked with Criterion due to long runtimes; uses `std::time::Duration` instead)

---

### `bls_r1cs_constraints`

Measures the **R1CS constraint count** for each component of a BLS signature verification circuit.

---

### `nova_folding_no_merkle`

Benchmarks the time required to use a **Nova + Groth16 folding-based SNARK** to prove committee rotation (without LMF).