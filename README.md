# Mím

**Mím** is a research prototype for verifying committee rotation in quorum-based blockchains using **folding-based SNARKs**.

## Key Features

- RFC9380-compliant [hash-to-curve](https://datatracker.ietf.org/doc/rfc9380/) implementation for **BLS12 curves** in the `arkworks` R1CS framework
- R1CS circuit for verifying **BLS signatures**, supporting both **native** and **emulated** fields
- Integration with `sonobe`'s `FCircuit`, enabling proof generation via **folding schemes**
- On-circuit and off-circuit implementation of [**Leveled Merkle Forests (LMFs)**](https://yuxqiu.github.io/assets/pdf/writings/2025/trustless-efficient-light-client.pdf#page=31)

## Getting Started

Add **Mím** as a dependency in your `Cargo.toml`:

```toml
[dependencies]
mim = { git = "https://github.com/yuxqiu/mim", package = "sig" }
```

## Module Overview

- `bc` — Abstractions for quorum-based blockchains and committee structures
- `bls` — BLS signature implementation (off-circuit and on-circuit)
- `folding` — Folding circuits for verifying committee rotation
- `hash` — Hash-to-curve R1CS gadgets for BLS12 curves
- `merkle` — Merkle tree and Leveled Merkle Forest implementations (off-circuit and on-circuit)
- `tests` — Test harnesses and debug utilities, including [a known issue](https://github.com/arkworks-rs/r1cs-std/pull/157) with `EmulatedFpVar` causing unsatisfiable constraints

Example usage and benchmarking experiments are located in [`sig/benches`](./sig/benches/), with experiment outputs stored in [`exp`](./exp/).

## License

This project is licensed under the [MIT License](./LICENSE).

## Acknowledgments

This work builds on the excellent libraries developed by:

- [arkworks](https://github.com/arkworks-rs)
- [sonobe](https://github.com/privacy-scaling-explorations/sonobe)

Special thanks to **Philipp Jovanovic** and **Alberto Sonnino** for their insightful discussions and valuable feedback during development.