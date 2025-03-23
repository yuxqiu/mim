# Mím

**Mím** is a work-in-progress research prototype designed to verify committee rotation in quorum-based blockchains using folding-based SNARKs.

## Highlights

- 🌀 [hash-to-curve](https://datatracker.ietf.org/doc/rfc9380/) implementation for **BLS12 curves** in the `arkworks` R1CS framework
- 🔏 R1CS circuit for verifying **BLS signatures** over BLS12 curves, supporting both **native** and **emulated** fields
- ♻️ Implementation of `FCircuit` from `sonobe`, enabling proof generation via **folding schemes**

## Usage

Add the dependency in your `Cargo.toml`:

```toml
[dependencies]
mim = { git = "https://github.com/yuxqiu/mim", package = "sig" }
```

### Module Overview

- `bc`: abstraction for a quorum-based blockchain
- `bls`: BLS signature implementation (off-circuit and R1CS circuit)
- `folding`: folding circuit verifying `bc`’s committee rotation
- `hash`: R1CS hash-to-curve for BLS12 curves
- `tests`: test harnesses and debugging notes exposing an issue in `EmulatedFpVar` that results in unsatisfiable constraints

📊 Example usage and experiments can be found in [`sig/benches`](./sig/benches/).

## License

This project is [MIT licensed](./LICENSE).

## Acknowledgments

This work builds on the excellent libraries from [arkworks](https://github.com/arkworks-rs) and [sonobe](https://github.com/privacy-scaling-explorations/sonobe).

Special thanks to **Philipp Jovanovic** and **Alberto Sonnino** for their insightful discussions and invaluable feedback throughout the development of this project.