//! ## Overview
//!
//! This module implements a field gadget for a prime field `Fp` over another
//! prime field `Fq` where `p != q`.
//!
//! When writing constraint systems for many cryptographic proofs, we are
//! restricted to a native field (e.g., the scalar field of the pairing-friendly
//! curve). This can be inconvenient; for example, the recursive composition of
//! proofs via cycles of curves requires the verifier to compute over a
//! non-native field.
//!
//! The library makes it possible to write computations over a non-native field
//! in the same way one would write computations over the native field. This
//! naturally introduces additional overhead, which we minimize using a variety
//! of optimizations. (Nevertheless, the overhead is still substantial, and
//! native fields should be used where possible.)
//!
//! ## Usage
//!
//! Because [`EmulatedFpVar`] implements the [`FieldVar`] trait in arkworks,
//! we can treat it like a native prime field variable ([`FpVar`]).
//!
//! We can do the standard field operations, such as `+`, `-`, and `*`. See the
//! following example:
//!
//! ```rust
//! # fn main() -> Result<(), ark_relations::r1cs::SynthesisError> {
//! # use ark_std::UniformRand;
//! # use ark_relations::{ns, r1cs::ConstraintSystem};
//! # use ark_r1cs_std::prelude::*;
//! use ark_r1cs_std::fields::emulated_fp::EmulatedFpVar;
//! use ark_bls12_377::{Fr, Fq};
//!
//! # let mut rng = ark_std::test_rng();
//! # let a_value = Fr::rand(&mut rng);
//! # let b_value = Fr::rand(&mut rng);
//! # let cs = ConstraintSystem::<Fq>::new_ref();
//!
//! let a = EmulatedFpVar::<Fr, Fq>::new_witness(ns!(cs, "a"), || Ok(a_value))?;
//! let b = EmulatedFpVar::<Fr, Fq>::new_witness(ns!(cs, "b"), || Ok(b_value))?;
//!
//! // add
//! let a_plus_b = &a + &b;
//!
//! // sub
//! let a_minus_b = &a - &b;
//!
//! // multiply
//! let a_times_b = &a * &b;
//!
//! // enforce equality
//! a.enforce_equal(&b)?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Advanced optimization
//!
//! After each multiplication, our library internally performs a *reduce*
//! operation, which reduces an intermediate type [`MulResultVar`]
//! to the normalized type [`EmulatedFpVar`]. This enables a user to
//! seamlessly perform a sequence of operations without worrying about the
//! underlying details.
//!
//! However, this operation is expensive and is sometimes avoidable. We can
//! reduce the number of constraints by using this intermediate type, which only
//! supports additions. To multiply, it must be reduced back to
//! [`EmulatedFpVar`]. See below for a skeleton example.
//!
//! ---
//!
//! To compute `a * b + c * d`, the straightforward (but more expensive)
//! implementation is as follows:
//!
//! ```ignore
//! let a_times_b = &a * &b;
//! let c_times_d = &c * &d;
//! let res = &a_times_b + &c_times_d;
//! ```
//!
//! This performs two *reduce* operations in total, one for each multiplication.
//!
//! ---
//!
//! We can save one reduction by using [`MulResultVar`], as
//! follows:
//!
//! ```ignore
//! let a_times_b = a.mul_without_reduce(&b)?;
//! let c_times_d = c.mul_without_reduce(&d)?;
//! let res = (&a_times_b + &c_times_d)?.reduce()?;
//! ```
//!
//! It performs only one *reduce* operation and is roughly 2x faster than the
//! first implementation.
//!
//! ## Inspiration and basic design
//!
//! This implementation employs the standard idea of using multiple **limbs** to
//! represent an element of the target field. For example, an element in the
//! TargetF may be represented by three BaseF elements (i.e., the
//! limbs).
//!
//! ```text
//! TargetF -> limb 1, limb 2, and limb 3 (each is a BaseF element)
//! ```
//!
//! After some computation, the limbs become saturated and need to be
//! **reduced**, in order to engage in more computation.
//!
//! We heavily use the optimization techniques in [\[KPS18\]](https://akosba.github.io/papers/xjsnark.pdf) and [\[OWWB20\]](https://eprint.iacr.org/2019/1494).
//! Both works have their own open-source libraries:
//! [xJsnark](https://github.com/akosba/xjsnark) and
//! [bellman-bignat](https://github.com/alex-ozdemir/bellman-bignat).
//! Compared with these, this module works with the `arkworks` ecosystem.
//! It also provides the option (based on an `optimization_goal` for the
//! constraint system) to optimize for constraint density instead of number of
//! constraints, which improves efficiency in proof systems like [Marlin](https://github.com/arkworks-rs/marlin).
//!
//! ## References
//! \[KPS18\]: A. E. Kosba, C. Papamanthou, and E. Shi. "xJsnark: a framework for efficient verifiable computation," in *Proceedings of the 39th Symposium on Security and Privacy*, ser. S&P ’18, 2018, pp. 944–961.
//!
//! \[OWWB20\]: A. Ozdemir, R. S. Wahby, B. Whitehat, and D. Boneh. "Scaling verifiable computation using efficient set accumulators," in *Proceedings of the 29th USENIX Security Symposium*, ser. Security ’20, 2020.
//!
//! [`EmulatedFpVar`]: crate::fields::emulated_fp::EmulatedFpVar
//! [`MulResultVar`]: crate::fields::emulated_fp::MulResultVar
//! [`FpVar`]: crate::fields::fp::FpVar

#![allow(
    clippy::redundant_closure_call,
    clippy::enum_glob_use,
    clippy::missing_errors_doc,
    clippy::cast_possible_truncation,
    clippy::unseparated_literal_suffix
)]

use ark_std::fmt::Debug;

/// Utilities for sampling parameters for non-native field gadgets
///
/// - `BaseF`:              the constraint field
/// - `TargetF`:            the field being simulated
/// - `num_limbs`:              how many limbs are used
/// - `bits_per_limb`:          the size of the limbs
pub mod params;

// Debug: pub(crate) is removed for debug `EmulatedFpVar`
// This is not revered back to pub(crate) because
// of the MRE example in `sig/src/lib.rs`.
//
/// How are non-native elements reduced?
pub mod reduce;

/// a macro for computing ceil(log2(x)) for a field element x
macro_rules! overhead {
    ($x:expr) => {{
        use ark_ff::BigInteger;
        let num = $x;
        let num_bits = num.into_bigint().to_bits_be();

        let mut skipped_bits = 0;
        for b in num_bits.iter() {
            if *b == false {
                skipped_bits += 1;
            } else {
                break;
            }
        }

        let mut is_power_of_2 = true;
        for b in num_bits.iter().skip(skipped_bits + 1) {
            if *b == true {
                is_power_of_2 = false;
            }
        }

        // BUG: there might be a problem with the original impl here
        // - log(2) = 2
        // - log(3) = 3
        // if is_power_of_2 {
        //     num_bits.len() - skipped_bits
        // } else {
        //     num_bits.len() - skipped_bits + 1
        // }

        // let log(0) = 0 in our case
        if num == BaseF::zero() {
            0
        } else if is_power_of_2 {
            num_bits.len() - skipped_bits - 1
        } else {
            num_bits.len() - skipped_bits
        }
    }};
}

pub(crate) use overhead;

/// Parameters for a specific `EmulatedFpVar` instantiation
#[derive(Clone, Debug)]
pub struct NonNativeFieldConfig {
    /// The number of limbs (`BaseF` elements) used to represent a
    /// `TargetF` element. Highest limb first.
    pub num_limbs: usize,

    /// The number of bits of the limb
    pub bits_per_limb: usize,
}

mod allocated_field_var;
pub use allocated_field_var::*;

mod allocated_mul_result;
pub use allocated_mul_result::*;

mod field_var;
pub use field_var::*;

mod mul_result;
pub use mul_result::*;
