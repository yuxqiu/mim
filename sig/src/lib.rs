#![deny(clippy::cast_possible_truncation)]
#![deny(clippy::cast_possible_wrap)]
#![deny(clippy::cast_precision_loss)]
#![deny(clippy::cast_sign_loss)]
#![deny(clippy::cast_lossless)]

pub mod bc;
pub mod bls;
pub mod folding;
pub mod hash;
pub mod merkle;
pub mod params;
mod tests;
