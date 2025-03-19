#[expect(clippy::missing_errors_doc)]
pub mod bc;

#[expect(clippy::missing_errors_doc)]
pub mod bls;

#[expect(clippy::missing_errors_doc)]
#[cfg(not(feature = "emulated-field"))]
// only enable when BLS verification R1CS is implemented in native field
pub mod folding;

#[expect(clippy::missing_errors_doc)]
pub mod hash;

#[expect(clippy::missing_errors_doc)]
pub mod params;

mod tests;
