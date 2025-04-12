/* ====================Hash for Block==================== */
use blake2::digest::typenum::Unsigned;
use blake2::{digest::OutputSizeUser, Blake2s256};

pub type HashFunc = Blake2s256;
pub const HASH_OUTPUT_SIZE: usize = <HashFunc as OutputSizeUser>::OutputSize::USIZE;
/* ====================Hash for Block==================== */

/* ====================Sig==================== */
use crate::bls::{Parameters, PublicKey, SecretKey, Signature};
use crate::params::BlsSigConfig;

pub type AuthoritySecretKey = SecretKey<BlsSigConfig>;
pub type AuthorityPublicKey = PublicKey<BlsSigConfig>;
pub type AuthorityAggregatedSignature = Signature<BlsSigConfig>;
pub type AuthoritySigParams = Parameters<BlsSigConfig>;
/* ====================Sig==================== */

/* ====================Committee==================== */
pub type Weight = u64;
pub type Signers = Vec<AuthoritySecretKey>;

pub const TOTAL_VOTING_POWER: u64 = 10_000;
pub const STRONG_THRESHOLD: u64 = 6_667;
/* ====================Committee==================== */
