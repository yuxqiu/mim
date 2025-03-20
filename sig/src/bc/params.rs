/* ====================Hash for Checkpoint==================== */
use blake2::digest::typenum::Unsigned;
use blake2::{digest::OutputSizeUser, Blake2s256};

pub type HashFunc = Blake2s256;
pub const HASH_OUTPUT_SIZE: usize = <HashFunc as OutputSizeUser>::OutputSize::USIZE;
/* ====================Hash for Checkpoint==================== */

/* ====================Sig==================== */
use crate::bls::{Parameters, PublicKey, SecretKey, Signature};

type BlsSigConfig = ark_bls12_381::Config;
pub type AuthoritySecretKey = SecretKey<BlsSigConfig>;
pub type AuthorityPublicKey = PublicKey<BlsSigConfig>;
pub type AuthorityAggregatedSignature = Signature<BlsSigConfig>;
pub type AuthoritySigParams = Parameters<BlsSigConfig>;
/* ====================Sig==================== */

/* ====================Committee==================== */
type Weight = u64;
pub type Committee = Vec<(AuthorityPublicKey, Weight)>;
pub type Signers = Vec<AuthoritySecretKey>;

pub const TOTAL_VOTING_POWER: u64 = 10_000;
pub const STRONG_THRESHOLD: u64 = 6_667;
pub const MAX_COMMITTEE_SIZE: u64 = TOTAL_VOTING_POWER;
/* ====================Committee==================== */
