/// A hash to field implementation based on Poseidon hash function.
///
/// Because of the following reasons, this mod is not used in any other files in this project.
/// - Poseidon hash is not mentioned in IRTF's hash to curve specification
/// - It requires curve-dependent setup parameter selection.
///   - Specifically, this implementation only works for `MontBackend::<_, 4>` right now because `PoseidonDefacultConfig`
///     is only implemented for that.
use core::{array, marker::PhantomData};

use ark_crypto_primitives::sponge::{
    poseidon::{PoseidonConfig, PoseidonDefaultConfigField, PoseidonSponge},
    CryptographicSponge,
};
use ark_ff::{field_hashers::HashToField, Field};

/// Implement `PoseidonFieldHasher` to enable interopability with arkworks.
pub struct PoseidonFieldHasher<F: PoseidonDefaultConfigField, const SEC_LEVEL: usize = 128> {
    config: PoseidonConfig<F>,
    domain: Vec<u8>,
    _params: PhantomData<F>,
}

impl<TF: Field, F: PoseidonDefaultConfigField, const SEC_LEVEL: usize> HashToField<TF>
    for PoseidonFieldHasher<F, SEC_LEVEL>
{
    fn new(domain: &[u8]) -> Self {
        // set capacity based on the suggestion at https://www.poseidon-hash.info
        // ensure that the hash provides at least 128 bit security level
        //
        // capacity = ceil(SEC_LEVEL * 2 / MODULUS_BIT_SIZE)
        let mut config = F::get_default_poseidon_parameters(2, false).unwrap();
        config.capacity = ((SEC_LEVEL << 1) + F::BasePrimeField::MODULUS_BIT_SIZE as usize - 1)
            / (F::BasePrimeField::MODULUS_BIT_SIZE) as usize;

        Self {
            config,
            domain: domain.into(),
            _params: PhantomData,
        }
    }

    fn hash_to_field<const N: usize>(&self, msg: &[u8]) -> [TF; N] {
        // let msg: Vec<F::BasePrimeField> = msg.to_field_elements().unwrap();
        let mut sponge = PoseidonSponge::new(&self.config);
        sponge.absorb(&self.domain);
        sponge.absorb(&msg);

        let ext_degree = usize::try_from(TF::extension_degree())
            .expect("extension degree should be able to store in usize");
        // if TF::BasePrimeFielf is the same as F, this will be equivalent to squeeze_native_field_elements
        // (with a runtime type check)
        let res: Vec<TF::BasePrimeField> = sponge.squeeze_field_elements(N * ext_degree);

        let cb = |i| {
            TF::from_base_prime_field_elems((0..ext_degree).map(|j| res[i * ext_degree + j]))
                .unwrap()
        };

        array::from_fn::<TF, N, _>(cb)
    }
}
