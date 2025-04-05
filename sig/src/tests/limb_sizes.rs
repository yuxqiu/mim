#[cfg(test)]
mod test {
    use ark_ff::PrimeField;
    use ark_r1cs_std::fields::emulated_fp::params::{find_parameters, OptimizationType};

    #[test]
    fn limb_size() {
        dbg!(find_parameters(
            ark_mnt4_298::Fr::MODULUS_BIT_SIZE as usize,
            ark_bls12_381::Fq::MODULUS_BIT_SIZE as usize,
            OptimizationType::Constraints
        ));
    }
}
