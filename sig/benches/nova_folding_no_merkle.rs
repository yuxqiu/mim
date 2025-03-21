/// This example performs the full flow:
/// - define the circuit to be folded
/// - fold the circuit with Nova+CycleFold's IVC
/// - generate a `DeciderEthCircuit` final proof
/// - generate the Solidity contract that verifies the proof
/// - verify the proof in the EVM
///
/// It's adapted from `sonobe/examples/full_flow.rs`
use ark_mnt4_753::{Fr, G1Projective as G1, MNT4_753 as MNT4};
use ark_mnt6_753::{G1Projective as G2, MNT6_753 as MNT6};

use ark_ff::PrimeField;
use ark_groth16::Groth16;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use std::marker::PhantomData;
use std::time::Instant;

use folding_schemes::{
    commitment::kzg::KZG,
    folding::{
        nova::{decider::Decider as NovaDecider, Nova, PreprocessorParam},
        traits::CommittedInstanceOps,
    },
    frontend::FCircuit,
    transcript::poseidon::poseidon_canonical_config,
    Decider, Error, FoldingScheme,
};

/// Test circuit to be folded
#[derive(Clone, Copy, Debug)]
pub struct CubicFCircuit<F: PrimeField> {
    _f: PhantomData<F>,
}
impl<F: PrimeField> FCircuit<F> for CubicFCircuit<F> {
    type Params = ();
    type ExternalInputs = ();
    type ExternalInputsVar = ();

    fn new(_params: Self::Params) -> Result<Self, Error> {
        Ok(Self { _f: PhantomData })
    }
    fn state_len(&self) -> usize {
        1
    }
    fn generate_step_constraints(
        &self,
        cs: ConstraintSystemRef<F>,
        _i: usize,
        z_i: Vec<FpVar<F>>,
        _external_inputs: Self::ExternalInputsVar,
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        let five = FpVar::<F>::new_constant(cs, F::from(5u32))?;
        let z_i = z_i[0].clone();

        Ok(vec![&z_i * &z_i * &z_i + &z_i + &five])
    }
}

fn main() -> Result<(), Error> {
    let n_steps = 5;

    // set the initial state
    let z_0 = vec![Fr::from(3_u32)];

    let f_circuit = CubicFCircuit::<Fr>::new(())?;

    // use Nova as FoldingScheme
    type N = Nova<G1, G2, CubicFCircuit<Fr>, KZG<'static, MNT4>, KZG<'static, MNT6>, false>;
    type D = NovaDecider<
        G1,
        G2,
        CubicFCircuit<Fr>,
        KZG<'static, MNT4>,
        KZG<'static, MNT6>,
        Groth16<MNT4>,
        Groth16<MNT6>,
        N, // here we define the FoldingScheme to use
    >;

    let poseidon_config = poseidon_canonical_config::<Fr>();
    let mut rng = rand::rngs::OsRng;

    // prepare the Nova prover & verifier params
    let nova_preprocess_params = PreprocessorParam::new(poseidon_config, f_circuit);
    let nova_params = N::preprocess(&mut rng, &nova_preprocess_params)?;

    // prepare the Decider prover & verifier params
    let (decider_pp, decider_vp) =
        D::preprocess(&mut rng, (nova_params.clone(), f_circuit.state_len()))?;

    // initialize the folding scheme engine, in our case we use Nova
    let mut nova = N::init(&nova_params, f_circuit, z_0)?;

    // run n steps of the folding iteration
    for i in 0..n_steps {
        let start = Instant::now();
        nova.prove_step(rng, (), None)?;
        println!("Nova::prove_step {}: {:?}", i, start.elapsed());
    }

    let start = Instant::now();
    let proof = D::prove(rng, decider_pp, nova.clone())?;
    println!("generated Decider proof: {:?}", start.elapsed());

    let verified = D::verify(
        decider_vp,
        nova.i,
        nova.z_0.clone(),
        nova.z_i.clone(),
        &nova.U_i.get_commitments(),
        &nova.u_i.get_commitments(),
        &proof,
    )?;
    assert!(verified);
    println!("Decider proof verification: {verified}");

    Ok(())
}
