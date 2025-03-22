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

use ark_groth16::Groth16;
use ark_r1cs_std::convert::ToConstraintFieldGadget;
use ark_r1cs_std::R1CSVar;
use ark_r1cs_std::{alloc::AllocVar, uint64::UInt64};
use ark_relations::r1cs::ConstraintSystem;
use sig::{
    bc::checkpoints::gen_blockchain_with_params,
    bls::Parameters,
    folding::{bc::CommitteeVar, circuit::BCCircuitNoMerkle},
};
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

fn main() -> Result<(), Error> {
    let f_circuit = BCCircuitNoMerkle::<Fr>::new(Parameters::setup())?;

    // use Nova as FoldingScheme
    type N = Nova<G1, G2, BCCircuitNoMerkle<Fr>, KZG<'static, MNT4>, KZG<'static, MNT6>, false>;
    type D = NovaDecider<
        G1,
        G2,
        BCCircuitNoMerkle<Fr>,
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

    // prepare num steps and blockchain
    let n_steps = 5;
    let bc = gen_blockchain_with_params(n_steps + 1, 100);

    let cs = ConstraintSystem::new_ref();
    let mut z_0 = CommitteeVar::new_constant(cs, bc.get(0).unwrap().committee.clone())?
        .to_constraint_field()?;
    z_0.push(UInt64::constant(bc.get(0).unwrap().epoch).to_fp()?);
    let z_0 = z_0.iter().map(|fpvar| fpvar.value().unwrap()).collect();

    // initialize the folding scheme engine, in our case we use Nova
    let mut nova = N::init(&nova_params, f_circuit, z_0)?;

    // run n steps of the folding iteration
    for (i, cp) in (0..n_steps).zip(bc.into_iter().skip(1)) {
        let start = Instant::now();
        nova.prove_step(rng, cp, None)?;
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
