/// This example performs the full flow:
/// - define the circuit to be folded
/// - fold the circuit with Nova+CycleFold's IVC
/// - generate a `DeciderEthCircuit` final proof
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
    bc::block::gen_blockchain_with_params,
    bls::Parameters,
    folding::{bc::CommitteeVar, circuit::BCCircuitNoMerkle},
};
use std::time::Instant;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, Layer};
use tracing_tree::HierarchicalLayer;

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
    tracing_subscriber::registry()
        .with(
            HierarchicalLayer::new(2)
                .with_indent_amount(4)
                // for old tracing_subscriber::fmt::layer
                // treat span enter/exit as an event
                // .with_span_events(
                //     tracing_subscriber::fmt::format::FmtSpan::EXIT
                //         | tracing_subscriber::fmt::format::FmtSpan::ENTER,
                // )
                // .without_time()
                .with_ansi(false)
                // log functions inside our crate + pairing
                .with_filter(tracing_subscriber::filter::FilterFn::new(|metadata| {
                    // 1. target filtering - include target that has sig
                    metadata.target().contains("sig")
                        // 2. name filtering - include name that contains `miller_loop` and `final_exponentiation`
                        || ["miller_loop", "final_exponentiation"]
                            .into_iter()
                            .any(|s| metadata.name().contains(s))
                        // 3. event filtering
                        // - to ensure all events from spans match above rules are included
                        // - events from spans that do not match either of the above two rules will not be considered
                        //   because as long as the spans of these events do not match the first two rules, their children
                        //   events will not be triggered.
                        || metadata.is_event()
                })),
        )
        .init();

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
    let committee_size = 100; // needs to <= MAX_COMMITTEE_SIZE
    let bc = gen_blockchain_with_params(n_steps + 1, committee_size);

    let cs = ConstraintSystem::new_ref();
    let z_0 = {
        let mut z_0: Vec<_> = CommitteeVar::new_constant(cs, bc.get(0).unwrap().committee.clone())?
            .to_constraint_field()?
            .iter()
            .map(|fpvar| fpvar.value().unwrap())
            .collect();
        z_0.push(
            UInt64::constant(bc.get(0).unwrap().epoch)
                .to_fp()?
                .value()
                .unwrap(),
        );
        z_0
    };

    // initialize the folding scheme engine, in our case we use Nova
    let mut nova = N::init(&nova_params, f_circuit, z_0)?;

    // run n steps of the folding iteration
    for (i, block) in (0..n_steps).zip(bc.into_blocks().skip(1)) {
        let start = Instant::now();
        nova.prove_step(rng, block, None)?;
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
