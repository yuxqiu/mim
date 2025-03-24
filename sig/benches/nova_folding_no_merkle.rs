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
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
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

use std::fs::{self, File};
use std::path::Path;

fn load_or_generate<T, F, S, D>(
    path: &str,
    generate_fn: F,
    ser_fn: S,
    deser_fn: D,
) -> Result<T, Error>
where
    F: FnOnce() -> Result<T, Error>,
    S: FnOnce(&T, &mut dyn ark_serialize::Write) -> Result<(), Error>,
    D: FnOnce(&mut dyn ark_serialize::Read) -> Result<T, Error>,
{
    let path = Path::new(path);

    if let Ok(mut file) = File::open(path) {
        return deser_fn(&mut file);
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let val = generate_fn()?;
    let mut file = File::create(path)?;
    ser_fn(&val, &mut file)?;
    Ok(val)
}

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
    // - can serialize this when the circuit is stable
    tracing::info!("nova folding preprocess");
    let nova_preprocess_params = PreprocessorParam::new(poseidon_config, f_circuit);
    let nova_params = load_or_generate(
        "data/nova_folding_params.dat",
        || N::preprocess(&mut rng, &nova_preprocess_params),
        |val, writer| Ok(val.serialize_compressed(writer)?),
        |reader| {
            Ok((
                N::pp_deserialize_with_mode(
                    &mut *reader,
                    Compress::Yes,
                    Validate::No,
                    <BCCircuitNoMerkle<Fr> as FCircuit<Fr>>::Params::setup(),
                )?,
                N::vp_deserialize_with_mode(
                    reader,
                    Compress::Yes,
                    Validate::No,
                    <BCCircuitNoMerkle<Fr> as FCircuit<Fr>>::Params::setup(),
                )?,
            ))
        },
    )?;
    // prepare num steps and blockchain
    tracing::info!("generate blockchain instance");
    let n_steps = 2;
    let committee_size = 25; // needs to <= MAX_COMMITTEE_SIZE
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
    tracing::info!("nova init");
    let mut nova = N::init(&nova_params, f_circuit, z_0)?;

    // run n steps of the folding iteration
    tracing::info!("nova folding prove step");
    for (i, block) in (0..n_steps).zip(bc.into_blocks().skip(1)) {
        let start = Instant::now();
        nova.prove_step(rng, block, None)?;
        tracing::info!("Nova::prove_step {}: {:?}", i, start.elapsed());
    }

    // prepare the Decider prover & verifier params
    // - can serialize this when the circuit is stable
    tracing::info!("nova decider preprocess");
    let (decider_pp, decider_vp) = load_or_generate(
        "data/nova_decider_params.dat",
        || D::preprocess(&mut rng, (nova_params.clone(), f_circuit.state_len())),
        |val, writer| Ok(val.serialize_compressed(writer)?),
        |reader| {
            Ok(<(
                <D as Decider<G1, G2, BCCircuitNoMerkle<Fr>, N>>::ProverParam,
                <D as Decider<G1, G2, BCCircuitNoMerkle<Fr>, N>>::VerifierParam,
            )>::deserialize_compressed(reader)?)
        },
    )?;

    tracing::info!("nova decider prove");
    let start = Instant::now();
    let proof = D::prove(rng, decider_pp, nova.clone())?;
    tracing::info!("generated decider proof: {:?}", start.elapsed());

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
    tracing::info!("decider proof verification: {verified}");

    Ok(())
}
