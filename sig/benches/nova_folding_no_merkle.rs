/// This example performs the full flow:
/// - define the circuit to be folded
/// - fold the circuit with Nova+CycleFold's IVC
/// - generate a `DeciderEthCircuit` final proof
///
/// It's adapted from `sonobe/examples/full_flow.rs`
mod utils;

use ark_mnt4_753::{Fr, G1Projective as G1, MNT4_753 as MNT4};
use ark_mnt6_753::{G1Projective as G2, MNT6_753 as MNT6};

use ark_groth16::Groth16;
use ark_r1cs_std::convert::ToConstraintFieldGadget;
use ark_r1cs_std::R1CSVar;
use ark_r1cs_std::{alloc::AllocVar, uint64::UInt64};
use ark_relations::r1cs::ConstraintSystem;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use memmap2::Mmap;
use rand::rngs::StdRng;
use rand::SeedableRng;
use sig::{
    bc::block::gen_blockchain_with_params,
    bls::Parameters,
    folding::{bc::CommitteeVar, circuit::BCCircuitNoMerkle},
};
use std::io::Read;

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
use std::path::{Path, PathBuf};

// `Read` wrapper for `Mmap` to interop with `ark_serialize`
struct MmapReader {
    mmap: Mmap,
    position: usize,
}

impl MmapReader {
    fn new(file: File) -> std::io::Result<Self> {
        let mmap = unsafe { Mmap::map(&file)? };
        Ok(Self { mmap, position: 0 })
    }
}

impl Read for MmapReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let remaining = &self.mmap[self.position..];
        let len = remaining.len().min(buf.len());
        buf[..len].copy_from_slice(&remaining[..len]);
        self.position += len;
        Ok(len)
    }
}

fn load_or_generate<T, F, S, D>(
    path: &PathBuf,
    generate_fn: F,
    ser_fn: S,
    deser_fn: D,
    deser: bool,
) -> Result<T, Error>
where
    F: FnOnce() -> Result<T, Error>,
    S: FnOnce(&T, &mut dyn ark_serialize::Write) -> Result<(), Error>,
    D: FnOnce(&mut dyn ark_serialize::Read) -> Result<T, Error>,
{
    if deser {
        if let Ok(file) = File::open(path) {
            println!("found data at {}. loading ...", path.to_string_lossy());
            let val = timeit!(format!("deserialize from {}", path.to_string_lossy()), {
                let mut mmap_reader = MmapReader::new(file)?;
                deser_fn(&mut mmap_reader)?
            });
            return Ok(val);
        }
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let val = generate_fn()?;
    let mut file = File::create(path)?;
    timeit!(format!("serialize to {}", path.to_string_lossy()), {
        ser_fn(&val, &mut file)?
    });
    return Ok(val);
}

fn main() -> Result<(), Error> {
    let f_circuit = BCCircuitNoMerkle::<Fr>::new(Parameters::setup())?;

    // use Nova as FoldingScheme
    type FC = BCCircuitNoMerkle<Fr>;
    type N = Nova<G1, G2, FC, KZG<'static, MNT4>, KZG<'static, MNT6>, false>;
    type D = NovaDecider<
        G1,
        G2,
        FC,
        KZG<'static, MNT4>,
        KZG<'static, MNT6>,
        Groth16<MNT4>,
        Groth16<MNT6>,
        N, // here we define the FoldingScheme to use
    >;

    let data_path = Path::new("../data");
    let poseidon_config = poseidon_canonical_config::<Fr>();
    let mut rng = StdRng::from_seed([42; 32]); // deterministic seeding

    // prepare the Nova prover & verifier params
    // - can serialize this when the circuit is stable
    println!("nova folding preprocess");
    let nova_preprocess_params = PreprocessorParam::new(poseidon_config, f_circuit);
    let nova_params = load_or_generate(
        &data_path.join("nova_folding_params.dat"),
        || {
            timeit!("generate nova folding preprocess params", {
                N::preprocess(&mut rng, &nova_preprocess_params)
            })
        },
        |val, writer| Ok(val.serialize_uncompressed(writer)?),
        |reader| {
            Ok((
                N::pp_deserialize_with_mode(
                    &mut *reader,
                    Compress::No,
                    Validate::No,
                    <FC as FCircuit<Fr>>::Params::setup(),
                )?,
                N::vp_deserialize_with_mode(
                    reader,
                    Compress::No,
                    Validate::No,
                    <FC as FCircuit<Fr>>::Params::setup(),
                )?,
            ))
        },
        true,
    )?;

    // prepare num steps and blockchain
    println!("generate blockchain instance");
    const N_STEPS_TO_PROVE: usize = 2;

    let n_steps_proven = load_or_generate(
        &data_path.join("n_steps_proven.dat"),
        || Ok(0_usize),
        |_, _| Ok(()),
        |reader| {
            let mut buf = String::new();
            reader.read_to_string(&mut buf)?;
            Ok(buf.trim().parse().expect("invalid usize"))
        },
        true,
    )?;

    println!("already prove {} steps", n_steps_proven);

    let committee_size = 25; // needs to <= MAX_COMMITTEE_SIZE
    let bc = gen_blockchain_with_params(
        n_steps_proven + N_STEPS_TO_PROVE + 1,
        committee_size,
        &mut rng,
    );

    // initialize the folding scheme engine, in our case we use Nova
    println!("nova init");
    let mut nova = load_or_generate(
        &data_path.join("nova_folding_state.dat"),
        || {
            let cs = ConstraintSystem::new_ref();
            let z_0 = {
                let mut z_0: Vec<_> = CommitteeVar::new_constant(
                    cs,
                    bc.get(n_steps_proven).unwrap().committee.clone(),
                )?
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

            timeit!("nova folding init", {
                N::init(&nova_params, f_circuit, z_0)
            })
        },
        |_, _| Ok(()),
        |reader| {
            <N as FoldingScheme<G1, G2, FC>>::from_ivc_proof(
                <<N as FoldingScheme<G1, G2, FC>>::IVCProof>::deserialize_with_mode(
                    reader,
                    Compress::No,
                    Validate::No,
                )?,
                <FC as FCircuit<Fr>>::Params::setup(),
                nova_params.clone(), // unfortunately, `FoldingScheme` API requires us to `clone` here
            )
        },
        true,
    )?;

    // run `N_STEPS_TO_PROVE` steps of the folding iteration
    println!("nova folding prove step");
    for (i, block) in (0..N_STEPS_TO_PROVE).zip(bc.into_blocks().skip(n_steps_proven + 1)) {
        timeit!(format!("nova prove_step {}", n_steps_proven + i), {
            nova.prove_step(&mut rng, block, None)?;
        })
    }

    // ser number of steps proven and nova states
    load_or_generate(
        &data_path.join("n_steps_proven.dat"),
        || Ok(n_steps_proven + N_STEPS_TO_PROVE),
        |val, writer| Ok(writer.write_all(&val.to_string().into_bytes())?),
        |_| Ok(0),
        false,
    )?;
    load_or_generate(
        &data_path.join("nova_folding_state.dat"),
        || Ok(&nova),
        |val, writer| Ok(val.ivc_proof().serialize_uncompressed(writer)?),
        |_| Ok(&nova), // this is just a placehold deser fn
        false,
    )?;

    // prepare the Decider prover & verifier params
    // - can serialize this when the circuit is stable
    println!("nova decider preprocess");
    let (decider_pp, decider_vp) = load_or_generate(
        &data_path.join("nova_decider_params.dat"),
        || {
            timeit!("nova decider preprocess", {
                D::preprocess(&mut rng, (nova_params, f_circuit.state_len()))
            })
        },
        |val, writer| Ok(val.serialize_uncompressed(writer)?),
        |reader| {
            Ok(<(
                <D as Decider<G1, G2, FC, N>>::ProverParam,
                <D as Decider<G1, G2, FC, N>>::VerifierParam,
            )>::deserialize_with_mode(
                reader, Compress::No, Validate::No
            )?)
        },
        true,
    )?;

    println!("nova decider prove");
    let proof = timeit!("generate decider proof", {
        D::prove(&mut rng, decider_pp, nova.clone())?
    });
    let verified = timeit!("verify decider proof", {
        D::verify(
            decider_vp,
            nova.i,
            nova.z_0.clone(),
            nova.z_i.clone(),
            &nova.U_i.get_commitments(),
            &nova.u_i.get_commitments(),
            &proof,
        )?
    });
    assert!(verified);
    println!("decider proof verification: {verified}");

    Ok(())
}
