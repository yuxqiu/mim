use ark_groth16::Groth16;
use ark_snark::{CircuitSpecificSetupSNARK, SNARK};
use rand::thread_rng;
use sig::bls::{get_bls_instance, BLSCircuit, SNARKCurve};

#[macro_export]
macro_rules! timeit {
    ($label:expr, $block:block) => {{
        use std::time::Instant;
        let start = Instant::now();
        let result = $block;
        let duration = start.elapsed();
        println!("Time elapsed in {}: {:?}", $label, duration);
        result
    }};
}

fn bench_groth16() {
    let (msg, params, _, pk_bls, sig) = get_bls_instance();
    let mut rng = thread_rng();

    // ===============Setup pk and vk===============
    let mut pk_vk_gen = || {
        // in setup node, we don't need to provide assignment
        let msg = vec![None; msg.len()];
        let circuit = BLSCircuit::new(None, None, &msg, None);
        Groth16::<SNARKCurve>::setup(circuit.clone(), &mut rng).unwrap()
    };

    {
        timeit!("pk and vk generation", {
            pk_vk_gen();
        });
    }

    let (pk, vk) = pk_vk_gen();

    let pvk_gen = || Groth16::<SNARKCurve>::process_vk(&vk).unwrap();

    {
        timeit!("pvk generation", {
            pvk_gen();
        });
    }

    let pvk = Groth16::<SNARKCurve>::process_vk(&vk).unwrap();

    // ===============Setup circuit===============
    let msg = msg
        .as_bytes()
        .iter()
        .copied()
        .map(Option::Some)
        .collect::<Vec<_>>();

    let circuit = BLSCircuit::new(Some(params), Some(pk_bls), &msg, Some(sig));

    // ===============Get public inputs===============
    let public_inputs = circuit.get_public_inputs().unwrap();

    // ===============Create a proof===============
    let proof_gen =
        || Groth16::<SNARKCurve>::create_proof_with_reduction_no_zk(circuit.clone(), &pk).unwrap();

    {
        timeit!("proof generation", {
            proof_gen();
        });
    }

    let proof = proof_gen();

    // ===============Verify the proof===============
    let verification =
        || Groth16::<SNARKCurve>::verify_with_processed_vk(&pvk, &public_inputs, &proof).unwrap();

    {
        timeit!("verification", {
            verification();
        });
    }

    let verified = verification();
    assert!(verified);
    println!("Proof verified successfully!");
}

fn main() {
    bench_groth16();
}
