#[expect(clippy::missing_errors_doc)]
pub mod bls;
#[expect(clippy::missing_errors_doc)]
pub mod hash;

#[cfg(test)]
mod tests {
    use ark_ff::{BigInt, Fp, PrimeField};
    use ark_groth16::{prepare_verifying_key, Groth16};
    use ark_r1cs_std::{
        alloc::AllocVar,
        eq::EqGadget,
        fields::{
            emulated_fp::{AllocatedEmulatedFpVar, EmulatedFpVar},
            fp::FpVar,
        },
        prelude::Boolean,
        uint8::UInt8,
        R1CSVar,
    };
    use ark_relations::r1cs::ConstraintSystem;
    use ark_snark::SNARK;
    use bls::{
        BLSAggregateSignatureVerifyGadget, BLSCircuit, BaseSNARKField, Parameters, ParametersVar,
        PublicKey, PublicKeyVar, SecretKey, Signature, SignatureVar, BaseSigCurveField,
    };
    use rand::{thread_rng, Rng};
    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, Layer};

    type Curve = ark_bw6_761::BW6_761;

    use super::*;

    fn get_instance() -> (&'static str, Parameters, SecretKey, PublicKey, Signature) {
        let msg = "Hello World";
        let mut rng = thread_rng();

        let params = Parameters::setup();
        let sk = SecretKey::new(&mut rng);
        let pk = PublicKey::new(&sk, &params);

        let sig = Signature::sign(msg.as_bytes(), &sk, &params);

        (msg, params, sk, pk, sig)
    }

    fn get_aggregate_instances() -> (
        &'static str,
        Parameters,
        Vec<SecretKey>,
        Vec<PublicKey>,
        Signature,
    ) {
        const N: usize = 1000;

        let msg = "Hello World";
        let mut rng = thread_rng();

        let params = Parameters::setup();
        let secret_keys: Vec<SecretKey> = (0..N).map(|_| SecretKey::new(&mut rng)).collect();
        let public_keys: Vec<PublicKey> = secret_keys
            .iter()
            .map(|sk| PublicKey::new(sk, &params))
            .collect();

        let sig = Signature::aggregate_sign(msg.as_bytes(), &secret_keys, &params).unwrap();

        (msg, params, secret_keys, public_keys, sig)
    }

    #[test]
    fn check_signature() {
        let (msg, params, _, pk, sig) = get_instance();
        assert!(Signature::verify_slow(msg.as_bytes(), &sig, &pk, &params));
        assert!(Signature::verify(msg.as_bytes(), &sig, &pk, &params));
    }

    #[test]
    fn check_verify_failure() {
        let (msg, params, _, pk, sig) = get_instance();
        assert!(!Signature::verify_slow(
            &[msg.as_bytes(), &[1]].concat(),
            &sig,
            &pk,
            &params
        ));
        assert!(!Signature::verify(
            &[msg.as_bytes(), &[1]].concat(),
            &sig,
            &pk,
            &params
        ));
    }

    #[test]
    fn check_aggregate_signature() {
        let (msg, params, _, public_keys, sig) = get_aggregate_instances();
        assert!(Signature::aggregate_verify(msg.as_bytes(), &sig, &public_keys, &params).unwrap());
    }

    #[test]
    fn check_r1cs() {
        let cs = ConstraintSystem::new_ref();
        let (msg, params, _, pk, sig) = get_instance();

        let msg_var: Vec<UInt8<BaseSNARKField>> = msg
            .as_bytes()
            .iter()
            .map(|b| UInt8::new_input(cs.clone(), || Ok(b)).unwrap())
            .collect();
        let params_var = ParametersVar::new_input(cs.clone(), || Ok(params)).unwrap();
        let pk_var = PublicKeyVar::new_input(cs.clone(), || Ok(pk)).unwrap();
        let sig_var = SignatureVar::new_input(cs.clone(), || Ok(sig)).unwrap();

        BLSAggregateSignatureVerifyGadget::verify(&params_var, &pk_var, &msg_var, &sig_var)
            .unwrap();

        println!("Number of constraints: {}", cs.num_constraints());
        assert!(cs.is_satisfied().unwrap());

        println!("RC1S is satisfied!");
    }

    #[test_fuzz::test_fuzz]
    fn check_emulated_helper(a: [u64; 6], b: [u64; 6]) {
        let cs = ConstraintSystem::new_ref();

        let av: FpVar<BaseSigCurveField> =
            FpVar::new_constant(cs.clone(), Fp::new(BigInt::new(a))).unwrap();
        let bv = FpVar::new_constant(cs, Fp::new(BigInt::new(b))).unwrap();
        let cv = av * bv;
        let c = cv.value().unwrap().into_bigint();

        let cs = ConstraintSystem::new_ref();
        let a = BigInt::new(a);
        let b = BigInt::new(b);

        let v1: EmulatedFpVar<BaseSigCurveField, BaseSNARKField> = EmulatedFpVar::Var(
            AllocatedEmulatedFpVar::new_input(cs.clone(), || Ok(Fp::new(a))).unwrap(),
        );
        let v2: EmulatedFpVar<BaseSigCurveField, BaseSNARKField> = EmulatedFpVar::Var(
            AllocatedEmulatedFpVar::new_input(cs.clone(), || Ok(Fp::new(b))).unwrap(),
        );
        let v3: EmulatedFpVar<BaseSigCurveField, BaseSNARKField> = EmulatedFpVar::Var(
            AllocatedEmulatedFpVar::new_input(cs.clone(), || Ok(Fp::new(c))).unwrap(),
        );

        let v1v2 = v1 * v2;
        let v1v2v = v1v2.value().unwrap().into_bigint();
        (v1v2)
            .is_eq(&v3)
            .unwrap()
            .enforce_equal(&Boolean::TRUE)
            .unwrap();

        assert!(
            cs.is_satisfied().unwrap(),
            "{:?} x {:?} = {:?} (got {})",
            a,
            b,
            c,
            v1v2v
        );
    }

    #[test]
    fn check_emulated() {
        let mut rng = thread_rng();
        let mut a: [u64; 6] = [0; 6];
        let mut b: [u64; 6] = [0; 6];
        rng.fill(&mut a[..]);
        rng.fill(&mut b[..]);
        check_emulated_helper(a, b);
    }

    #[test]
    fn check_snark() {
        let (msg, params, _, pk, sig) = get_instance();
        let mut rng = thread_rng();

        let circuit = BLSCircuit::new(params, pk, msg.as_bytes(), sig);

        // Setup pk
        let pk =
            Groth16::<Curve>::generate_random_parameters_with_reduction(circuit.clone(), &mut rng)
                .unwrap();

        // Create a proof
        let proof = Groth16::<Curve>::prove(&pk, circuit.clone(), &mut rng).unwrap();

        // Verify the proof
        let pvk = prepare_verifying_key(&pk.vk);
        let verified =
            Groth16::<Curve>::verify_proof(&pvk, &proof, &circuit.get_public_inputs().unwrap())
                .unwrap();
        assert!(verified);

        println!("Proof verified successfully!");
    }

    #[test]
    fn tracing_num_constraints() {
        let file_appender = tracing_appender::rolling::hourly("./", "constraints.log");
        let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

        tracing_subscriber::registry()
            .with(
                tracing_subscriber::fmt::layer()
                    // treat span enter/exit as an event
                    .with_span_events(
                        tracing_subscriber::fmt::format::FmtSpan::EXIT
                            | tracing_subscriber::fmt::format::FmtSpan::ENTER,
                    )
                    // write to a log file
                    .with_ansi(false)
                    .with_writer(non_blocking)
                    // log functions inside our crate + pairing
                    .with_filter(tracing_subscriber::filter::FilterFn::new(|metadata| {
                        // 1. target filtering
                        metadata.target().contains("sig")
                            // 2. name filtering
                            || ["miller_loop", "final_exponentiation"]
                                .into_iter()
                                .any(|s| metadata.name().contains(s))
                            // 3. event filtering
                            // - event from spans that do not match either of the above two rules will not be considered
                            || metadata.is_event()
                    })),
            )
            .init();

        let cs = ConstraintSystem::new_ref();
        let (msg, params, _, pk, sig) = get_instance();

        let msg_var: Vec<UInt8<BaseSNARKField>> = msg
            .as_bytes()
            .iter()
            .map(|b| UInt8::new_input(cs.clone(), || Ok(b)).unwrap())
            .collect();
        let params_var = ParametersVar::new_input(cs.clone(), || Ok(params)).unwrap();
        let pk_var = PublicKeyVar::new_input(cs.clone(), || Ok(pk)).unwrap();
        let sig_var = SignatureVar::new_input(cs.clone(), || Ok(sig)).unwrap();

        BLSAggregateSignatureVerifyGadget::verify(&params_var, &pk_var, &msg_var, &sig_var)
            .unwrap();

        let num_constraints = cs.num_constraints();
        tracing::info!("Number of constraints: {}", num_constraints);
        assert!(cs.is_satisfied().unwrap());

        tracing::info!("R1CS is satisfied!");
    }
}
