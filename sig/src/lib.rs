#[expect(clippy::missing_errors_doc)]
pub mod bc;
#[expect(clippy::missing_errors_doc)]
pub mod bls;
#[expect(clippy::missing_errors_doc)]
pub mod hash;

#[cfg(test)]
mod tests {
    use ark_r1cs_std::{
        alloc::AllocVar,
        groups::{
            bls12::{G1PreparedVar, G2PreparedVar},
            CurveVar,
        },
        pairing::bls12,
        prelude::PairingVar,
        uint8::UInt8,
    };
    use ark_relations::r1cs::ConstraintSystem;
    use bls::{
        BLSAggregateSignatureVerifyGadget, BaseSNARKField, BaseSigCurveField, Parameters,
        ParametersVar, PublicKey, PublicKeyVar, SecretKey, Signature, SignatureVar,
    };
    use rand::thread_rng;
    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, Layer};

    use crate::bls::BLSSigCurveConfig;

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

    #[test]
    fn check_emulated_helper() {
        let cs = ConstraintSystem::new_ref();
        let (_, params, _, pk, sig) = get_instance();

        let params_var = ParametersVar::new_constant(cs.clone(), params).unwrap();
        let pk_var = PublicKeyVar::new_constant(cs.clone(), pk).unwrap();
        let sig_var = SignatureVar::new_constant(cs.clone(), sig).unwrap();

        // we don't check any equality here, so it's ok to use `params_var.g2_generator` as placeholder
        let _ = bls12::PairingVar::product_of_pairings(
            &[
                G1PreparedVar::<
                    BLSSigCurveConfig,
                    fp_var!(BaseSigCurveField, BaseSNARKField),
                    BaseSNARKField,
                >::from_group_var(&params_var.g1_generator.negate().unwrap())
                .unwrap(),
                G1PreparedVar::<
                    BLSSigCurveConfig,
                    fp_var!(BaseSigCurveField, BaseSNARKField),
                    BaseSNARKField,
                >::from_group_var(&pk_var.pub_key)
                .unwrap(),
            ],
            &[
                G2PreparedVar::from_group_var(&sig_var.signature).unwrap(),
                G2PreparedVar::from_group_var(&params_var.g2_generator).unwrap(),
            ],
        );

        // then, we ensure during the computation, there are no unsatisfiable constraints generated
        assert!(cs.is_satisfied().unwrap());
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
