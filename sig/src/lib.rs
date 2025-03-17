#[expect(clippy::missing_errors_doc)]
pub mod bc;
#[expect(clippy::missing_errors_doc)]
pub mod bls;
#[expect(clippy::missing_errors_doc)]
pub mod hash;

mod ark_r1cs_std_test;

#[cfg(test)]
mod tests {
    use ark_r1cs_std::{alloc::AllocVar, uint8::UInt8};
    use ark_relations::r1cs::ConstraintSystem;
    use bls::{
        BLSAggregateSignatureVerifyGadget, BaseSNARKField, ParametersVar, PublicKeyVar,
        SignatureVar,
    };
    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, Layer};

    use crate::bls::get_bls_instance;

    use super::*;

    /// Trace number of constraints used by each component.
    /// Used in evalaution.
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
        let (msg, params, _, pk, sig) = get_bls_instance();

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
