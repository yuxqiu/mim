#[expect(clippy::missing_errors_doc)]
pub mod bc;
#[expect(clippy::missing_errors_doc)]
pub mod bls;
#[expect(clippy::missing_errors_doc)]
pub mod hash;

#[cfg(test)]
mod tests {
    use ark_bls12_381::Fq;
    use ark_ec::bls12::{Bls12, Bls12Config};
    use ark_ff::{
        BigInt, BitIteratorBE, CubicExtField, Fp2ConfigWrapper, Fp6ConfigWrapper, QuadExtField,
    };
    use ark_r1cs_std::fields::fp2::Fp2Var;
    use ark_r1cs_std::fields::fp6_3over2::Fp6Var;
    use ark_r1cs_std::fields::quadratic_extension::QuadExtVar;
    use ark_r1cs_std::fields::FieldVar;
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
    fn emulation_bug_example() {
        let cs = ConstraintSystem::new_ref();
        let (_, params, _, pk, sig) = get_instance();

        let params_var = ParametersVar::new_input(cs.clone(), || Ok(params)).unwrap();
        let pk_var = PublicKeyVar::new_constant(cs.clone(), pk).unwrap();
        let sig_var = SignatureVar::new_constant(cs.clone(), sig).unwrap();

        // Debug Story: Aggregate Sig -> product_of_pairing -> miller loop ->
        /*
             // for convenience, just read 0
            if let Some(p) = ps.get(0) {
                let cs = p.0.x.cs();
                tracing::info!(num_constraints = cs.num_constraints());
            }

            let mut pairs = vec![];
            for (p, q) in ps.iter().zip(qs.iter()) {
                pairs.push((p, q.ell_coeffs.iter()));
            }
            let mut f = Self::GTVar::one();

            for i in BitIteratorBE::new(P::X).skip(1) {
                f.square_in_place()?;

                for &mut (p, ref mut coeffs) in pairs.iter_mut() {
                    Self::ell(&mut f, coeffs.next().unwrap(), &p.0)?;
                }

                if i {
                    for &mut (p, ref mut coeffs) in pairs.iter_mut() {
                        Self::ell(&mut f, &coeffs.next().unwrap(), &p.0)?;
                    }
                }
            }
        */
        // -> ell -> partial ell

        // /*
        let ps = [
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
        ];
        let qs: [G2PreparedVar<BLSSigCurveConfig, _, _>; 2] = [
            G2PreparedVar::from_group_var(&sig_var.signature).unwrap(),
            G2PreparedVar::from_group_var(&params_var.g2_generator).unwrap(),
        ];

        let mut pairs = vec![];
        for (p, q) in ps.iter().zip(qs.iter()) {
            pairs.push((p, q.ell_coeffs.iter()));
        }

        type MyPairingVar = bls12::PairingVar<
            BLSSigCurveConfig,
            fp_var!(BaseSigCurveField, BaseSNARKField),
            BaseSNARKField,
        >;
        let mut f =
            <MyPairingVar as PairingVar<Bls12<BLSSigCurveConfig>, BaseSNARKField>>::GTVar::one();

        for (idx, i) in BitIteratorBE::new(<BLSSigCurveConfig as Bls12Config>::X)
            .skip(1)
            .enumerate()
        {
            println!("at {}", idx);

            f.square_in_place().unwrap();
            println!(
                "cs.satisfied = {} at {}",
                cs.is_satisfied().unwrap(),
                line!()
            );

            for &mut (p, ref mut coeffs) in pairs.iter_mut() {
                MyPairingVar::ell(&mut f, coeffs.next().unwrap(), &p.0).unwrap();
            }
            println!(
                "cs.satisfied = {} at {}",
                cs.is_satisfied().unwrap(),
                line!()
            );

            if i {
                for &mut (p, ref mut coeffs) in pairs.iter_mut() {
                    MyPairingVar::ell(&mut f, coeffs.next().unwrap(), &p.0).unwrap();
                }
            }
            println!(
                "cs.satisfied = {} at {}",
                cs.is_satisfied().unwrap(),
                line!()
            );

            let unsat = cs.which_is_unsatisfied().unwrap();
            if let Some(s) = unsat {
                println!("{}", s);
                assert!(false);
            }
            println!();
        }
        // */
        // -> Fp12Var::mul_by_014 -> directly copying values pass the assertion

        /* Debug Story Part 2
        - After finding the input that triggers the error with the above code, I tried to directly construct error-triggering
        input and then run the code that triggers the error. But this time, test passes. This possibly suggests that the bug is
        only going to happen after doing some computations on the Emulated FpVar.

        // let s: CubicExtField<Fp6ConfigWrapper<<BLSSigCurveConfig as Bls12Config>::Fp6Config>> = CubicExtField { c0: QuadExtField { c0: BaseSigCurveField::new(BigInt!("1396647618126876491551238897028281182182662946814742239452658799494849612884112015940766337389283670758378407669858")), c1: BaseSigCurveField::new(BigInt!("489300199753474263487139255028045766852234638962321376174587026474133093607716596781998693009932963140607730310874")) }, c1: QuadExtField { c0: BaseSigCurveField::new(BigInt!("2076779849093790960004645082128074049749284347384508349411906451297833786449525588244671694689239114308470534722")), c1: BaseSigCurveField::new(BigInt!("3429111531654932568292424302827161866150960261911970054523238888922579513273636064340952974092751506611613309106989")) }, c2: QuadExtField { c0: BaseSigCurveField::new(BigInt!("3105552301778060130939400582219924301640386073897117038804000010537014450986416157402674422832457578419365373540100")), c1: BaseSigCurveField::new(BigInt!("3876225650084791655496417842379490798548983675921971746960092311091188678494876118677610567726216270877190335329985")) } };
        // let c0 = QuadExtField { c0: BaseSigCurveField::new(BigInt!("3793885288740742725797458173051012191755498788871183885026428963711034866571316645935841285200271690995591479553459")), c1: BaseSigCurveField::new(BigInt!("2996901763584276916617790377778099338968936475300200779862307371169240467862390136884092754318251205909929343510514")) };
        // let c1: QuadExtField<Fp2ConfigWrapper<<BLSSigCurveConfig as Bls12Config>::Fp2Config>> = QuadExtField { c0: BaseSigCurveField::new(BigInt!("1390118126216571966813929905681038212433944121124097261166221724113580654669884433532201829614388003564787124846154")), c1: BaseSigCurveField::new(BigInt!("3841297017270657899921787036732710213975700732339081708515654031471901412628370576261289604985108475530657932751769")) };

        // let sv = Fp6Var::new_input(cs.clone(), || Ok(s)).unwrap();
        // let c0v = Fp2Var::new_input(cs.clone(), || Ok(c0)).unwrap();
        // let c1v: QuadExtVar<
        //     fp_var!(BaseSigCurveField, BaseSNARKField),
        //     Fp2ConfigWrapper<ark_bls12_381::Fq2Config>,
        //     BaseSNARKField,
        // > = Fp2Var::new_input(cs.clone(), || Ok(c1)).unwrap();
        // let _ = sv.mul_by_c0_c1_0(&c0v, &c1v).unwrap();
        //
        
        As the above doesn't work, I decided to go deeper to find the exact line of code that triggers the error.
        It goes a few more levels deeper and find this:

        // -> Fp6_3over2::mul_by_c0_c1_0 -> Fp6_3over2 (`let c1 = a0_plus_a1 * b0_plus_b1;`) -> QuadExtVar::Mul
        */

        /* Debug Story Part 3
        After finding the above trigger, I am a little bit lost in the debug process, as it's hard to instrument Mul
        to find the line that triggers the error. So, I decided to
        - Find the index of the unsat constraint
        - Hook enforce_constraint function to capture and print a backtrace
        - Examine the function where the constraint is enforced and print out some critical values.

        The problem turns out to be at `ucl-fyp-poc/third_party/r1cs-std/src/fields/emulated_fp/reduce.rs:317:13`
        where `eqn_left != eqn_right`. Here are their values:

        // 23252872595569798916603490018121983261169516409351989185471321936430228531624039882909318699407103270056525561855
        // 23252872595439065348059082123193723220894689263884242676051508218077876654384480135773347350432660641585800675328
        eqn_left.conditional_enforce_equal(&eqn_right, &Boolean::<BaseF>::TRUE)?;
        
        Sidenote: I used this strategy and examined this function before, and I believed it is implemented correctly.
        But, I will take a closer look later.
        - The benefit of Debug Story 1 and 2 is they speed up the process of triggering the bug (no need to wait for 10+ mins). 
        */

        // then, we ensure during the computation, there are no unsatisfiable constraints generated
        println!("{}", cs.num_constraints());
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
