use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::AllocVar,
    eq::EqGadget,
    fields::{emulated_fp::EmulatedFpVar, fp::FpVar},
    prelude::Boolean,
    uint64::UInt64,
    uint8::UInt8,
};
use ark_relations::r1cs::{ConstraintSystemRef, OptimizationGoal, SynthesisError};
use derivative::Derivative;
use folding_schemes::{frontend::FCircuit, Error};
use sig::{
    bc::{
        block::{Block, QuorumSignature},
        params::HASH_OUTPUT_SIZE,
    },
    bls::Parameters as BlsParameters,
    bls::SignatureVar,
    folding::{bc::CommitteeVar, from_constraint_field::FromConstraintFieldGadget},
    params::BlsSigConfig,
};
use std::ops::Mul;
use tikv_jemalloc_ctl::{epoch, stats::resident};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, Layer};
use tracing_tree::HierarchicalLayer;

#[allow(dead_code)]
pub fn register_tracing() {
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
}

#[macro_export]
macro_rules! timeit {
    ($label:expr, $block:block) => {{
        use std::time::Instant;
        let start = Instant::now();
        let result = $block;
        let duration = start.elapsed();
        println!("{}: {:?}", $label, duration);
        result
    }};
}

#[allow(dead_code)]
pub struct Timer(Instant);

impl Timer {
    #[allow(dead_code)]
    pub fn start() -> Timer {
        Timer(Instant::now())
    }

    #[allow(dead_code)]
    pub fn end(self) -> f64 {
        self.0.elapsed().as_secs_f64()
    }
}

#[allow(dead_code)]
pub struct MemRecorder {
    stop_flag: Arc<AtomicBool>,
    handle: Option<JoinHandle<usize>>,
}

impl MemRecorder {
    #[allow(dead_code)]
    pub fn start() -> MemRecorder {
        let stop_flag = Arc::new(AtomicBool::new(false));
        let flag_clone = Arc::clone(&stop_flag);

        let e = epoch::mib().unwrap();
        let resident_mib = resident::mib().unwrap();

        let handle = thread::spawn(move || {
            let mut peak = 0;
            while !flag_clone.load(Ordering::Relaxed) {
                e.advance().ok(); // Refresh stats
                if let Ok(mem) = resident_mib.read() {
                    peak = peak.max(mem);
                }
                thread::sleep(Duration::from_millis(5));
            }
            peak
        });

        MemRecorder {
            stop_flag,
            handle: Some(handle),
        }
    }

    #[allow(dead_code)]
    pub fn end(mut self) -> usize {
        self.stop_flag.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            match handle.join() {
                Ok(peak) => peak,
                Err(_) => 0, // In case the thread panicked
            }
        } else {
            0
        }
    }
}

#[derive(Clone, Debug)]
struct DummyQuorumSignatureVar;

#[derive(Clone, Debug)]
pub struct DummyBlockVar;

impl<CF: PrimeField> AllocVar<QuorumSignature, CF> for DummyQuorumSignatureVar {
    fn new_variable<T: std::borrow::Borrow<QuorumSignature>>(
        cs: impl Into<ark_relations::r1cs::Namespace<CF>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: ark_r1cs_std::prelude::AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into();

        let quorum_signature = f();

        let _ =
            SignatureVar::<BlsSigConfig, EmulatedFpVar<_, _>, _>::new_variable_omit_on_curve_check(
                cs.clone(),
                || {
                    quorum_signature
                        .as_ref()
                        .map(|qsig| qsig.borrow().sig)
                        .map_err(SynthesisError::clone)
                },
                mode,
            )?;

        let _ = Vec::<Boolean<CF>>::new_variable(
            cs,
            || {
                quorum_signature
                    .as_ref()
                    .map(|qsig| qsig.borrow().signers)
                    .map_err(SynthesisError::clone)
            },
            mode,
        )?;

        Ok(Self)
    }
}

impl<CF: PrimeField> AllocVar<Block, CF> for DummyBlockVar {
    fn new_variable<T: std::borrow::Borrow<Block>>(
        cs: impl Into<ark_relations::r1cs::Namespace<CF>>,
        f: impl FnOnce() -> Result<T, ark_relations::r1cs::SynthesisError>,
        mode: ark_r1cs_std::prelude::AllocationMode,
    ) -> Result<Self, ark_relations::r1cs::SynthesisError> {
        let cs = cs.into();

        let block = f();

        let _ = UInt64::new_variable(
            cs.clone(),
            || {
                block
                    .as_ref()
                    .map(|block| block.borrow().epoch)
                    .map_err(SynthesisError::clone)
            },
            mode,
        )?;

        let _ =
            <[UInt8<CF>; HASH_OUTPUT_SIZE] as AllocVar<[u8; HASH_OUTPUT_SIZE], CF>>::new_variable(
                cs.clone(),
                || {
                    block
                        .as_ref()
                        .map(|block| block.borrow().prev_digest)
                        .map_err(SynthesisError::clone)
                },
                mode,
            )?;

        let _ = DummyQuorumSignatureVar::new_variable(
            cs.clone(),
            || {
                block
                    .as_ref()
                    .map(|block| block.borrow().sig.clone())
                    .map_err(SynthesisError::clone)
            },
            mode,
        )?;

        let _ = CommitteeVar::new_variable(
            cs,
            || {
                block
                    .as_ref()
                    .map(|block| {
                        let block = block.borrow();
                        block.committee.clone()
                    })
                    .map_err(SynthesisError::clone)
            },
            mode,
        )?;

        Ok(Self)
    }
}

#[derive(Clone, Derivative)]
#[derivative(Debug)]
pub struct MockBCCircuit<CF: ark_ff::PrimeField> {
    params: BlsParameters<BlsSigConfig>,
    target_constraints: usize,
    _cf: std::marker::PhantomData<CF>,
}

impl<CF: ark_ff::PrimeField> MockBCCircuit<CF> {
    #[allow(dead_code)]
    pub fn new(
        params: BlsParameters<BlsSigConfig>,
        target_constraints: usize,
    ) -> Result<Self, Error> {
        Ok(Self {
            params,
            target_constraints,
            _cf: std::marker::PhantomData,
        })
    }
}

impl<CF: ark_ff::PrimeField> FCircuit<CF> for MockBCCircuit<CF> {
    type Params = BlsParameters<BlsSigConfig>;
    type ExternalInputs = Block;
    type ExternalInputsVar = DummyBlockVar;

    fn new(params: Self::Params) -> Result<Self, Error> {
        Ok(Self {
            params,
            target_constraints: 0, // default, overridden in experiments
            _cf: std::marker::PhantomData,
        })
    }

    fn state_len(&self) -> usize {
        // Same state length as BCCircuitNoMerkle
        CommitteeVar::<CF>::num_constraint_var_needed(OptimizationGoal::Constraints)
            + UInt64::<CF>::num_constraint_var_needed(OptimizationGoal::Constraints)
    }

    fn generate_step_constraints(
        &self,
        cs: ConstraintSystemRef<CF>,
        _: usize,
        z: Vec<FpVar<CF>>,
        _: Self::ExternalInputsVar,
    ) -> Result<Vec<FpVar<CF>>, SynthesisError> {
        // Generate dummy constraints to reach target_constraints
        let current_constraints = cs.num_constraints();
        let constraints_to_add = self.target_constraints.saturating_sub(current_constraints);

        // Add arithmetic constraints: e.g., x * y = z
        for j in 0..constraints_to_add {
            let x = FpVar::new_witness(cs.clone(), || Ok(CF::from((j + 1) as u64)))?;
            let y = FpVar::new_witness(cs.clone(), || Ok(CF::from((j + 2) as u64)))?;
            let z =
                FpVar::new_witness(cs.clone(), || Ok(CF::from((j + 1) as u64 * (j + 2) as u64)))?;
            x.mul(&y).enforce_equal(&z)?;
        }

        // Return new state (same as BCCircuit)
        Ok(z)
    }
}
