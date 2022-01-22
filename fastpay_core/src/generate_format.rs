// Copyright (c) Facebook, Inc. and its affiliates.
// SPDX-License-Identifier: Apache-2.0

use bls12_381::{G1Projective as G1, G2Projective as G2, Scalar};
use fastpay_core::{error, messages, serialize};
use serde_reflection::{Registry, Result, Samples, Tracer, TracerConfig};
use std::{fs::File, io::Write};
use structopt::{clap::arg_enum, StructOpt};

fn make_range_proof() -> bulletproofs::RangeProof {
    use bulletproofs::*;
    use coconut::rand::{self, Rng as _};
    use ff::Field as _;
    use merlin::Transcript;

    let m = 1;
    let n = 32;
    let max_bitsize = 64;
    let max_parties = 8;
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(max_bitsize, max_parties);

    let mut rng = rand::thread_rng();

    let (min, max) = (0u64, ((1u128 << n) - 1) as u64);
    let values: Vec<u64> = (0..m).map(|_| rng.gen_range(min..max)).collect();
    let blindings: Vec<Scalar> = (0..m).map(|_| Scalar::random(&mut rng)).collect();

    let mut transcript = Transcript::new(b"AggregatedRangeProofTest");
    let (proof, _) =
        RangeProof::prove_multiple(&bp_gens, &pc_gens, &mut transcript, &values, &blindings, n)
            .unwrap();
    proof
}

fn get_registry() -> Result<Registry> {
    let mut tracer = Tracer::new(
        TracerConfig::default()
            .record_samples_for_newtype_structs(true)
            .record_samples_for_tuple_structs(true),
    );
    let mut samples = Samples::new();
    // 1. Record samples for types with custom deserializers.
    tracer.trace_value(&mut samples, &G1::generator())?;
    tracer.trace_value(&mut samples, &G2::generator())?;
    tracer.trace_value(&mut samples, &Scalar::zero())?;
    tracer.trace_value(&mut samples, &make_range_proof())?;
    // 2. Trace the main entry point(s) + every enum separately.
    tracer.trace_type::<messages::Address>(&samples)?;
    tracer.trace_type::<messages::Operation>(&samples)?;
    tracer.trace_type::<messages::Value>(&samples)?;
    tracer.trace_type::<messages::Asset>(&samples)?;
    tracer.trace_type::<messages::ConsensusDecision>(&samples)?;
    tracer.trace_type::<messages::ConsensusOrder>(&samples)?;
    tracer.trace_type::<messages::CrossShardRequest>(&samples)?;
    tracer.trace_type::<error::FastPayError>(&samples)?;
    tracer.trace_type::<serialize::SerializedMessage>(&samples)?;
    tracer.registry()
}

arg_enum! {
#[derive(Debug, StructOpt, Clone, Copy)]
enum Action {
    Print,
    Test,
    Record,
}
}

#[derive(Debug, StructOpt)]
#[structopt(
    name = "FastPay format generator",
    about = "Trace serde (de)serialization to generate format descriptions for FastPay types"
)]
struct Options {
    #[structopt(possible_values = &Action::variants(), default_value = "Print", case_insensitive = true)]
    action: Action,
}

const FILE_PATH: &str = "fastpay_core/tests/staged/fastpay.yaml";

fn main() {
    let options = Options::from_args();
    let registry = get_registry().unwrap();
    match options.action {
        Action::Print => {
            let content = serde_yaml::to_string(&registry).unwrap();
            println!("{}", content);
        }
        Action::Record => {
            let content = serde_yaml::to_string(&registry).unwrap();
            let mut f = File::create(FILE_PATH).unwrap();
            writeln!(f, "{}", content).unwrap();
        }
        Action::Test => {
            let reference = std::fs::read_to_string(FILE_PATH).unwrap();
            let content = serde_yaml::to_string(&registry).unwrap() + "\n";
            similar_asserts::assert_str_eq!(&reference, &content);
        }
    }
}
