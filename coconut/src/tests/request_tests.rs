// Copyright (c) Facebook, Inc. and its affiliates.
// SPDX-License-Identifier: Apache-2.0

use crate::fixtures::{input_attributes, keypair, offset, parameters, request};

#[test]
fn verify_request() {
    let input_keys = vec![input_attributes()[0].key, input_attributes()[1].key];
    assert!(request()
        .verify(&parameters(), &keypair().public, &input_keys, &offset())
        .is_ok());
}

// Run with:
// cargo test --release --features micro_bench bench_ -p coconut -- --nocapture --test-threads=1
#[cfg(feature = "micro_bench")]
#[test]
fn bench_request() {
    use crate::fixtures::{coin1, coin2, output_attributes};
    use rand::SeedableRng;
    use statistical::{standard_deviation, mean};
    use std::time::Instant;
    use super::*;

    const RUNS: usize = 100;
    const PRECISION: usize = 10;

    let parameters = parameters();
    let input_attributes = input_attributes();
    let output_attributes = output_attributes();
    let public_key = keypair().public;
    let sigmas = vec![coin1(), coin2()];

    let mut data = Vec::new();
    println!("Benchmarking 'request'...");
    for _ in 0..RUNS {
        let now = Instant::now();
        for _ in 0..PRECISION {
            let _result = CoinsRequest::new(
                rand::rngs::StdRng::seed_from_u64(37),
                &parameters,
                &public_key,
                &sigmas,
                &input_attributes,
                &output_attributes,
            );
        }
        let elapsed = now.elapsed().as_millis() as f64;
        data.push(elapsed / PRECISION as f64); 
    }  
    println!("Result: {:.2} +/- {:.2} ms", mean(&data), standard_deviation(&data, None));
}

// Run with:
// cargo test --release --features micro_bench bench_ -p coconut -- --nocapture --test-threads=1
#[cfg(feature = "micro_bench")]
#[test]
fn bench_verify_request() {
    use statistical::{standard_deviation, mean};
    use std::time::Instant;

    const RUNS: usize = 100;
    const PRECISION: usize = 10;

    let request = request();
    let parameters = parameters();
    let public_key = keypair().public;
    let input_keys = vec![input_attributes()[0].key, input_attributes()[1].key];
    let offset = offset();

    let mut data = Vec::new();
    println!("benchmarking 'verify request'...");
    for _ in 0..RUNS {
        let now = Instant::now();
        for _ in 0..PRECISION {
            let _result = request.verify(&parameters, &public_key, &input_keys, &offset);
        }
        let elapsed = now.elapsed().as_millis() as f64;
        data.push(elapsed / PRECISION as f64); 
    }  
    println!("Result: {:.2} +/- {:.2} ms", mean(&data), standard_deviation(&data, None));
}