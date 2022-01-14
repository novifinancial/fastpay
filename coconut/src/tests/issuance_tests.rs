// Copyright (c) Facebook, Inc. and its affiliates.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::fixtures::{
    aggregated_key, coin1, input_attribute1, keypair, keypairs, output_attributes, parameters,
    request,
};

#[test]
fn verify_coin() {
    let mut coin = coin1();
    coin.randomize(&mut rand::thread_rng());

    let ok = coin.plain_verify(
        &parameters(),
        &keypair().public,
        /* value */ input_attribute1().value,
        /* seed */ input_attribute1().seed,
        /* key */ input_attribute1().key,
    );
    assert!(ok);
}

#[test]
fn issue() {
    let blinded_coins = BlindedCoins::new(
        &parameters(),
        &keypair().secret,
        &request().cms,
        &request().cs,
    );

    let coins = blinded_coins.unblind(&keypair().public, &output_attributes());
    assert_eq!(coins.len(), 2);

    let ok = coins[0].plain_verify(
        &parameters(),
        &keypair().public,
        /* value */ output_attributes()[0].value,
        /* seed */ output_attributes()[0].seed,
        /* key */ output_attributes()[0].key,
    );
    assert!(ok);

    let ok = coins[1].plain_verify(
        &parameters(),
        &keypair().public,
        /* value */ output_attributes()[1].value,
        /* seed */ output_attributes()[1].seed,
        /* key */ output_attributes()[1].key,
    );
    assert!(ok);
}

#[test]
fn aggregate_coin() {
    // Create enough coin shares.
    let shares: Vec<_> = keypairs()
        .iter()
        .skip(1)
        .map(|key| {
            let coin = Coin::default(
                &parameters(),
                &key.secret,
                /* value */ &input_attribute1().value,
                /* seed */ &input_attribute1().seed,
                /* key */ &input_attribute1().key,
            );
            (coin, key.index)
        })
        .collect();

    // Aggregate the coin.
    let coin = Coin::aggregate(&shares);

    // Ensure the coin is valid.
    let ok = coin.plain_verify(
        &parameters(),
        &aggregated_key(),
        /* value */ input_attribute1().value,
        /* seed */ input_attribute1().seed,
        /* key */ input_attribute1().key,
    );
    assert!(ok);
}

#[test]
fn aggregate_coin_fail() {
    // Create t-1 shares of coin.
    let shares: Vec<_> = keypairs()
        .iter()
        .skip(2)
        .map(|key| {
            let coin = Coin::default(
                &parameters(),
                &key.secret,
                /* value */ &input_attribute1().value,
                /* seed */ &input_attribute1().seed,
                /* key */ &input_attribute1().key,
            );
            (coin, key.index)
        })
        .collect();

    // Aggregate the coin.
    let coin = Coin::aggregate(&shares);

    // Ensure the coin is not valid.
    let ok = coin.plain_verify(
        &parameters(),
        &aggregated_key(),
        /* value */ input_attribute1().value,
        /* seed */ input_attribute1().seed,
        /* key */ input_attribute1().key,
    );
    assert!(!ok);
}

// Run with:
// cargo test --release --features micro_bench bench_ -p coconut -- --nocapture --test-threads=1
#[cfg(feature = "micro_bench")]
#[test]
fn bench_issue() {
    use statistical::{mean, standard_deviation};
    use std::time::Instant;

    const RUNS: usize = 100;
    const PRECISION: usize = 10;

    let request = request();
    let parameters = parameters();
    let secret_key = keypair().secret;

    let mut data = Vec::new();
    println!("benchmarking 'issue'...");
    for _ in 0..RUNS {
        let now = Instant::now();
        for _ in 0..PRECISION {
            let _result = BlindedCoins::new(&parameters, &secret_key, &request.cms, &request.cs);
        }
        let elapsed = now.elapsed().as_millis() as f64;
        data.push(elapsed / PRECISION as f64);
    }
    println!(
        "Result: {:.2} +/- {:.2} ms",
        mean(&data),
        standard_deviation(&data, None)
    );
}

// Run with:
// cargo test --release --features micro_bench bench_ -p coconut -- --nocapture --test-threads=1
#[cfg(feature = "micro_bench")]
#[test]
fn bench_aggregate() {
    use statistical::{mean, standard_deviation};
    use std::time::Instant;

    const RUNS: usize = 100;
    const PRECISION: usize = 10;

    let shares: Vec<_> = keypairs()
        .iter()
        .skip(1)
        .map(|key| {
            let coin = Coin::default(
                &parameters(),
                &key.secret,
                /* value */ &input_attribute1().value,
                /* seed */ &input_attribute1().seed,
                /* key */ &input_attribute1().key,
            );
            (coin, key.index)
        })
        .collect();

    let mut data = Vec::new();
    println!("benchmarking 'aggregate'...");
    for _ in 0..RUNS {
        let now = Instant::now();
        for _ in 0..PRECISION {
            let _result = Coin::aggregate(&shares);
        }
        let elapsed = now.elapsed().as_millis() as f64;
        data.push(elapsed / PRECISION as f64);
    }
    println!(
        "Result: {:.2} +/- {:.2} ms",
        mean(&data),
        standard_deviation(&data, None)
    );
}

// Run with:
// cargo test --release --features micro_bench bench_ -p coconut -- --nocapture --test-threads=1
#[cfg(feature = "micro_bench")]
#[test]
fn bench_plain_verify() {
    use statistical::{mean, standard_deviation};
    use std::time::Instant;

    const RUNS: usize = 100;
    const PRECISION: usize = 10;

    let coin = coin1();
    let parameters = parameters();
    let public_key = keypair().public;
    let coin_attributes = input_attribute1();

    let mut data = Vec::new();
    println!("benchmarking 'plain_verify'...");
    for _ in 0..RUNS {
        let now = Instant::now();
        for _ in 0..PRECISION {
            let _result = coin.plain_verify(
                &parameters,
                &public_key,
                coin_attributes.value,
                coin_attributes.seed,
                coin_attributes.key,
            );
        }
        let elapsed = now.elapsed().as_millis() as f64;
        data.push(elapsed / PRECISION as f64);
    }
    println!(
        "Result: {:.2} +/- {:.2} ms",
        mean(&data),
        standard_deviation(&data, None)
    );
}

// Run with:
// cargo test --release --features micro_bench bench_ -p coconut -- --nocapture --test-threads=1
#[cfg(feature = "micro_bench")]
#[test]
fn bench_unblind() {
    use statistical::{mean, standard_deviation};
    use std::time::Instant;

    const RUNS: usize = 100;
    const PRECISION: usize = 10;

    let public_key = keypair().public;
    let output_attributes = output_attributes();
    let blinded_coins = BlindedCoins::new(
        &parameters(),
        &keypair().secret,
        &request().cms,
        &request().cs,
    );

    let mut data = Vec::new();
    println!("benchmarking 'unblind'...");
    for _ in 0..RUNS {
        let now = Instant::now();
        for _ in 0..PRECISION {
            let _result = blinded_coins.unblind(&public_key, &output_attributes);
        }
        let elapsed = now.elapsed().as_millis() as f64;
        data.push(elapsed / PRECISION as f64);
    }
    println!(
        "Result: {:.2} +/- {:.2} ms",
        mean(&data),
        standard_deviation(&data, None)
    );
}
