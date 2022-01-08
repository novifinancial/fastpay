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
