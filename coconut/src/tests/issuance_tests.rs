// Copyright (c) Facebook, Inc. and its affiliates.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::fixtures::{
    aggregated_key, coin1, input_attribute1, keypair, keypairs, output_attributes, parameters,
    request,
};

impl Coin {
    pub fn default(
        parameters: &Parameters,
        secret: &SecretKey,
        value: &Scalar,
        seed: &Scalar,
        key: &Scalar,
    ) -> Self {
        let h0 = parameters.hs[0];
        let h1 = parameters.hs[1];
        let h2 = parameters.hs[2];
        let o = Scalar::one();
        let cm = h0 * value + h1 * seed + h2 * key + parameters.g1 * o;

        let h = Parameters::hash_to_g1(cm.to_bytes());

        let y0 = &secret.ys[0];
        let y1 = &secret.ys[1];
        let y2 = &secret.ys[2];

        let s = h * (value * y0 + seed * y1 + key * y2 + secret.x);
        Self(h, s)
    }
}

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
