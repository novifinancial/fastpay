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
        id: &Scalar,
    ) -> Self {
        let h0 = parameters.hs[0];
        let h1 = parameters.hs[1];
        let o = Scalar::one();
        let cm = h0 * value + h1 * id + parameters.g1 * o;

        let h = Parameters::hash_to_g1(cm.to_bytes());

        let y0 = &secret.ys[0];
        let y1 = &secret.ys[1];
        Self(h, h * value * y0 + h * id * y1 + h * secret.x)
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
        /* id */ input_attribute1().id,
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
        /* id */ output_attributes()[0].id,
    );
    assert!(ok);

    let ok = coins[1].plain_verify(
        &parameters(),
        &keypair().public,
        /* value */ output_attributes()[1].value,
        /* id */ output_attributes()[1].id,
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
                /* id */ &input_attribute1().id,
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
        /* id */ input_attribute1().id,
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
                /* id */ &input_attribute1().id,
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
        /* id */ input_attribute1().id,
    );
    assert!(!ok);
}

/*
#[test]
fn issue_and_aggregate() {
    let (coins_request, blinding_factors) = request();

    // Create enough coin shares. The shares have the following structure:
    //  vec![
    //      vec![coin1_share1, coin2_share_1],
    //      vec![coin1_share2, coin2_share_2],
    //      vec![coin1_share3, coin2_share_3],
    //      vec![coin1_share4, coin2_share_4],
    //  ]
    let (shares, indices): (Vec<_>, Vec<_>) = keypairs()
        .iter()
        .skip(1)
        .map(|key| {
            let coin = BlindedCoins::new(
                &parameters(),
                &key.secret,
                &coins_request.cms,
                &coins_request.cs,
            )
            .unblind(&key.public, &blinding_factors);

            (coin, key.index)
        })
        .unzip();

    // Transpose the shares so that we have the following structure:
    //  vec![
    //      vec![coin1_share1, coin1_share_2, coin1_share3, coin1_share4],
    //      vec![coin2_share1, coin2_share_2, coin2_share3, coin1_share4],
    //  ]
    let shares = transpose(shares);

    // Aggregate the coin.
    let full_coins: Vec<_> = shares
        .into_iter()
        .map(|x| {
            let tmp: Vec<_> = x.into_iter().zip(indices.iter().cloned()).collect();
            Coin::aggregate(&tmp)
        })
        .collect();

    // Ensure the coins are valid.
    assert_eq!(full_coins.len(), 2);

    let ok = full_coins[0].plain_verify(
        &parameters(),
        &aggregated_key(),
        /* value */ Scalar::from(2),
        /* id */ Scalar::from(9123),
    );
    assert!(ok);

    let ok = full_coins[1].plain_verify(
        &parameters(),
        &aggregated_key(),
        /* value */ Scalar::from(2),
        /* id */ Scalar::from(4567),
    );
    assert!(ok);
}
*/

// Helper function to transpose nested vectors.
pub fn transpose<T>(v: Vec<Vec<T>>) -> Vec<Vec<T>> {
    assert!(!v.is_empty());
    let len = v[0].len();
    let mut iters: Vec<_> = v.into_iter().map(|n| n.into_iter()).collect();
    (0..len)
        .map(|_| {
            iters
                .iter_mut()
                .map(|n| n.next().unwrap())
                .collect::<Vec<T>>()
        })
        .collect()
}
