use super::*;
use crate::fixtures::{aggregated_key, coin1, keypair, keypairs, parameters, request};

impl Coin {
    pub fn default(
        parameters: &mut Parameters,
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
    coin.randomize(&mut parameters());

    let ok = coin.plain_verify(
        &parameters(),
        &keypair().public,
        /* value */ Scalar::from(1),
        /* id */ Scalar::from(1234),
    );
    assert!(ok);
}

#[test]
fn issue() {
    let (coins_request, blinding_factors) = request();
    let blinded_coins = BlindedCoins::new(
        &parameters(),
        &keypair().secret,
        &coins_request.cms,
        &coins_request.cs,
    );

    let coins = blinded_coins.unblind(&keypair().public, &blinding_factors);
    assert_eq!(coins.len(), 2);

    let ok = coins[0].plain_verify(
        &parameters(),
        &keypair().public,
        /* value */ Scalar::from(2),
        /* id */ Scalar::from(9123),
    );
    assert!(ok);

    let ok = coins[1].plain_verify(
        &parameters(),
        &keypair().public,
        /* value */ Scalar::from(2),
        /* id */ Scalar::from(4567),
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
                &mut parameters(),
                &key.secret,
                /* value */ &Scalar::one(),
                /* id */ &Scalar::from(1234),
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
        /* value */ Scalar::one(),
        /* id */ Scalar::from(1234),
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
                &mut parameters(),
                &key.secret,
                /* value */ &Scalar::one(),
                /* id */ &Scalar::from(1234),
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
        /* value */ Scalar::from(1),
        /* id */ Scalar::from(1234),
    );
    assert!(!ok);
}
