use crate::fixtures::{aggregated_key, keypairs, parameters, request};
use crate::issuance::{BlindedCoins, Coin};
use bls12_381::Scalar;

#[test]
fn end_to_end() {
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
