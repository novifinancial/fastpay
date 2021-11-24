// Copyright (c) Facebook, Inc. and its affiliates.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    lagrange::Polynomial,
    request::OutputAttribute,
    setup::{Parameters, PublicKey, SecretKey},
};
use bls12_381::{G1Projective, Scalar};
use ff::Field;
use group::GroupEncoding as _;
#[cfg(feature = "with_serde")]
use serde::{Deserialize, Serialize};

#[cfg(test)]
#[path = "tests/issuance_tests.rs"]
pub mod issuance_tests;

#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "with_serde", derive(Serialize, Deserialize))]
pub struct Coin(pub G1Projective, pub G1Projective);

impl Coin {
    pub fn randomize(&mut self, rng: impl rand::RngCore) {
        let r = Scalar::random(rng);
        self.0 *= r;
        self.1 *= r;
    }

    /// Verify the value, seed, and key of the coin.
    pub fn plain_verify(
        &self,
        parameters: &Parameters,
        public_key: &PublicKey,
        value: Scalar,
        seed: Scalar,
        key: Scalar,
    ) -> bool {
        if public_key.betas.len() < 3 {
            return false;
        }
        let beta0 = &public_key.betas[0];
        let beta1 = &public_key.betas[1];
        let beta2 = &public_key.betas[2];
        let kappa = public_key.alpha + beta0 * value + beta1 * seed + beta2 * id;
        !bool::from(self.0.is_identity())
            && Parameters::check_pairing(&self.0, &kappa, &self.1, &parameters.g2)
    }

    /// Aggregates multiple shares of coins into a single coin.
    pub fn aggregate(shares: &[(Self, u64)]) -> Self {
        assert!(!shares.is_empty());
        let (coin, _) = &shares[0];
        let shares: Vec<_> = shares.iter().map(|(coin, i)| (coin.1, *i)).collect();
        let s = Polynomial::lagrange_interpolate(&shares);
        Self(coin.0, s)
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "with_serde", derive(Serialize, Deserialize))]
pub struct BlindedCoins {
    /// A vector of blinded coins.
    coins: Vec<(G1Projective, G1Projective)>,
}

impl BlindedCoins {
    pub fn new(
        // The system parameters.
        parameters: &Parameters,
        // The secret key of the authority.
        secret: &SecretKey,
        // The common commitments Cm of the coin values and keys.
        cms: &[G1Projective],
        // The blinded output coin values and keys.
        cs: &[(G1Projective, G1Projective, G1Projective)],
    ) -> Self {
        assert!(cms.len() == cs.len());
        assert!(parameters.max_attributes() >= 3);

        // Compute the base group element h.
        let base_hs = cms.iter().map(|cm| Parameters::hash_to_g1(cm.to_bytes()));

        // Homomorphically computes the blinded credential.
        let y0 = &secret.ys[0];
        let y1 = &secret.ys[1];
        let y2 = &secret.ys[2];
        let coins = cs
            .iter()
            .zip(base_hs.into_iter())
            .map(|((v, seed, key), h)| (h, v * y0 + seed * y1 + key * y2 + h * secret.x))
            .collect();

        Self { coins }
    }

    /// Number of blinded coins.
    pub fn len(&self) -> usize {
        self.coins.len()
    }

    /// Whether there is no coin. (Needed for https://rust-lang.github.io/rust-clippy/master/index.html#len_without_is_empty)
    pub fn is_empty(&self) -> bool {
        self.coins.is_empty()
    }

    /// Unblinds the coins.
    pub fn unblind(
        &self,
        // The public key of the authority.
        public_key: &PublicKey,
        // The blinding factors used to produce the coin requests.
        output_attributes: &[OutputAttribute],
    ) -> Vec<Coin> {
        let gamma_0 = &public_key.gammas[0];
        let gamma_1 = &public_key.gammas[1];
        let gamma_2 = &public_key.gammas[2];
        self.coins
            .iter()
            .zip(output_attributes.iter())
            .map(|((h, b), attribute)| {
                Coin(
                    *h,
                    b + gamma_0 * (-attribute.value_blinding_factor)
                        + gamma_1 * (-attribute.seed_blinding_factor)
                        + gamma_2 * (-attribute.key_blinding_factor),
                )
            })
            .collect()
    }
}
