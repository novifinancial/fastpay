use crate::error::{CoconutError, CoconutResult};
use crate::lagrange::Polynomial;
use crate::setup::{Parameters, PublicKey, SecretKey};
use bls12_381::{G1Projective, Scalar};
use group::GroupEncoding as _;

#[cfg(test)]
#[path = "tests/issue_tests.rs"]
pub mod issue_tests;

#[derive(Clone)]
pub struct Coin(pub G1Projective, pub G1Projective);

impl Coin {
    pub fn randomize(&mut self, parameters: &mut Parameters) {
        let r = parameters.random_scalar();
        self.0 *= r;
        self.1 *= r;
    }

    /// Verify the value and id of the coin.
    pub fn plain_verify(
        &self,
        parameters: &Parameters,
        public_key: PublicKey,
        value: Scalar,
        id: Scalar,
    ) -> bool {
        let beta0 = &public_key.betas[0];
        let beta1 = &public_key.betas[1];
        let kappa = public_key.alpha + beta0 * value + beta1 * id;
        Parameters::check_pairing(&self.0, &kappa, &self.1, &parameters.g2)
    }

    /// Aggregates multiple shares of coins into a single coin.
    pub fn aggregate(shares: &[(Self, u64)]) -> CoconutResult<Self> {
        let (mut part1, part2): (Vec<_>, Vec<_>) =
            shares.iter().map(|(x, i)| (x.0, (x.1, *i))).unzip();
        let h = part1.pop().ok_or(CoconutError::EmptyShares)?;
        let s = Polynomial::lagrange_interpolate(&part2);
        Ok(Self(h, s))
    }
}

pub struct BlindedCoins {
    /// A vector of blinded coins.
    blind: Vec<(G1Projective, G1Projective)>,
}

impl BlindedCoins {
    pub fn new(
        // The system parameters.
        parameters: &Parameters,
        // The secret key of the authority.
        secret: &SecretKey,
        // The common commitments Cm of the coin values and ids.
        cms: &[G1Projective],
        // The blinded output coin values and ids.
        cs: &[(G1Projective, G1Projective)],
    ) -> Self {
        debug_assert!(cms.len() == cs.len());
        debug_assert!(parameters.max_attributes() >= 2);

        // Compute the base group element h.
        let base_hs = cms.iter().map(|cm| Parameters::hash_to_g1(cm.to_bytes()));

        // Homomorphically computes the blinded credential.
        let y0 = &secret.ys[0];
        let y1 = &secret.ys[1];
        let blind = cs
            .iter()
            .zip(base_hs.into_iter())
            .map(|((v, id), h)| (h, v * y0 + id * y1 + h * secret.x))
            .collect();

        Self { blind }
    }

    /// Unblinds the coins.
    pub fn unblind(
        &self,
        // The public key of the authority.
        public_key: &PublicKey,
        // The blinding factors used to produce the coin requests.
        blinding_factors: &[(Scalar, Scalar)],
    ) -> Vec<Coin> {
        let gamma_0 = &public_key.gammas[0];
        let gamma_1 = &public_key.gammas[1];
        self.blind
            .iter()
            .zip(blinding_factors.iter())
            .map(|((h, b), (k_value, k_id))| Coin(*h, b + gamma_0 * (-k_value) + gamma_1 * (-k_id)))
            .collect()
    }
}
