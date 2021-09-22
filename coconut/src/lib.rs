mod error;
pub mod issuance;
pub mod setup;

use crate::setup::{Parameters, PublicKey};
use bls12_381::{G1Projective, Scalar};

#[derive(Clone)]
pub struct Coin(pub G1Projective, pub G1Projective);

impl Coin {
    pub fn randomize(&mut self, parameters: &mut Parameters) {
        let r = parameters.random_scalar();
        self.0 *= r;
        self.1 *= r;
    }

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
}
