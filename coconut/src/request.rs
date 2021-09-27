use crate::error::{CoconutError, CoconutResult};
use crate::issue::Coin;
use crate::setup::{Parameters, PublicKey};
use bls12_381::{G1Projective, G2Projective, Scalar};
use group::GroupEncoding as _;
use sha2::{Digest as _, Sha512};
use std::convert::TryInto;

#[cfg(test)]
#[path = "tests/request_tests.rs"]
pub mod request_tests;

pub struct CoinsRequest {
    /// Input credentials representing coins.
    sigmas: Vec<Coin>,
    /// Kappa group elements associated with the input credentials (`sigmas`).
    kappas: Vec<G2Projective>,
    /// Nu group elements associated with the input credentials (`sigmas`).
    nus: Vec<G1Projective>,
    /// The common commitments Cm of the output coin values and ids.
    pub cms: Vec<G1Projective>,
    /// The blinded output coin values and ids.
    pub cs: Vec<(G1Projective, G1Projective)>,
    /// A ZK-proof asserting correctness of all the other fields and that the sum of the input
    /// coins equals the sum of the output coins.
    proof: RequestCoinsProof,
}

impl CoinsRequest {
    pub fn new(
        // The system parameters.
        parameters: &mut Parameters,
        // The aggregated public key of the authorities.
        public_key: &PublicKey,
        // The credentials representing the input coins. Each credential has two attributes, a coin
        // value and a id.
        sigmas: &[Coin],
        // The attributes of the credentials `sigmas`. Each input attribute is a tuple of (coin value, id).
        input_attributes: &[(Scalar, Scalar)],
        // Each output attribute is a tuple of (coin value, id).
        output_attributes: &[(Scalar, Scalar)],
        // Each element contains one blinding factor for the coin value and one for the id. There should
        // as many blinding factors as output attributes.
        blinding_factors: &[(Scalar, Scalar)],
    ) -> Self {
        debug_assert!(sigmas.len() == input_attributes.len());
        debug_assert!(output_attributes.len() == blinding_factors.len());
        debug_assert!(parameters.max_attributes() >= 2);
        debug_assert!(public_key.max_attributes() >= 2);

        // Randomize the input credentials; each credential represents an input coin.
        let sigmas: Vec<_> = sigmas
            .iter()
            .cloned()
            .map(|mut sigma| {
                sigma.randomize(parameters);
                sigma
            })
            .collect();

        // Pick a random scalar for each value to blind (ie. each input coin value and id).
        #[cfg(not(test))]
        let rs = parameters.n_random_scalars(input_attributes.len());
        #[cfg(test)]
        let rs: Vec<_> = input_attributes.iter().map(|_| Scalar::from(100)).collect();

        // Compute Kappa and Nu for each input credential.
        let beta0 = &public_key.betas[0];
        let beta1 = &public_key.betas[1];
        let kappas = input_attributes
            .iter()
            .zip(rs.iter())
            .map(|((v, id), r)| public_key.alpha + beta0 * v + beta1 * id + parameters.g2 * r)
            .collect();
        let nus = rs
            .iter()
            .zip(sigmas.iter())
            .map(|(r, sigma)| sigma.0 * r)
            .collect();

        // Compute the common commitment Cm for the outputs.
        let os = parameters.n_random_scalars(output_attributes.len());
        let h0 = &parameters.hs[0];
        let h1 = &parameters.hs[1];
        let cms: Vec<_> = output_attributes
            .iter()
            .zip(os.iter())
            .map(|((v, id), o)| h0 * v + h1 * id + parameters.g1 * o)
            .collect();

        // Compute the base group element h.
        let base_hs: Vec<_> = cms
            .iter()
            .map(|cm| Parameters::hash_to_g1(cm.to_bytes()))
            .collect();

        // Commit to the output attributes.
        let cs = output_attributes
            .iter()
            .zip(blinding_factors.iter())
            .zip(base_hs.iter())
            .map(|(((value, id), (k_value, k_id)), h)| {
                (
                    h * value + parameters.g1 * k_value,
                    h * id + parameters.g1 * k_id,
                )
            })
            .collect();

        // Compute the ZK proof asserting correctness of the computations above.
        let proof = RequestCoinsProof::new(
            parameters,
            &input_attributes,
            &output_attributes,
            &blinding_factors,
            &rs,
            &public_key,
            &base_hs,
            &sigmas,
        );

        Self {
            sigmas,
            kappas,
            nus,
            cms,
            cs,
            proof,
        }
    }

    /// Verifies the coin request.
    pub fn verify(&self, parameters: &Parameters, public_key: &PublicKey) -> CoconutResult<()> {
        // Verify the ZK proof.
        self.proof.verify(
            parameters,
            public_key,
            &self.sigmas,
            &self.kappas,
            &self.nus,
            &self.cms,
            &self.cs,
        )?;

        // Check the pairing equations.
        self.kappas
            .iter()
            .zip(self.nus.iter())
            .zip(self.sigmas.iter())
            .all(|((kappa, nu), sigma)| {
                !bool::from(sigma.0.is_identity())
                    && Parameters::check_pairing(&sigma.0, kappa, &(sigma.1 + nu), &parameters.g2)
            })
            .then(|| ())
            .ok_or(CoconutError::PairingCheckFailed)
    }
}

/// Represents a ZK proof of valid coin requests.
pub struct RequestCoinsProof {
    challenge: Scalar,
    input_attributes_responses: Vec<(Scalar, Scalar)>,
    output_attributes_responses: Vec<(Scalar, Scalar)>,
    blinding_factors_responses: Vec<(Scalar, Scalar)>,
    rs_responses: Vec<Scalar>,
}

impl RequestCoinsProof {
    fn new(
        parameters: &mut Parameters,
        input_attributes: &[(Scalar, Scalar)],
        output_attributes: &[(Scalar, Scalar)],
        blinding_factors: &[(Scalar, Scalar)],
        rs: &[Scalar],
        public_key: &PublicKey,
        base_hs: &[G1Projective],
        sigmas: &[Coin],
    ) -> Self {
        debug_assert!(rs.len() == input_attributes.len());
        debug_assert!(output_attributes.len() == blinding_factors.len());
        debug_assert!(parameters.max_attributes() >= 2);
        debug_assert!(public_key.max_attributes() >= 2);

        // Compute the witnesses.
        let input_attributes_witnesses: Vec<_> = input_attributes
            .iter()
            .map(|_| (parameters.random_scalar(), parameters.random_scalar()))
            .collect();
        let output_attributes_witnesses: Vec<_> = output_attributes
            .iter()
            .map(|_| (parameters.random_scalar(), parameters.random_scalar()))
            .collect();
        let blinding_factors_witnesses: Vec<_> = blinding_factors
            .iter()
            .map(|_| (parameters.random_scalar(), parameters.random_scalar()))
            .collect();
        let rs_witnesses = parameters.n_random_scalars(rs.len());

        // Compute Kappa and Nu from the witnesses.
        let beta0 = &public_key.betas[0];
        let beta1 = &public_key.betas[1];
        let kappas: Vec<_> = input_attributes_witnesses
            .iter()
            .zip(rs_witnesses.iter())
            .map(|((v, id), r)| public_key.alpha + beta0 * v + beta1 * id + parameters.g2 * r)
            .collect();
        let nus: Vec<_> = rs_witnesses
            .iter()
            .zip(sigmas.iter())
            .map(|(r, sigma)| sigma.0 * r)
            .collect();

        // Compute the commitments to the output attributes from the witnesses.
        let cs: Vec<_> = output_attributes_witnesses
            .iter()
            .zip(blinding_factors_witnesses.iter())
            .zip(base_hs.iter())
            .map(|(((value, id), (k_value, k_id)), h)| {
                (
                    h * value + parameters.g1 * k_value,
                    h * id + parameters.g1 * k_id,
                )
            })
            .collect();

        // Compute the challenge.
        let challenge = Self::to_challenge(&public_key, &base_hs, &kappas, &nus, &cs);

        // Computes responses.
        let input_attributes_responses = input_attributes
            .iter()
            .zip(input_attributes_witnesses.iter())
            .map(|((value, id), (v_witness, id_witness))| {
                (v_witness - challenge * value, id_witness - challenge * id)
            })
            .collect();
        let output_attributes_responses = output_attributes
            .iter()
            .zip(output_attributes_witnesses.iter())
            .map(|((value, id), (v_witness, id_witness))| {
                (v_witness - challenge * value, id_witness - challenge * id)
            })
            .collect();
        let blinding_factors_responses = blinding_factors
            .iter()
            .zip(blinding_factors_witnesses.iter())
            .map(|((part1, part2), (part1_witness, part2_witness))| {
                (
                    part1_witness - challenge * part1,
                    part2_witness - challenge * part2,
                )
            })
            .collect();
        let rs_responses = rs
            .iter()
            .zip(rs_witnesses.iter())
            .map(|(r, w)| w - challenge * r)
            .collect();

        Self {
            challenge,
            input_attributes_responses,
            output_attributes_responses,
            blinding_factors_responses,
            rs_responses,
        }
    }

    /// Verify the ZK proof of coins request.
    pub fn verify(
        &self,
        parameters: &Parameters,
        public_key: &PublicKey,
        sigmas: &[Coin],
        kappas: &[G2Projective],
        nus: &[G1Projective],
        cms: &[G1Projective],
        cs: &[(G1Projective, G1Projective)],
    ) -> CoconutResult<()> {
        debug_assert!(sigmas.len() == kappas.len());
        debug_assert!(sigmas.len() == nus.len());
        debug_assert!(sigmas.len() == cms.len());
        debug_assert!(sigmas.len() == cs.len());
        debug_assert!(parameters.max_attributes() >= 2);
        debug_assert!(public_key.max_attributes() >= 2);

        // Compute the Kappa and Nu witnesses.
        let beta0 = &public_key.betas[0];
        let beta1 = &public_key.betas[1];
        let kappas: Vec<_> = kappas
            .iter()
            .zip(self.input_attributes_responses.iter())
            .zip(self.rs_responses.iter())
            .map(|((kappa, (value, id)), r)| {
                kappa * self.challenge
                    + public_key.alpha * (Scalar::one() - self.challenge)
                    + beta0 * value
                    + beta1 * id
                    + parameters.g2 * r
            })
            .collect();
        let nus: Vec<_> = nus
            .iter()
            .zip(sigmas.iter())
            .zip(self.rs_responses.iter())
            .map(|((nu, sigma), r)| nu * self.challenge + sigma.0 * r)
            .collect();

        // Compute the base group element h.
        let base_hs: Vec<_> = cms
            .iter()
            .map(|cm| Parameters::hash_to_g1(cm.to_bytes()))
            .collect();

        // Compute the commitments witnesses.
        let cs: Vec<_> = cs
            .iter()
            .zip(self.output_attributes_responses.iter())
            .zip(self.blinding_factors_responses.iter())
            .zip(base_hs.iter())
            .map(|((((part1, part2), (value, id)), (k_value, k_id)), h)| {
                (
                    part1 * self.challenge + h * value + parameters.g1 * k_value,
                    part2 * self.challenge + h * id + parameters.g1 * k_id,
                )
            })
            .collect();

        // Check the challenge.
        let challenge = Self::to_challenge(&public_key, &base_hs, &kappas, &nus, &cs);
        ensure!(challenge == self.challenge, CoconutError::ZKCheckFailed);
        Ok(())
    }

    /// Helper function to calculate the challenge of the ZK proof (Fiat-Shamir heuristic).
    fn to_challenge(
        public_key: &PublicKey,
        base_hs: &[G1Projective],
        kappas: &[G2Projective],
        nus: &[G1Projective],
        cs: &[(G1Projective, G1Projective)],
    ) -> Scalar {
        debug_assert!(public_key.max_attributes() >= 2);

        let mut hasher = Sha512::new();
        hasher.update(b"RequestCoinsProof");
        hasher.update(public_key.alpha.to_bytes());
        hasher.update(public_key.betas[0].to_bytes());
        hasher.update(public_key.betas[1].to_bytes());
        for h in base_hs {
            hasher.update(h.to_bytes());
        }
        for kappa in kappas {
            hasher.update(kappa.to_bytes());
        }
        for nu in nus {
            hasher.update(nu.to_bytes());
        }
        for (part1, part2) in cs {
            hasher.update(part1.to_bytes());
            hasher.update(part2.to_bytes());
        }

        let digest = hasher.finalize();
        Scalar::from_bytes_wide(digest.as_slice()[..64].try_into().unwrap())
    }
}
