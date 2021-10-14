use crate::{
    ensure,
    error::{CoconutError, CoconutResult},
    issuance::Coin,
    request::{InputAttribute, OutputAttribute, Randomness},
    setup::{Parameters, PublicKey},
};
use bls12_381::{G1Projective, G2Projective, Scalar};
use group::GroupEncoding as _;
use sha2::{Digest as _, Sha512};
use std::convert::TryInto;

#[cfg(test)]
#[path = "tests/proof_tests.rs"]
pub mod proof_tests;

/// Represents a ZK proof of valid coin requests.
pub struct RequestCoinsProof {
    challenge: Scalar,
    input_attributes_responses: Vec<InputAttribute>,
    output_attributes_responses: Vec<OutputAttribute>,
    randomness_responses: Randomness,
    zero_sum_response: Scalar,
}

impl RequestCoinsProof {
    pub fn new(
        parameters: &mut Parameters,
        public_key: &PublicKey,
        base_hs: &[G1Projective],
        sigmas: &[Coin],
        input_attributes: &[InputAttribute],
        output_attributes: &[OutputAttribute],
        randomness: &Randomness,
    ) -> Self {
        assert!(parameters.max_attributes() >= 2);
        assert!(public_key.max_attributes() >= 2);

        // Compute the witnesses.
        let input_attributes_witnesses: Vec<_> = input_attributes
            .iter()
            .map(|_| InputAttribute {
                value: parameters.random_scalar(),
                id: parameters.random_scalar(),
            })
            .collect();
        let output_attributes_witnesses: Vec<_> = output_attributes
            .iter()
            .map(|_| OutputAttribute {
                value: parameters.random_scalar(),
                value_blinding_factor: parameters.random_scalar(),
                id: parameters.random_scalar(),
                id_blinding_factor: parameters.random_scalar(),
            })
            .collect();
        let randomness_witnesses =
            Randomness::new(parameters, input_attributes.len(), output_attributes.len());

        // Compute Kappa and Nu from the witnesses.
        let beta0 = &public_key.betas[0];
        let beta1 = &public_key.betas[1];
        let kappas: Vec<_> = input_attributes_witnesses
            .iter()
            .zip(randomness_witnesses.rs.iter())
            .map(|(x, r)| public_key.alpha + beta0 * x.value + beta1 * x.id + parameters.g2 * r)
            .collect();
        let nus: Vec<_> = randomness_witnesses
            .rs
            .iter()
            .zip(sigmas.iter())
            .map(|(r, sigma)| sigma.0 * r)
            .collect();

        // Compute the commitments to the output attributes from the witnesses.
        let h0 = &parameters.hs[0];
        let h1 = &parameters.hs[1];
        let cms: Vec<_> = output_attributes_witnesses
            .iter()
            .zip(randomness_witnesses.os.iter())
            .map(|(x, o)| h0 * x.value + h1 * x.id + parameters.g1 * o)
            .collect();

        let cs: Vec<_> = output_attributes_witnesses
            .iter()
            .zip(base_hs.iter())
            .map(|(x, h)| {
                (
                    h * x.value + parameters.g1 * x.value_blinding_factor,
                    h * x.id + parameters.g1 * x.id_blinding_factor,
                )
            })
            .collect();

        // Compute the cryptographic material to prove the sum of the input coins equals the output.
        let input_commitments: Vec<_> = input_attributes_witnesses
            .iter()
            .zip(randomness_witnesses.input_rs.iter())
            .map(|(x, r)| parameters.hs[0] * x.value + parameters.g1 * r)
            .collect();
        let output_commitments: Vec<_> = output_attributes_witnesses
            .iter()
            .zip(randomness_witnesses.output_rs.iter())
            .map(|(x, r)| parameters.hs[0] * x.value + parameters.g1 * r)
            .collect();

        let zero_sum = randomness.output_rs.iter().sum::<Scalar>()
            - randomness.input_rs.iter().sum::<Scalar>();
        let zero_sum_witness = randomness_witnesses.output_rs.iter().sum::<Scalar>()
            - randomness_witnesses.input_rs.iter().sum::<Scalar>();

        // Compute the challenge.
        let challenge = Self::to_challenge(
            public_key,
            base_hs,
            &kappas,
            &nus,
            &cms,
            &cs,
            &input_commitments,
            &output_commitments,
            /* zero_sum */ &(parameters.g1 * zero_sum_witness),
        );

        // Computes responses.
        let input_attributes_responses = input_attributes
            .iter()
            .zip(input_attributes_witnesses.iter())
            .map(|(attribute, witness)| InputAttribute {
                value: witness.value - challenge * attribute.value,
                id: witness.id - challenge * attribute.id,
            })
            .collect();
        let output_attributes_responses = output_attributes
            .iter()
            .zip(output_attributes_witnesses.iter())
            .map(|(attribute, witness)| OutputAttribute {
                value: witness.value - challenge * attribute.value,
                value_blinding_factor: witness.value_blinding_factor
                    - challenge * attribute.value_blinding_factor,
                id: witness.id - challenge * attribute.id,
                id_blinding_factor: witness.id_blinding_factor
                    - challenge * attribute.id_blinding_factor,
            })
            .collect();

        let randomness_responses = Randomness {
            rs: randomness
                .rs
                .iter()
                .zip(randomness_witnesses.rs.iter())
                .map(|(r, w)| w - challenge * r)
                .collect(),
            os: randomness
                .os
                .iter()
                .zip(randomness_witnesses.os.iter())
                .map(|(o, w)| w - challenge * o)
                .collect(),
            input_rs: randomness
                .input_rs
                .iter()
                .zip(randomness_witnesses.input_rs)
                .map(|(r, w)| w - challenge * r)
                .collect(),
            output_rs: randomness
                .output_rs
                .iter()
                .zip(randomness_witnesses.output_rs)
                .map(|(r, w)| w - challenge * r)
                .collect(),
        };
        let zero_sum_response = zero_sum_witness - challenge * zero_sum;

        Self {
            challenge,
            input_attributes_responses,
            output_attributes_responses,
            randomness_responses,
            zero_sum_response,
        }
    }

    /// Verify the ZK proof of coins request.
    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        &self,
        parameters: &Parameters,
        public_key: &PublicKey,
        sigmas: &[Coin],
        kappas: &[G2Projective],
        nus: &[G1Projective],
        cms: &[G1Projective],
        cs: &[(G1Projective, G1Projective)],
        input_commitments: &[G1Projective],
        output_commitments: &[G1Projective],
    ) -> CoconutResult<()> {
        assert!(sigmas.len() == kappas.len());
        assert!(sigmas.len() == nus.len());
        assert!(sigmas.len() == cms.len());
        assert!(sigmas.len() == input_commitments.len());
        assert!(output_commitments.len() == cs.len());
        assert!(parameters.max_attributes() >= 2);
        assert!(public_key.max_attributes() >= 2);

        // Compute the Kappa and Nu witnesses.
        let beta0 = &public_key.betas[0];
        let beta1 = &public_key.betas[1];
        let kappas_reconstruct: Vec<_> = kappas
            .iter()
            .zip(self.input_attributes_responses.iter())
            .zip(self.randomness_responses.rs.iter())
            .map(|((kappa, attribute), r)| {
                kappa * self.challenge
                    + public_key.alpha * (Scalar::one() - self.challenge)
                    + beta0 * attribute.value
                    + beta1 * attribute.id
                    + parameters.g2 * r
            })
            .collect();
        let nus_reconstruct: Vec<_> = nus
            .iter()
            .zip(sigmas.iter())
            .zip(self.randomness_responses.rs.iter())
            .map(|((nu, sigma), r)| nu * self.challenge + sigma.0 * r)
            .collect();

        // Compute the base group element h.
        let base_hs: Vec<_> = cms
            .iter()
            .map(|cm| Parameters::hash_to_g1(cm.to_bytes()))
            .collect();

        // Compute the commitments witnesses.
        let h0 = &parameters.hs[0];
        let h1 = &parameters.hs[1];
        let cms_reconstruct: Vec<_> = cms
            .iter()
            .zip(self.output_attributes_responses.iter())
            .zip(self.randomness_responses.os.iter())
            .map(|((cm, attribute), o)| {
                cm * self.challenge + h0 * attribute.value + h1 * attribute.id + parameters.g1 * o
            })
            .collect();

        let cs_reconstruct: Vec<_> = cs
            .iter()
            .zip(self.output_attributes_responses.iter())
            .zip(base_hs.iter())
            .map(|(((part1, part2), attribute), h)| {
                (
                    part1 * self.challenge
                        + h * attribute.value
                        + parameters.g1 * attribute.value_blinding_factor,
                    part2 * self.challenge
                        + h * attribute.id
                        + parameters.g1 * attribute.id_blinding_factor,
                )
            })
            .collect();

        // Ensure the sum of the input values equals the sum of the output values.
        let input_commitments_reconstruct: Vec<_> = input_commitments
            .iter()
            .zip(self.input_attributes_responses.iter())
            .zip(self.randomness_responses.input_rs.iter())
            .map(|((c, attribute), r)| {
                c * self.challenge + parameters.hs[0] * attribute.value + parameters.g1 * r
            })
            .collect();
        let output_commitments_reconstruct: Vec<_> = output_commitments
            .iter()
            .zip(self.output_attributes_responses.iter())
            .zip(self.randomness_responses.output_rs.iter())
            .map(|((c, attribute), r)| {
                c * self.challenge + parameters.hs[0] * attribute.value + parameters.g1 * r
            })
            .collect();
        let zero_sum = output_commitments.iter().sum::<G1Projective>()
            - input_commitments.iter().sum::<G1Projective>();
        let zero_sum_reconstruct =
            zero_sum * self.challenge + parameters.g1 * self.zero_sum_response;

        // Check the challenge.
        let challenge = Self::to_challenge(
            public_key,
            &base_hs,
            &kappas_reconstruct,
            &nus_reconstruct,
            &cms_reconstruct,
            &cs_reconstruct,
            &input_commitments_reconstruct,
            &output_commitments_reconstruct,
            &zero_sum_reconstruct,
        );
        ensure!(challenge == self.challenge, CoconutError::ZKCheckFailed);
        Ok(())
    }

    /// Helper function to calculate the challenge of the ZK proof (Fiat-Shamir heuristic).
    #[allow(clippy::too_many_arguments)]
    fn to_challenge(
        public_key: &PublicKey,
        base_hs: &[G1Projective],
        kappas: &[G2Projective],
        nus: &[G1Projective],
        cms: &[G1Projective],
        cs: &[(G1Projective, G1Projective)],
        input_commitments: &[G1Projective],
        output_commitments: &[G1Projective],
        zero_sum: &G1Projective,
    ) -> Scalar {
        assert!(public_key.max_attributes() >= 2);

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
        for cm in cms {
            hasher.update(cm.to_bytes());
        }
        for (part1, part2) in cs {
            hasher.update(part1.to_bytes());
            hasher.update(part2.to_bytes());
        }
        for c in input_commitments {
            hasher.update(c.to_bytes());
        }
        for c in output_commitments {
            hasher.update(c.to_bytes());
        }
        hasher.update(zero_sum.to_bytes());

        let digest = hasher.finalize();
        Scalar::from_bytes_wide(digest.as_slice()[..64].try_into().unwrap())
    }
}
