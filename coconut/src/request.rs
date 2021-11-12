// Copyright (c) Facebook, Inc. and its affiliates.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    error::{CoconutError, CoconutResult},
    issuance::Coin,
    proof::RequestCoinsProof,
    setup::{Parameters, PublicKey},
};
use bls12_381::{G1Projective, G2Projective, Scalar};
use bulletproofs::{PedersenGens, RangeProof};
use group::GroupEncoding as _;
use merlin::Transcript;
#[cfg(feature = "with_serde")]
use serde::{Deserialize, Serialize};
use std::convert::TryInto as _;

#[cfg(test)]
#[path = "tests/request_tests.rs"]
pub mod request_tests;

/// The attributes of the input coin.
#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "with_serde", derive(Serialize, Deserialize))]
pub struct InputAttribute {
    /// The seed of the input coin.
    pub seed: Scalar,
    /// The value of the input coin.
    pub value: Scalar,
    // The id of the input coin.
    pub id: Scalar,
}

/// The attributes of the output coins along with their blinding factors.
#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "with_serde", derive(Serialize, Deserialize))]
pub struct OutputAttribute {
    /// The seed of the output coin.
    pub seed: Scalar,
    /// The blinding factor used to hide the seed of the output coin.
    pub seed_blinding_factor: Scalar,
    /// The value of the output coin.
    pub value: Scalar,
    /// The blinding factor used to hide the value of the output coin.
    pub value_blinding_factor: Scalar,
    /// The id of the output coin.
    pub id: Scalar,
    /// The blinding factor used to hide the id of the output coin.
    pub id_blinding_factor: Scalar,
}

/// The randomness used in the coin request.
#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "with_serde", derive(Serialize, Deserialize))]
pub struct Randomness {
    pub rs: Vec<Scalar>,
    pub os: Vec<Scalar>,
    pub input_rs: Vec<Scalar>,
    pub output_rs: Vec<Scalar>,
}

impl Randomness {
    pub fn new(mut rng: impl rand::RngCore, input_len: usize, output_len: usize) -> Self {
        Self {
            rs: Parameters::n_random_scalars(&mut rng, input_len),
            os: Parameters::n_random_scalars(&mut rng, output_len),
            input_rs: Parameters::n_random_scalars(&mut rng, input_len),
            output_rs: Parameters::n_random_scalars(&mut rng, output_len),
        }
    }
}

#[derive(Clone, Debug)]
#[cfg_attr(feature = "with_serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "with_equality", derive(Eq, PartialEq))]
pub struct CoinsRequest {
    /// Input credentials representing coins.
    pub sigmas: Vec<Coin>,
    /// Kappa group elements associated with the input credentials (`sigmas`).
    pub kappas: Vec<G2Projective>,
    /// The common commitments Cm of the output coin values and ids.
    pub cms: Vec<G1Projective>,
    /// The blinded output coin values and ids.
    pub cs: Vec<(G1Projective, G1Projective, G1Projective)>,
    /// Commitments to the input value (used in the ZK proof).
    pub input_commitments: Vec<G1Projective>,
    /// Commitments to the output value (used in the ZK proof).
    pub output_commitments: Vec<G1Projective>,
    /// A ZK-proof asserting correctness of all the other fields and that the sum of the input
    /// coins equals the sum of the output coins.
    pub proof: RequestCoinsProof,
    /// The aggregated range proof over the output values.
    pub range_proof: RangeProof,
}

impl CoinsRequest {
    pub fn new(
        mut rng: impl rand::RngCore,
        // The system parameters.
        parameters: &Parameters,
        // The aggregated public key of the authorities.
        public_key: &PublicKey,
        // The credentials representing the input coins. Each credential has two attributes, a coin
        // value and a id.
        sigmas: &[Coin],
        // The attributes of the input coins (i.e., credentials `sigmas`).
        input_attributes: &[InputAttribute],
        // The attributes of the output coins along with their blinding factors.
        output_attributes: &[OutputAttribute],
    ) -> Self {
        assert!(sigmas.len() == input_attributes.len());
        assert!(parameters.max_attributes() >= 3);
        assert!(public_key.max_attributes() >= 3);
        assert!(parameters.max_attributes() >= output_attributes.len());

        // Generate all random values for the commitments.
        let randomness = Randomness::new(&mut rng, input_attributes.len(), output_attributes.len());

        // Randomize the input credentials; each credential represents an input coin.
        let sigmas: Vec<_> = sigmas
            .iter()
            .cloned()
            .zip(randomness.rs.iter())
            .map(|(mut sigma, r)| {
                sigma.randomize(&mut rng);
                Coin(sigma.0, sigma.1 + sigma.0 * r)
            })
            .collect();

        // Compute Kappa for each input coin.
        let beta0 = &public_key.betas[0];
        let beta1 = &public_key.betas[1];
        let kappas = input_attributes
            .iter()
            .zip(randomness.rs.iter())
            .map(|(x, r)| public_key.alpha + beta0 * x.value + beta1 * x.seed + parameters.g2 * r)
            .collect();

        // Compute the common commitment Cm for the outputs.
        let h0 = &parameters.hs[0];
        let h1 = &parameters.hs[1];
        let h2 = &parameters.hs[2];
        let cms: Vec<_> = output_attributes
            .iter()
            .zip(randomness.os.iter())
            .map(|(x, o)| h0 * x.value + h1 * x.seed + h2 * x.id + parameters.g1 * o)
            .collect();

        // Compute the base group element h.
        let base_hs: Vec<_> = cms
            .iter()
            .map(|cm| Parameters::hash_to_g1(cm.to_bytes()))
            .collect();

        // Commit to the output attributes.
        let cs: Vec<_> = output_attributes
            .iter()
            .zip(base_hs.iter())
            .map(|(x, h)| {
                (
                    h * x.value + parameters.g1 * x.value_blinding_factor,
                    h * x.seed + parameters.g1 * x.seed_blinding_factor,
                    h * x.id + parameters.g1 * x.id_blinding_factor,
                )
            })
            .collect();

        // Commit to the input coin values to prove that the sum of the inputs equals the sum of the outputs.
        // The commitments to the output values is made as part of bulletproof.
        let input_commitments: Vec<_> = input_attributes
            .iter()
            .zip(randomness.input_rs.iter())
            .map(|(x, r)| parameters.hs[0] * x.value + parameters.g1 * r)
            .collect();

        // Compute the ZK proof asserting correctness of the computations above.
        let proof = RequestCoinsProof::new(
            rng,
            parameters,
            public_key,
            &base_hs,
            input_attributes,
            output_attributes,
            &randomness,
        );

        // Make the range proofs over the output values.
        let bp_gens = &parameters.bulletproof_gens;
        let pc_gens = PedersenGens {
            B: parameters.hs[0],
            B_blinding: parameters.g1,
        };
        let mut prover_transcript = Transcript::new(b"CocoBullets");
        let secret_values: Vec<_> = output_attributes
            .iter()
            .map(|x| {
                let bytes_value: [u8; 8] = x.value.to_bytes()[0..8].try_into().unwrap();
                u64::from_le_bytes(bytes_value)
            })
            .collect();
        let (range_proof, output_commitments) = RangeProof::prove_multiple(
            bp_gens,
            &pc_gens,
            &mut prover_transcript,
            &secret_values,
            &randomness.output_rs.to_vec(),
            32,
        )
        .expect("Failed to generate range proof");

        Self {
            sigmas,
            kappas,
            cms,
            cs,
            input_commitments,
            output_commitments,
            proof,
            range_proof,
        }
    }

    /// Verifies the coin request.
    pub fn verify(
        &self,
        // The system parameters.
        parameters: &Parameters,
        // The authorities aggregated key.
        public_key: &PublicKey,
        // The ids of the input coins.
        input_ids: &[Scalar],
        // The offset between the input and output coins: output = input + offset.
        offset: &Scalar,
    ) -> CoconutResult<()> {
        // Verify the ZK proof.
        self.proof.verify(
            parameters,
            public_key,
            &self.sigmas,
            &self.kappas,
            &self.cms,
            &self.cs,
            &self.input_commitments,
            &self.output_commitments,
            offset,
        )?;

        // Check the range proofs.
        let bp_gens = &parameters.bulletproof_gens;
        let pc_gens = PedersenGens {
            B: parameters.hs[0],
            B_blinding: parameters.g1,
        };
        let mut verifier_transcript = Transcript::new(b"CocoBullets");
        self.range_proof.verify_multiple(
            bp_gens,
            &pc_gens,
            &mut verifier_transcript,
            &self.output_commitments,
            32,
        )?;

        // Check the pairing equations.
        let beta2 = &public_key.betas[2];
        self.kappas
            .iter()
            .zip(self.sigmas.iter())
            .zip(input_ids.iter())
            .all(|((kappa, sigma), id)| {
                !bool::from(sigma.0.is_identity())
                    && Parameters::check_pairing(
                        &sigma.0,
                        &(kappa + beta2 * id),
                        &sigma.1,
                        &parameters.g2,
                    )
            })
            .then(|| ())
            .ok_or(CoconutError::PairingCheckFailed)
    }
}
