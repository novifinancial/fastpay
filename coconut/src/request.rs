use crate::{
    error::{CoconutError, CoconutResult},
    issuance::Coin,
    proof::RequestCoinsProof,
    setup::{Parameters, PublicKey},
};
use bls12_381::{G1Projective, G2Projective, Scalar};
use group::GroupEncoding as _;
#[cfg(feature = "with_serde")]
use serde::{Deserialize, Serialize};
use bulletproofs::{RangeProof, PedersenGens,};
use merlin::Transcript;
use std::convert::TryInto as _;

#[cfg(test)]
#[path = "tests/request_tests.rs"]
pub mod request_tests;

/// The attributes of the input coin.
#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "with_serde", derive(Serialize, Deserialize))]
pub struct InputAttribute {
    /// The id of the input coin.
    pub id: Scalar,
    /// The value of the input coin.
    pub value: Scalar,
}

/// The attributes of the output coins along with their blinding factors.
#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "with_serde", derive(Serialize, Deserialize))]
pub struct OutputAttribute {
    /// The id of the output coin.
    pub id: Scalar,
    /// The blinding factor used to hide the id of the output coin.
    pub id_blinding_factor: Scalar,
    /// The value of the output coin.
    pub value: Scalar,
    /// The blinding factor used to hide the value of the output coin.
    pub value_blinding_factor: Scalar,
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

#[derive(Clone)]
#[cfg_attr(feature = "with_serde", derive(Serialize, Deserialize))]
pub struct CoinsRequest {
    /// Input credentials representing coins.
    pub sigmas: Vec<Coin>,
    /// Kappa group elements associated with the input credentials (`sigmas`).
    pub kappas: Vec<G2Projective>,
    /// Nu group elements associated with the input credentials (`sigmas`).
    pub nus: Vec<G1Projective>,
    /// The common commitments Cm of the output coin values and ids.
    pub cms: Vec<G1Projective>,
    /// The blinded output coin values and ids.
    pub cs: Vec<(G1Projective, G1Projective)>,
    /// Commitments to the input value (used in the ZK proof).
    pub input_commitments: Vec<G1Projective>,
    /// Commitments to the output value (used in the ZK proof).
    pub output_commitments: Vec<G1Projective>,
    /// A ZK-proof asserting correctness of all the other fields and that the sum of the input
    /// coins equals the sum of the output coins.
    pub proof: RequestCoinsProof,
    /// The range proofs over the output values.
    pub range_proofs: Vec<RangeProof>
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
        assert!(parameters.max_attributes() >= 2);
        assert!(public_key.max_attributes() >= 2);

        // Generate all random values for the commitments.
        let randomness = Randomness::new(&mut rng, input_attributes.len(), output_attributes.len());

        // Randomize the input credentials; each credential represents an input coin.
        let sigmas: Vec<_> = sigmas
            .iter()
            .cloned()
            .map(|mut sigma| {
                sigma.randomize(&mut rng);
                sigma
            })
            .collect();

        // Compute Kappa and Nu for each input coin.
        let beta0 = &public_key.betas[0];
        let beta1 = &public_key.betas[1];
        let kappas = input_attributes
            .iter()
            .zip(randomness.rs.iter())
            .map(|(x, r)| public_key.alpha + beta0 * x.value + beta1 * x.id + parameters.g2 * r)
            .collect();
        let nus = randomness
            .rs
            .iter()
            .zip(sigmas.iter())
            .map(|(r, sigma)| sigma.0 * r)
            .collect();

        // Compute the common commitment Cm for the outputs.
        let h0 = &parameters.hs[0];
        let h1 = &parameters.hs[1];
        let cms: Vec<_> = output_attributes
            .iter()
            .zip(randomness.os.iter())
            .map(|(x, o)| h0 * x.value + h1 * x.id + parameters.g1 * o)
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
                    h * x.id + parameters.g1 * x.id_blinding_factor,
                )
            })
            .collect();

        // Commit to the input coin values to prove that the sum of the inputs equals the sum of the outputs.
        let input_commitments: Vec<_> = input_attributes
            .iter()
            .zip(randomness.input_rs.iter())
            .map(|(x, r)| parameters.hs[0] * x.value + parameters.g1 * r)
            .collect();
        /*
        let output_commitments: Vec<_> = output_attributes
            .iter()
            .zip(randomness.output_rs.iter())
            .map(|(x, r)| parameters.hs[0] * x.value + parameters.g1 * r)
            .collect();
        */

        // Compute the ZK proof asserting correctness of the computations above.
        let proof = RequestCoinsProof::new(
            rng,
            parameters,
            public_key,
            &base_hs,
            &sigmas,
            input_attributes,
            output_attributes,
            &randomness,
        );

        // Make the range proofs over the output values.
        let bp_gens = &parameters.bulletproof_gens;
        let pc_gens = PedersenGens {
            B: parameters.hs[0].clone(),
            B_blinding: parameters.g1.clone()
        };
        let mut prover_transcript = Transcript::new(b"CocoBullets");
        let mut range_proofs = Vec::new();
        let mut output_commitments = Vec::new();
        for (out, blinding) in output_attributes.iter().zip(randomness.output_rs.iter()) {
            let bytes_value: [u8; 8] = out.value.to_bytes()[0..8].try_into().unwrap();
            let secret_value = u64::from_le_bytes(bytes_value);
            
            let (proof, committed_value) = RangeProof::prove_single(
                &bp_gens,
                &pc_gens,
                &mut prover_transcript,
                secret_value,
                &blinding,
                32,
            ).expect("Failed to generate range proof");
            range_proofs.push(proof);
            output_commitments.push(committed_value);
        }

        Self {
            sigmas,
            kappas,
            nus,
            cms,
            cs,
            input_commitments,
            output_commitments,
            proof,
            range_proofs
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
            &self.input_commitments,
            &self.output_commitments,
        )?;

        // Check the range proofs.
        let bp_gens = &parameters.bulletproof_gens;
        let pc_gens = PedersenGens {
            B: parameters.hs[0].clone(),
            B_blinding: parameters.g1.clone()
        };
        let mut verifier_transcript = Transcript::new(b"CocoBullets");
        for (proof, commitment) in self.range_proofs.iter().zip(self.output_commitments.iter()) {
            proof.verify_single(&bp_gens, &pc_gens, &mut verifier_transcript, &commitment, 32)?;
        }

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
