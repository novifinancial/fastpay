use crate::error::{CoconutError, CoconutResult};
use crate::setup::{Parameters, PublicKey, SecretKey};
use crate::Coin;
use bls12_381::{G1Projective, G2Projective, Scalar};
use group::GroupEncoding as _;

/// Represents a ZK proof of valid coin requests.
type RequestCoinsProof = usize;

pub struct CoinsRequest {
    /// Input credentials representing coins.
    sigmas: Vec<Coin>,
    /// Kappa group elements associated with the input credentials (`sigmas`).
    kappas: Vec<G2Projective>,
    /// Nu group elements associated with the input credentials (`sigmas`).
    nus: Vec<G1Projective>,
    /// The common commitments Cm of the output coin values and ids.
    _cms: Vec<G1Projective>,
    /// The blinded output coin values and ids.
    _cs: Vec<(G1Projective, G1Projective)>,
    /// A ZK-proof asserting correctness of all the other fields and that the sum of the input
    /// coins equals the sum of the output coins.
    _proof: RequestCoinsProof,
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
        debug_assert!(output_attributes.len() * 2 == blinding_factors.len());
        debug_assert!(parameters.max_attributes() >= 2);

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
        let rs: Vec<_> = parameters.n_random_scalars(input_attributes.len());

        // Compute Kappa and Nu for each input credential.
        let beta0 = &public_key.betas[0];
        let beta1 = &public_key.betas[1];
        let kappas: Vec<_> = input_attributes
            .iter()
            .zip(rs.iter())
            .map(|((v, id), r)| public_key.alpha + beta0 * v + beta1 * id + parameters.g2 * r)
            .collect();
        let nus: Vec<_> = rs
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
        let proof = Self::make_proof();

        Self {
            sigmas,
            kappas,
            nus,
            _cms: cms,
            _cs: cs,
            _proof: proof,
        }
    }

    pub fn verify(&self, parameters: &Parameters) -> CoconutResult<()> {
        // Verify the ZK proof.
        self.verify_proof()?;

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
            .ok_or_else(|| CoconutError::PairingCheckFailed)
    }

    fn make_proof() -> RequestCoinsProof {
        // TODO
        unimplemented!()
    }

    fn verify_proof(&self) -> CoconutResult<()> {
        // TODO
        unimplemented!()
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
        let base_hs: Vec<_> = cms
            .iter()
            .map(|cm| Parameters::hash_to_g1(cm.to_bytes()))
            .collect();

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
            .map(|((h, b), (k_value, k_id))| {
                Coin(h.clone(), b + gamma_0 * (-k_value) + gamma_1 * (-k_id))
            })
            .collect()
    }
}
