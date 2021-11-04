use crate::lagrange::Polynomial;
use bls12_381::{
    hash_to_curve::{ExpandMsgXmd, HashToCurve},
    G1Projective, G2Prepared, G2Projective, Scalar,
};
use bulletproofs::BulletproofGens;
use ff::Field as _;
use group::{Curve as _, Group as _};
use rand::RngCore;
#[cfg(feature = "with_serde")]
use serde::{Deserialize, Serialize};
use sha2::Sha512;

#[cfg(test)]
#[path = "tests/setup_tests.rs"]
pub mod setup_tests;

/// G1 hash domain as defined by IETF:
/// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-11#appendix-J.9.1
const G1_HASH_DOMAIN: &[u8] = b"COCONUT-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_RO_";

/// The global system parameters (public).
#[derive(Clone)]
#[cfg_attr(feature = "with_serde", derive(Serialize, Deserialize))]
pub struct Parameters {
    /// A generator of G1.
    pub g1: G1Projective,
    /// Other generators of G1. The length of `hs` defines the maximum number of attributes
    /// that can be embedded into a credential.
    pub hs: Vec<G1Projective>,
    /// A generator of G2.
    pub g2: G2Projective,
    // Bulletproofs generators.
    pub bulletproof_gens: BulletproofGens,
}

impl Parameters {
    pub fn new(max_attributes: usize) -> Parameters {
        assert!(max_attributes > 0);

        Self {
            g1: G1Projective::generator(),
            hs: (0..max_attributes)
                .map(|x| Self::hash_to_g1(format!("h{}", x)))
                .collect(),
            g2: G2Projective::generator(),
            bulletproof_gens: BulletproofGens::new(64, 2),
        }
    }

    /// Return the maximum number of attributes that can be embedded into a credential.
    pub fn max_attributes(&self) -> usize {
        self.hs.len()
    }

    /// Pick n random scalars.
    pub fn n_random_scalars(mut rng: impl RngCore, n: usize) -> Vec<Scalar> {
        (0..n).map(|_| Scalar::random(&mut rng)).collect()
    }

    /// Hash a message into an element of G1.
    pub fn hash_to_g1<M: AsRef<[u8]>>(msg: M) -> G1Projective {
        <G1Projective as HashToCurve<ExpandMsgXmd<Sha512>>>::hash_to_curve(msg, G1_HASH_DOMAIN)
    }

    /// Check whether `e(P, Q) * e(-R, S) == id`.
    pub fn check_pairing(
        p: &G1Projective,
        q: &G2Projective,
        r: &G1Projective,
        s: &G2Projective,
    ) -> bool {
        let p = &p.to_affine();
        let q = &G2Prepared::from(q.to_affine());
        let r = &r.to_affine();
        let s = &G2Prepared::from(s.to_affine());

        bls12_381::multi_miller_loop(&[(p, q), (&(-r), s)])
            .final_exponentiation()
            .is_identity()
            .into()
    }
}

/// The secret key of each authority.
#[cfg_attr(feature = "with_serde", derive(Serialize, Deserialize))]
pub struct SecretKey {
    pub x: Scalar,
    pub ys: Vec<Scalar>,
}

/// The public key. This structure can represent the public key of a single authority or their
/// aggregated public key (aggregated keys are undistinguishable from single-authority keys).
#[derive(Clone, Debug, Eq, PartialEq, Default)]
#[cfg_attr(feature = "with_serde", derive(Serialize, Deserialize))]
pub struct PublicKey {
    pub alpha: G2Projective,
    pub betas: Vec<G2Projective>,
    pub gammas: Vec<G1Projective>,
}

impl PublicKey {
    /// Make a new public key from a secret key.
    pub fn new(parameters: &Parameters, secret: &SecretKey) -> Self {
        Self {
            alpha: parameters.g2 * secret.x,
            betas: secret.ys.iter().map(|y| parameters.g2 * y).collect(),
            gammas: secret.ys.iter().map(|y| parameters.g1 * y).collect(),
        }
    }

    /// Return the maximum number of attributes that can be embedded into a credential.
    pub fn max_attributes(&self) -> usize {
        self.betas.len()
    }
}

/// Convenience structure representing the keypair of an authority.
#[cfg_attr(feature = "with_serde", derive(Serialize, Deserialize))]
pub struct KeyPair {
    /// The index of this authority (used for Lagrange interpolation).
    pub index: u64,
    /// The secret key of the authority.
    pub secret: SecretKey,
    /// The public key of the authority.
    pub public: PublicKey,
}

impl KeyPair {
    /// Compute the keys of all authorities along with the aggregated public key. This function
    /// should be distributed so that no single authority learns the master secret key.
    pub fn ttp(
        mut rng: impl rand::RngCore,
        parameters: &Parameters,
        threshold: usize,
        committee: usize,
    ) -> (PublicKey, Vec<KeyPair>) {
        assert!(threshold <= committee && threshold > 0);

        let v = Polynomial::random(&mut rng, threshold - 1);
        let ws: Vec<_> = (0..parameters.max_attributes())
            .map(|_| Polynomial::random(&mut rng, threshold - 1))
            .collect();

        Self::derive_keys(parameters, committee, v, ws)
    }

    /// Helper function to derive keys from the polynomial. Separating `ttp` and `derive_keys` into
    /// separate functions is handy for tests.
    fn derive_keys(
        parameters: &Parameters,
        committee: usize,
        v: Polynomial,
        ws: Vec<Polynomial>,
    ) -> (PublicKey, Vec<KeyPair>) {
        // Compute the key of each authority
        let keys = (1..=committee)
            .map(|i| {
                let index = i as u64;
                let x = v.evaluate(&Scalar::from(index));
                let ys = ws
                    .iter()
                    .map(|w| w.evaluate(&Scalar::from(index)))
                    .collect();
                let secret = SecretKey { x, ys };
                let public = PublicKey::new(parameters, &secret);
                KeyPair {
                    index,
                    secret,
                    public,
                }
            })
            .collect();

        // Make the aggregated public key.
        let master_secret = SecretKey {
            x: v.evaluate(&Scalar::zero()),
            ys: ws.iter().map(|w| w.evaluate(&Scalar::zero())).collect(),
        };
        let master_public = PublicKey::new(parameters, &master_secret);
        (master_public, keys)
    }
}
