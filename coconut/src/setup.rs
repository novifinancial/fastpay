use bls12_381::hash_to_curve::{ExpandMsgXmd, HashToCurve};
use bls12_381::{G1Projective, G2Prepared, G2Projective, Scalar};
use ff::Field as _;
use group::{Curve as _, Group as _};
use rand::rngs::ThreadRng;
use rand::thread_rng;
use sha2::Sha512;

/// G1 hash domain as defined by IETF:
/// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-11#appendix-J.9.1
const G1_HASH_DOMAIN: &[u8] = b"QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_RO_";

/// The global system parameters (public).
pub struct Parameters {
    /// A generator of G1.
    pub g1: G1Projective,
    /// Other generators of G1. The length of `hs` defines the maximum number of attributes
    /// that can be embedded into a credential.
    pub hs: Vec<G1Projective>,
    /// A generator of G2.
    pub g2: G2Projective,
    /// A RNG for fast randomness generation.
    rng: ThreadRng,
}

impl Parameters {
    pub fn new(max_attributes: usize) -> Parameters {
        Self {
            g1: G1Projective::generator(),
            hs: (0..max_attributes)
                .map(|x| Self::hash_to_g1(format!("h{}", x)))
                .collect(),
            g2: G2Projective::generator(),
            rng: thread_rng(),
        }
    }

    /// Return the maximum number of attributes that can be embedded into a credential.
    pub fn max_attributes(&self) -> usize {
        self.hs.len()
    }

    /// Pick a random scalar.
    pub fn random_scalar(&mut self) -> Scalar {
        Scalar::random(&mut self.rng)
    }

    /// Pick n random scalars.
    pub fn n_random_scalars(&mut self, n: usize) -> Vec<Scalar> {
        (0..n).map(|_| self.random_scalar()).collect()
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
pub struct SecretKey {
    pub x: Scalar,
    pub ys: Vec<Scalar>,
}

impl SecretKey {
    pub fn new(parameters: &mut Parameters) -> Self {
        Self {
            x: parameters.random_scalar(),
            ys: (0..parameters.max_attributes())
                .map(|_| parameters.random_scalar())
                .collect(),
        }
    }
}

/// The public key. This structure can represent the public key of a single authority or their
/// aggregated public key (aggregated keys are undistinguishable from single-authority keys).
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
}

/// Convenience structure representing the keypair of an authority.
pub struct KeyPair {
    /// The index of this authority (used for Lagrange interpolation).
    pub index: u64,
    /// The secret key of the authority.
    pub secret: SecretKey,
    /// The public key of the authority.
    pub public: PublicKey,
}

impl KeyPair {
    pub fn new(parameters: &mut Parameters, index: u64) -> Self {
        let secret = SecretKey::new(parameters);
        let public = PublicKey::new(parameters, &secret);
        Self {
            index,
            secret,
            public,
        }
    }
}
