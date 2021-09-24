use super::*;
use crate::fixtures::parameters;

impl KeyPair {
    pub fn default_ttp(
        parameters: &Parameters,
        committee: usize,
        threshold: usize,
    ) -> (PublicKey, Vec<KeyPair>) {
        let v = Polynomial {
            coefficients: (0..threshold).map(|_| Scalar::one()).collect(),
        };
        let ws: Vec<_> = (0..parameters.max_attributes())
            .map(|i| Polynomial {
                coefficients: (0..threshold)
                    .map(|_| Scalar::from(100 + i as u64))
                    .collect(),
            })
            .collect();

        // Compute the key of each authority
        KeyPair::derive_keys(&parameters, committee, v, ws)
    }
}

#[test]
fn check_pairing() {
    let p = parameters().g1 * Scalar::from(2);
    let q = parameters().g2 * Scalar::from(2);
    let r = parameters().g1 * Scalar::one();
    let s = parameters().g2 * Scalar::from(4);

    let ok = Parameters::check_pairing(&p, &q, &r, &s);
    assert!(ok);
}

#[test]
fn aggregate_key() {
    let (expected, keys) = KeyPair::default_ttp(
        &parameters(),
        /* committee */ 4,
        /* threshold */ 3,
    );

    // Aggregate alpha
    let shares: Vec<_> = keys
        .iter()
        .skip(1)
        .map(|key| (key.public.alpha, key.index))
        .collect();
    let alpha = Polynomial::lagrange_interpolate(&shares);
    assert_eq!(expected.alpha, alpha);

    // Aggregate the betas
    let betas: Vec<_> = (0..parameters().max_attributes())
        .map(|i| {
            let shares: Vec<_> = keys
                .iter()
                .skip(1)
                .map(|key| (key.public.betas[i], key.index))
                .collect();
            Polynomial::lagrange_interpolate(&shares)
        })
        .collect();
    assert_eq!(expected.betas, betas);

    // Aggregate the gammas
    let gammas: Vec<_> = (0..parameters().max_attributes())
        .map(|i| {
            let shares: Vec<_> = keys
                .iter()
                .skip(1)
                .map(|key| (key.public.gammas[i], key.index))
                .collect();
            Polynomial::lagrange_interpolate(&shares)
        })
        .collect();
    assert_eq!(expected.gammas, gammas);
}
