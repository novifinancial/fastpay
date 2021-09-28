use crate::issuance::Coin;
use crate::request::CoinsRequest;
use crate::setup::{KeyPair, Parameters, PublicKey};
use bls12_381::Scalar;

// Fixture
pub fn parameters() -> Parameters {
    Parameters::new(2)
}

// Fixture
pub fn keypairs() -> Vec<KeyPair> {
    let (_, keys) = KeyPair::default_ttp(
        &parameters(),
        /* committee */ 4,
        /* threshold */ 3,
    );
    keys
}

// Fixture
pub fn keypair() -> KeyPair {
    keypairs().pop().unwrap()
}

// Fixture
pub fn aggregated_key() -> PublicKey {
    let (key, _) = KeyPair::default_ttp(
        &parameters(),
        /* committee */ 4,
        /* threshold */ 3,
    );
    key
}

// Fixture
pub fn coin1() -> Coin {
    let value = Scalar::one();
    let id = Scalar::from(1234);
    Coin::default(&mut parameters(), &keypair().secret, &value, &id)
}

// Fixture
pub fn coin2() -> Coin {
    let value = Scalar::from(3);
    let id = Scalar::from(5678);
    Coin::default(&mut parameters(), &keypair().secret, &value, &id)
}

// Fixture
pub fn request() -> (CoinsRequest, Vec<(Scalar, Scalar)>) {
    let public_key = keypair().public;
    let sigmas = vec![coin1(), coin2()];
    let input_attributes = vec![
        (Scalar::from(1), Scalar::from(1234)),
        (Scalar::from(3), Scalar::from(5678)),
    ];
    let output_attributes = vec![
        (Scalar::from(2), Scalar::from(9123)),
        (Scalar::from(2), Scalar::from(4567)),
    ];
    let blinding_factors = vec![
        (Scalar::from(10), Scalar::from(20)),
        (Scalar::from(30), Scalar::from(40)),
    ];

    let request = CoinsRequest::new(
        &mut parameters(),
        &public_key,
        &sigmas,
        &input_attributes,
        &output_attributes,
        &blinding_factors,
    );

    (request, blinding_factors)
}
