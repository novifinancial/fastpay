use crate::issue::Coin;
use crate::setup::{KeyPair, Parameters, PublicKey, SecretKey};
use bls12_381::Scalar;

// Fixture
pub fn parameters() -> Parameters {
    Parameters::new(2)
}

// Fixture
pub fn keypairs() -> Vec<KeyPair> {
    (0..4)
        .map(|i| {
            let secret = SecretKey {
                x: Scalar::from(100 + i),
                ys: vec![Scalar::from(200 + i), Scalar::from(300 + i)],
            };
            let public = PublicKey::new(&parameters(), &secret);
            KeyPair {
                index: i,
                secret,
                public,
            }
        })
        .collect()
}

// Fixture
pub fn keypair() -> KeyPair {
    keypairs().pop().unwrap()
}

// Fixture
pub fn coin1() -> Coin {
    let value = Scalar::one();
    let id = Scalar::from(1234);
    Coin::new(&mut parameters(), &keypair().secret, &value, &id)
}

// Fixture
pub fn coin3() -> Coin {
    let value = Scalar::from(3);
    let id = Scalar::from(5678);
    Coin::new(&mut parameters(), &keypair().secret, &value, &id)
}
