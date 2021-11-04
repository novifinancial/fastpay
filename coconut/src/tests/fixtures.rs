// Copyright (c) Facebook, Inc. and its affiliates.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    issuance::Coin,
    request::{CoinsRequest, InputAttribute, OutputAttribute},
    setup::{KeyPair, Parameters, PublicKey},
};
use bls12_381::Scalar;
use rand::SeedableRng;

// Fixture
pub fn parameters() -> Parameters {
    Parameters::new(2, 2)
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

pub fn input_attribute1() -> InputAttribute {
    InputAttribute {
        value: Scalar::one(),
        id: Scalar::from(1234),
    }
}

pub fn input_attribute2() -> InputAttribute {
    InputAttribute {
        value: Scalar::from(3),
        id: Scalar::from(5678),
    }
}

// Fixture
pub fn input_attributes() -> Vec<InputAttribute> {
    vec![input_attribute1(), input_attribute2()]
}

// Fixture
pub fn output_attributes() -> Vec<OutputAttribute> {
    vec![
        OutputAttribute {
            value: Scalar::from(2),
            value_blinding_factor: Scalar::from(10),
            id: Scalar::from(9123),
            id_blinding_factor: Scalar::from(20),
        },
        OutputAttribute {
            value: Scalar::from(3),
            value_blinding_factor: Scalar::from(30),
            id: Scalar::from(4567),
            id_blinding_factor: Scalar::from(40),
        },
    ]
}

// Fixture
pub fn offset() -> Scalar {
    Scalar::one()
}

// Fixture
pub fn coin1() -> Coin {
    Coin::default(
        &parameters(),
        &keypair().secret,
        &input_attribute1().value,
        &input_attribute1().id,
    )
}

// Fixture
pub fn coin2() -> Coin {
    Coin::default(
        &parameters(),
        &keypair().secret,
        &input_attribute2().value,
        &input_attribute2().id,
    )
}

// Fixture
pub fn request() -> CoinsRequest {
    CoinsRequest::new(
        rand::rngs::StdRng::seed_from_u64(37),
        &parameters(),
        &keypair().public,
        /* sigmas */ &vec![coin1(), coin2()],
        &input_attributes(),
        &output_attributes(),
    )
}
