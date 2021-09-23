use super::*;
use crate::common::{coin1, coin3, keypair};

#[test]
fn request() {
    let mut parameters = Parameters::new(2);
    let public_key = keypair().public;
    let sigmas = vec![coin1(), coin3()];
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
        &mut parameters,
        &public_key,
        &sigmas,
        &input_attributes,
        &output_attributes,
        &blinding_factors,
    );

    assert!(request.verify(&parameters).is_ok());
}
