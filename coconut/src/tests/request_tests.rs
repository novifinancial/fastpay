use super::*;
use crate::fixtures::{keypair, parameters, request};

#[test]
fn verify_zk_proof() {
    let input_attributes = vec![
        (Scalar::from(1), Scalar::from(1234)),
        (Scalar::from(3), Scalar::from(5678)),
    ];
    let output_attributes = vec![
        (Scalar::from(2), Scalar::from(9123)),
        (Scalar::from(2), Scalar::from(4567)),
    ];
    let os = vec![Scalar::from(400), Scalar::from(400)];
    let rs = vec![Scalar::from(100), Scalar::from(100)];
    let input_rs = vec![Scalar::from(200), Scalar::from(200)];
    let output_rs = vec![Scalar::from(300), Scalar::from(300)];
    let (request_message, blinding_factors) = request();

    let base_hs: Vec<_> = request_message
        .cms
        .iter()
        .map(|cm| Parameters::hash_to_g1(cm.to_bytes()))
        .collect();

    let proof = RequestCoinsProof::new(
        &mut parameters(),
        &keypair().public,
        &base_hs,
        &request_message.sigmas,
        &input_attributes,
        &output_attributes,
        &blinding_factors,
        &os,
        &rs,
        &input_rs,
        &output_rs,
    );

    let result = proof.verify(
        &parameters(),
        &keypair().public,
        &request_message.sigmas,
        &request_message.kappas,
        &request_message.nus,
        &request_message.cms,
        &request_message.cs,
        &request_message.input_commitments,
        &request_message.output_commitments,
    );
    assert!(result.is_ok());
}

#[test]
fn verify_request() {
    let (message, _) = request();
    assert!(message.verify(&parameters(), &keypair().public).is_ok());
}
