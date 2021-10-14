use super::*;
use crate::fixtures::{input_attributes, keypair, output_attributes, parameters, request};

#[test]
fn verify_zk_proof() {
    let rs = vec![Scalar::from(100), Scalar::from(100)];
    let os = vec![Scalar::from(200), Scalar::from(200)];
    let input_rs = vec![Scalar::from(300), Scalar::from(300)];
    let output_rs = vec![Scalar::from(400), Scalar::from(400)];

    let coin_request = request();

    let base_hs: Vec<_> = coin_request
        .cms
        .iter()
        .map(|cm| Parameters::hash_to_g1(cm.to_bytes()))
        .collect();

    let proof = RequestCoinsProof::new(
        &mut parameters(),
        &keypair().public,
        &base_hs,
        &coin_request.sigmas,
        &input_attributes(),
        &output_attributes(),
        &os,
        &rs,
        &input_rs,
        &output_rs,
    );

    let result = proof.verify(
        &parameters(),
        &keypair().public,
        &coin_request.sigmas,
        &coin_request.kappas,
        &coin_request.nus,
        &coin_request.cms,
        &coin_request.cs,
        &coin_request.input_commitments,
        &coin_request.output_commitments,
    );
    assert!(result.is_ok());
}
