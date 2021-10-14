use super::*;
use crate::fixtures::{input_attributes, keypair, output_attributes, parameters, request};

#[test]
fn verify_zk_proof() {
    let coin_request = request();
    let randomness = Randomness::test(/* input_len */ 2, /* output_len */ 2);

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
        &randomness,
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
