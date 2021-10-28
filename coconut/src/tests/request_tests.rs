use crate::fixtures::{keypair, parameters, request};

#[test]
fn verify_request() {
    assert!(request().verify(&parameters(), &keypair().public).is_ok());
}
