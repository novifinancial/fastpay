use crate::fixtures::{parameters, request};

#[test]
fn verify_request() {
    let (message, _) = request();
    assert!(message.verify(&parameters()).is_ok());
}
