use super::*;
use crate::fixtures::{keypair, parameters, request};

impl Randomness {
    pub fn test(input_len: usize, output_len: usize) -> Self {
        Self {
            rs: (0..input_len)
                .map(|i| Scalar::from(100 + i as u64))
                .collect(),
            os: (0..output_len)
                .map(|i| Scalar::from(200 + i as u64))
                .collect(),
            input_rs: (0..input_len)
                .map(|i| Scalar::from(300 + i as u64))
                .collect(),
            output_rs: (0..output_len)
                .map(|i| Scalar::from(400 + i as u64))
                .collect(),
        }
    }
}

#[test]
fn verify_request() {
    assert!(request().verify(&parameters(), &keypair().public).is_ok());
}
