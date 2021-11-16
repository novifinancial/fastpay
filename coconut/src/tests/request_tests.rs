// Copyright (c) Facebook, Inc. and its affiliates.
// SPDX-License-Identifier: Apache-2.0

use crate::fixtures::{input_attributes, keypair, offset, parameters, request};

#[test]
fn verify_request() {
    let input_keys = vec![input_attributes()[0].key, input_attributes()[1].key];
    assert!(request()
        .verify(&parameters(), &keypair().public, &input_keys, &offset())
        .is_ok());
}
