// Copyright (c) Facebook, Inc. and its affiliates.
// SPDX-License-Identifier: Apache-2.0

use crate::fixtures::{input_attributes, keypair, offset, parameters, request};

#[test]
fn verify_request() {
    let input_ids = vec![input_attributes()[0].id, input_attributes()[1].id];
    assert!(request()
        .verify(&parameters(), &keypair().public, &input_ids, &offset())
        .is_ok());
}
