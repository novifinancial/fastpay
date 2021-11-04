// Copyright (c) Facebook, Inc. and its affiliates.
// SPDX-License-Identifier: Apache-2.0

use crate::fixtures::{keypair, offset, parameters, request};

#[test]
fn verify_request() {
    assert!(request()
        .verify(&parameters(), &keypair().public, &offset())
        .is_ok());
}
