// Copyright (c) Facebook, Inc. and its affiliates.
// SPDX-License-Identifier: Apache-2.0

use crate::fixtures::{keypair, parameters, request};

#[test]
fn verify_request() {
    assert!(request().verify(&parameters(), &keypair().public).is_ok());
}
