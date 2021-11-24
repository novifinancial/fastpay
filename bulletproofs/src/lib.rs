// Copyright (c) 2018 Chain, Inc.
// SPDX-License-Identifier: MIT
// Copyright (c) Facebook, Inc. and its affiliates.
// SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]
#![allow(clippy::many_single_char_names)]

mod errors;
mod generators;
mod inner_product_proof;
mod range_proof;
mod transcript;
mod util;

pub use crate::{
    errors::ProofError,
    generators::{BulletproofGens, BulletproofGensShare, PedersenGens},
    range_proof::RangeProof,
};

pub mod range_proof_mpc {
    pub use crate::{
        errors::MPCError,
        range_proof::{dealer, messages, party},
    };
}
