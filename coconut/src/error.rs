// Copyright (c) Facebook, Inc. and its affiliates.
// SPDX-License-Identifier: Apache-2.0

use bulletproofs::ProofError;
use thiserror::Error;

#[macro_export]
macro_rules! bail {
    ($e:expr) => {
        return Err($e);
    };
}

#[macro_export(local_inner_macros)]
macro_rules! ensure {
    ($cond:expr, $e:expr) => {
        if !($cond) {
            bail!($e);
        }
    };
}

pub type CoconutResult<T> = Result<T, CoconutError>;

#[derive(Debug, Error)]
pub enum CoconutError {
    #[error("Pairing check failed")]
    PairingCheckFailed,

    #[error("ZK check failed")]
    MalformedCoinRequest,

    #[error("Range proof check failed")]
    ValueOutOfRange(#[from] ProofError),
}
