// Copyright (c) 2018 Chain, Inc.
// SPDX-License-Identifier: MIT
// Copyright (c) Facebook, Inc. and its affiliates.
// SPDX-License-Identifier: Apache-2.0

use thiserror::Error;

/// Represents an error in proof creation, verification, or parsing.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum ProofError {
    #[error("Proof verification failed.")]
    VerificationError,

    #[error("Proof data could not be parsed.")]
    FormatError,

    #[error("Wrong number of blinding factors supplied.")]
    WrongNumBlindingFactors,

    #[error("Invalid bitsize, must have n = 8,16,32,64.")]
    InvalidBitsize,

    #[error("Invalid aggregation size, m must be a power of 2.")]
    InvalidAggregation,

    #[error("Invalid generators size, too few generators for proof")]
    InvalidGeneratorsLength,

    #[error("Internal error during proof creation: {0}")]
    ProvingError(MPCError),
}

impl From<MPCError> for ProofError {
    fn from(e: MPCError) -> ProofError {
        match e {
            MPCError::InvalidBitsize => ProofError::InvalidBitsize,
            MPCError::InvalidAggregation => ProofError::InvalidAggregation,
            MPCError::InvalidGeneratorsLength => ProofError::InvalidGeneratorsLength,
            _ => ProofError::ProvingError(e),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum MPCError {
    #[error("Dealer gave a malicious challenge value.")]
    MaliciousDealer,

    #[error("Invalid bitsize, must have n = 8,16,32,64")]
    InvalidBitsize,

    #[error("Invalid aggregation size, m must be a power of 2")]
    InvalidAggregation,

    #[error("Invalid generators size, too few generators for proof")]
    InvalidGeneratorsLength,

    #[error("Wrong number of value commitments")]
    WrongNumBitCommitments,

    #[error("Wrong number of value commitments")]
    WrongNumPolyCommitments,

    #[error("Wrong number of proof shares")]
    WrongNumProofShares,

    #[error("Malformed proof shares from parties {bad_shares:?}")]
    MalformedProofShares { bad_shares: Vec<usize> },
}
