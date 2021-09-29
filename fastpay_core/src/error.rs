// Copyright (c) Facebook Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::{base_types::*, messages::Value};
use failure::Fail;
use serde::{Deserialize, Serialize};

#[macro_export]
macro_rules! fp_bail {
    ($e:expr) => {
        return Err($e);
    };
}

#[macro_export(local_inner_macros)]
macro_rules! fp_ensure {
    ($cond:expr, $e:expr) => {
        if !($cond) {
            fp_bail!($e);
        }
    };
}

#[derive(Eq, PartialEq, Clone, Debug, Serialize, Deserialize, Fail, Hash)]
/// Custom error type for FastPay.
pub enum FastPayError {
    // Signature verification
    #[fail(display = "Request was not signed by an authorized owner")]
    InvalidOwner,
    #[fail(display = "Signature for object {} is not valid: {}", type_name, error)]
    InvalidSignature { error: String, type_name: String },
    #[fail(display = "Value was not signed by a known authority")]
    UnknownSigner,
    // Certificate verification
    #[fail(display = "Signatures in a certificate must form a quorum")]
    CertificateRequiresQuorum,
    // Transfer processing
    #[fail(display = "Transfers must have positive amount")]
    IncorrectTransferAmount,
    #[fail(
        display = "The given sequence number must match the next expected sequence number of the account"
    )]
    UnexpectedSequenceNumber,
    #[fail(
        display = "The transferred amount must be not exceed the current account balance: {:?}",
        current_balance
    )]
    InsufficientFunding { current_balance: Balance },
    #[fail(display = "Invalid new account id: {}", 0)]
    InvalidNewAccountId(AccountId),
    #[fail(
        display = "Cannot initiate transfer while a transfer order is still pending confirmation: {:?}",
        pending
    )]
    PreviousRequestMustBeConfirmedFirst { pending: Value },
    #[fail(display = "Request order was processed but no signature was produced by authority")]
    ErrorWhileProcessingRequestOrder,
    #[fail(
        display = "An invalid answer was returned by the authority while requesting a certificate"
    )]
    ErrorWhileRequestingCertificate,
    #[fail(
        display = "Cannot confirm a request while previous request orders are still pending confirmation: {:?}",
        current_sequence_number
    )]
    MissingEarlierConfirmations {
        current_sequence_number: VersionNumber,
    },
    // Synchronization validation
    #[fail(display = "Transaction index must increase by one")]
    UnexpectedTransactionIndex,
    // Account access
    #[fail(display = "No certificate for this account and sequence number")]
    CertificateNotFound,
    #[fail(display = "The account being queried is not active {:?}", 0)]
    InactiveAccount(AccountId),
    #[fail(display = "Signatures in a certificate must be from different authorities.")]
    CertificateAuthorityReuse,
    #[fail(display = "Sequence numbers above the maximal value are not usable for requests.")]
    InvalidSequenceNumber,
    #[fail(display = "Sequence number overflow.")]
    SequenceOverflow,
    #[fail(display = "Sequence number underflow.")]
    SequenceUnderflow,
    #[fail(display = "Amount overflow.")]
    AmountOverflow,
    #[fail(display = "Amount underflow.")]
    AmountUnderflow,
    #[fail(display = "Account balance overflow.")]
    BalanceOverflow,
    #[fail(display = "Account balance underflow.")]
    BalanceUnderflow,
    #[fail(display = "Wrong shard used.")]
    WrongShard,
    #[fail(display = "Invalid cross shard request.")]
    InvalidCrossShardRequest,
    #[fail(display = "Cannot deserialize.")]
    InvalidDecoding,
    #[fail(display = "Unexpected message.")]
    UnexpectedMessage,
    #[fail(display = "Invalid request order.")]
    InvalidRequestOrder,
    #[fail(display = "Invalid confirmation order.")]
    InvalidConfirmationOrder,
    #[fail(display = "Invalid coin creation order.")]
    InvalidCoinCreationOrder,
    #[fail(display = "Invalid coin.")]
    InvalidCoin,
    #[fail(display = "Network error while querying service: {:?}.", error)]
    ClientIoError { error: String },
}
