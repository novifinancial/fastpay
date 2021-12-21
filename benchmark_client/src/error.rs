use fastpay_core::{error::FastPayError, serialize::SerializedMessage};
use std::{fmt::Debug, net::SocketAddr};
use thiserror::Error;
use tokio::task::JoinError;

#[derive(Error, Debug)]
pub enum BenchError {
    #[error("Failed to connect to {0}: {1}")]
    FailedToConnect(SocketAddr, std::io::Error),

    #[error("Failed to send message to {0}: {1}")]
    FailedToSendMessage(SocketAddr, std::io::Error),

    #[error("Failed to receive reply from {0}")]
    FailedToReceiveReply(SocketAddr),

    #[error("Receive unexpected reply from {0:?}")]
    UnexpectedReply(SerializedMessage),

    #[error("{0}")]
    SerializationError(String),

    #[error("{0}")]
    FastPayError(FastPayError),

    #[error("Received a response without a vote")]
    ResponseWithoutVote,

    #[error("Connection dropped")]
    ConnectionDropped,

    #[error(transparent)]
    ClientError(#[from] JoinError),
}

impl From<failure::Error> for BenchError {
    fn from(error: failure::Error) -> Self {
        BenchError::SerializationError(error.to_string())
    }
}

impl From<FastPayError> for BenchError {
    fn from(error: FastPayError) -> Self {
        BenchError::FastPayError(error)
    }
}
