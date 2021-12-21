use fastpay_core::{error::FastPayError, serialize::SerializedMessage};
use std::{fmt::Debug, net::SocketAddr};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum NetworkError {
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
}

impl From<failure::Error> for NetworkError {
    fn from(error: failure::Error) -> Self {
        NetworkError::SerializationError(error.to_string())
    }
}

impl From<FastPayError> for NetworkError {
    fn from(error: FastPayError) -> Self {
        NetworkError::FastPayError(error)
    }
}
