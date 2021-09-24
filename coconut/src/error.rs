use thiserror::Error;

pub type CoconutResult<T> = Result<T, CoconutError>;

#[derive(Debug, Error)]
pub enum CoconutError {
    #[error("Pairing check failed")]
    PairingCheckFailed,
}
