use thiserror::Error;

/*
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
*/

pub type CoconutResult<T> = Result<T, CoconutError>;

#[derive(Debug, Error)]
pub enum CoconutError {
    #[error("Unexpected number of attributes; expected {expected:}, got {got:}")]
    TooManyAttributes { expected: usize, got: usize },

    #[error("Invalid message")]
    InvalidMessage,

    #[error("Pairing check failed")]
    PairingCheckFailed,
}
