use thiserror::Error;
use bulletproofs::ProofError;

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
    ZKCheckFailed,

    #[error("Range proof check failed")]
    RangeCheckFailed(#[from] ProofError)
}
