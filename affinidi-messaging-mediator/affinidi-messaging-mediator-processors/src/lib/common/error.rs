use thiserror::Error;

#[derive(Error, Debug)]
pub enum ProcessorError {
    #[error("ForwardingError: {0}")]
    ForwardingError(String),
    #[error("MessageExpiryCleanupError: {0}")]
    MessageExpiryCleanupError(String),
}
