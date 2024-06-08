use thiserror::Error;

/// ATMError
#[derive(Error, Debug)]
pub enum ATMError {
    #[error("DID error: {0}")]
    DIDError(String),
    #[error("Secrets error: {0}")]
    SecretsError(String),
    #[error("SSL error: {0}")]
    SSLError(String),
    #[error("HTTPS error: {0}")]
    HTTPSError(String),
    #[error("Message sending error: {0}")]
    MsgSendError(String),
    #[error("Config error: {0}")]
    ConfigError(String),
    #[error("Authentication error: {0}")]
    AuthenticationError(String),
    #[error("DIDComm message error: {0}. Reason: {1}")]
    DidcommError(String, String),
}
