use thiserror::Error;

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("TLS error: {0}")]
    Tls(#[from] rustls::Error),

    #[error("Certificate error: {0}")]
    Certificate(String),

    #[error("Private key error: {0}")]
    PrivateKey(String),

    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Certificate verification failed: {0}")]
    VerificationFailed(String),

    #[error("rcgen error: {0}")]
    Rcgen(#[from] rcgen::Error),
}

pub type Result<T> = std::result::Result<T, TransportError>;