use thiserror::Error;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("configuration error: {0}")]
    Config(#[from] anyhow::Error),

    #[error("transport error: {0}")]
    Transport(#[from] TransportError),

    #[error("module error: {0}")]
    Module(#[from] ModuleError),

    #[error("agent not running")]
    NotRunning,

    #[error("agent already running")]
    AlreadyRunning,
}

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("connection failed: {0}")]
    ConnectionFailed(String),

    #[error("TLS error: {0}")]
    Tls(#[from] rustls::Error),

    #[error("certificate error: {0}")]
    Certificate(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Error)]
pub enum ModuleError {
    #[error("module not found: {0}")]
    NotFound(String),

    #[error("module initialization failed: {0}")]
    InitFailed(String),

    #[error("module execution failed: {0}")]
    ExecutionFailed(String),
}

pub type Result<T> = std::result::Result<T, CoreError>;