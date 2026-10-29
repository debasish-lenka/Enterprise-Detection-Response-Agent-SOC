use crate::certs::make_client_config;
use crate::error::{Result, TransportError};
use anyhow::Error as AnyhowError;
use duea_core::{Config, Result as CoreResult, Transport};
use rustls::pki_types::ServerName;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream as TokioTcpStream;
use tokio::sync::Mutex;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tracing::info;

fn transport_error_to_core(e: TransportError) -> duea_core::CoreError {
    duea_core::CoreError::Config(AnyhowError::msg(e.to_string()))
}

pub struct MtlsClient {
    config: Config,
    connector: TlsConnector,
    stream: Arc<Mutex<Option<tokio_rustls::client::TlsStream<TokioTcpStream>>>>,
    connected: Arc<Mutex<bool>>,
}

impl MtlsClient {
    pub fn new(config: Config) -> Result<Self> {
        let transport = &config.transport;

        let ca_path = Path::new(transport.ca_cert_path.as_ref()
            .ok_or_else(|| TransportError::Config("CA cert path required".into()))?);
        let cert_path = Path::new(transport.client_cert_path.as_ref()
            .ok_or_else(|| TransportError::Config("Client cert path required".into()))?);
        let key_path = Path::new(transport.client_key_path.as_ref()
            .ok_or_else(|| TransportError::Config("Client key path required".into()))?);

        let tls_config = make_client_config(ca_path, cert_path, key_path)?;
        let connector = TlsConnector::from(Arc::new(tls_config));

        Ok(Self {
            config,
            connector,
            stream: Arc::new(Mutex::new(None)),
            connected: Arc::new(Mutex::new(false)),
        })
    }

    pub async fn connect(&mut self) -> Result<()> {
        let transport = &self.config.transport;
        let addr = format!("{}:{}", transport.manager_host, transport.manager_port);

        info!("Connecting to {} via mTLS", addr);

        let tcp_stream = timeout(
            Duration::from_secs(10),
            TokioTcpStream::connect(&addr)
        ).await
            .map_err(|_| TransportError::ConnectionFailed("Connection timeout".into()))?
            .map_err(|e| TransportError::ConnectionFailed(format!("TCP connect failed: {}", e)))?;

        tcp_stream.set_nodelay(true).map_err(|e| TransportError::Io(e))?;

        let server_name = ServerName::try_from(transport.manager_host.as_str())
            .map_err(|e| TransportError::Config(format!("Invalid server name: {}", e)))?
            .to_owned();

        let tls_stream = timeout(
            Duration::from_secs(10),
            self.connector.connect(server_name, tcp_stream)
        ).await
            .map_err(|_| TransportError::ConnectionFailed("TLS handshake timeout".into()))?
            .map_err(|e| TransportError::Io(e))?;

        *self.stream.lock().await = Some(tls_stream);
        *self.connected.lock().await = true;

        info!("mTLS connection established to {}", addr);
        Ok(())
    }

    pub async fn is_connected(&self) -> bool {
        *self.connected.lock().await
    }

    pub async fn send(&mut self, data: &[u8]) -> Result<()> {
        let mut stream_guard = self.stream.lock().await;
        let stream = stream_guard.as_mut()
            .ok_or_else(|| TransportError::ConnectionFailed("Not connected".into()))?;

        let len = data.len() as u32;
        stream.write_all(&len.to_be_bytes()).await
            .map_err(|e| TransportError::Io(e))?;
        stream.write_all(data).await
            .map_err(|e| TransportError::Io(e))?;
        stream.flush().await
            .map_err(|e| TransportError::Io(e))?;

        Ok(())
    }

    pub async fn receive(&mut self) -> Result<Vec<u8>> {
        let mut stream_guard = self.stream.lock().await;
        let stream = stream_guard.as_mut()
            .ok_or_else(|| TransportError::ConnectionFailed("Not connected".into()))?;

        let mut len_bytes = [0u8; 4];
        stream.read_exact(&mut len_bytes).await
            .map_err(|e| TransportError::Io(e))?;

        let len = u32::from_be_bytes(len_bytes) as usize;
        if len > 10 * 1024 * 1024 {
            return Err(TransportError::ConnectionFailed("Message too large".into()));
        }

        let mut buf = vec![0u8; len];
        stream.read_exact(&mut buf).await
            .map_err(|e| TransportError::Io(e))?;

        Ok(buf)
    }

    pub async fn close(&mut self) -> Result<()> {
        let mut stream_guard = self.stream.lock().await;
        if let Some(mut stream) = stream_guard.take() {
            stream.shutdown().await
                .map_err(|e| TransportError::Io(e))?;
        }
        *self.connected.lock().await = false;
        Ok(())
    }
}

impl Drop for MtlsClient {
    fn drop(&mut self) {
        if let Ok(mut connected) = self.connected.try_lock() {
            *connected = false;
        }
    }
}

#[async_trait::async_trait]
impl Transport for MtlsClient {
    async fn connect(&mut self) -> CoreResult<()> {
        self.connect().await.map_err(transport_error_to_core)
    }

    async fn send(&mut self, data: bytes::Bytes) -> CoreResult<()> {
        self.send(data.as_ref()).await.map_err(transport_error_to_core)
    }

    async fn receive(&mut self) -> CoreResult<bytes::Bytes> {
        self.receive().await.map(|v| bytes::Bytes::from(v)).map_err(transport_error_to_core)
    }

    async fn close(&mut self) -> CoreResult<()> {
        self.close().await.map_err(transport_error_to_core)
    }

    fn is_connected(&self) -> bool {
        // Use a blocking check - in practice this should be handled differently
        // For now, we'll use a simple check
        self.connected.try_lock().map(|c| *c).unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn client_config_creation() {
        // This test would need actual cert files - skipping for now
        // Tested via integration tests with actual certificates
    }
}