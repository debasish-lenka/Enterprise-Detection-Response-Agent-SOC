use async_trait::async_trait;
use bytes::Bytes;

#[async_trait]
pub trait Transport: Send + Sync {
    async fn connect(&mut self) -> crate::Result<()>;
    async fn send(&mut self, data: Bytes) -> crate::Result<()>;
    async fn receive(&mut self) -> crate::Result<Bytes>;
    async fn close(&mut self) -> crate::Result<()>;
    fn is_connected(&self) -> bool;
}