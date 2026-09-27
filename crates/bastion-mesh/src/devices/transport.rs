//! Frames between primary and node: JSON text over a WebSocket, TLS on the
//! wire (§5.2). The session logic only sees [`FrameConn`], so a host can
//! serve the primary side from its own HTTP server (an axum upgrade) and
//! tests can use [`memory_pair`].
//!
//! There is deliberately no listener here for the node side: a node only
//! ever dials out ([`connect`]); it has no code path that accepts a
//! connection (BMD-09).

use std::sync::Arc;

use async_trait::async_trait;
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

/// A bidirectional stream of text frames. `recv` must be cancel-safe (the
/// session loop races it against outgoing messages); `Ok(None)` is a clean
/// close.
#[async_trait]
pub trait FrameConn: Send {
    async fn send(&mut self, text: String) -> anyhow::Result<()>;
    async fn recv(&mut self) -> anyhow::Result<Option<String>>;
    async fn close(&mut self) {}
}

/// An in-process pair, for tests and for hosts that bridge another way.
pub struct MemoryConn {
    tx: mpsc::UnboundedSender<String>,
    rx: mpsc::UnboundedReceiver<String>,
}

pub fn memory_pair() -> (MemoryConn, MemoryConn) {
    let (a_tx, a_rx) = mpsc::unbounded_channel();
    let (b_tx, b_rx) = mpsc::unbounded_channel();
    (
        MemoryConn { tx: a_tx, rx: b_rx },
        MemoryConn { tx: b_tx, rx: a_rx },
    )
}

#[async_trait]
impl FrameConn for MemoryConn {
    async fn send(&mut self, text: String) -> anyhow::Result<()> {
        self.tx
            .send(text)
            .map_err(|_| anyhow::anyhow!("connection closed"))
    }

    async fn recv(&mut self) -> anyhow::Result<Option<String>> {
        Ok(self.rx.recv().await)
    }

    async fn close(&mut self) {
        self.rx.close();
    }
}

/// A tungstenite WebSocket over any byte stream (TLS or not).
pub struct WsConn<S> {
    inner: WebSocketStream<S>,
}

impl<S> WsConn<S> {
    pub fn new(inner: WebSocketStream<S>) -> Self {
        Self { inner }
    }
}

#[async_trait]
impl<S> FrameConn for WsConn<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    async fn send(&mut self, text: String) -> anyhow::Result<()> {
        self.inner.send(Message::Text(text)).await?;
        Ok(())
    }

    async fn recv(&mut self) -> anyhow::Result<Option<String>> {
        loop {
            match self.inner.next().await {
                None => return Ok(None),
                Some(Err(e)) => return Err(e.into()),
                Some(Ok(Message::Text(text))) => return Ok(Some(text)),
                Some(Ok(Message::Close(_))) => return Ok(None),
                // Ping/pong are answered by tungstenite; binary frames are
                // not part of the protocol.
                Some(Ok(_)) => continue,
            }
        }
    }

    async fn close(&mut self) {
        let _ = self.inner.close(None).await;
    }
}

/// The node dials the primary. `url` is `wss://…` (or `ws://` only when the
/// host passed no TLS config — a test or a loopback bridge). The TLS config
/// decides which primary certificates are trusted; the device handshake on
/// top authenticates the primary either way.
pub async fn connect(
    url: &str,
    tls: Option<Arc<rustls::ClientConfig>>,
) -> anyhow::Result<WsConn<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>> {
    if url.starts_with("ws://") && tls.is_some() {
        anyhow::bail!("a TLS config was given for a plain ws:// URL");
    }
    let connector = tls.map(tokio_tungstenite::Connector::Rustls);
    let (stream, _) =
        tokio_tungstenite::connect_async_tls_with_config(url, None, false, connector).await?;
    Ok(WsConn::new(stream))
}

/// The primary side of an already accepted byte stream (TLS terminated by
/// the host): run the WebSocket upgrade on it.
pub async fn accept<S>(stream: S) -> anyhow::Result<WsConn<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    Ok(WsConn::new(tokio_tungstenite::accept_async(stream).await?))
}
