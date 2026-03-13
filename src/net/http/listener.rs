use crate::net::http::{
    HttpConnection, HttpError,
    handler::HttpHandler,
    session::Session,
};
use crate::net::socket::TcpListener;
use crate::net::wire::ip::IpAddress;
use crate::rt::task::spawn;

/// An HTTP listener that accepts incoming connections.
///
/// Wraps `TcpListener` and produces `HttpConnection` instances.
/// Must be created inside `LocalRuntime::run()`. Panics otherwise.
pub struct HttpListener {
    inner: TcpListener,
}

impl HttpListener {
    /// Create a new HTTP listener bound to the given address and port.
    ///
    /// Wraps `TcpListener::listen()` internally. Must be called inside
    /// `LocalRuntime::run()`. Panics otherwise.
    pub fn listen(addr: IpAddress, port: u16) -> Result<Self, HttpError> {
        let inner = TcpListener::listen(addr, port).map_err(HttpError::Bind)?;
        Ok(Self { inner })
    }

    /// Accept the next HTTP connection.
    ///
    /// Returns an `HttpConnection` wrapping the accepted TCP stream
    /// with a fresh HTTP/0.9 session.
    pub async fn accept(&self) -> Result<HttpConnection, HttpError> {
        let stream = self.inner.accept().await;
        Ok(HttpConnection::new(stream, Session::http09()))
    }

    /// Convenience method: accept loop + spawn a task per connection.
    ///
    /// Spawned tasks that return errors are silently dropped
    /// (the connection is closed by `TcpStream::drop()`).
    pub async fn serve<H: HttpHandler>(&self, handler: H) -> Result<(), HttpError> {
        loop {
            let mut conn = self.accept().await?;
            let handler = handler.clone();
            spawn(async move {
                loop {
                    match conn.next_request().await {
                        Ok(Some(req)) => {
                            let writer = conn.respond();
                            if handler.handle(req, writer).await.is_err() {
                                break;
                            }
                        }
                        Ok(None) => break,
                        Err(_) => break,
                    }
                }
            });
        }
    }

    /// Returns the local address this listener is bound to.
    pub fn local_addr(&self) -> IpAddress {
        self.inner.local_addr()
    }

    /// Returns the local port this listener is bound to.
    pub fn local_port(&self) -> u16 {
        self.inner.local_port()
    }
}
