use std::{net::SocketAddr, sync::Arc, time::Duration};

use anyhow::{anyhow, Error};
use axum::{extract::Request, Router};
use futures_util::pin_mut;
use hyper::body::Incoming;
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::select;
use tokio_rustls::TlsAcceptor;
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tower_service::Service;
use tracing::{debug, warn};

// Blanket async read+write trait to box streams
trait AsyncReadWrite: AsyncRead + AsyncWrite + Send + Sync + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Sync + Unpin> AsyncReadWrite for T {}

pub struct Conn {
    addr: SocketAddr,
    remote_addr: SocketAddr,
    router: Router,
    tls_acceptor: Option<TlsAcceptor>,
}

impl Conn {
    pub async fn handle(&self, stream: TcpStream) -> Result<(), Error> {
        debug!(
            "Server {}: {}: got a new connection",
            self.addr, self.remote_addr
        );

        // Disable Nagle's algo
        stream.set_nodelay(true)?;

        // Perform TLS handshake if we're in TLS mode
        let stream: Box<dyn AsyncReadWrite> = if let Some(v) = &self.tls_acceptor {
            debug!("{}: performing TLS handshake", self.remote_addr);
            Box::new(v.accept(stream).await?)
        } else {
            Box::new(stream)
        };

        // Convert stream from Tokio to Hyper
        let stream = TokioIo::new(stream);

        // Convert router to Hyper service
        let service = hyper::service::service_fn(move |request: Request<Incoming>| {
            self.router.clone().call(request)
        });

        // Call the service
        Builder::new(TokioExecutor::new())
            .serve_connection(stream, service)
            .await
            // It shouldn't really fail since Axum routers are infallible
            .map_err(|e| anyhow!("unable to call service: {e}"))?;

        debug!(
            "Server {}: {}: connection finished",
            self.addr, self.remote_addr
        );

        Ok(())
    }
}

// Listens for new connections on addr with an optional TLS and serves provided Router
pub struct Server {
    addr: SocketAddr,
    backlog: u32,
    router: Router,
    token: CancellationToken,
    tracker: TaskTracker,
    tls_acceptor: Option<TlsAcceptor>,
}

impl Server {
    pub fn new(
        addr: SocketAddr,
        backlog: u32,
        router: Router,
        token: CancellationToken,
        rustls_cfg: Option<rustls::ServerConfig>,
    ) -> Self {
        Self {
            addr,
            backlog,
            router,
            token,
            tracker: TaskTracker::new(),
            tls_acceptor: rustls_cfg.map(|x| TlsAcceptor::from(Arc::new(x))),
        }
    }

    pub async fn start(&self) -> Result<(), Error> {
        let listener = listen_tcp_backlog(self.addr, self.backlog)?;
        pin_mut!(listener);

        loop {
            select! {
                () = self.token.cancelled() => {
                    warn!("Server {}: shutting down, waiting for the active connections to close for 30s", self.addr);
                    self.tracker.close();
                    select! {
                        () = self.tracker.wait() => {},
                        () = tokio::time::sleep(Duration::from_secs(30)) => {},
                    }
                    warn!("Server {}: shut down", self.addr);
                    return Ok(());
                },

                // Try to accept the connection
                v = listener.accept() => {
                    let (stream, remote_addr) = match v {
                        Ok((a, b)) => (a, b),
                        Err(e) => {
                            warn!("Unable to accept connection: {e}");
                            continue;
                        }
                    };

                    // Create a new connection
                    // Router & TlsAcceptor are both Arc<> inside so it's cheap to clone
                    let conn = Conn {
                        addr: self.addr,
                        remote_addr,
                        router: self.router.clone(),
                        tls_acceptor: self.tls_acceptor.clone(),
                    };

                    // Spawn a task to handle connection
                    self.tracker.spawn(async move {
                        match conn.handle(stream).await {
                            Ok(()) => {},
                            Err(e) => warn!("Server {}: {}: failed to handle connection: {e}", conn.addr, remote_addr),
                        }
                    });
                }
            }
        }
    }
}

// Creates a listener with a backlog set
pub fn listen_tcp_backlog(addr: SocketAddr, backlog: u32) -> Result<TcpListener, Error> {
    let socket = match addr {
        SocketAddr::V4(_) => TcpSocket::new_v4()?,
        SocketAddr::V6(_) => TcpSocket::new_v6()?,
    };

    socket.bind(addr)?;
    Ok(socket.listen(backlog)?)
}
