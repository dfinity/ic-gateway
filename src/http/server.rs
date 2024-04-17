use std::{net::SocketAddr, sync::Arc, time::Duration};

use anyhow::{anyhow, Error};
use async_trait::async_trait;
use axum::{extract::Request, Router};
use futures_util::pin_mut;
use hyper::body::Incoming;
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, TcpSocket, TcpStream},
    select,
};
use tokio_rustls::TlsAcceptor;
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tower_service::Service;
use tracing::{debug, warn};

use crate::core::Run;

// Blanket async read+write trait to box streams
trait AsyncReadWrite: AsyncRead + AsyncWrite + Send + Sync + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Sync + Unpin> AsyncReadWrite for T {}

struct Conn {
    addr: SocketAddr,
    remote_addr: SocketAddr,
    router: Router,
    token: CancellationToken,
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
        let mut builder = Builder::new(TokioExecutor::new());

        // Some sensible defaults
        // TODO make configurable?
        builder
            .http2()
            .adaptive_window(true)
            .max_concurrent_streams(Some(100))
            .keep_alive_interval(Some(Duration::from_secs(20)))
            .keep_alive_timeout(Duration::from_secs(10));

        let conn = builder.serve_connection(stream, service);
        pin_mut!(conn);

        loop {
            select! {
                v = conn.as_mut() => {
                    if let Err(e) = v {
                        return Err(anyhow!("Unable to serve connection: {e}"));
                    }

                    break;
                },

                () = self.token.cancelled() => {
                    conn.as_mut().graceful_shutdown();
                }
            }
        }

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
    grace_period: Duration,
    tracker: TaskTracker,
    tls_acceptor: Option<TlsAcceptor>,
}

impl Server {
    pub fn new(
        addr: SocketAddr,
        backlog: u32,
        router: Router,
        grace_period: Duration,
        rustls_cfg: Option<rustls::ServerConfig>,
    ) -> Self {
        Self {
            addr,
            backlog,
            router,
            grace_period,
            tracker: TaskTracker::new(),
            tls_acceptor: rustls_cfg.map(|x| TlsAcceptor::from(Arc::new(x))),
        }
    }
}

#[async_trait]
impl Run for Server {
    async fn run(&self, token: CancellationToken) -> Result<(), Error> {
        let listener = listen_tcp_backlog(self.addr, self.backlog)?;
        pin_mut!(listener);

        warn!(
            "Server {}: running (TLS: {})",
            self.addr,
            self.tls_acceptor.is_some()
        );

        loop {
            select! {
                () = token.cancelled() => {
                    warn!("Server {}: shutting down, waiting for the active connections to close for {}s", self.addr, self.grace_period.as_secs());
                    self.tracker.close();
                    select! {
                        () = self.tracker.wait() => {},
                        () = tokio::time::sleep(self.grace_period) => {},
                    }
                    warn!("Server {}: shut down", self.addr);
                    return Ok(());
                },

                // Try to accept the connection
                v = listener.accept() => {
                    let (stream, remote_addr) = match v {
                        Ok(v) => v,
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
                        token: token.child_token(),
                        tls_acceptor: self.tls_acceptor.clone(),
                    };

                    // Spawn a task to handle connection
                    self.tracker.spawn(async move {
                        if let Err(e) = conn.handle(stream).await {
                            warn!("Server {}: {}: failed to handle connection: {e}", conn.addr, remote_addr);
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
