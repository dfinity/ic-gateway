use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use crate::core::Run;
use anyhow::{anyhow, Error};
use async_trait::async_trait;
use axum::{extract::Request, Router};
use hyper::body::Incoming;
use hyper_util::{
    rt::{TokioExecutor, TokioIo, TokioTimer},
    server::conn::auto::Builder,
};
use rustls::{server::ServerConnection, CipherSuite, ProtocolVersion};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, TcpSocket, TcpStream},
    select,
};
use tokio_rustls::TlsAcceptor;
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tower_service::Service;
use tracing::{debug, warn};

// Blanket async read+write trait to box streams
trait AsyncReadWrite: AsyncRead + AsyncWrite + Send + Sync + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Sync + Unpin> AsyncReadWrite for T {}

// TLS information about the connection
// To be injected into the request as an extension
#[derive(Clone)]
struct TlsInfo {
    sni: String,
    alpn: String,
    protocol: ProtocolVersion,
    cipher: CipherSuite,
}

impl From<&ServerConnection> for TlsInfo {
    fn from(c: &ServerConnection) -> Self {
        Self {
            sni: c.server_name().unwrap_or("unknown").into(),
            alpn: c
                .alpn_protocol()
                .map_or("unknown".into(), |x| String::from_utf8_lossy(x).to_string()),
            protocol: c.protocol_version().unwrap_or(ProtocolVersion::Unknown(0)),
            cipher: c
                .negotiated_cipher_suite()
                // Some default cipher, it should never be None in fact, but just in case we don't use unwrap()
                .map_or(rustls::CipherSuite::TLS13_AES_128_CCM_SHA256, |x| x.suite()),
        }
    }
}

struct Conn {
    addr: SocketAddr,
    remote_addr: SocketAddr,
    router: Router,
    builder: Builder<TokioExecutor>,
    token: CancellationToken,
    grace_period: Duration,
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
        let (stream, tls_info): (Box<dyn AsyncReadWrite>, _) = if let Some(v) = &self.tls_acceptor {
            debug!(
                "Server {}: {}: performing TLS handshake",
                self.addr, self.remote_addr
            );

            let start = Instant::now();
            let stream = v.accept(stream).await?;
            let latency = start.elapsed();

            let conn = stream.get_ref().1;
            let tls_info = TlsInfo::from(conn);

            debug!(
                "Server {}: {}: handshake finished in {}ms (server: {}, proto: {:?}, cipher: {:?}, ALPN: {})",
                self.addr,
                self.remote_addr,
                latency.as_millis(),
                tls_info.sni,
                tls_info.protocol,
                tls_info.cipher,
                tls_info.alpn,
            );

            (Box::new(stream), Some(tls_info))
        } else {
            (Box::new(stream), None)
        };

        // Convert stream from Tokio to Hyper
        let stream = TokioIo::new(stream);

        // Convert router to Hyper service
        let service = hyper::service::service_fn(move |mut request: Request<Incoming>| {
            // Inject TLS information if it's a TLS session
            // TODO avoid cloning due to Fn() somehow?
            if let Some(v) = tls_info.clone() {
                request.extensions_mut().insert(v);
            }

            self.router.clone().call(request)
        });

        // Call the service
        let conn = self.builder.serve_connection(stream, service);
        // Using mutable future reference requires pinning, otherwise .await consumes it
        tokio::pin!(conn);

        select! {
            biased; // Poll top-down

            () = self.token.cancelled() => {
                // Start graceful shutdown of the connection
                // For H2: sends GOAWAY frames to the client
                // For H1: disables keepalives
                conn.as_mut().graceful_shutdown();

                // Wait for the grace period to finish or connection to complete.
                // Connection must still be polled for shutdown to proceed.
                select! {
                    biased;
                    () = tokio::time::sleep(self.grace_period) => {},
                    _ = conn.as_mut() => {},
                }
            }

            v = conn.as_mut() => {
                if let Err(e) = v {
                    return Err(anyhow!("Unable to serve connection: {e}"));
                }
            },
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

        // Setup Hyper connection builder with some defaults
        // TODO make configurable?
        let mut builder = Builder::new(TokioExecutor::new());
        builder
            .http1()
            .keep_alive(true)
            .http2()
            .adaptive_window(true)
            .max_concurrent_streams(Some(100))
            .timer(TokioTimer::new()) // Needed for the keepalives below
            .keep_alive_interval(Some(Duration::from_secs(20)))
            .keep_alive_timeout(Duration::from_secs(10));

        warn!(
            "Server {}: running (TLS: {})",
            self.addr,
            self.tls_acceptor.is_some()
        );

        loop {
            select! {
                biased; // Poll top-down

                () = token.cancelled() => {
                    // Stop accepting new connections
                    drop(listener);

                    warn!("Server {}: shutting down, waiting for the active connections to close for {}s", self.addr, self.grace_period.as_secs());
                    self.tracker.close();
                    self.tracker.wait().await;

                    // select! {
                    //     () = self.tracker.wait() => {},
                    //     () = tokio::time::sleep(self.grace_period) => {},
                    // }
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
                    // Builder is a bit more complex, but cloning is better than to create it again
                    let conn = Conn {
                        addr: self.addr,
                        remote_addr,
                        router: self.router.clone(),
                        builder: builder.clone(),
                        token: token.child_token(),
                        grace_period: self.grace_period,
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
