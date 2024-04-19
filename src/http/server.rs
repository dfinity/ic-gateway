use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use crate::core::Run;
use anyhow::{anyhow, Context, Error};
use async_trait::async_trait;
use axum::{extract::Request, Router};
use hyper::body::Incoming;
use hyper_util::{
    rt::{TokioExecutor, TokioIo, TokioTimer},
    server::conn::auto::Builder,
};
use rustls::{server::ServerConnection, CipherSuite, ProtocolVersion};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpSocket, TcpStream},
    select,
};
use tokio_rustls::{server::TlsStream, TlsAcceptor};
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tower_service::Service;
use tracing::{debug, warn};

use crate::{cli, tls::is_http_alpn};

// Blanket async read+write trait to box streams
trait AsyncReadWrite: AsyncRead + AsyncWrite + Send + Sync + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Sync + Unpin> AsyncReadWrite for T {}

#[derive(Clone, Copy)]
pub struct Options {
    pub backlog: u32,
    pub http2_max_streams: u32,
    pub http2_keepalive_interval: Duration,
    pub http2_keepalive_timeout: Duration,
    pub grace_period: Duration,
}

impl From<&cli::HttpServer> for Options {
    fn from(c: &cli::HttpServer) -> Self {
        Self {
            backlog: c.backlog,
            http2_keepalive_interval: c.http2_keepalive_interval,
            http2_keepalive_timeout: c.http2_keepalive_timeout,
            http2_max_streams: c.http2_max_streams,
            grace_period: c.grace_period,
        }
    }
}

// TLS information about the connection
#[derive(Clone, Debug)]
pub struct TlsInfo {
    pub sni: String,
    pub alpn: String,
    pub protocol: ProtocolVersion,
    pub cipher: CipherSuite,
}

#[derive(Clone, Debug)]
pub struct ConnInfo {
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,
    pub tls: Option<TlsInfo>,
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
                .map_or(rustls::CipherSuite::Unknown(0), |x| x.suite()),
        }
    }
}

struct Conn {
    addr: SocketAddr,
    remote_addr: SocketAddr,
    router: Router,
    builder: Builder<TokioExecutor>,
    token: CancellationToken,
    options: Options,
    tls_acceptor: Option<TlsAcceptor>,
}

impl Conn {
    pub async fn tls_handshake(
        &self,
        stream: TcpStream,
    ) -> Result<(TlsStream<TcpStream>, TlsInfo), Error> {
        debug!(
            "Server {}: {}: performing TLS handshake",
            self.addr, self.remote_addr
        );

        let start = Instant::now();
        let stream = self.tls_acceptor.as_ref().unwrap().accept(stream).await?;
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

        Ok((stream, tls_info))
    }

    pub async fn handle(&self, stream: TcpStream) -> Result<(), Error> {
        debug!(
            "Server {}: {}: got a new connection",
            self.addr, self.remote_addr
        );

        // Disable Nagle's algo
        stream.set_nodelay(true)?;

        // Perform TLS handshake if we're in TLS mode
        let (stream, tls_info): (Box<dyn AsyncReadWrite>, _) = if self.tls_acceptor.is_some() {
            let (mut stream, tls_info) = self.tls_handshake(stream).await?;

            // Close the connection if agreed ALPN is not HTTP - probably it was an ACME challenge
            if !is_http_alpn(tls_info.alpn.as_bytes()) {
                debug!("Not HTTP ALPN ('{}') - closing connection", tls_info.alpn);
                stream.shutdown().await.context("error in shutdown()")?;
                return Ok(());
            }

            (Box::new(stream), Some(tls_info))
        } else {
            (Box::new(stream), None)
        };

        // Since it will be cloned for each request served over this connection
        // it's probably better to wrap it into Arc
        let conn_info = ConnInfo {
            local_addr: self.addr,
            remote_addr: self.remote_addr,
            tls: tls_info,
        };
        let conn_info = Arc::new(conn_info);

        // Convert stream from Tokio to Hyper
        let stream = TokioIo::new(stream);

        // Convert router to Hyper service
        let service = hyper::service::service_fn(move |mut request: Request<Incoming>| {
            // Inject connection information
            request.extensions_mut().insert(conn_info.clone());
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
                    () = tokio::time::sleep(self.options.grace_period) => {},
                    _ = conn.as_mut() => {},
                }
            }

            v = conn.as_mut() => {
                if let Err(e) = v {
                    return Err(anyhow!("Unable to serve connection: {e}"));
                }
            },
        }

        Ok(())
    }
}

// Listens for new connections on addr with an optional TLS and serves provided Router
pub struct Server {
    addr: SocketAddr,
    router: Router,
    tracker: TaskTracker,
    options: Options,
    tls_acceptor: Option<TlsAcceptor>,
}

impl Server {
    pub fn new(
        addr: SocketAddr,
        router: Router,
        options: Options,
        rustls_cfg: Option<rustls::ServerConfig>,
    ) -> Self {
        Self {
            addr,
            router,
            options,
            tracker: TaskTracker::new(),
            tls_acceptor: rustls_cfg.map(|x| TlsAcceptor::from(Arc::new(x))),
        }
    }
}

#[async_trait]
impl Run for Server {
    async fn run(&self, token: CancellationToken) -> Result<(), Error> {
        let listener = listen_tcp_backlog(self.addr, self.options.backlog)?;

        // Prepare Hyper connection builder
        // It automatically figures out whether to do HTTP1 or HTTP2
        let mut builder = Builder::new(TokioExecutor::new());
        builder
            .http1()
            .keep_alive(true)
            .http2()
            .adaptive_window(true)
            .max_concurrent_streams(Some(self.options.http2_max_streams))
            .timer(TokioTimer::new()) // Needed for the keepalives below
            .keep_alive_interval(Some(self.options.http2_keepalive_interval))
            .keep_alive_timeout(self.options.http2_keepalive_timeout);

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

                    warn!("Server {}: shutting down, waiting for the active connections to close for {}s", self.addr, self.options.grace_period.as_secs());
                    self.tracker.close();
                    self.tracker.wait().await;

                    warn!("Server {}: shut down", self.addr);
                    return Ok(());
                },

                // Try to accept the connection
                v = listener.accept() => {
                    let (stream, remote_addr) = match v {
                        Ok(v) => v,
                        Err(e) => {
                            warn!("Unable to accept connection: {e}");
                            // Wait few ms just in case that there's an overflowed backlog
                            // so that we don't run into infinite error loop
                            tokio::time::sleep(Duration::from_millis(10)).await;
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
                        options: self.options,
                        tls_acceptor: self.tls_acceptor.clone(),
                    };

                    // Spawn a task to handle connection & track it
                    self.tracker.spawn(async move {
                        if let Err(e) = conn.handle(stream).await {
                            warn!("Server {}: {}: failed to handle connection: {e}", conn.addr, remote_addr);
                        }

                        debug!(
                            "Server {}: {}: connection finished",
                            conn.addr, remote_addr
                        );
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
