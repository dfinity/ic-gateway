use std::{
    fmt::Display,
    net::SocketAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use anyhow::{anyhow, Context, Error};
use axum::{extract::Request, Router};
use hyper::body::Incoming;
use hyper_util::{
    rt::{TokioExecutor, TokioIo, TokioTimer},
    server::conn::auto::Builder,
};
use prometheus::{
    register_histogram_vec_with_registry, register_int_counter_vec_with_registry,
    register_int_gauge_vec_with_registry, HistogramVec, IntCounterVec, IntGaugeVec, Registry,
};
use rustls::{server::ServerConnection, CipherSuite, ProtocolVersion};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpSocket, TcpStream},
    select,
};
use tokio_rustls::TlsAcceptor;
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tower_service::Service;
use tracing::{debug, warn};
use uuid::Uuid;

use super::{AsyncCounter, Stats, ALPN_ACME};

pub const CONN_DURATION_BUCKETS: &[f64] = &[1.0, 8.0, 32.0, 64.0, 256.0, 512.0, 1024.0];
pub const CONN_REQUESTS: &[f64] = &[1.0, 4.0, 8.0, 16.0, 32.0, 64.0, 256.0];

// Blanket async read+write trait for streams Box-ing
trait AsyncReadWrite: AsyncRead + AsyncWrite + Send + Sync + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Sync + Unpin> AsyncReadWrite for T {}

#[derive(Clone)]
pub struct Metrics {
    pub conns_open: IntGaugeVec,
    pub requests: IntCounterVec,
    pub bytes_sent: IntCounterVec,
    pub bytes_rcvd: IntCounterVec,
    pub conn_duration: HistogramVec,
    pub requests_per_conn: HistogramVec,
}

impl Metrics {
    pub fn new(registry: &Registry) -> Self {
        const LABELS: &[&str] = &["addr", "tls", "family"];

        Self {
            conns_open: register_int_gauge_vec_with_registry!(
                format!("conn_open"),
                format!("Number of currently open connections"),
                LABELS,
                registry
            )
            .unwrap(),

            requests: register_int_counter_vec_with_registry!(
                format!("conn_requests_total"),
                format!("Counts the number of requests"),
                LABELS,
                registry
            )
            .unwrap(),

            bytes_sent: register_int_counter_vec_with_registry!(
                format!("conn_bytes_sent_total"),
                format!("Counts number of bytes sent"),
                LABELS,
                registry
            )
            .unwrap(),

            bytes_rcvd: register_int_counter_vec_with_registry!(
                format!("conn_bytes_rcvd_total"),
                format!("Counts number of bytes received"),
                LABELS,
                registry
            )
            .unwrap(),

            conn_duration: register_histogram_vec_with_registry!(
                format!("conn_duration_sec"),
                format!("Records the duration of connection in seconds"),
                LABELS,
                CONN_DURATION_BUCKETS.to_vec(),
                registry
            )
            .unwrap(),

            requests_per_conn: register_histogram_vec_with_registry!(
                format!("conn_requests_per_conn"),
                format!("Records the number of requests per connection"),
                LABELS,
                CONN_REQUESTS.to_vec(),
                registry
            )
            .unwrap(),
        }
    }
}

#[derive(Clone, Copy)]
pub struct Options {
    pub backlog: u32,
    pub http2_max_streams: u32,
    pub http2_keepalive_interval: Duration,
    pub http2_keepalive_timeout: Duration,
    pub grace_period: Duration,
}

// TLS information about the connection
#[derive(Clone, Debug)]
pub struct TlsInfo {
    pub sni: Option<String>,
    pub alpn: Option<String>,
    pub protocol: ProtocolVersion,
    pub cipher: CipherSuite,
    pub handshake_dur: Duration,
}

impl TryFrom<&ServerConnection> for TlsInfo {
    type Error = Error;

    fn try_from(c: &ServerConnection) -> Result<Self, Self::Error> {
        Ok(Self {
            handshake_dur: Duration::ZERO,

            sni: c.server_name().map(|x| x.to_string()),
            alpn: c
                .alpn_protocol()
                .map(|x| String::from_utf8_lossy(x).to_string()),
            protocol: c
                .protocol_version()
                .ok_or_else(|| anyhow!("No TLS protocol found"))?,
            cipher: c
                .negotiated_cipher_suite()
                .map(|x| x.suite())
                .ok_or_else(|| anyhow!("No TLS ciphersuite found"))?,
        })
    }
}

#[derive(Debug)]
pub struct ConnInfo {
    pub id: Uuid,
    pub accepted_at: Instant,
    pub remote_addr: SocketAddr,
    pub traffic: Arc<Stats>,
    pub req_count: AtomicU64,
}

struct Conn {
    addr: SocketAddr,
    remote_addr: SocketAddr,
    router: Router,
    builder: Builder<TokioExecutor>,
    token: CancellationToken,
    options: Options,
    metrics: Metrics,
    tls_acceptor: Option<TlsAcceptor>,
}

impl Display for Conn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Server {}: {}", self.addr, self.remote_addr,)
    }
}

impl Conn {
    async fn tls_handshake(
        &self,
        stream: impl AsyncReadWrite,
    ) -> Result<(impl AsyncReadWrite, TlsInfo), Error> {
        debug!("{}: performing TLS handshake", self);

        // Perform the TLS handshake
        let start = Instant::now();
        let stream = self.tls_acceptor.as_ref().unwrap().accept(stream).await?;
        let duration = start.elapsed();

        let conn = stream.get_ref().1;
        let mut tls_info = TlsInfo::try_from(conn)?;
        tls_info.handshake_dur = duration;

        debug!(
            "{}: handshake finished in {}ms (server: {:?}, proto: {:?}, cipher: {:?}, ALPN: {:?})",
            self,
            duration.as_millis(),
            tls_info.sni,
            tls_info.protocol,
            tls_info.cipher,
            tls_info.alpn,
        );

        Ok((stream, tls_info))
    }

    async fn handle(&self, stream: TcpStream) -> Result<(), Error> {
        let accepted_at = Instant::now();

        debug!("{}: got a new connection", self);

        // Prepare metric labels
        let addr = self.addr.to_string();
        let labels = &[
            addr.as_str(), // Listening addr
            if self.tls_acceptor.is_some() {
                "yes"
            } else {
                "no"
            }, // Is TLS
            if self.remote_addr.is_ipv4() {
                "v4"
            } else {
                "v6"
            }, // IP Family
        ];

        self.metrics.conns_open.with_label_values(labels).inc();

        // Disable Nagle's algo
        stream.set_nodelay(true).context("unable to set NODELAY")?;

        // Wrap with traffic counter
        let stats = Arc::new(Stats::new());
        let stream = AsyncCounter::new(stream, stats.clone());

        let conn_info = Arc::new(ConnInfo {
            id: Uuid::now_v7(),
            accepted_at,
            remote_addr: self.remote_addr,
            traffic: stats.clone(),
            req_count: AtomicU64::new(0),
        });

        let result = self.handle_inner(stream, conn_info.clone()).await;

        // Record connection metrics
        let (sent, rcvd) = (stats.sent(), stats.rcvd());
        let dur = accepted_at.elapsed().as_secs_f64();
        let reqs = conn_info.req_count.load(Ordering::SeqCst);

        self.metrics.conns_open.with_label_values(labels).dec();
        self.metrics.requests.with_label_values(labels).inc_by(reqs);
        self.metrics
            .bytes_rcvd
            .with_label_values(labels)
            .inc_by(rcvd);
        self.metrics
            .bytes_sent
            .with_label_values(labels)
            .inc_by(sent);
        self.metrics
            .conn_duration
            .with_label_values(labels)
            .observe(dur);
        self.metrics
            .requests_per_conn
            .with_label_values(labels)
            .observe(reqs as f64);

        debug!(
            "{}: connection closed (rcvd: {}, sent: {}, reqs: {}, duration: {})",
            self, rcvd, sent, reqs, dur,
        );

        result
    }

    async fn handle_inner(
        &self,
        stream: impl AsyncReadWrite + 'static,
        conn_info: Arc<ConnInfo>,
    ) -> Result<(), Error> {
        // Perform TLS handshake if we're in TLS mode
        let (stream, tls_info): (Box<dyn AsyncReadWrite>, _) = if self.tls_acceptor.is_some() {
            let (mut stream, tls_info) = self.tls_handshake(stream).await?;

            // Close the connection if agreed ALPN is ACME - the handshake is enough for challenge
            if tls_info
                .alpn
                .as_ref()
                .map(|x| x.as_bytes() == ALPN_ACME)
                .unwrap_or(false)
            {
                debug!("{}: ACME ALPN - closing connection", self);

                stream
                    .shutdown()
                    .await
                    .context("unable to shutdown stream")?;

                return Ok(());
            }

            (Box::new(stream), Some(Arc::new(tls_info)))
        } else {
            (Box::new(stream), None)
        };

        // Convert stream from Tokio to Hyper
        let stream = TokioIo::new(stream);

        // Convert router to Hyper service
        let service = hyper::service::service_fn(move |mut request: Request<Incoming>| {
            conn_info.req_count.fetch_add(1, Ordering::SeqCst);
            // Inject connection information
            request.extensions_mut().insert(conn_info.clone());
            if let Some(v) = &tls_info {
                request.extensions_mut().insert(v.clone());
            }

            // Serve the request
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
                // Connection must still be polled for the shutdown to proceed.
                select! {
                    biased;
                    () = tokio::time::sleep(self.options.grace_period) => return Ok(()),
                    _ = conn.as_mut() => {},
                }
            }

            v = conn.as_mut() => {
                if let Err(e) = v {
                    return Err(anyhow!("Unable to serve connection: {e:#}"));
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
    metrics: Metrics,
    tls_acceptor: Option<TlsAcceptor>,
}

impl Server {
    pub fn new(
        addr: SocketAddr,
        router: Router,
        options: Options,
        metrics: Metrics,
        rustls_cfg: Option<rustls::ServerConfig>,
    ) -> Self {
        Self {
            addr,
            router,
            options,
            metrics,
            tracker: TaskTracker::new(),
            tls_acceptor: rustls_cfg.map(|x| TlsAcceptor::from(Arc::new(x))),
        }
    }

    pub async fn serve(&self, token: CancellationToken) -> Result<(), Error> {
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

                    select! {
                        _ = tokio::time::sleep(self.options.grace_period + Duration::from_secs(5)) => {
                            warn!("Server {}: connections didn't close in time, shutting down anyway", self.addr);
                        },
                        _ = self.tracker.wait() => {},
                    }

                    warn!("Server {}: shut down", self.addr);
                    return Ok(());
                },

                // Try to accept the connection
                v = listener.accept() => {
                    let (stream, remote_addr) = match v {
                        Ok(v) => v,
                        Err(e) => {
                            warn!("Unable to accept connection: {e:#}");
                            // Wait few ms just in case that there's an overflown backlog
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
                        metrics: self.metrics.clone(), // All metrics have Arc inside
                        tls_acceptor: self.tls_acceptor.clone(),
                    };

                    // Spawn a task to handle connection & track it
                    self.tracker.spawn(async move {
                        if let Err(e) = conn.handle(stream).await {
                            warn!("Server {}: {}: failed to handle connection: {e:#}", conn.addr, remote_addr);
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

    socket.set_reuseaddr(true)?;
    socket.bind(addr)?;
    Ok(socket.listen(backlog)?)
}
