use std::time::Duration;

use anyhow::{anyhow, Context, Error};
use clickhouse::{inserter::Inserter, Client};
use serde::{Deserialize, Serialize};
use tokio::{
    select,
    sync::mpsc::{channel, Receiver, Sender},
};
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tracing::{debug, error, warn};

use crate::cli;

#[derive(clickhouse::Row, Serialize, Deserialize)]
pub struct Row {
    pub env: &'static str,
    pub hostname: &'static str,
    #[serde(with = "clickhouse::serde::time::datetime")]
    pub date: time::OffsetDateTime,
    #[serde(with = "clickhouse::serde::uuid")]
    pub request_id: uuid::Uuid,
    pub conn_id: uuid::Uuid,
    pub method: &'static str,
    pub http_version: &'static str,
    pub request_type: String,
    pub status: u16,
    pub domain: String,
    pub host: String,
    pub path: String,
    pub canister_id: String,
    pub ic_streaming: bool,
    pub ic_upgrade: bool,
    pub ic_node_id: String,
    pub ic_subnet_id: String,
    pub ic_subnet_type: String,
    pub ic_method_name: String,
    pub ic_sender: String,
    pub ic_canister_id_cbor: String,
    pub ic_error_cause: String,
    pub ic_retries: u8,
    pub ic_cache_status: String,
    pub ic_cache_bypass_reason: String,
    pub error_cause: String,
    pub tls_version: String,
    pub tls_cipher: String,
    pub req_sent: u64,
    pub req_rcvd: u64,
    pub conn_sent: u64,
    pub conn_rcvd: u64,
    pub duration: f64,
    pub duration_full: f64,
    pub duration_conn: f64,
    pub cache_status: &'static str,
    pub cache_bypass_reason: &'static str,
}

pub struct Clickhouse {
    token: CancellationToken,
    tracker: TaskTracker,
    tx: Sender<Row>,
}

impl Clickhouse {
    pub fn new(cli: &cli::Clickhouse) -> Result<Self, Error> {
        let (tx, rx) = channel(65536);
        let token = CancellationToken::new();
        let actor = Actor::new(cli.clone(), rx)?;

        let child_token = token.child_token();
        let tracker = TaskTracker::new();
        tracker.spawn(async move {
            if let Err(e) = actor.run(child_token).await {
                error!("Clickhouse: error during run: {e:#}");
            }
        });

        Ok(Self { token, tracker, tx })
    }

    pub fn send(&self, r: Row) {
        // If it fails we'll lose the message, but it's better than to block & eat memory.
        let _ = self.tx.try_send(r);
    }

    pub async fn stop(&self) {
        self.token.cancel();
        self.tracker.close();
        self.tracker.wait().await;
    }
}

struct Actor {
    inserter: Inserter<Row>,
    rx: Receiver<Row>,
}

impl Actor {
    fn new(c: cli::Clickhouse, rx: Receiver<Row>) -> Result<Self, Error> {
        let mut client = Client::default().with_url(
            c.log_clickhouse_url
                .ok_or_else(|| anyhow!("no URL specified"))?,
        );
        if let Some(v) = c.log_clickhouse_user {
            client = client.with_user(v);
        }
        if let Some(v) = c.log_clickhouse_pass {
            client = client.with_password(v);
        }
        if let Some(v) = c.log_clickhouse_db {
            client = client.with_database(v);
        }

        let inserter = client
            .inserter(
                &c.log_clickhouse_table
                    .ok_or_else(|| anyhow!("no table specified"))?,
            )?
            .with_max_rows(c.log_clickhouse_batch)
            .with_period(Some(c.log_clickhouse_interval))
            .with_period_bias(0.1); // add 10% random variance to interval

        Ok(Self { inserter, rx })
    }

    async fn run(mut self, token: CancellationToken) -> Result<(), Error> {
        let mut interval = tokio::time::interval(Duration::from_secs(1));

        warn!("Clickhouse: started");
        loop {
            select! {
                biased;

                () = token.cancelled() => {
                    // Close the channel
                    self.rx.close();

                    // Drain remaining rows
                    while let Some(v) = self.rx.recv().await {
                        self.inserter.write(&v).context("unable insert row")?;
                    }

                    // Flush the buffer
                    self.inserter.end().await.context("unable to flush buffer")?;
                    warn!("Clickhouse: stopped");
                    return Ok(());
                },

                // Periodically poke inserter to commit if time has come.
                // If the thresholds are not reached - it doesn't do anything.
                _ = interval.tick() => {
                    match self.inserter.commit().await {
                        Ok(v) => debug!("Clickhouse: inserted rows: {}, bytes: {}", v.rows, v.bytes),
                        Err(e) => error!("Clickhouse: unable to commit: {e:#}"),
                    }
                }

                row = self.rx.recv() => {
                    if let Some(v) = row {
                        if let Err(e) = self.inserter.write(&v) {
                            error!("Clickhouse: unable to insert row: {e:#}");
                        }
                    }
                }
            }
        }
    }
}
