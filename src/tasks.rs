use std::sync::Arc;

use crate::http;
use anyhow::Error;
use async_trait::async_trait;
use derive_new::new;
use discower_bowndary::{route_provider::HealthCheckRouteProvider, snapshot::Snapshot};
use std::fmt::Debug;
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tracing::error;

// Long running task that can be cancelled by a token
#[async_trait]
pub trait Run: Send + Sync {
    async fn run(&self, token: CancellationToken) -> Result<(), Error>;
}

#[derive(Clone)]
struct Task(pub String, pub Arc<dyn Run>);

// Starts & tracks Tasks that implement Run
#[derive(new)]
pub struct TaskManager {
    #[new(default)]
    tracker: TaskTracker,
    #[new(default)]
    tasks: Vec<Task>,
}

impl TaskManager {
    pub fn add(&mut self, name: &str, task: Arc<dyn Run>) {
        self.tasks.push(Task(name.into(), task));
    }

    pub fn start(&mut self, token: &CancellationToken) {
        for task in self.tasks.clone() {
            let token = token.child_token();
            self.tracker.spawn(async move {
                if let Err(e) = task.1.run(token).await {
                    error!("Runner '{}' exited with an error: {e:#}", task.0);
                }
            });
        }
    }

    pub async fn stop(&self) {
        self.tracker.close();
        self.tracker.wait().await;
    }
}

#[async_trait]
impl Run for http::Server {
    async fn run(&self, token: CancellationToken) -> Result<(), Error> {
        self.serve(token).await
    }
}

#[async_trait]
impl Run for ocsp_stapler::Stapler {
    async fn run(&self, token: CancellationToken) -> Result<(), Error> {
        token.cancelled().await;
        self.stop().await;
        Ok(())
    }
}

pub struct TaskRouteProvider<S>(pub Arc<HealthCheckRouteProvider<S>>);

#[async_trait]
impl<S> Run for TaskRouteProvider<S>
where
    S: Send + Sync + Debug + Clone + Snapshot + 'static,
{
    async fn run(&self, token: CancellationToken) -> Result<(), Error> {
        self.0.run().await;
        token.cancelled().await;
        self.0.stop().await;
        Ok(())
    }
}
