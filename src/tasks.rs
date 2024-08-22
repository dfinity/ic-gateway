use std::sync::Arc;

use anyhow::Error;
use async_trait::async_trait;
use derive_new::new;
use ic_bn_lib::http;
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tracing::{error, warn};

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

    pub fn start(&self, token: &CancellationToken) {
        warn!("TaskManager: starting {} tasks", self.tasks.len());

        for task in self.tasks.clone() {
            let token = token.child_token();
            self.tracker.spawn(async move {
                if let Err(e) = task.1.run(token).await {
                    error!("TaskManager: task '{}' exited with an error: {e:#}", task.0);
                }
            });
        }
    }

    pub async fn stop(&self) {
        warn!("TaskManager: stopping {} tasks", self.tasks.len());
        self.tracker.close();
        self.tracker.wait().await;
    }
}

#[async_trait]
impl Run for http::Server {
    async fn run(&self, token: CancellationToken) -> Result<(), Error> {
        self.serve(token).await?;
        Ok(())
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
