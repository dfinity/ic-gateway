use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::Arc,
    time::Duration,
};

use arc_swap::ArcSwap;
use rand::Rng;

use ic_agent::agent::route_provider::dynamic_routing::{
    health_check::HealthCheckStatus, node::Node, snapshot::routing_snapshot::RoutingSnapshot,
};

// Determines the size of the sliding window used for storing latencies and availabilities of nodes.
const WINDOW_SIZE: usize = 15;
// Determines the decay rate of the exponential decay function, which is used for generating weights over the sliding window.
const LAMBDA_DECAY: f64 = 0.3;

/// Generates exponentially decaying weights for the sliding window.
/// Weights are higher for more recent observations and decay exponentially for older ones.
fn generate_exp_decaying_weights(n: usize, lambda: f64) -> Vec<f64> {
    let mut weights: Vec<f64> = Vec::with_capacity(n);
    for i in 0..n {
        let weight = (-lambda * i as f64).exp();
        weights.push(weight);
    }
    weights
}

// A node, which is selected to participate in the routing.
// The choice for selection is based on node's ranking (score).
#[derive(Clone, Debug)]
struct RoutingNode {
    node: Node,
    score: f64,
}

impl RoutingNode {
    fn new(node: Node, score: f64) -> Self {
        Self { node, score }
    }
}

// Stores node's meta information and metrics (latencies, availabilities).
// Routing URLs are generated based on the score field.
#[derive(Clone, Debug)]
struct NodeMetrics {
    // Size of the sliding window used for store latencies and availabilities of the node.
    window_size: usize,
    /// Reflects the status of the most recent health check. It should be the same as the last element in `availabilities`.
    is_healthy: bool,
    /// Sliding window with latency measurements.
    latencies: VecDeque<f64>,
    /// Sliding window with availability measurements.
    availabilities: VecDeque<bool>,
    /// Overall score of the node. Calculated based on latencies and availabilities arrays. This score is used in `next_n_nodes()` and `next_node()` methods.
    score: f64,
}

impl NodeMetrics {
    pub fn new(window_size: usize) -> Self {
        Self {
            window_size,
            is_healthy: false,
            latencies: VecDeque::with_capacity(window_size + 1),
            availabilities: VecDeque::with_capacity(window_size + 1),
            score: 0.0,
        }
    }

    pub fn add_latency_measurement(&mut self, latency: Option<Duration>) {
        self.is_healthy = latency.is_some();
        if let Some(duration) = latency {
            self.latencies.push_back(duration.as_secs_f64());
            while self.latencies.len() > self.window_size {
                self.latencies.pop_front();
            }
            self.availabilities.push_back(true);
        } else {
            self.availabilities.push_back(false);
        }
        while self.availabilities.len() > self.window_size {
            self.availabilities.pop_front();
        }
    }
}

/// Computes the score of the node based on the latencies, availabilities and window weights.
/// `window_weights_sum` is passed for efficiency reasons, as it is pre-calculated.
fn compute_score(
    window_weights: &[f64],
    window_weights_sum: f64,
    availabilities: &VecDeque<bool>,
    latencies: &VecDeque<f64>,
    use_availability_penalty: bool,
) -> f64 {
    let weights_size = window_weights.len();
    let availabilities_size = availabilities.len();
    let latencies_size = latencies.len();

    if weights_size < availabilities_size {
        panic!(
            "Configuration error: Weights array of size {weights_size} is smaller than array of availabilities of size {availabilities_size}.",
        );
    } else if weights_size < latencies_size {
        panic!(
            "Configuration error: Weights array of size {weights_size} is smaller than array of latencies of size {latencies_size}.",
        );
    }

    // Compute normalized availability score [0.0, 1.0].
    let score_a = if !use_availability_penalty {
        1.0
    } else if availabilities.is_empty() {
        0.0
    } else {
        let mut score = 0.0;

        // Compute weighted score. Weights are applied in reverse order.
        for (idx, availability) in availabilities.iter().rev().enumerate() {
            score += window_weights[idx] * (*availability as u8 as f64);
        }

        // Normalize the score.
        let weights_sum = if availabilities_size < weights_size {
            // Use partial sum of weights, if the window is not full.
            let partial_weights_sum: f64 = window_weights.iter().take(availabilities_size).sum();
            partial_weights_sum
        } else {
            // Use pre-calculated sum, if the window is full.
            window_weights_sum
        };

        score /= weights_sum;

        score
    };

    // Compute latency score (not normalized).
    let score_l = if latencies.is_empty() {
        0.0
    } else {
        let mut score = 0.0;

        // Compute weighted score. Weights are applied in reverse order. Latency is inverted, so that smaller latencies have higher score.
        for (idx, latency) in latencies.iter().rev().enumerate() {
            score += window_weights[idx] / latency;
        }

        let weights_sum = if latencies_size < weights_size {
            let partial_weights_sum: f64 = window_weights.iter().take(latencies.len()).sum();
            partial_weights_sum
        } else {
            // Use pre-calculated sum.
            window_weights_sum
        };

        score /= weights_sum;

        score
    };

    // Combine availability and latency scores via product to emphasize the importance of both metrics.
    score_l * score_a
}

/// # Latency-based dynamic routing
///
/// This module implements a routing strategy that uses weighted random selection of nodes based on their historical data (latencies and availabilities).
/// The main features of this strategy are:
///
/// - Uses sliding windows for storing latencies and availabilities of each node
/// - The overall score of each node is computed as a product of latency and availability scores, score = score_l * score_a
/// - Latency and availability scores are computed from sliding windows using an additional array of weights, allowing prioritization of more recent observations. By default, exponentially decaying weights are used.
/// - Uses weighted random selection of nodes for load balancing
///
/// ## Configuration Options
///
/// - `k_top_nodes`: Limit routing to only the top K nodes with highest score
/// - `use_availability_penalty`: Whether to penalize nodes for being unavailable
/// - Custom window weights can be provided for specialized decay functions
#[derive(Default, Debug, Clone)]
pub struct LatencyRoutingSnapshot {
    // If set, only k nodes with best scores are used for routing
    k_top_nodes: Option<usize>,
    // Stores all existing nodes in the topology along with their historical data (latencies and availabilities)
    existing_nodes: HashMap<Node, NodeMetrics>,
    // Snapshot of selected nodes, which are participating in routing. Snapshot is published via publish_routing_nodes() when either: topology changes or a health check of some node is received.
    routing_nodes: Arc<ArcSwap<Vec<RoutingNode>>>,
    // Weights used to compute the availability score of a node.
    window_weights: Vec<f64>,
    // Pre-computed weights sum, passed for efficiency purpose as this sum doesn't change.
    window_weights_sum: f64,
    // Whether or not penalize nodes score for being unavailable
    use_availability_penalty: bool,
}

/// Implementation of the LatencyRoutingSnapshot.
impl LatencyRoutingSnapshot {
    /// Creates a new LatencyRoutingSnapshot with default configuration.
    pub fn new() -> Self {
        // Weights are ordered from left to right, where the leftmost weight is for the most recent health check.
        let window_weights = generate_exp_decaying_weights(WINDOW_SIZE, LAMBDA_DECAY);
        // Pre-calculate the sum of weights for efficiency reasons.
        let window_weights_sum: f64 = window_weights.iter().sum();

        Self {
            k_top_nodes: None,
            existing_nodes: HashMap::new(),
            routing_nodes: Arc::new(ArcSwap::new(vec![].into())),
            use_availability_penalty: true,
            window_weights,
            window_weights_sum,
        }
    }

    /// Sets whether to use only k nodes with the highest score for routing.
    #[allow(unused)]
    pub fn set_k_top_nodes(mut self, k_top_nodes: usize) -> Self {
        self.k_top_nodes = Some(k_top_nodes);
        self
    }

    /// Sets whether to use availability penalty in the score computation.
    #[allow(unused)]
    pub fn set_availability_penalty(mut self, use_penalty: bool) -> Self {
        self.use_availability_penalty = use_penalty;
        self
    }

    /// Sets the weights for the sliding window.
    /// The weights are ordered from left to right, where the leftmost weight is for the most recent health check.
    #[allow(unused)]
    pub fn set_window_weights(mut self, weights: &[f64]) -> Self {
        self.window_weights_sum = weights.iter().sum();
        self.window_weights = weights.to_vec();
        self
    }

    /// Atomically updates the routing_nodes
    fn publish_routing_nodes(&self) {
        let mut routing_nodes: Vec<RoutingNode> = self
            .existing_nodes
            .iter()
            .filter(|(_, v)| v.is_healthy)
            .map(|(k, v)| RoutingNode::new(k.clone(), v.score))
            .collect();

        // In case requests are routed to only k top nodes, select these top nodes
        if let Some(k_top) = self.k_top_nodes {
            routing_nodes.sort_by(|a, b| {
                b.score
                    .partial_cmp(&a.score)
                    .unwrap_or(std::cmp::Ordering::Equal)
            });

            if routing_nodes.len() > k_top {
                routing_nodes.truncate(k_top);
            }
        }
        // Atomically update the routing table
        self.routing_nodes.store(Arc::new(routing_nodes));
    }
}

/// Helper function to sample nodes based on their weights.
/// Node index is selected based on the input number in range [0.0, 1.0]
#[inline(always)]
fn weighted_sample(weighted_nodes: &[RoutingNode], number: f64) -> Option<usize> {
    if !(0.0..=1.0).contains(&number) || weighted_nodes.is_empty() {
        return None;
    }
    let sum: f64 = weighted_nodes.iter().map(|n| n.score).sum();

    if sum == 0.0 {
        return None;
    }

    let mut weighted_number = number * sum;
    for (idx, node) in weighted_nodes.iter().enumerate() {
        weighted_number -= node.score;
        if weighted_number <= 0.0 {
            return Some(idx);
        }
    }

    // If this part is reached due to floating-point precision, return the last index
    Some(weighted_nodes.len() - 1)
}

impl RoutingSnapshot for LatencyRoutingSnapshot {
    fn has_nodes(&self) -> bool {
        !self.routing_nodes.load().is_empty()
    }

    fn next_node(&self) -> Option<Node> {
        self.next_n_nodes(1).into_iter().next()
    }

    // Uses weighted random sampling algorithm n times. Node can be selected at most once (sampling without replacement).
    fn next_n_nodes(&self, n: usize) -> Vec<Node> {
        if n == 0 {
            return Vec::new();
        }

        let mut routing_nodes: Vec<RoutingNode> = self.routing_nodes.load().as_ref().clone();

        // Limit the number of returned nodes to the number of available nodes
        let n = std::cmp::min(n, routing_nodes.len());
        let mut nodes = Vec::with_capacity(n);
        let mut rng = rand::thread_rng();

        for _ in 0..n {
            let rand_num = rng.gen::<f64>();
            if let Some(idx) = weighted_sample(routing_nodes.as_slice(), rand_num) {
                let removed_node = routing_nodes.swap_remove(idx);
                nodes.push(removed_node.node);
            }
        }

        nodes
    }

    fn sync_nodes(&mut self, nodes: &[Node]) -> bool {
        let new_nodes: HashSet<&Node> = nodes.iter().collect();
        let mut has_changes = false;

        // Remove nodes that are no longer present
        self.existing_nodes.retain(|node, _| {
            let keep = new_nodes.contains(node);
            if !keep {
                has_changes = true;
            }
            keep
        });

        // Add new nodes that don't exist yet
        for node in nodes {
            if !self.existing_nodes.contains_key(node) {
                self.existing_nodes
                    .insert(node.clone(), NodeMetrics::new(self.window_weights.len()));
                has_changes = true;
            }
        }

        if has_changes {
            self.publish_routing_nodes();
        }

        has_changes
    }

    fn update_node(&mut self, node: &Node, health: HealthCheckStatus) -> bool {
        // Get mut reference to the existing node metrics or return false if not found
        let updated_node: &mut NodeMetrics = match self.existing_nodes.get_mut(node) {
            Some(metrics) => metrics,
            None => return false,
        };
        // Update the node's metrics
        updated_node.add_latency_measurement(health.latency());

        updated_node.score = compute_score(
            &self.window_weights,
            self.window_weights_sum,
            &updated_node.availabilities,
            &updated_node.latencies,
            self.use_availability_penalty,
        );

        self.publish_routing_nodes();

        true
    }
}
