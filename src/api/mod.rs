//! REST API Module for RustShield IDS
//!
//! Provides HTTP endpoints for:
//! - Alert querying and management
//! - System statistics and metrics
//! - Real-time WebSocket streaming
//! - Health checks

use axum::{
    extract::{State, WebSocketUpgrade},
    response::{IntoResponse, Json},
    routing::get,
    Router,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tower::ServiceBuilder;
use tower_http::{
    compression::CompressionLayer,
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};
use tracing::{info, warn};
use uuid::Uuid;

use crate::{
    config::Config,
    models::{Alert, Severity},
};

pub mod alerts;
pub mod analytics;
pub mod correlation;
pub mod health;
pub mod metrics;
pub mod stats;
pub mod websocket;

pub use alerts::AlertStore;
pub use analytics::AIAnalyst;
pub use correlation::CorrelationEngine;

/// Shared application state
#[derive(Clone)]
pub struct ApiState {
    pub config: Arc<Config>,
    pub alert_store: Arc<RwLock<AlertStore>>,
    pub correlation_engine: Arc<RwLock<CorrelationEngine>>,
    pub analyst: Arc<AIAnalyst>,
    pub ws_tx: tokio::sync::broadcast::Sender<WebSocketMessage>,
}

/// WebSocket message types
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WebSocketMessage {
    Alert { data: Alert },
    Stats { data: SystemStats },
    CorrelatedEvent { data: CorrelatedEvent },
    Ping,
    Pong,
}

/// System statistics
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SystemStats {
    pub packets_processed: u64,
    pub packets_per_second: f64,
    pub alerts_generated: u64,
    pub alerts_per_second: f64,
    pub active_correlations: usize,
    pub anomaly_rate: f64,
    pub uptime_seconds: u64,
    pub memory_usage_mb: f64,
    pub cpu_usage_percent: f64,
}

/// Correlated security event
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CorrelatedEvent {
    pub id: String,
    pub correlation_id: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub severity: Severity,
    pub confidence: f64,
    pub summary: String,
    pub description: String,
    pub source_ips: Vec<std::net::IpAddr>,
    pub alert_ids: Vec<String>,
    pub attack_type: String,
    pub duration_seconds: u64,
    pub recommended_actions: Vec<String>,
    pub key_indicators: Vec<String>,
}

/// Alert query parameters
#[derive(Debug, Deserialize)]
pub struct AlertQueryParams {
    pub severity: Option<String>,
    pub source_ip: Option<String>,
    pub start_time: Option<chrono::DateTime<chrono::Utc>>,
    pub end_time: Option<chrono::DateTime<chrono::Utc>>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

/// Paginated response wrapper
#[derive(Debug, Serialize)]
pub struct PaginatedResponse<T> {
    pub data: Vec<T>,
    pub total: usize,
    pub page: usize,
    pub per_page: usize,
    pub has_more: bool,
}

/// API error response
#[derive(Debug, Serialize)]
pub struct ApiError {
    pub error: String,
    pub message: String,
    pub code: u16,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        let status = axum::http::StatusCode::from_u16(self.code)
            .unwrap_or(axum::http::StatusCode::INTERNAL_SERVER_ERROR);
        (status, Json(self)).into_response()
    }
}

impl ApiState {
    pub fn new(config: Arc<Config>) -> Self {
        let (ws_tx, _) = tokio::sync::broadcast::channel(1000);

        Self {
            config,
            alert_store: Arc::new(RwLock::new(AlertStore::new())),
            correlation_engine: Arc::new(RwLock::new(CorrelationEngine::new())),
            analyst: Arc::new(AIAnalyst::new()),
            ws_tx,
        }
    }

    /// Broadcast a message to all connected WebSocket clients
    pub fn broadcast(&self, msg: WebSocketMessage) {
        let _ = self.ws_tx.send(msg);
    }
}

/// Create the API router
pub fn create_router(state: ApiState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    Router::new()
        // Health and system endpoints
        .route("/health", get(health::health_check))
        .route("/metrics", get(metrics::get_metrics))
        .route("/stats", get(stats::get_stats))
        // Alert endpoints
        .route("/alerts", get(alerts::list_alerts))
        .route("/alerts/:id", get(alerts::get_alert))
        .route("/alerts/:id/analyze", get(alerts::analyze_alert))
        // Analytics endpoints
        .route("/analytics/traffic", get(analytics::traffic_stats))
        .route("/analytics/threats", get(analytics::top_threats))
        .route("/analytics/timeline", get(analytics::alert_timeline))
        // Correlation endpoints
        .route("/correlations", get(correlation::list_correlations))
        .route("/correlations/:id", get(correlation::get_correlation))
        // WebSocket endpoint
        .route("/ws/alerts", get(websocket::ws_handler))
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(CompressionLayer::new())
                .layer(cors),
        )
        .with_state(state)
}

/// Start the API server
pub async fn start_api_server(state: ApiState, addr: SocketAddr) -> anyhow::Result<()> {
    let app = create_router(state);

    info!("Starting API server on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

/// Run both IDS core and API server
pub async fn run_integrated(config: Arc<Config>, api_addr: SocketAddr) -> anyhow::Result<()> {
    let state = ApiState::new(config.clone());

    // Spawn API server
    let api_state = state.clone();
    let api_handle = tokio::spawn(async move {
        if let Err(e) = start_api_server(api_state, api_addr).await {
            warn!("API server error: {}", e);
        }
    });

    info!("RustShield IDS Platform started");
    info!("API server: http://{}", api_addr);

    // Wait for API server
    api_handle.await?;

    Ok(())
}
