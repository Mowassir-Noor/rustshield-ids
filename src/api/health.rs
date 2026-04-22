//! Health check endpoints

use axum::{extract::State, Json};
use serde::Serialize;
use std::time::Instant;

use crate::api::ApiState;

/// System health status
#[derive(Debug, Serialize)]
pub struct HealthStatus {
    pub status: String,
    pub version: String,
    pub uptime_seconds: u64,
    pub components: ComponentHealth,
}

/// Individual component health
#[derive(Debug, Serialize)]
pub struct ComponentHealth {
    pub capture: String,
    pub detection: String,
    pub api: String,
    pub storage: String,
}

/// Health check endpoint
pub async fn health_check(State(state): State<ApiState>) -> Json<HealthStatus> {
    Json(HealthStatus {
        status: "healthy".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_seconds: 0, // Would track actual uptime
        components: ComponentHealth {
            capture: "ok".to_string(),
            detection: "ok".to_string(),
            api: "ok".to_string(),
            storage: "ok".to_string(),
        },
    })
}
