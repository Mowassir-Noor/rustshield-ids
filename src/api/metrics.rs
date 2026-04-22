//! Prometheus-compatible metrics endpoint

use axum::{extract::State, response::Response, body::Body};
use std::time::Duration;

use crate::api::ApiState;

/// Metrics response
pub async fn get_metrics(State(_state): State<ApiState>) -> Response<Body> {
    // In production, this would expose Prometheus-compatible metrics
    let metrics = format!(
        r#"# HELP rustshield_packets_total Total packets processed
# TYPE rustshield_packets_total counter
rustshield_packets_total 0

# HELP rustshield_alerts_total Total alerts generated
# TYPE rustshield_alerts_total counter
rustshield_alerts_total 0

# HELP rustshield_api_requests_total Total API requests
# TYPE rustshield_api_requests_total counter
rustshield_api_requests_total 0
"#
    );

    Response::builder()
        .header("Content-Type", "text/plain; version=0.0.4")
        .body(Body::from(metrics))
        .unwrap()
}
