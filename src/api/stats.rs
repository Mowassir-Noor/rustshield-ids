//! System statistics endpoint

use axum::{extract::State, Json};
use serde::Serialize;

use crate::api::{ApiState, SystemStats};

/// Detailed system statistics
#[derive(Debug, Serialize)]
pub struct DetailedStats {
    pub system: SystemStats,
    pub alerts_by_severity: std::collections::HashMap<String, usize>,
    pub top_source_ips: Vec<(String, usize)>,
    pub top_rules_triggered: Vec<(String, usize)>,
    pub capture_stats: CaptureStats,
}

/// Capture-specific statistics
#[derive(Debug, Serialize)]
pub struct CaptureStats {
    pub interface: String,
    pub datalink_type: String,
    pub packets_captured: u64,
    pub packets_dropped: u64,
    pub bytes_captured: u64,
}

/// Get current system statistics
pub async fn get_stats(State(state): State<ApiState>) -> Json<DetailedStats> {
    let store = state.alert_store.read().await;
    let alert_stats = store.get_stats();

    // Build severity map
    let mut alerts_by_severity: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for (severity, count) in alert_stats.by_severity {
        alerts_by_severity.insert(format!("{:?}", severity), count);
    }

    let stats = DetailedStats {
        system: SystemStats {
            packets_processed: 0,
            packets_per_second: 0.0,
            alerts_generated: alert_stats.total as u64,
            alerts_per_second: 0.0,
            active_correlations: 0,
            anomaly_rate: 0.0,
            uptime_seconds: 0,
            memory_usage_mb: 0.0,
            cpu_usage_percent: 0.0,
        },
        alerts_by_severity,
        top_source_ips: vec![],
        top_rules_triggered: vec![],
        capture_stats: CaptureStats {
            interface: state.config.capture.interface.clone().unwrap_or_default(),
            datalink_type: "Ethernet".to_string(),
            packets_captured: 0,
            packets_dropped: 0,
            bytes_captured: 0,
        },
    };

    Json(stats)
}
