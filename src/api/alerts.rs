//! Alert API endpoints

use axum::{
    extract::{Path, Query, State},
    Json,
};
use chrono::{DateTime, Utc};
use std::collections::VecDeque;
use std::net::IpAddr;
use std::str::FromStr;
use tracing::{debug, info, warn};

use crate::{
    api::{
        ApiError, ApiState, AlertQueryParams, PaginatedResponse, WebSocketMessage,
    },
    models::{Alert, AlertDetails, AlertType, Severity},
};

/// In-memory alert store with retention
pub struct AlertStore {
    alerts: VecDeque<Alert>,
    max_size: usize,
}

impl AlertStore {
    pub fn new() -> Self {
        Self {
            alerts: VecDeque::with_capacity(10000),
            max_size: 10000,
        }
    }

    /// Store a new alert
    pub fn add_alert(&mut self, alert: Alert) {
        if self.alerts.len() >= self.max_size {
            self.alerts.pop_front();
        }
        self.alerts.push_back(alert);
    }

    /// Get all alerts (optionally filtered)
    pub fn get_alerts(&self, filter: &AlertFilter) -> Vec<Alert> {
        self.alerts
            .iter()
            .filter(|a| filter.matches(a))
            .cloned()
            .collect()
    }

    /// Get a specific alert by ID
    pub fn get_alert(&self, id: &str) -> Option<Alert> {
        self.alerts.iter().find(|a| a.id == id).cloned()
    }

    /// Get recent alerts count
    pub fn count(&self) -> usize {
        self.alerts.len()
    }

    /// Get alerts by severity
    pub fn get_by_severity(&self, severity: Severity) -> Vec<Alert> {
        self.alerts
            .iter()
            .filter(|a| a.severity == severity)
            .cloned()
            .collect()
    }

    /// Get alerts from a specific source IP
    pub fn get_by_source_ip(&self, ip: IpAddr) -> Vec<Alert> {
        self.alerts
            .iter()
            .filter(|a| a.source_ip == Some(ip))
            .cloned()
            .collect()
    }

    /// Get alerts in time range
    pub fn get_in_range(&self, start: DateTime<Utc>, end: DateTime<Utc>) -> Vec<Alert> {
        self.alerts
            .iter()
            .filter(|a| a.timestamp >= start && a.timestamp <= end)
            .cloned()
            .collect()
    }

    /// Get latest N alerts
    pub fn get_latest(&self, n: usize) -> Vec<Alert> {
        self.alerts.iter().rev().take(n).cloned().collect()
    }

    /// Get statistics
    pub fn get_stats(&self) -> AlertStats {
        let mut by_severity: std::collections::HashMap<Severity, usize> = std::collections::HashMap::new();
        
        for alert in &self.alerts {
            *by_severity.entry(alert.severity.clone()).or_insert(0) += 1;
        }

        AlertStats {
            total: self.alerts.len(),
            by_severity,
            last_hour: self.alerts.iter().filter(|a| {
                a.timestamp > Utc::now() - chrono::Duration::hours(1)
            }).count(),
            last_24h: self.alerts.iter().filter(|a| {
                a.timestamp > Utc::now() - chrono::Duration::days(1)
            }).count(),
        }
    }
}

/// Alert statistics
#[derive(Debug, Default)]
pub struct AlertStats {
    pub total: usize,
    pub by_severity: std::collections::HashMap<Severity, usize>,
    pub last_hour: usize,
    pub last_24h: usize,
}

/// Alert filter criteria
#[derive(Debug, Default)]
pub struct AlertFilter {
    pub severity: Option<Severity>,
    pub source_ip: Option<IpAddr>,
    pub start_time: Option<DateTime<Utc>>,
    pub end_time: Option<DateTime<Utc>>,
}

impl AlertFilter {
    fn matches(&self, alert: &Alert) -> bool {
        if let Some(ref severity) = self.severity {
            if alert.severity != *severity {
                return false;
            }
        }

        if let Some(ref source_ip) = self.source_ip {
            if alert.source_ip != Some(*source_ip) {
                return false;
            }
        }

        if let Some(ref start) = self.start_time {
            if alert.timestamp < *start {
                return false;
            }
        }

        if let Some(ref end) = self.end_time {
            if alert.timestamp > *end {
                return false;
            }
        }

        true
    }
}

/// List alerts with filtering
pub async fn list_alerts(
    State(state): State<ApiState>,
    Query(params): Query<AlertQueryParams>,
) -> Result<Json<PaginatedResponse<Alert>>, ApiError> {
    debug!("Listing alerts with params: {:?}", params);

    let filter = build_filter(&params)?;
    let limit = params.limit.unwrap_or(50).min(1000);
    let offset = params.offset.unwrap_or(0);

    let store = state.alert_store.read().await;
    let all_alerts = store.get_alerts(&filter);
    let total = all_alerts.len();

    let paginated: Vec<Alert> = all_alerts
        .into_iter()
        .skip(offset)
        .take(limit)
        .collect();

    let has_more = offset + paginated.len() < total;

    let page = if offset == 0 { 1 } else { offset / limit + 1 };

    Ok(Json(PaginatedResponse {
        data: paginated,
        total,
        page,
        per_page: limit,
        has_more,
    }))
}

/// Get a single alert by ID
pub async fn get_alert(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Result<Json<Alert>, ApiError> {
    debug!("Getting alert: {}", id);

    let store = state.alert_store.read().await;
    
    match store.get_alert(&id) {
        Some(alert) => Ok(Json(alert)),
        None => Err(ApiError {
            error: "NotFound".to_string(),
            message: format!("Alert with ID '{}' not found", id),
            code: 404,
        }),
    }
}

/// Analyze an alert and generate insights
pub async fn analyze_alert(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Result<Json<AlertAnalysis>, ApiError> {
    debug!("Analyzing alert: {}", id);

    let store = state.alert_store.read().await;
    
    let alert = match store.get_alert(&id) {
        Some(alert) => alert,
        None => {
            return Err(ApiError {
                error: "NotFound".to_string(),
                message: format!("Alert with ID '{}' not found", id),
                code: 404,
            });
        }
    };

    // Use AI analyst to generate insights
    let analysis = state.analyst.analyze_alert(&alert).await;

    Ok(Json(analysis))
}

/// Alert analysis response
#[derive(Debug, serde::Serialize)]
pub struct AlertAnalysis {
    pub alert_id: String,
    pub summary: String,
    pub confidence: f64,
    pub severity: String,
    pub key_indicators: Vec<String>,
    pub recommended_actions: Vec<String>,
    pub related_alerts_count: usize,
    pub attack_pattern: Option<String>,
}

/// Build filter from query params
fn build_filter(params: &AlertQueryParams) -> Result<AlertFilter, ApiError> {
    let mut filter = AlertFilter::default();

    if let Some(ref severity_str) = params.severity {
        filter.severity = Some(
            Severity::from_str(severity_str).map_err(|_| ApiError {
                error: "InvalidSeverity".to_string(),
                message: format!("Invalid severity level: {}", severity_str),
                code: 400,
            })?
        );
    }

    if let Some(ref ip_str) = params.source_ip {
        filter.source_ip = Some(
            IpAddr::from_str(ip_str).map_err(|_| ApiError {
                error: "InvalidIP".to_string(),
                message: format!("Invalid IP address: {}", ip_str),
                code: 400,
            })?
        );
    }

    filter.start_time = params.start_time;
    filter.end_time = params.end_time;

    Ok(filter)
}

impl Severity {
    fn from_str(s: &str) -> Result<Self, ()> {
        match s.to_lowercase().as_str() {
            "low" => Ok(Severity::Low),
            "medium" => Ok(Severity::Medium),
            "high" => Ok(Severity::High),
            "critical" => Ok(Severity::Critical),
            _ => Err(()),
        }
    }
}
