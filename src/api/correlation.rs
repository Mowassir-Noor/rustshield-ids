//! Event Correlation Engine
//!
//! Groups related alerts into attack scenarios to reduce noise and detect multi-stage attacks.

use crate::{
    api::{CorrelatedEvent, WebSocketMessage},
    models::{Alert, AlertType, Severity},
};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use tracing::{debug, info, warn};
use uuid::Uuid;

/// Correlation engine for grouping related alerts
pub struct CorrelationEngine {
    /// Active correlation windows
    windows: Vec<CorrelationWindow>,
    /// Completed correlations
    completed: Vec<CorrelatedEvent>,
    /// Window size in seconds
    window_size: i64,
    /// Maximum number of active windows
    max_windows: usize,
    /// Maximum stored completed correlations
    max_completed: usize,
}

/// A correlation window groups alerts by source IP and time
#[derive(Clone, Debug)]
struct CorrelationWindow {
    /// Unique correlation ID
    id: String,
    /// Source IP address
    source_ip: IpAddr,
    /// When the window started
    start_time: DateTime<Utc>,
    /// When the window ends
    end_time: DateTime<Utc>,
    /// Alerts in this window
    alerts: Vec<Alert>,
    /// Detected attack patterns
    patterns: Vec<AttackPattern>,
    /// Current severity level
    severity: Severity,
    /// Confidence score (0.0 - 1.0)
    confidence: f64,
}

/// Attack patterns that can be detected
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
enum AttackPattern {
    PortScan,
    SynFlood,
    DnsTunneling,
    SmbLateralMovement,
    IcmpTunneling,
    Reconnaissance,
    BruteForce,
    DataExfiltration,
    DDoS,
    MultiStageAttack,
}

impl CorrelationEngine {
    /// Create a new correlation engine
    pub fn new() -> Self {
        Self {
            windows: Vec::new(),
            completed: Vec::new(),
            window_size: 60, // 60 second windows
            max_windows: 1000,
            max_completed: 10000,
        }
    }

    /// Process a new alert and correlate it with existing windows
    pub fn process_alert(&mut self, alert: &Alert) -> Option<CorrelatedEvent> {
        // Get source IP from alert
        let source_ip = match alert.source_ip {
            Some(ip) => ip,
            None => return None, // Can't correlate without source IP
        };

        // Check if this alert fits into an existing window
        let mut matched_window = None;

        for (idx, window) in self.windows.iter_mut().enumerate() {
            if window.matches(source_ip, alert.timestamp) {
                matched_window = Some(idx);
                break;
            }
        }

        let should_finalize = if let Some(idx) = matched_window {
            // Add to existing window
            let window = &mut self.windows[idx];
            window.add_alert(alert.clone());
            window.analyze_patterns();

            // Check if window should be finalized (older than window_size)
            let now = Utc::now();
            window.end_time < now
        } else {
            // Create new window
            if self.windows.len() >= self.max_windows {
                // Remove oldest window
                let old = self.windows.remove(0);
                self.finalize_window(old);
            }

            let window = CorrelationWindow::new(source_ip, alert.clone());
            self.windows.push(window);
            false
        };

        // Finalize expired windows
        if should_finalize {
            if let Some(idx) = matched_window {
                let window = self.windows.remove(idx);
                return self.finalize_window(window);
            }
        }

        None
    }

    /// Finalize a correlation window and create a correlated event
    fn finalize_window(&mut self, window: CorrelationWindow) -> Option<CorrelatedEvent> {
        if window.alerts.is_empty() {
            return None;
        }

        let event = window.to_correlated_event();

        // Store completed correlation
        if self.completed.len() >= self.max_completed {
            self.completed.remove(0);
        }
        self.completed.push(event.clone());

        info!(
            "Correlated event finalized: {} ({} alerts, confidence: {:.2})",
            event.summary,
            window.alerts.len(),
            event.confidence
        );

        Some(event)
    }

    /// Get all active correlations
    pub fn get_active_correlations(&self) -> Vec<CorrelatedEvent> {
        self.windows
            .iter()
            .map(|w| w.to_correlated_event())
            .collect()
    }

    /// Get completed correlations
    pub fn get_completed_correlations(&self) -> &[CorrelatedEvent] {
        &self.completed
    }

    /// Get a specific correlation by ID
    pub fn get_correlation(&self, id: &str) -> Option<CorrelatedEvent> {
        // Check active windows
        for window in &self.windows {
            if window.id == id {
                return Some(window.to_correlated_event());
            }
        }

        // Check completed
        self.completed.iter().find(|c| c.id == id).cloned()
    }

    /// Clean up expired windows
    pub fn cleanup_expired(&mut self) -> Vec<CorrelatedEvent> {
        let now = Utc::now();
        let mut finalized = vec![];

        // Find expired windows
        let expired: Vec<usize> = self
            .windows
            .iter()
            .enumerate()
            .filter(|(_, w)| w.end_time < now)
            .map(|(idx, _)| idx)
            .collect();

        // Remove expired windows (in reverse order to maintain indices)
        for idx in expired.iter().rev() {
            let window = self.windows.remove(*idx);
            if let Some(event) = self.finalize_window(window) {
                finalized.push(event);
            }
        }

        finalized
    }

    /// Get correlation statistics
    pub fn get_stats(&self) -> CorrelationStats {
        CorrelationStats {
            active_windows: self.windows.len(),
            completed_correlations: self.completed.len(),
            detected_patterns: self.count_patterns(),
        }
    }

    /// Count detected patterns
    fn count_patterns(&self) -> HashMap<String, usize> {
        let mut counts: HashMap<String, usize> = HashMap::new();

        for window in &self.windows {
            for pattern in &window.patterns {
                *counts.entry(format!("{:?}", pattern)).or_insert(0) += 1;
            }
        }

        for event in &self.completed {
            *counts.entry(event.attack_type.clone()).or_insert(0) += 1;
        }

        counts
    }
}

/// Correlation statistics
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CorrelationStats {
    pub active_windows: usize,
    pub completed_correlations: usize,
    pub detected_patterns: HashMap<String, usize>,
}

impl CorrelationWindow {
    /// Create a new correlation window
    fn new(source_ip: IpAddr, initial_alert: Alert) -> Self {
        let start_time = initial_alert.timestamp;
        let end_time = start_time + Duration::seconds(60);

        Self {
            id: format!(
                "CORR-{}",
                Uuid::new_v4().to_string().split('-').next().unwrap_or("")
            ),
            source_ip,
            start_time,
            end_time,
            alerts: vec![initial_alert],
            patterns: vec![],
            severity: Severity::Low,
            confidence: 0.0,
        }
    }

    /// Check if an alert matches this window
    fn matches(&self, source_ip: IpAddr, timestamp: DateTime<Utc>) -> bool {
        self.source_ip == source_ip && timestamp <= self.end_time
    }

    /// Add an alert to this window
    fn add_alert(&mut self, alert: Alert) {
        // Extend window if needed (up to 2x original size)
        let max_end = self.start_time + Duration::seconds(120);
        if alert.timestamp > self.end_time && alert.timestamp < max_end {
            self.end_time = alert.timestamp + Duration::seconds(60);
        }

        self.alerts.push(alert);
    }

    /// Analyze patterns in the alerts
    fn analyze_patterns(&mut self) {
        let mut patterns = HashSet::new();
        let mut has_port_scan = false;
        let mut has_syn_flood = false;
        let mut has_dns_tunnel = false;
        let mut has_smb = false;
        let mut has_icmp_tunnel = false;
        let mut has_anomaly = false;

        for alert in &self.alerts {
            match &alert.alert_type {
                AlertType::RuleBased { rule_id, .. } => {
                    match rule_id.as_str() {
                        "RULE-001" => {
                            // SSH
                            if self.alerts.len() > 5 {
                                patterns.insert(AttackPattern::BruteForce);
                            }
                        }
                        "RULE-002" => { // Telnet
                             // Just informational
                        }
                        "RULE-003" => {
                            // DNS TCP Large
                            has_dns_tunnel = true;
                            patterns.insert(AttackPattern::DnsTunneling);
                        }
                        "RULE-004" => {
                            // SMB
                            has_smb = true;
                            patterns.insert(AttackPattern::SmbLateralMovement);
                        }
                        "RULE-005" => { // RDP
                             // Just informational
                        }
                        "RULE-006" => {
                            // ICMP Large
                            has_icmp_tunnel = true;
                            patterns.insert(AttackPattern::IcmpTunneling);
                        }
                        _ => {}
                    }
                }
                AlertType::AnomalyBased { .. } => {
                    has_anomaly = true;

                    // Check description for patterns
                    if alert.description.contains("port scan") {
                        has_port_scan = true;
                        patterns.insert(AttackPattern::PortScan);
                    }
                    if alert.description.contains("SYN flood") {
                        has_syn_flood = true;
                        patterns.insert(AttackPattern::SynFlood);
                    }
                }
            }
        }

        // Detect multi-stage attacks
        if has_port_scan && (has_syn_flood || has_anomaly) {
            patterns.insert(AttackPattern::MultiStageAttack);
        }

        // Detect reconnaissance followed by exploitation
        if has_port_scan && has_smb {
            patterns.insert(AttackPattern::Reconnaissance);
        }

        // Calculate confidence based on alert count and pattern diversity
        let pattern_count = patterns.len();
        let alert_count = self.alerts.len();

        self.confidence = ((pattern_count as f64 * 0.2) + (alert_count as f64 * 0.05)).min(1.0);

        // Determine severity
        self.severity = if patterns.contains(&AttackPattern::MultiStageAttack) {
            Severity::Critical
        } else if pattern_count >= 2 || alert_count > 10 {
            Severity::High
        } else if alert_count > 3 {
            Severity::Medium
        } else {
            Severity::Low
        };

        self.patterns = patterns.into_iter().collect();
    }

    /// Convert to correlated event
    fn to_correlated_event(&self) -> CorrelatedEvent {
        let attack_type = if self.patterns.is_empty() {
            "Unknown".to_string()
        } else {
            self.patterns
                .iter()
                .map(|p| format!("{:?}", p))
                .collect::<Vec<_>>()
                .join(" + ")
        };

        let summary = self.generate_summary(&attack_type);
        let description = self.generate_description();
        let recommendations = self.generate_recommendations();
        let indicators = self.extract_indicators();

        let duration = (self.end_time - self.start_time).num_seconds() as u64;

        CorrelatedEvent {
            id: self.id.clone(),
            correlation_id: self.id.clone(),
            timestamp: self.start_time,
            severity: self.severity.clone(),
            confidence: self.confidence,
            summary,
            description,
            source_ips: vec![self.source_ip],
            alert_ids: self.alerts.iter().map(|a| a.id.clone()).collect(),
            attack_type,
            duration_seconds: duration,
            recommended_actions: recommendations,
            key_indicators: indicators,
        }
    }

    /// Generate summary text
    fn generate_summary(&self, attack_type: &str) -> String {
        format!(
            "{} from {} ({} alerts over {} seconds)",
            attack_type,
            self.source_ip,
            self.alerts.len(),
            (self.end_time - self.start_time).num_seconds()
        )
    }

    /// Generate detailed description
    fn generate_description(&self) -> String {
        let mut parts = vec![];

        // Count by type
        let mut rule_count = 0;
        let mut anomaly_count = 0;

        for alert in &self.alerts {
            match alert.alert_type {
                AlertType::RuleBased { .. } => rule_count += 1,
                AlertType::AnomalyBased { .. } => anomaly_count += 1,
            }
        }

        parts.push(format!(
            "Correlation window contains {} rule-based and {} anomaly-based alerts from IP {}.",
            rule_count, anomaly_count, self.source_ip
        ));

        if !self.patterns.is_empty() {
            parts.push(format!(
                "Detected attack patterns: {}.",
                self.patterns
                    .iter()
                    .map(|p| format!("{:?}", p))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }

        parts.join(" ")
    }

    /// Generate recommendations based on patterns
    fn generate_recommendations(&self) -> Vec<String> {
        let mut recs = vec![];

        for pattern in &self.patterns {
            match pattern {
                AttackPattern::PortScan => {
                    recs.push("Deploy port scan detection and rate limiting".to_string());
                    recs.push("Consider network segmentation".to_string());
                }
                AttackPattern::SynFlood => {
                    recs.push("Enable SYN cookies on affected systems".to_string());
                    recs.push("Implement DDoS mitigation".to_string());
                }
                AttackPattern::BruteForce => {
                    recs.push("Implement account lockout policies".to_string());
                    recs.push("Deploy fail2ban or similar protection".to_string());
                }
                AttackPattern::DnsTunneling => {
                    recs.push("Enable DNS query logging and analysis".to_string());
                    recs.push("Deploy DNS filtering".to_string());
                }
                AttackPattern::SmbLateralMovement => {
                    recs.push("Block SMB at perimeter firewall".to_string());
                    recs.push("Enable SMB encryption and signing".to_string());
                }
                AttackPattern::MultiStageAttack => {
                    recs.push("Immediate incident response required".to_string());
                    recs.push("Isolate affected systems".to_string());
                    recs.push("Perform full forensic investigation".to_string());
                }
                _ => {}
            }
        }

        if recs.is_empty() {
            recs.push("Monitor source IP for continued suspicious activity".to_string());
            recs.push("Review security policies for this traffic type".to_string());
        }

        recs
    }

    /// Extract key indicators
    fn extract_indicators(&self) -> Vec<String> {
        let mut indicators = vec![];

        // Alert count
        indicators.push(format!("Total alerts: {}", self.alerts.len()));

        // Time window
        indicators.push(format!(
            "Time window: {} seconds",
            (self.end_time - self.start_time).num_seconds()
        ));

        // Severity breakdown
        let mut severity_counts: HashMap<String, usize> = HashMap::new();
        for alert in &self.alerts {
            *severity_counts
                .entry(format!("{:?}", alert.severity))
                .or_insert(0) += 1;
        }

        for (sev, count) in severity_counts {
            indicators.push(format!("{} severity: {}", sev, count));
        }

        indicators
    }
}

/// List all correlations endpoint
pub async fn list_correlations(
    axum::extract::State(state): axum::extract::State<crate::api::ApiState>,
) -> axum::response::Json<Vec<CorrelatedEvent>> {
    let engine = state.correlation_engine.read().await;
    let mut all: Vec<CorrelatedEvent> = vec![];

    // Get active
    all.extend(engine.get_active_correlations());

    // Get completed
    all.extend(engine.get_completed_correlations().iter().cloned());

    axum::response::Json(all)
}

/// Get a specific correlation
pub async fn get_correlation(
    axum::extract::State(state): axum::extract::State<crate::api::ApiState>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<axum::response::Json<CorrelatedEvent>, crate::api::ApiError> {
    let engine = state.correlation_engine.read().await;

    match engine.get_correlation(&id) {
        Some(event) => Ok(axum::response::Json(event)),
        None => Err(crate::api::ApiError {
            error: "NotFound".to_string(),
            message: format!("Correlation with ID '{}' not found", id),
            code: 404,
        }),
    }
}
