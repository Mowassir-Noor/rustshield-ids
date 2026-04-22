use crate::config::Config;
use crate::models::{
    Alert, AlertDetails, AlertType, FeatureDeviation, PacketInfo, Severity, TrafficFeatures,
};
use crate::utils::{generate_alert_id, SlidingWindowCounter};
use anyhow::Result;
use chrono::Utc;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;

mod rules;

pub use rules::{RuleEngine, RuleMatcher};

/// Main detection engine that combines rule-based and anomaly detection
pub struct DetectionEngine {
    config: Arc<Config>,
    rule_engine: RuleEngine,
    port_scan_tracker: Arc<RwLock<PortScanTracker>>,
    syn_flood_tracker: Arc<RwLock<SynFloodTracker>>,
}

/// Tracks potential port scan activity
struct PortScanTracker {
    connections: HashMap<IpAddr, HashSet<u16>>,
    timestamps: HashMap<IpAddr, Vec<std::time::Instant>>,
    window_secs: u64,
    threshold: u32,
}

/// Tracks potential SYN flood attacks
struct SynFloodTracker {
    syn_counters: SlidingWindowCounter,
    threshold: u32,
}

impl DetectionEngine {
    pub fn new(config: Arc<Config>) -> Result<Self> {
        let rule_engine = RuleEngine::load(&config.detection.rules_file)?;

        let port_scan_tracker = Arc::new(RwLock::new(PortScanTracker {
            connections: HashMap::new(),
            timestamps: HashMap::new(),
            window_secs: config.detection.port_scan_time_window_secs,
            threshold: config.detection.port_scan_threshold,
        }));

        let syn_flood_tracker = Arc::new(RwLock::new(SynFloodTracker {
            syn_counters: SlidingWindowCounter::new(config.detection.syn_flood_time_window_secs),
            threshold: config.detection.syn_flood_threshold,
        }));

        info!(
            "Detection engine initialized with {} rules",
            rule_engine.rule_count()
        );

        Ok(Self {
            config,
            rule_engine,
            port_scan_tracker,
            syn_flood_tracker,
        })
    }

    /// Process a single packet and generate alerts
    pub async fn process_packet(&self, packet: &PacketInfo) -> Vec<Alert> {
        let mut alerts = Vec::new();

        // Rule-based detection
        if self.config.detection.enable_rule_based {
            if let Some(alert) = self.check_rules(packet).await {
                alerts.push(alert);
            }
        }

        // Port scan detection
        if let Some(alert) = self.check_port_scan(packet).await {
            alerts.push(alert);
        }

        // SYN flood detection
        if let Some(alert) = self.check_syn_flood(packet).await {
            alerts.push(alert);
        }

        alerts
    }

    /// Analyze traffic features for anomaly detection
    pub async fn analyze_traffic_features(
        &self,
        features: &TrafficFeatures,
        anomaly_score: f64,
        deviations: Vec<FeatureDeviation>,
    ) -> Option<Alert> {
        if anomaly_score < self.config.ai.anomaly_threshold {
            return None;
        }

        let severity = Self::score_to_severity(anomaly_score);

        let recommendations = Self::generate_recommendations(&deviations);

        Some(Alert {
            id: generate_alert_id(),
            timestamp: Utc::now(),
            severity,
            alert_type: AlertType::AnomalyBased {
                model_version: "1.0".to_string(),
            },
            source_ip: None, // Would be populated with actual source in real implementation
            destination_ip: None,
            description: format!(
                "Anomalous traffic pattern detected (score: {:.2})",
                anomaly_score
            ),
            details: AlertDetails {
                triggered_features: deviations.iter().map(|d| d.feature_name.clone()).collect(),
                feature_deviations: deviations,
                raw_features: Some(features.clone()),
                recommendation: recommendations,
            },
            score: anomaly_score,
        })
    }

    async fn check_rules(&self, packet: &PacketInfo) -> Option<Alert> {
        if let Some(rule_match) = self.rule_engine.match_packet(packet) {
            return Some(Alert {
                id: generate_alert_id(),
                timestamp: Utc::now(),
                severity: rule_match.rule.severity.clone(),
                alert_type: AlertType::RuleBased {
                    rule_id: rule_match.rule.id.clone(),
                    rule_name: rule_match.rule.name.clone(),
                },
                source_ip: Some(packet.source_ip),
                destination_ip: Some(packet.destination_ip),
                description: rule_match.rule.description.clone(),
                details: AlertDetails {
                    triggered_features: vec!["rule_match".to_string()],
                    feature_deviations: vec![],
                    raw_features: None,
                    recommendation: format!(
                        "Investigate traffic matching rule: {}",
                        rule_match.rule.name
                    ),
                },
                score: Self::severity_to_score(&rule_match.rule.severity),
            });
        }
        None
    }

    async fn check_port_scan(&self, packet: &PacketInfo) -> Option<Alert> {
        // Only track TCP packets with destination ports
        let dest_port = packet.destination_port?;
        let source_ip = packet.source_ip;

        let (should_alert, unique_ports, window_secs, threshold) = {
            let mut tracker = self.port_scan_tracker.write().await;
            let now = std::time::Instant::now();
            let window_secs = tracker.window_secs;
            let window = std::time::Duration::from_secs(window_secs);
            let threshold = tracker.threshold;

            // Get or create entries using get_mut pattern
            if !tracker.connections.contains_key(&source_ip) {
                tracker.connections.insert(source_ip, HashSet::new());
            }
            if !tracker.timestamps.contains_key(&source_ip) {
                tracker.timestamps.insert(source_ip, Vec::new());
            }

            // Update ports
            let ports = tracker.connections.get_mut(&source_ip).unwrap();
            ports.insert(dest_port);
            let unique_ports = ports.len();

            // Update timestamps
            let timestamps = tracker.timestamps.get_mut(&source_ip).unwrap();
            timestamps.retain(|&t| now.duration_since(t) < window);
            timestamps.push(now);
            let recent_connections = timestamps.len();

            let should_alert =
                unique_ports >= threshold as usize && recent_connections >= threshold as usize;

            if should_alert {
                // Clear entries
                tracker.connections.get_mut(&source_ip).unwrap().clear();
                tracker.timestamps.get_mut(&source_ip).unwrap().clear();
            }

            (should_alert, unique_ports, window_secs, threshold)
        }; // tracker lock released here

        if should_alert {
            return Some(Alert {
                id: generate_alert_id(),
                timestamp: Utc::now(),
                severity: Severity::High,
                alert_type: AlertType::RuleBased {
                    rule_id: "PORT_SCAN".to_string(),
                    rule_name: "Port Scan Detection".to_string(),
                },
                source_ip: Some(source_ip),
                destination_ip: Some(packet.destination_ip),
                description: format!(
                    "Potential port scan detected: {} unique ports in {} seconds",
                    unique_ports, window_secs
                ),
                details: AlertDetails {
                    triggered_features: vec![
                        "high_port_diversity".to_string(),
                        "connection_frequency".to_string(),
                    ],
                    feature_deviations: vec![FeatureDeviation {
                        feature_name: "unique_destination_ports".to_string(),
                        expected_value: threshold as f64,
                        actual_value: unique_ports as f64,
                        deviation_score: (unique_ports as f64) / (threshold as f64),
                        explanation: format!(
                            "Source IP contacted {} unique ports within {} seconds",
                            unique_ports, window_secs
                        ),
                    }],
                    raw_features: None,
                    recommendation: "Investigate source IP for reconnaissance activity".to_string(),
                },
                score: 0.85,
            });
        }

        None
    }

    async fn check_syn_flood(&self, packet: &PacketInfo) -> Option<Alert> {
        // Check for SYN packets
        let flags = packet.flags?;
        let is_syn = (flags & 0x02) != 0; // SYN flag
        let is_ack = (flags & 0x10) != 0; // ACK flag

        if !is_syn || is_ack {
            return None;
        }

        let mut tracker = self.syn_flood_tracker.write().await;
        let syn_count = tracker.syn_counters.add_event(packet.source_ip);

        if syn_count >= tracker.threshold as usize {
            return Some(Alert {
                id: generate_alert_id(),
                timestamp: Utc::now(),
                severity: Severity::Critical,
                alert_type: AlertType::RuleBased {
                    rule_id: "SYN_FLOOD".to_string(),
                    rule_name: "SYN Flood Detection".to_string(),
                },
                source_ip: Some(packet.source_ip),
                destination_ip: Some(packet.destination_ip),
                description: format!(
                    "Potential SYN flood attack: {} SYN packets in {} seconds",
                    syn_count, self.config.detection.syn_flood_time_window_secs
                ),
                details: AlertDetails {
                    triggered_features: vec!["high_syn_rate".to_string()],
                    feature_deviations: vec![FeatureDeviation {
                        feature_name: "syn_packets_per_second".to_string(),
                        expected_value: 10.0,
                        actual_value: syn_count as f64,
                        deviation_score: (syn_count as f64) / 10.0,
                        explanation: format!(
                            "Unusually high rate of SYN packets without completing handshakes"
                        ),
                    }],
                    raw_features: None,
                    recommendation: "Consider implementing SYN cookies or rate limiting"
                        .to_string(),
                },
                score: 0.95,
            });
        }

        None
    }

    fn score_to_severity(score: f64) -> Severity {
        match score {
            s if s >= 0.9 => Severity::Critical,
            s if s >= 0.75 => Severity::High,
            s if s >= 0.6 => Severity::Medium,
            _ => Severity::Low,
        }
    }

    fn severity_to_score(severity: &Severity) -> f64 {
        match severity {
            Severity::Critical => 0.95,
            Severity::High => 0.8,
            Severity::Medium => 0.65,
            Severity::Low => 0.4,
        }
    }

    fn generate_recommendations(deviations: &[FeatureDeviation]) -> String {
        if deviations.is_empty() {
            return "Monitor traffic patterns".to_string();
        }

        let recommendations: Vec<String> = deviations
            .iter()
            .map(|d| match d.feature_name.as_str() {
                "connection_frequency" => "Check for automated/bot traffic".to_string(),
                "packet_size_distribution" => "Investigate data exfiltration".to_string(),
                "port_entropy" => "Scan for unauthorized services".to_string(),
                "bytes_per_second" => "Check bandwidth usage patterns".to_string(),
                _ => format!("Investigate abnormal {}", d.feature_name),
            })
            .collect();

        recommendations.join("; ")
    }
}
