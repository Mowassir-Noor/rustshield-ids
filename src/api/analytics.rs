//! AI Analyst module for explainable insights

use crate::models::{Alert, AlertType, FeatureDeviation, Severity};
use axum::Json;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// AI-generated analysis of an alert
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AIInsight {
    pub summary: String,
    pub confidence: f64,
    pub severity: String,
    pub key_indicators: Vec<String>,
    pub recommended_actions: Vec<String>,
    pub attack_pattern: String,
    pub related_techniques: Vec<String>, // MITRE ATT&CK
}

/// Traffic analytics
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TrafficAnalytics {
    pub packets_per_second: f64,
    pub bytes_per_second: f64,
    pub connection_count: usize,
    pub anomaly_score_avg: f64,
    pub top_protocols: Vec<(String, usize)>,
    pub top_ports: Vec<(u16, usize)>,
}

/// Threat summary
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ThreatSummary {
    pub top_ips: Vec<(String, usize, String)>, // (IP, alert_count, threat_type)
    pub top_rules: Vec<(String, usize)>,
    pub attack_trends: Vec<(String, usize)>, // (attack_type, count)
}

/// Timeline data point
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TimelinePoint {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub alert_count: usize,
    pub severity_counts: HashMap<String, usize>,
    pub anomaly_score: f64,
}

/// AI Analyst for generating human-readable insights
pub struct AIAnalyst;

impl AIAnalyst {
    pub fn new() -> Self {
        Self
    }

    /// Analyze a single alert and generate insights
    pub async fn analyze_alert(&self, alert: &Alert) -> crate::api::alerts::AlertAnalysis {
        let insight = self.generate_insight(alert);

        crate::api::alerts::AlertAnalysis {
            alert_id: alert.id.clone(),
            summary: insight.summary,
            confidence: insight.confidence,
            severity: insight.severity,
            key_indicators: insight.key_indicators,
            recommended_actions: insight.recommended_actions,
            related_alerts_count: 0, // Would query correlation engine
            attack_pattern: Some(insight.attack_pattern),
        }
    }

    /// Generate insight from alert
    fn generate_insight(&self, alert: &Alert) -> AIInsight {
        match &alert.alert_type {
            AlertType::RuleBased { rule_id, rule_name } => {
                self.analyze_rule_based(rule_id, rule_name, alert)
            }
            AlertType::AnomalyBased { .. } => self.analyze_anomaly_based(alert),
        }
    }

    /// Analyze rule-based alerts
    fn analyze_rule_based(&self, rule_id: &str, rule_name: &str, alert: &Alert) -> AIInsight {
        let (summary, pattern, techniques) = match rule_id {
            "RULE-001" => (
                "SSH connection detected. May be legitimate access or brute force attempt.".to_string(),
                "SSH Connection",
                vec!["T1021.004".to_string()], // Remote Services: SSH
            ),
            "RULE-002" => (
                "Insecure Telnet protocol detected. Traffic is unencrypted and vulnerable to interception.".to_string(),
                "Insecure Protocol Usage",
                vec!["T1040".to_string()], // Network Sniffing
            ),
            "RULE-003" => (
                "Large DNS query over TCP detected. Possible DNS tunneling for data exfiltration.".to_string(),
                "DNS Tunneling",
                vec!["T1071.004".to_string()], // Application Layer Protocol: DNS
            ),
            "RULE-004" => (
                "SMB traffic to external destination. Potential lateral movement or ransomware activity.".to_string(),
                "SMB Lateral Movement",
                vec!["T1021.002".to_string(), "T1486".to_string()], // SMB/Windows Admin Shares, Data Encrypted for Impact
            ),
            "RULE-006" => (
                "Large ICMP packet detected. Possible ICMP tunneling or covert channel.".to_string(),
                "ICMP Tunneling",
                vec!["T1095".to_string()], // Traffic Signaling
            ),
            "RULE-011" => (
                "Docker API exposed to network. High risk of container escape and cluster compromise.".to_string(),
                "Container Escape",
                vec!["T1611".to_string()], // Escape to Host
            ),
            _ => (
                format!("Rule-based alert: {}", rule_name),
                "Generic Rule Match",
                vec![],
            ),
        };

        let confidence = match alert.severity {
            Severity::Critical => 0.95,
            Severity::High => 0.85,
            Severity::Medium => 0.70,
            Severity::Low => 0.50,
        };

        AIInsight {
            summary: summary.to_string(),
            confidence,
            severity: format!("{:?}", alert.severity),
            key_indicators: vec![format!("Triggered rule: {}", rule_id)],
            recommended_actions: self.get_rule_recommendations(rule_id),
            attack_pattern: pattern.to_string(),
            related_techniques: techniques,
        }
    }

    /// Analyze anomaly-based alerts
    fn analyze_anomaly_based(&self, alert: &Alert) -> AIInsight {
        // Extract feature deviations for analysis
        let deviations = &alert.details.feature_deviations;

        let indicators: Vec<String> = deviations
            .iter()
            .map(|d| format!("{}: {:.2}x deviation", d.feature_name, d.deviation_score))
            .collect();

        // Determine attack pattern from deviations
        let (pattern, techniques) = self.identify_pattern(&deviations);

        AIInsight {
            summary: format!(
                "Anomalous traffic pattern detected. {} suspicious indicators identified.",
                indicators.len()
            ),
            confidence: alert.score,
            severity: format!("{:?}", alert.severity),
            key_indicators: indicators,
            recommended_actions: self.get_anomaly_recommendations(&deviations),
            attack_pattern: pattern,
            related_techniques: techniques,
        }
    }

    /// Identify attack pattern from feature deviations
    fn identify_pattern(&self, deviations: &[FeatureDeviation]) -> (String, Vec<String>) {
        let mut has_high_syn = false;
        let mut has_high_ports = false;
        let mut has_high_entropy = false;
        let mut has_high_volume = false;

        for dev in deviations {
            match dev.feature_name.as_str() {
                "syn_ratio" | "connection_count" if dev.deviation_score > 2.0 => {
                    has_high_syn = true;
                }
                "unique_ports" | "port_entropy" if dev.deviation_score > 2.0 => {
                    has_high_ports = true;
                }
                "packet_count" | "bytes_per_second" if dev.deviation_score > 3.0 => {
                    has_high_volume = true;
                }
                _ => {}
            }
        }

        match (has_high_syn, has_high_ports, has_high_volume) {
            (true, true, _) => (
                "Port Scan followed by SYN Flood".to_string(),
                vec!["T1046".to_string(), "T1498".to_string()], // Network Service Scanning, Network Denial of Service
            ),
            (true, false, true) => (
                "Distributed Denial of Service (DDoS)".to_string(),
                vec!["T1498".to_string(), "T1499".to_string()], // Network Denial of Service, Endpoint Denial of Service
            ),
            (false, true, _) => (
                "Network Reconnaissance (Port Scan)".to_string(),
                vec!["T1046".to_string()], // Network Service Scanning
            ),
            (true, false, false) => (
                "Potential SYN Flood Attack".to_string(),
                vec!["T1498".to_string()], // Network Denial of Service
            ),
            _ => (
                "Anomalous Traffic Pattern".to_string(),
                vec!["T1071".to_string()], // Application Layer Protocol
            ),
        }
    }

    /// Get recommendations for rule-based alerts
    fn get_rule_recommendations(&self, rule_id: &str) -> Vec<String> {
        match rule_id {
            "RULE-001" => vec![
                "Review authentication logs for this source IP".to_string(),
                "Consider implementing fail2ban for SSH protection".to_string(),
                "Enable key-based authentication only".to_string(),
            ],
            "RULE-002" => vec![
                "Migrate to SSH immediately".to_string(),
                "Block Telnet port 23 at firewall".to_string(),
                "Audit systems for Telnet usage".to_string(),
            ],
            "RULE-003" => vec![
                "Investigate source host for DNS tunneling tools".to_string(),
                "Enable DNS query logging".to_string(),
                "Consider DNS filtering solutions".to_string(),
            ],
            "RULE-004" => vec![
                "Block SMB port 445 at perimeter firewall".to_string(),
                "Enable SMB signing and encryption".to_string(),
                "Review file share permissions".to_string(),
            ],
            "RULE-006" => vec![
                "Block large ICMP packets at firewall".to_string(),
                "Inspect source host for tunneling software".to_string(),
                "Enable ICMP rate limiting".to_string(),
            ],
            "RULE-011" => vec![
                "Immediately restrict Docker API access".to_string(),
                "Enable Docker TLS authentication".to_string(),
                "Review container security policies".to_string(),
            ],
            _ => vec![
                "Review triggered rule details".to_string(),
                "Investigate source IP activity".to_string(),
            ],
        }
    }

    /// Get recommendations for anomaly-based alerts
    fn get_anomaly_recommendations(&self, deviations: &[FeatureDeviation]) -> Vec<String> {
        let mut recommendations = vec![];

        for dev in deviations {
            match dev.feature_name.as_str() {
                "syn_ratio" => {
                    recommendations.push("Enable SYN cookies on affected systems".to_string());
                    recommendations.push("Implement connection rate limiting".to_string());
                }
                "unique_ports" | "port_entropy" => {
                    recommendations.push("Deploy port scan detection rules".to_string());
                    recommendations.push("Consider network segmentation".to_string());
                }
                "bytes_per_second" | "packets_per_second" => {
                    recommendations.push("Enable DDoS mitigation".to_string());
                    recommendations.push("Scale infrastructure if legitimate traffic".to_string());
                }
                _ => {}
            }
        }

        if recommendations.is_empty() {
            recommendations.push("Investigate anomalous traffic pattern".to_string());
            recommendations.push("Review baseline model for this time period".to_string());
        }

        recommendations
    }

    /// Generate summary for multiple alerts
    pub fn summarize_alerts(&self, alerts: &[Alert]) -> String {
        if alerts.is_empty() {
            return "No alerts to analyze".to_string();
        }

        let rule_count = alerts
            .iter()
            .filter(|a| matches!(a.alert_type, AlertType::RuleBased { .. }))
            .count();

        let anomaly_count = alerts.len() - rule_count;

        let mut severity_counts: HashMap<String, usize> = HashMap::new();
        for alert in alerts {
            *severity_counts
                .entry(format!("{:?}", alert.severity))
                .or_insert(0) += 1;
        }

        format!(
            "Analysis of {} alerts: {} rule-based, {} anomaly-based. Severity distribution: {:?}",
            alerts.len(),
            rule_count,
            anomaly_count,
            severity_counts
        )
    }
}

/// Traffic statistics endpoint
pub async fn traffic_stats() -> Json<TrafficAnalytics> {
    Json(TrafficAnalytics {
        packets_per_second: 0.0,
        bytes_per_second: 0.0,
        connection_count: 0,
        anomaly_score_avg: 0.0,
        top_protocols: vec![],
        top_ports: vec![],
    })
}

/// Top threats endpoint
pub async fn top_threats() -> Json<ThreatSummary> {
    Json(ThreatSummary {
        top_ips: vec![],
        top_rules: vec![],
        attack_trends: vec![],
    })
}

/// Alert timeline endpoint
pub async fn alert_timeline() -> Json<Vec<TimelinePoint>> {
    Json(vec![])
}
