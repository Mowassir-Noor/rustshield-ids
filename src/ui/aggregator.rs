//! Alert Aggregation and Deduplication
//!
//! Groups similar alerts to reduce noise and provide summary statistics.

use crate::models::{AggregatedAlert, DetectionResult, EnrichedAlert, Severity};
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Alert aggregator for grouping similar alerts
pub struct AlertAggregator {
    /// Active alert groups by type
    groups: HashMap<String, AggregatedAlert>,
    /// Time window for aggregation
    window_secs: u64,
    /// Last cleanup time
    last_cleanup: Instant,
}

impl AlertAggregator {
    pub fn new(window_secs: u64) -> Self {
        Self {
            groups: HashMap::new(),
            window_secs,
            last_cleanup: Instant::now(),
        }
    }

    /// Add a new alert to the aggregator
    pub fn add_alert(&mut self, alert: EnrichedAlert) -> Option<AggregatedAlert> {
        // Create a key based on alert type and severity
        let key = format!(
            "{:?}-{:?}-{:?}",
            alert.alert_type, alert.severity, alert.detection_result.pattern
        );

        let now = chrono::Utc::now();

        if let Some(group) = self.groups.get_mut(&key) {
            // Update existing group
            group.count += 1;
            group.last_seen = now;
            
            // Track unique source IPs
            if !group.source_ips.contains(&alert.source_ip) {
                group.source_ips.push(alert.source_ip);
            }
            
            // Track unique destination ports
            if let Some(port) = alert.destination_port {
                if !group.destination_ports.contains(&port) {
                    group.destination_ports.push(port);
                }
            }
            
            None // No new group created
        } else {
            // Create new group
            let group = AggregatedAlert {
                group_id: format!("GRP-{}", now.timestamp_millis()),
                alert_type: format!("{:?}", alert.alert_type),
                severity: alert.severity,
                description: alert.description.clone(),
                source_ips: vec![alert.source_ip],
                destination_ports: alert.destination_port.into_iter().collect(),
                count: 1,
                first_seen: now,
                last_seen: now,
                sample_alert: alert.clone(),
                detection_result: alert.detection_result.clone(),
            };
            
            self.groups.insert(key.clone(), group);
            self.groups.get(&key).cloned()
        }
    }

    /// Get all aggregated alerts
    pub fn get_aggregated_alerts(&self) -> Vec<&AggregatedAlert> {
        self.groups.values().collect()
    }

    /// Get aggregated alerts sorted by severity and count
    pub fn get_top_alerts(&self, limit: usize) -> Vec<&AggregatedAlert> {
        let mut alerts: Vec<&AggregatedAlert> = self.groups.values().collect();
        alerts.sort_by(|a, b| {
            // Sort by severity first (Critical > High > Medium > Low)
            let severity_cmp = b.severity.cmp(&a.severity);
            if severity_cmp != std::cmp::Ordering::Equal {
                return severity_cmp;
            }
            // Then by count
            b.count.cmp(&a.count)
        });
        alerts.into_iter().take(limit).collect()
    }

    /// Get alert counts by severity
    pub fn get_severity_counts(&self) -> HashMap<Severity, usize> {
        let mut counts = HashMap::new();
        for group in self.groups.values() {
            *counts.entry(group.severity).or_insert(0) += group.count;
        }
        counts
    }

    /// Cleanup old groups
    pub fn cleanup(&mut self) {
        if self.last_cleanup.elapsed() < Duration::from_secs(self.window_secs) {
            return;
        }

        let now = chrono::Utc::now();
        let cutoff = now - chrono::Duration::seconds(self.window_secs as i64);
        
        self.groups.retain(|_, group| group.last_seen > cutoff);
        self.last_cleanup = Instant::now();
    }

    /// Get total unique attackers
    pub fn get_unique_attackers(&self) -> usize {
        let mut all_ips = std::collections::HashSet::new();
        for group in self.groups.values() {
            for ip in &group.source_ips {
                all_ips.insert(*ip);
            }
        }
        all_ips.len()
    }

    /// Clear all groups
    pub fn clear(&mut self) {
        self.groups.clear();
    }
}

impl Default for AlertAggregator {
    fn default() -> Self {
        Self::new(300) // 5 minute default window
    }
}

/// Calculate threat score based on alert frequency and severity
pub fn calculate_threat_score(alerts: &[&AggregatedAlert]) -> f64 {
    let mut score = 0.0;
    
    for alert in alerts {
        let severity_weight = match alert.severity {
            Severity::Critical => 10.0,
            Severity::High => 5.0,
            Severity::Medium => 2.0,
            Severity::Low => 0.5,
        };
        
        let count_factor = (alert.count as f64).log10().max(1.0);
        score += severity_weight * count_factor;
    }
    
    score.min(100.0)
}
