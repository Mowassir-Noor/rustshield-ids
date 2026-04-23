//! Statistical anomaly detection module

use crate::engine::{DetectionContext, Detector};
use crate::models::{DetectionResult, PacketInfo, Protocol, Severity};
use std::collections::VecDeque;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Statistical anomaly detector
pub struct AnomalyDetector {
    state: Arc<RwLock<AnomalyState>>,
    threshold: f64,
}

#[derive(Debug, Clone)]
struct AnomalyState {
    /// Recent packet sizes for statistical analysis
    packet_sizes: VecDeque<usize>,
    /// Recent packet rates
    packet_times: VecDeque<u64>,
    /// Connection patterns
    connection_patterns: VecDeque<(u64, bool)>, // (timestamp, has_syn)
}

impl Default for AnomalyState {
    fn default() -> Self {
        Self {
            packet_sizes: VecDeque::with_capacity(1000),
            packet_times: VecDeque::with_capacity(1000),
            connection_patterns: VecDeque::with_capacity(500),
        }
    }
}

impl AnomalyDetector {
    pub fn new() -> Self {
        Self {
            state: Arc::new(RwLock::new(AnomalyState::default())),
            threshold: 0.70,
        }
    }

    fn current_timestamp() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    fn calculate_mean(values: &[f64]) -> f64 {
        if values.is_empty() {
            return 0.0;
        }
        values.iter().sum::<f64>() / values.len() as f64
    }

    fn calculate_std(values: &[f64], mean: f64) -> f64 {
        if values.len() < 2 {
            return 0.0;
        }
        let variance = values
            .iter()
            .map(|&v| (v - mean).powi(2))
            .sum::<f64>()
            / (values.len() - 1) as f64;
        variance.sqrt()
    }

    fn z_score(value: f64, mean: f64, std: f64) -> f64 {
        if std == 0.0 {
            return 0.0;
        }
        (value - mean).abs() / std
    }
}

#[async_trait::async_trait]
impl Detector for AnomalyDetector {
    fn name(&self) -> &str {
        "AnomalyDetector"
    }

    fn threshold(&self) -> f64 {
        self.threshold
    }

    async fn analyze(&self, packet: &PacketInfo, _context: &DetectionContext) -> Option<DetectionResult> {
        let mut state = self.state.write().await;
        let now = Self::current_timestamp();

        // Track packet size
        state.packet_sizes.push_back(packet.size_bytes);
        if state.packet_sizes.len() > 1000 {
            state.packet_sizes.pop_front();
        }

        // Track packet timing
        state.packet_times.push_back(now);
        if state.packet_times.len() > 1000 {
            state.packet_times.pop_front();
        }

        // Track SYN patterns for anomaly detection
        if packet.protocol == Protocol::Tcp {
            let has_syn = packet.flags.map_or(false, |f| f & 0x02 != 0);
            state.connection_patterns.push_back((now, has_syn));
            if state.connection_patterns.len() > 500 {
                state.connection_patterns.pop_front();
            }
        }

        // Need enough data for statistical analysis
        if state.packet_sizes.len() < 100 {
            return None;
        }

        // Calculate packet size anomaly
        let sizes: Vec<f64> = state.packet_sizes.iter().map(|&s| s as f64).collect();
        let size_mean = Self::calculate_mean(&sizes[..sizes.len() - 1]); // Exclude current
        let size_std = Self::calculate_std(&sizes[..sizes.len() - 1], size_mean);
        let current_size = packet.size_bytes as f64;
        let size_zscore = Self::z_score(current_size, size_mean, size_std);

        // Calculate rate anomaly (packets per second)
        let time_window = 10; // seconds
        let recent_packets = state
            .packet_times
            .iter()
            .filter(|&&t| now - t <= time_window)
            .count();
        let rate = recent_packets as f64 / time_window as f64;

        // Calculate SYN ratio anomaly
        let syn_count = state
            .connection_patterns
            .iter()
            .filter(|&&(t, has_syn)| now - t <= 30 && has_syn)
            .count();
        let total_connections = state
            .connection_patterns
            .iter()
            .filter(|&&(t, _)| now - t <= 30)
            .count();
        let syn_ratio = if total_connections > 0 {
            syn_count as f64 / total_connections as f64
        } else {
            0.0
        };

        // Anomaly detection thresholds
        let mut anomalies = Vec::new();
        let mut confidence = 0.0;

        // Large packet anomaly
        if size_zscore > 3.0 && packet.size_bytes > 1500 {
            anomalies.push(format!(
                "Large packet: {} bytes (z-score: {:.1})",
                packet.size_bytes, size_zscore
            ));
            confidence += 0.25;
        }

        // High rate anomaly
        if rate > 100.0 {
            anomalies.push(format!(
                "High packet rate: {:.0} packets/sec",
                rate
            ));
            confidence += 0.30;
        }

        // SYN flood pattern
        if syn_ratio > 0.8 && syn_count > 20 {
            anomalies.push(format!(
                "High SYN ratio: {:.0}% ({}/{})",
                syn_ratio * 100.0, syn_count, total_connections
            ));
            confidence += 0.35;
        }

        if anomalies.len() >= 2 && confidence >= self.threshold {
            let severity = if confidence > 0.85 {
                Severity::High
            } else if confidence > 0.75 {
                Severity::Medium
            } else {
                Severity::Low
            };

            return Some(DetectionResult {
                detected: true,
                confidence,
                reason: format!("Traffic anomaly detected: {}", anomalies.join("; ")),
                pattern: "Statistical Anomaly".to_string(),
                severity,
                indicators: anomalies,
            });
        }

        None
    }
}

impl Default for AnomalyDetector {
    fn default() -> Self {
        Self::new()
    }
}
