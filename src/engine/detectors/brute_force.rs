//! Brute force detection module

use crate::engine::{DetectionContext, Detector};
use crate::models::{DetectionResult, PacketInfo, Protocol, Severity};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Brute force attack detector (SSH, RDP, etc.)
pub struct BruteForceDetector {
    state: Arc<RwLock<BruteForceState>>,
    threshold: f64,
}

#[derive(Debug, Clone, Default)]
struct BruteForceState {
    /// (source_ip, target_port) -> (attempt_count, first_attempt, last_attempt)
    tracker: HashMap<(IpAddr, u16), (u32, u64, u64)>,
}

impl BruteForceDetector {
    pub fn new() -> Self {
        Self {
            state: Arc::new(RwLock::new(BruteForceState::default())),
            threshold: 0.75,
        }
    }

    /// Minimum attempts to trigger detection
    const ATTEMPT_THRESHOLD: u32 = 5;
    /// Time window in seconds
    const TIME_WINDOW_SECS: u64 = 60;
    fn current_timestamp() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    fn is_target_port(port: u16) -> bool {
        let ports = [22, 23, 25, 3389, 3306, 5432, 5900, 1433];
        ports.contains(&port)
    }
}

#[async_trait::async_trait]
impl Detector for BruteForceDetector {
    fn name(&self) -> &str {
        "BruteForceDetector"
    }

    fn threshold(&self) -> f64 {
        self.threshold
    }

    async fn analyze(
        &self,
        packet: &PacketInfo,
        _context: &DetectionContext,
    ) -> Option<DetectionResult> {
        // Only analyze TCP packets to interesting ports
        let dst_port = packet.destination_port?;

        if packet.protocol != Protocol::Tcp {
            return None;
        }

        // Focus on commonly attacked ports
        if !Self::is_target_port(dst_port) {
            return None;
        }

        let mut state = self.state.write().await;
        let now = Self::current_timestamp();
        let key = (packet.source_ip, dst_port);

        // Update or create entry
        let entry = state.tracker.entry(key).or_insert((0, now, now));
        entry.0 += 1; // Increment count
        entry.2 = now; // Update last attempt

        let attempt_count = entry.0;
        let first_attempt = entry.1;
        let time_window = now - first_attempt;

        // Detection logic
        if attempt_count >= Self::ATTEMPT_THRESHOLD && time_window <= Self::TIME_WINDOW_SECS {
            // Calculate confidence
            let rate = attempt_count as f64 / (time_window.max(1) as f64);
            let confidence = ((rate / 0.5) * 0.7 + (attempt_count as f64 / 20.0) * 0.3).min(1.0);

            let service_name = super::get_port_description(dst_port);

            // Determine severity based on attempt count
            let severity = if attempt_count >= 20 {
                Severity::Critical
            } else if attempt_count >= 10 {
                Severity::High
            } else {
                Severity::Medium
            };

            let indicators = vec![
                format!("{} connection attempts", attempt_count),
                format!("Target: {} (port {})", service_name, dst_port),
                format!("Time window: {} seconds", time_window),
                format!("Rate: {:.1} attempts/sec", rate),
            ];

            // Clear the tracker to avoid repeated alerts
            state.tracker.remove(&key);

            return Some(DetectionResult {
                detected: true,
                confidence: confidence.max(self.threshold),
                reason: format!(
                    "Brute force attack detected on {}: {} attempts in {} seconds",
                    service_name, attempt_count, time_window
                ),
                pattern: format!("{} Brute Force", service_name),
                severity,
                indicators,
            });
        }

        // Clean old entries periodically
        if state.tracker.len() > 10000 {
            let cutoff = now - Self::TIME_WINDOW_SECS * 2;
            state
                .tracker
                .retain(|_, (_, first, last)| *first > cutoff || *last > cutoff);
        }

        None
    }
}

impl Default for BruteForceDetector {
    fn default() -> Self {
        Self::new()
    }
}
