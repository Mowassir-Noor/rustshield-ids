//! Port scan detection module

use crate::engine::{DetectionContext, Detector};
use crate::models::{DetectionResult, PacketInfo, Protocol, Severity};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Port scan detector - tracks unique destination ports per source IP
pub struct PortScanDetector {
    state: Arc<RwLock<PortScanState>>,
    threshold: f64,
}

#[derive(Debug, Clone, Default)]
struct PortScanState {
    /// Source IP -> (target_ports, timestamps, destination_ips)
    tracker: HashMap<IpAddr, (HashSet<u16>, Vec<u64>, HashSet<IpAddr>)>,
}

impl PortScanDetector {
    pub fn new() -> Self {
        Self {
            state: Arc::new(RwLock::new(PortScanState::default())),
            threshold: 0.75,
        }
    }

    /// Minimum unique ports to trigger detection
    const PORT_THRESHOLD: usize = 10;
    /// Time window in seconds
    const TIME_WINDOW_SECS: u64 = 10;

    fn current_timestamp() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

#[async_trait::async_trait]
impl Detector for PortScanDetector {
    fn name(&self) -> &str {
        "PortScanDetector"
    }

    fn threshold(&self) -> f64 {
        self.threshold
    }

    async fn analyze(&self, packet: &PacketInfo, _context: &DetectionContext) -> Option<DetectionResult> {
        // Only analyze TCP/UDP packets with destination ports
        let dst_port = packet.destination_port?;
        
        if packet.protocol != Protocol::Tcp && packet.protocol != Protocol::Udp {
            return None;
        }

        let mut state = self.state.write().await;
        let now = Self::current_timestamp();
        let cutoff = now - Self::TIME_WINDOW_SECS;

        // Get or create entry for source IP
        let entry = state.tracker.entry(packet.source_ip).or_default();
        
        // Add the port
        entry.0.insert(dst_port);
        entry.1.push(now);
        entry.2.insert(packet.destination_ip);
        
        // Clean old timestamps
        entry.1.retain(|&ts| ts >= cutoff);
        
        let unique_ports = entry.0.len();
        let recent_attempts = entry.1.len();
        let unique_targets = entry.2.len();
        
        // Detection logic
        if unique_ports >= Self::PORT_THRESHOLD {
            // Calculate confidence based on scan intensity
            let port_confidence = (unique_ports as f64 / 50.0).min(1.0);
            let rate_confidence = (recent_attempts as f64 / 100.0).min(1.0);
            let confidence = (port_confidence * 0.6 + rate_confidence * 0.4).max(self.threshold);
            
            // Determine severity
            let severity = if unique_ports >= 50 {
                Severity::Critical
            } else if unique_ports >= 25 {
                Severity::High
            } else if unique_ports >= 15 {
                Severity::Medium
            } else {
                Severity::Low
            };
            
            let pattern = if unique_targets > 1 {
                "Distributed Port Scan"
            } else {
                "Targeted Port Scan"
            };
            
            let indicators = vec![
                format!("{} unique ports scanned", unique_ports),
                format!("{} unique targets", unique_targets),
                format!("{} connection attempts", recent_attempts),
            ];
            
            // Clear the tracker for this IP to avoid repeated alerts
            state.tracker.remove(&packet.source_ip);
            
            return Some(DetectionResult {
                detected: true,
                confidence,
                reason: format!(
                    "Port scan detected: {} unique ports on {} in {} seconds",
                    unique_ports,
                    if unique_targets == 1 {
                        packet.destination_ip.to_string()
                    } else {
                        format!("{} targets", unique_targets)
                    },
                    Self::TIME_WINDOW_SECS
                ),
                pattern: pattern.to_string(),
                severity,
                indicators,
            });
        }
        
        None
    }
}

impl Default for PortScanDetector {
    fn default() -> Self {
        Self::new()
    }
}
