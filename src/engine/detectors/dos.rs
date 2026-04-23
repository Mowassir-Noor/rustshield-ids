//! Denial of Service detection module

use crate::engine::{DetectionContext, Detector};
use crate::models::{DetectionResult, PacketInfo, Protocol, Severity};
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::RwLock;

/// DoS/DDoS attack detector
pub struct DosDetector {
    state: Arc<RwLock<DosState>>,
    threshold: f64,
}

#[derive(Debug, Clone)]
struct DosState {
    /// Per-source packet rates: source_ip -> (timestamps)
    source_rates: HashMap<IpAddr, VecDeque<u64>>,
    /// Global SYN packet tracking
    syn_packets: VecDeque<u64>,
    /// Per-destination connection counts
    dest_connections: HashMap<IpAddr, VecDeque<u64>>,
}

impl Default for DosState {
    fn default() -> Self {
        Self {
            source_rates: HashMap::new(),
            syn_packets: VecDeque::with_capacity(1000),
            dest_connections: HashMap::new(),
        }
    }
}

impl DosDetector {
    pub fn new() -> Self {
        Self {
            state: Arc::new(RwLock::new(DosState::default())),
            threshold: 0.75,
        }
    }

    /// High rate threshold (packets per second)
    const HIGH_RATE_THRESHOLD: usize = 100;
    /// SYN flood threshold
    const SYN_FLOOD_THRESHOLD: usize = 50;
    /// Time window for analysis
    const TIME_WINDOW_SECS: u64 = 5;

    fn current_timestamp() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

#[async_trait::async_trait]
impl Detector for DosDetector {
    fn name(&self) -> &str {
        "DosDetector"
    }

    fn threshold(&self) -> f64 {
        self.threshold
    }

    async fn analyze(
        &self,
        packet: &PacketInfo,
        _context: &DetectionContext,
    ) -> Option<DetectionResult> {
        let mut state = self.state.write().await;
        let now = Self::current_timestamp();
        let cutoff = now - Self::TIME_WINDOW_SECS;

        // Track per-source rate
        let source_entry = state.source_rates.entry(packet.source_ip).or_default();
        source_entry.push_back(now);
        source_entry.retain(|&t| t >= cutoff);
        let source_rate = source_entry.len();

        // Track SYN packets
        if packet.protocol == Protocol::Tcp {
            if packet.flags.map_or(false, |f| f & 0x02 != 0) {
                state.syn_packets.push_back(now);
            }
        }
        state.syn_packets.retain(|&t| t >= cutoff);
        let syn_count = state.syn_packets.len();

        // Track per-destination connections
        let dest_entry = state
            .dest_connections
            .entry(packet.destination_ip)
            .or_default();
        dest_entry.push_back(now);
        dest_entry.retain(|&t| t >= cutoff);
        let dest_rate = dest_entry.len();

        // Detection: High volume from single source
        if source_rate >= Self::HIGH_RATE_THRESHOLD {
            let confidence = (source_rate as f64 / 200.0).min(1.0);

            // Clean up this source's tracking
            state.source_rates.remove(&packet.source_ip);

            return Some(DetectionResult {
                detected: true,
                confidence: confidence.max(self.threshold),
                reason: format!(
                    "High volume DoS attack: {} packets/sec from {}",
                    source_rate, packet.source_ip
                ),
                pattern: "Volume-based DoS".to_string(),
                severity: if source_rate > 500 {
                    Severity::Critical
                } else if source_rate > 200 {
                    Severity::High
                } else {
                    Severity::Medium
                },
                indicators: vec![
                    format!("Rate: {} packets/sec", source_rate),
                    format!("Source: {}", packet.source_ip),
                    format!("Target: {}", packet.destination_ip),
                ],
            });
        }

        // Detection: SYN flood
        if syn_count >= Self::SYN_FLOOD_THRESHOLD {
            let confidence = (syn_count as f64 / 100.0).min(1.0);

            return Some(DetectionResult {
                detected: true,
                confidence: confidence.max(self.threshold),
                reason: format!(
                    "SYN flood attack: {} SYN packets in {} seconds",
                    syn_count,
                    Self::TIME_WINDOW_SECS
                ),
                pattern: "SYN Flood".to_string(),
                severity: if syn_count > 100 {
                    Severity::Critical
                } else {
                    Severity::High
                },
                indicators: vec![
                    format!("SYN count: {}", syn_count),
                    format!("Time window: {}s", Self::TIME_WINDOW_SECS),
                    "Potential connection exhaustion".to_string(),
                ],
            });
        }

        // Detection: Target overload
        if dest_rate >= Self::HIGH_RATE_THRESHOLD * 2 {
            let confidence = (dest_rate as f64 / 500.0).min(1.0);

            return Some(DetectionResult {
                detected: true,
                confidence: confidence.max(self.threshold),
                reason: format!(
                    "Target {} receiving {} packets/sec - potential DDoS",
                    packet.destination_ip, dest_rate
                ),
                pattern: "DDoS Target".to_string(),
                severity: Severity::Critical,
                indicators: vec![
                    format!("Target: {}", packet.destination_ip),
                    format!("Incoming rate: {} packets/sec", dest_rate),
                    "Multiple sources likely involved".to_string(),
                ],
            });
        }

        // Cleanup old entries periodically
        if state.source_rates.len() > 10000 {
            state.source_rates.retain(|_, times| {
                times.retain(|&t| t >= cutoff);
                !times.is_empty()
            });
        }

        None
    }
}

impl Default for DosDetector {
    fn default() -> Self {
        Self::new()
    }
}
