//! Individual detector implementations

use crate::engine::{DetectionContext, Detector};
use crate::models::{DetectionResult, PacketInfo, Protocol, Severity};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::RwLock;

pub mod port_scan;
pub mod brute_force;
pub mod anomaly;
pub mod dos;

pub use port_scan::PortScanDetector;
pub use brute_force::BruteForceDetector;
pub use anomaly::AnomalyDetector;
pub use dos::DosDetector;

/// Shared state for tracking across packets
#[derive(Debug, Clone, Default)]
pub struct DetectorState {
    /// Port scan tracking: (source_ip) -> (target_ports, timestamps)
    pub port_scan_tracker: HashMap<IpAddr, (HashSet<u16>, Vec<u64>)>,
    
    /// Brute force tracking: (source_ip, target_port) -> attempt_count
    pub brute_force_tracker: HashMap<(IpAddr, u16), (u32, u64)>,
    
    /// Connection tracking for DoS detection
    pub connection_tracker: HashMap<IpAddr, Vec<u64>>,
    
    /// Packet counts for anomaly detection
    pub packet_history: Vec<(u64, PacketInfo)>,
}

/// Utility functions for detectors
pub fn is_suspicious_port(port: u16) -> bool {
    matches!(port, 22 | 23 | 25 | 53 | 110 | 143 | 445 | 3389 | 3306 | 5432 | 6379 | 9200 | 27017)
}

pub fn get_port_description(port: u16) -> &'static str {
    match port {
        22 => "SSH",
        23 => "Telnet",
        25 => "SMTP",
        53 => "DNS",
        80 => "HTTP",
        110 => "POP3",
        143 => "IMAP",
        443 => "HTTPS",
        445 => "SMB",
        3389 => "RDP",
        3306 => "MySQL",
        5432 => "PostgreSQL",
        6379 => "Redis",
        9200 => "Elasticsearch",
        27017 => "MongoDB",
        _ => "Unknown",
    }
}
