//! Behavior Profiling System
//!
//! Learns normal traffic patterns and flags deviations.
//! Uses sliding window statistics for baseline establishment.

use crate::models::{PacketInfo, Protocol, Severity};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Window size for baseline calculation (in seconds)
const BASELINE_WINDOW_SECS: u64 = 300; // 5 minutes
/// Number of windows to keep for trend analysis
const MAX_WINDOWS: usize = 12; // 1 hour of history
/// Minimum samples required for baseline
const MIN_SAMPLES: usize = 10;
/// Z-score threshold for anomaly detection
const Z_SCORE_THRESHOLD: f64 = 3.0;

/// Profile for a specific IP address
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpProfile {
    pub ip: IpAddr,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub total_packets: u64,
    pub total_bytes: u64,
    pub baseline: TrafficBaseline,
    pub behavior_flags: Vec<BehaviorFlag>,
    pub risk_score: f64, // 0.0 - 1.0
    pub is_known_good: bool,
    pub is_known_bad: bool,
    pub tags: Vec<String>,
}

/// Statistical baseline for traffic patterns
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TrafficBaseline {
    pub packets_per_second_mean: f64,
    pub packets_per_second_std: f64,
    pub bytes_per_second_mean: f64,
    pub bytes_per_second_std: f64,
    pub avg_packet_size_mean: f64,
    pub avg_packet_size_std: f64,
    pub unique_ports_per_minute_mean: f64,
    pub unique_ports_per_minute_std: f64,
    pub syn_ratio_mean: f64,
    pub syn_ratio_std: f64,
    pub window_count: usize,
    pub last_updated: Option<DateTime<Utc>>,
}

/// A behavior flag indicating suspicious activity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorFlag {
    pub flag_type: BehaviorType,
    pub timestamp: DateTime<Utc>,
    pub severity: Severity,
    pub description: String,
    pub confidence: f64,
}

/// Types of behavioral anomalies
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BehaviorType {
    NewIp,                // Never seen before
    TrafficSpike,         // Sudden volume increase
    PortScanBehavior,     // Unusual port access patterns
    ProtocolAnomaly,      // Unexpected protocol usage
    ConnectionRateSpike,  // Too many connections
    OffHoursActivity,     // Activity outside business hours
    GeographicAnomaly,    // Unusual geo location (if GeoIP enabled)
    PayloadPatternChange, // Payload characteristics changed
    LongLivedConnection,  // Unusually long connections
    BurstActivity,        // Sudden burst then silence
}

impl BehaviorType {
    pub fn as_str(&self) -> &'static str {
        match self {
            BehaviorType::NewIp => "New IP Detected",
            BehaviorType::TrafficSpike => "Traffic Spike",
            BehaviorType::PortScanBehavior => "Port Scan Behavior",
            BehaviorType::ProtocolAnomaly => "Protocol Anomaly",
            BehaviorType::ConnectionRateSpike => "Connection Rate Spike",
            BehaviorType::OffHoursActivity => "Off-Hours Activity",
            BehaviorType::GeographicAnomaly => "Geographic Anomaly",
            BehaviorType::PayloadPatternChange => "Payload Pattern Change",
            BehaviorType::LongLivedConnection => "Long-Lived Connection",
            BehaviorType::BurstActivity => "Burst Activity Pattern",
        }
    }

    pub fn default_severity(&self) -> Severity {
        match self {
            BehaviorType::NewIp => Severity::Low,
            BehaviorType::TrafficSpike => Severity::Medium,
            BehaviorType::PortScanBehavior => Severity::High,
            BehaviorType::ProtocolAnomaly => Severity::Medium,
            BehaviorType::ConnectionRateSpike => Severity::Medium,
            BehaviorType::OffHoursActivity => Severity::Low,
            BehaviorType::GeographicAnomaly => Severity::Medium,
            BehaviorType::PayloadPatternChange => Severity::High,
            BehaviorType::LongLivedConnection => Severity::Low,
            BehaviorType::BurstActivity => Severity::Medium,
        }
    }
}

/// Traffic statistics for a single time window
#[derive(Debug, Clone)]
struct WindowStats {
    timestamp: Instant,
    packet_count: u64,
    byte_count: u64,
    unique_ports: std::collections::HashSet<u16>,
    syn_count: u64,
    fin_count: u64,
    rst_count: u64,
    protocol_counts: HashMap<Protocol, u64>,
}

impl Default for WindowStats {
    fn default() -> Self {
        Self {
            timestamp: Instant::now(),
            packet_count: 0,
            byte_count: 0,
            unique_ports: std::collections::HashSet::new(),
            syn_count: 0,
            fin_count: 0,
            rst_count: 0,
            protocol_counts: HashMap::new(),
        }
    }
}

/// Main behavior profiling engine
pub struct BehaviorProfiler {
    /// IP profiles database
    profiles: Arc<RwLock<HashMap<IpAddr, IpProfile>>>,
    /// Recent window statistics per IP
    window_stats: Arc<RwLock<HashMap<IpAddr, VecDeque<WindowStats>>>>,
    /// Known good IPs (whitelist)
    whitelist: Arc<RwLock<HashSet<IpAddr>>>,
    /// Known bad IPs (blacklist)
    blacklist: Arc<RwLock<HashSet<IpAddr>>>,
    /// Global baseline for comparison
    global_baseline: Arc<RwLock<TrafficBaseline>>,
    /// Last baseline update
    last_baseline_update: Arc<RwLock<Instant>>,
}

/// Analysis result from behavior profiling
#[derive(Debug, Clone, Serialize)]
pub struct BehaviorAnalysis {
    pub ip: IpAddr,
    pub is_anomalous: bool,
    pub flags: Vec<BehaviorFlag>,
    pub risk_score: f64,
    pub z_scores: HashMap<String, f64>,
    pub recommendation: String,
}

impl BehaviorProfiler {
    pub fn new() -> Self {
        Self {
            profiles: Arc::new(RwLock::new(HashMap::new())),
            window_stats: Arc::new(RwLock::new(HashMap::new())),
            whitelist: Arc::new(RwLock::new(HashSet::new())),
            blacklist: Arc::new(RwLock::new(HashSet::new())),
            global_baseline: Arc::new(RwLock::new(TrafficBaseline::default())),
            last_baseline_update: Arc::new(RwLock::new(Instant::now())),
        }
    }

    /// Process a packet and update profiles
    pub async fn process_packet(&self, packet: &PacketInfo) -> Option<BehaviorAnalysis> {
        let src_ip = packet.source_ip;
        let now = Utc::now();

        // Check blacklist first
        let blacklist = self.blacklist.read().await;
        if blacklist.contains(&src_ip) {
            return Some(BehaviorAnalysis {
                ip: src_ip,
                is_anomalous: true,
                flags: vec![BehaviorFlag {
                    flag_type: BehaviorType::NewIp,
                    timestamp: now,
                    severity: Severity::Critical,
                    description: "Traffic from known malicious IP".to_string(),
                    confidence: 1.0,
                }],
                risk_score: 1.0,
                z_scores: HashMap::new(),
                recommendation: "Immediate blocking recommended - known malicious actor"
                    .to_string(),
            });
        }
        drop(blacklist);

        // Update or create profile
        let mut profiles = self.profiles.write().await;
        let is_new = !profiles.contains_key(&src_ip);

        let profile = profiles.entry(src_ip).or_insert_with(|| IpProfile {
            ip: src_ip,
            first_seen: now,
            last_seen: now,
            total_packets: 0,
            total_bytes: 0,
            baseline: TrafficBaseline::default(),
            behavior_flags: Vec::new(),
            risk_score: 0.0,
            is_known_good: false,
            is_known_bad: false,
            tags: Vec::new(),
        });

        profile.last_seen = now;
        profile.total_packets += 1;
        profile.total_bytes += packet.size_bytes as u64;
        drop(profiles);

        // If new IP, flag it
        let mut flags = Vec::new();
        if is_new {
            // Check if it's in whitelist
            let whitelist = self.whitelist.read().await;
            let is_whitelisted = whitelist.contains(&src_ip);
            drop(whitelist);

            if !is_whitelisted {
                flags.push(BehaviorFlag {
                    flag_type: BehaviorType::NewIp,
                    timestamp: now,
                    severity: Severity::Low,
                    description: format!("First contact from IP: {}", src_ip),
                    confidence: 0.7,
                });
            }
        }

        // Update window statistics
        self.update_window_stats(src_ip, packet).await;

        // Periodic baseline update (every 5 minutes)
        let should_update_baseline = {
            let last_update = self.last_baseline_update.read().await;
            last_update.elapsed().as_secs() > BASELINE_WINDOW_SECS
        };

        if should_update_baseline {
            self.update_baselines().await;
            let mut last_update = self.last_baseline_update.write().await;
            *last_update = Instant::now();
        }

        // Analyze for anomalies
        let analysis = self.analyze_behavior(src_ip).await;

        if !flags.is_empty() || analysis.is_anomalous {
            let mut result = analysis;
            result.flags.extend(flags);
            Some(result)
        } else {
            None
        }
    }

    /// Update window statistics for an IP
    async fn update_window_stats(&self, ip: IpAddr, packet: &PacketInfo) {
        let mut window_stats = self.window_stats.write().await;
        let windows = window_stats.entry(ip).or_insert_with(VecDeque::new);

        let now = Instant::now();

        // Get or create current window
        let current_window = if let Some(window) = windows.back_mut() {
            if window.timestamp.elapsed().as_secs() < 60 {
                window
            } else {
                // Start new window
                windows.push_back(WindowStats {
                    timestamp: now,
                    ..Default::default()
                });
                windows.back_mut().unwrap()
            }
        } else {
            windows.push_back(WindowStats {
                timestamp: now,
                ..Default::default()
            });
            windows.back_mut().unwrap()
        };

        // Update stats
        current_window.packet_count += 1;
        current_window.byte_count += packet.size_bytes as u64;

        if let Some(dport) = packet.destination_port {
            current_window.unique_ports.insert(dport);
        }

        // Track TCP flags
        if let Some(flags) = packet.flags {
            if flags & 0x02 != 0 {
                current_window.syn_count += 1;
            }
            if flags & 0x01 != 0 {
                current_window.fin_count += 1;
            }
            if flags & 0x04 != 0 {
                current_window.rst_count += 1;
            }
        }

        *current_window
            .protocol_counts
            .entry(packet.protocol)
            .or_insert(0) += 1;

        // Cleanup old windows
        while windows.len() > MAX_WINDOWS {
            windows.pop_front();
        }
    }

    /// Calculate baselines from window statistics
    async fn update_baselines(&self) {
        let window_stats = self.window_stats.read().await;
        let mut profiles = self.profiles.write().await;

        for (ip, windows) in window_stats.iter() {
            if windows.len() < MIN_SAMPLES {
                continue;
            }

            // Calculate statistics
            let pps_values: Vec<f64> = windows
                .iter()
                .map(|w| w.packet_count as f64 / 60.0)
                .collect();

            let bps_values: Vec<f64> = windows.iter().map(|w| w.byte_count as f64 / 60.0).collect();

            let avg_sizes: Vec<f64> = windows
                .iter()
                .map(|w| {
                    if w.packet_count > 0 {
                        w.byte_count as f64 / w.packet_count as f64
                    } else {
                        0.0
                    }
                })
                .collect();

            let port_counts: Vec<f64> = windows
                .iter()
                .map(|w| w.unique_ports.len() as f64)
                .collect();

            let syn_ratios: Vec<f64> = windows
                .iter()
                .map(|w| {
                    if w.packet_count > 0 {
                        w.syn_count as f64 / w.packet_count as f64
                    } else {
                        0.0
                    }
                })
                .collect();

            if let Some(profile) = profiles.get_mut(ip) {
                profile.baseline = TrafficBaseline {
                    packets_per_second_mean: Self::mean(&pps_values),
                    packets_per_second_std: Self::std_dev(&pps_values),
                    bytes_per_second_mean: Self::mean(&bps_values),
                    bytes_per_second_std: Self::std_dev(&bps_values),
                    avg_packet_size_mean: Self::mean(&avg_sizes),
                    avg_packet_size_std: Self::std_dev(&avg_sizes),
                    unique_ports_per_minute_mean: Self::mean(&port_counts),
                    unique_ports_per_minute_std: Self::std_dev(&port_counts),
                    syn_ratio_mean: Self::mean(&syn_ratios),
                    syn_ratio_std: Self::std_dev(&syn_ratios),
                    window_count: windows.len(),
                    last_updated: Some(Utc::now()),
                };
            }
        }

        // Update global baseline
        let all_pps: Vec<f64> = profiles
            .values()
            .map(|p| p.baseline.packets_per_second_mean)
            .filter(|v| *v > 0.0)
            .collect();

        let global = self.global_baseline.write().await;
        // Would update global baseline here
    }

    /// Analyze current behavior against baseline
    async fn analyze_behavior(&self, ip: IpAddr) -> BehaviorAnalysis {
        let mut flags = Vec::new();
        let mut z_scores = HashMap::new();
        let mut total_risk = 0.0;

        let profiles = self.profiles.read().await;
        let window_stats = self.window_stats.read().await;

        let profile = match profiles.get(&ip) {
            Some(p) => p.clone(),
            None => {
                return BehaviorAnalysis {
                    ip,
                    is_anomalous: false,
                    flags: vec![],
                    risk_score: 0.0,
                    z_scores,
                    recommendation: "No profile available".to_string(),
                };
            }
        };
        drop(profiles);

        // Get recent windows
        if let Some(windows) = window_stats.get(&ip) {
            if let Some(current) = windows.back() {
                let current_pps = current.packet_count as f64 / 60.0;
                let current_bps = current.byte_count as f64 / 60.0;
                let current_ports = current.unique_ports.len() as f64;

                // Check for traffic spike
                if profile.baseline.packets_per_second_std > 0.0 {
                    let z_score = (current_pps - profile.baseline.packets_per_second_mean)
                        / profile.baseline.packets_per_second_std;
                    z_scores.insert("pps".to_string(), z_score);

                    if z_score > Z_SCORE_THRESHOLD {
                        let severity = if z_score > 5.0 {
                            Severity::High
                        } else {
                            Severity::Medium
                        };
                        flags.push(BehaviorFlag {
                            flag_type: BehaviorType::TrafficSpike,
                            timestamp: Utc::now(),
                            severity,
                            description: format!(
                                "Traffic spike: {:.1} pps (baseline: {:.1} ± {:.1})",
                                current_pps,
                                profile.baseline.packets_per_second_mean,
                                profile.baseline.packets_per_second_std
                            ),
                            confidence: (z_score / 5.0).min(1.0),
                        });
                        total_risk += 0.3;
                    }
                }

                // Check for port scan behavior
                if profile.baseline.unique_ports_per_minute_std > 0.0 {
                    let z_score = (current_ports - profile.baseline.unique_ports_per_minute_mean)
                        / profile.baseline.unique_ports_per_minute_std;

                    if z_score > Z_SCORE_THRESHOLD && current_ports > 10.0 {
                        flags.push(BehaviorFlag {
                            flag_type: BehaviorType::PortScanBehavior,
                            timestamp: Utc::now(),
                            severity: Severity::High,
                            description: format!(
                                "Unusual port access: {} ports (baseline: {:.1})",
                                current_ports as u32, profile.baseline.unique_ports_per_minute_mean
                            ),
                            confidence: (z_score / 5.0).min(1.0),
                        });
                        total_risk += 0.4;
                    }
                }

                // Check for burst activity
                if windows.len() >= 3 {
                    let recent: Vec<_> = windows.iter().rev().take(3).collect();
                    if recent[0].packet_count > recent[1].packet_count * 10
                        && recent[0].packet_count > recent[2].packet_count * 10
                        && recent[0].packet_count > 100
                    {
                        flags.push(BehaviorFlag {
                            flag_type: BehaviorType::BurstActivity,
                            timestamp: Utc::now(),
                            severity: Severity::Medium,
                            description: "Burst activity detected - sudden spike then silence"
                                .to_string(),
                            confidence: 0.8,
                        });
                        total_risk += 0.2;
                    }
                }
            }
        }

        let risk_score = (total_risk + (flags.len() as f64 * 0.1)).min(1.0);

        let recommendation = if risk_score > 0.8 {
            "Immediate investigation required - high risk behavior detected"
        } else if risk_score > 0.5 {
            "Monitor closely - multiple behavioral anomalies"
        } else if !flags.is_empty() {
            "Review flagged behavior patterns"
        } else {
            "Normal behavior within baseline"
        }
        .to_string();

        BehaviorAnalysis {
            ip,
            is_anomalous: !flags.is_empty(),
            flags,
            risk_score,
            z_scores,
            recommendation,
        }
    }

    /// Calculate mean of a slice
    fn mean(values: &[f64]) -> f64 {
        if values.is_empty() {
            return 0.0;
        }
        values.iter().sum::<f64>() / values.len() as f64
    }

    /// Calculate standard deviation
    fn std_dev(values: &[f64]) -> f64 {
        if values.len() < 2 {
            return 0.0;
        }
        let mean = Self::mean(values);
        let variance =
            values.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / (values.len() - 1) as f64;
        variance.sqrt()
    }

    /// Add IP to whitelist
    pub async fn whitelist_ip(&self, ip: IpAddr) {
        let mut whitelist = self.whitelist.write().await;
        whitelist.insert(ip);

        let mut profiles = self.profiles.write().await;
        if let Some(profile) = profiles.get_mut(&ip) {
            profile.is_known_good = true;
            profile.tags.push("whitelisted".to_string());
        }
    }

    /// Add IP to blacklist
    pub async fn blacklist_ip(&self, ip: IpAddr) {
        let mut blacklist = self.blacklist.write().await;
        blacklist.insert(ip);

        let mut profiles = self.profiles.write().await;
        if let Some(profile) = profiles.get_mut(&ip) {
            profile.is_known_bad = true;
            profile.risk_score = 1.0;
            profile.tags.push("blacklisted".to_string());
        }
    }

    /// Get profile for an IP
    pub async fn get_profile(&self, ip: IpAddr) -> Option<IpProfile> {
        let profiles = self.profiles.read().await;
        profiles.get(&ip).cloned()
    }

    /// Get high-risk IPs
    pub async fn get_high_risk_ips(&self, threshold: f64) -> Vec<IpProfile> {
        let profiles = self.profiles.read().await;
        profiles
            .values()
            .filter(|p| p.risk_score >= threshold)
            .cloned()
            .collect()
    }

    /// Get profiler statistics
    pub async fn get_stats(&self) -> ProfilerStats {
        let profiles = self.profiles.read().await;
        let whitelist = self.whitelist.read().await;
        let blacklist = self.blacklist.read().await;

        ProfilerStats {
            total_profiles: profiles.len(),
            whitelisted: whitelist.len(),
            blacklisted: blacklist.len(),
            high_risk: profiles.values().filter(|p| p.risk_score > 0.7).count(),
        }
    }
}

/// Profiler statistics
#[derive(Debug, Clone, Serialize)]
pub struct ProfilerStats {
    pub total_profiles: usize,
    pub whitelisted: usize,
    pub blacklisted: usize,
    pub high_risk: usize,
}

impl Default for BehaviorProfiler {
    fn default() -> Self {
        Self::new()
    }
}
