//! Advanced Threat Correlation Engine
//!
//! Correlates individual alerts into multi-stage attack scenarios.
//! Tracks attacker behavior over time to identify complex attack patterns.

use crate::models::{DetectionResult, EnrichedAlert, PacketInfo, Severity};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::RwLock;
use uuid::Uuid;

/// Maximum age of alerts to consider for correlation
const CORRELATION_WINDOW_SECS: u64 = 300; // 5 minutes
/// Maximum number of attack chains to track per IP
const MAX_CHAINS_PER_IP: usize = 10;
/// Minimum confidence for correlation
const CORRELATION_THRESHOLD: f64 = 0.7;

/// A correlated attack scenario
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelatedAttack {
    pub id: String,
    pub attacker_ip: IpAddr,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub stages: Vec<AttackStage>,
    pub combined_confidence: f64,
    pub severity: Severity,
    pub attack_type: AttackCategory,
    pub indicators: Vec<String>,
    pub affected_targets: HashSet<IpAddr>,
    pub affected_ports: HashSet<u16>,
    pub is_ongoing: bool,
    pub summary: String,
}

/// Individual stage of a multi-stage attack
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackStage {
    pub stage_number: u32,
    pub stage_type: AttackStageType,
    pub timestamp: DateTime<Utc>,
    pub alerts: Vec<EnrichedAlert>,
    pub confidence: f64,
    pub description: String,
}

/// Types of attack stages in a kill chain
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AttackStageType {
    Reconnaissance, // Port scanning, service discovery
    InitialAccess,  // Brute force, exploitation attempts
    Execution,      // Command execution, payload delivery
    Persistence,    // Backdoors, cron jobs
    DefenseEvasion, // Log clearing, rootkits
    Collection,     // Data gathering
    Exfiltration,   // Data theft
    Impact,         // DoS, encryption (ransomware)
}

impl AttackStageType {
    pub fn as_str(&self) -> &'static str {
        match self {
            AttackStageType::Reconnaissance => "Reconnaissance",
            AttackStageType::InitialAccess => "Initial Access",
            AttackStageType::Execution => "Execution",
            AttackStageType::Persistence => "Persistence",
            AttackStageType::DefenseEvasion => "Defense Evasion",
            AttackStageType::Collection => "Collection",
            AttackStageType::Exfiltration => "Exfiltration",
            AttackStageType::Impact => "Impact",
        }
    }

    /// Returns the typical next stages in a kill chain
    pub fn possible_next_stages(&self) -> Vec<AttackStageType> {
        match self {
            AttackStageType::Reconnaissance => {
                vec![AttackStageType::InitialAccess, AttackStageType::Execution]
            }
            AttackStageType::InitialAccess => {
                vec![AttackStageType::Execution, AttackStageType::Persistence]
            }
            AttackStageType::Execution => vec![
                AttackStageType::Persistence,
                AttackStageType::DefenseEvasion,
                AttackStageType::Collection,
            ],
            AttackStageType::Persistence => {
                vec![AttackStageType::DefenseEvasion, AttackStageType::Collection]
            }
            AttackStageType::DefenseEvasion => {
                vec![AttackStageType::Collection, AttackStageType::Exfiltration]
            }
            AttackStageType::Collection => vec![AttackStageType::Exfiltration],
            AttackStageType::Exfiltration => vec![AttackStageType::Impact],
            AttackStageType::Impact => vec![],
        }
    }
}

/// Categories of multi-stage attacks
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttackCategory {
    MultiStageIntrusion,
    RansomwareCampaign,
    DataExfiltration,
    DoSCampaign,
    BruteForceCampaign,
    APTActivity,
    Unknown,
}

impl AttackCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            AttackCategory::MultiStageIntrusion => "Multi-Stage Intrusion",
            AttackCategory::RansomwareCampaign => "Ransomware Campaign",
            AttackCategory::DataExfiltration => "Data Exfiltration",
            AttackCategory::DoSCampaign => "DoS Campaign",
            AttackCategory::BruteForceCampaign => "Brute Force Campaign",
            AttackCategory::APTActivity => "APT Activity",
            AttackCategory::Unknown => "Unknown Attack Pattern",
        }
    }
}

impl std::fmt::Display for AttackCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Main correlation engine
pub struct CorrelationEngine {
    /// Active attack chains being tracked
    active_chains: Arc<RwLock<HashMap<IpAddr, Vec<AttackChain>>>>,
    /// Historical correlated attacks
    attack_history: Arc<RwLock<VecDeque<CorrelatedAttack>>>,
    /// Maximum history size
    max_history: usize,
    /// Correlation patterns database
    patterns: Vec<CorrelationPattern>,
}

/// An in-progress attack chain for a specific attacker
#[derive(Debug, Clone)]
struct AttackChain {
    stages: Vec<AttackStage>,
    created_at: Instant,
    last_activity: Instant,
    confidence: f64,
}

/// Predefined correlation patterns
#[derive(Debug, Clone)]
struct CorrelationPattern {
    name: String,
    stage_sequence: Vec<AttackStageType>,
    time_window_secs: u64,
    confidence_boost: f64,
}

impl CorrelationEngine {
    pub fn new() -> Self {
        let patterns = vec![
            // Port Scan → Brute Force → DoS (Multi-Stage)
            CorrelationPattern {
                name: "Scan-Exploit-Flood".to_string(),
                stage_sequence: vec![
                    AttackStageType::Reconnaissance,
                    AttackStageType::InitialAccess,
                    AttackStageType::Impact,
                ],
                time_window_secs: 300,
                confidence_boost: 0.9,
            },
            // Recon → Brute Force (Credential Stuffing)
            CorrelationPattern {
                name: "Recon-BruteForce".to_string(),
                stage_sequence: vec![
                    AttackStageType::Reconnaissance,
                    AttackStageType::InitialAccess,
                ],
                time_window_secs: 180,
                confidence_boost: 0.85,
            },
            // Multiple DoS stages
            CorrelationPattern {
                name: "Sustained-DoS".to_string(),
                stage_sequence: vec![
                    AttackStageType::Impact,
                    AttackStageType::Impact,
                    AttackStageType::Impact,
                ],
                time_window_secs: 600,
                confidence_boost: 0.8,
            },
        ];

        Self {
            active_chains: Arc::new(RwLock::new(HashMap::new())),
            attack_history: Arc::new(RwLock::new(VecDeque::with_capacity(1000))),
            max_history: 1000,
            patterns,
        }
    }

    /// Process a new alert and update correlation chains
    pub async fn correlate_alert(&self, alert: &EnrichedAlert) -> Option<CorrelatedAttack> {
        let source_ip = alert.source_ip;
        let stage_type = self.classify_alert_stage(alert);

        let mut chains = self.active_chains.write().await;
        let attacker_chains = chains.entry(source_ip).or_insert_with(Vec::new);

        // Clean up old chains
        self.cleanup_old_chains(attacker_chains);

        // Try to extend existing chains
        let mut best_match: Option<(usize, f64)> = None;

        for (idx, chain) in attacker_chains.iter_mut().enumerate() {
            let last_stage = chain.stages.last()?;
            let possible_next = last_stage.stage_type.possible_next_stages();

            if possible_next.contains(&stage_type) {
                // Check timing
                let time_since_last = Instant::now().duration_since(chain.last_activity).as_secs();
                if time_since_last <= CORRELATION_WINDOW_SECS {
                    let confidence = self.calculate_stage_confidence(&stage_type, alert);
                    let correlation_score =
                        self.calculate_correlation_strength(&chain.stages, stage_type, alert);

                    if correlation_score > CORRELATION_THRESHOLD {
                        if best_match
                            .as_ref()
                            .map_or(true, |(_, best_score)| correlation_score > *best_score)
                        {
                            best_match = Some((idx, correlation_score));
                        }
                    }
                }
            }
        }

        // Add to best matching chain or create new chain
        if let Some((idx, confidence)) = best_match {
            let chain = &mut attacker_chains[idx];
            let stage = AttackStage {
                stage_number: chain.stages.len() as u32 + 1,
                stage_type,
                timestamp: Utc::now(),
                alerts: vec![alert.clone()],
                confidence,
                description: alert.detection_result.reason.clone(),
            };
            chain.stages.push(stage);
            chain.last_activity = Instant::now();
            chain.confidence = (chain.confidence + confidence) / 2.0;

            // Check if this forms a complete correlated attack
            if chain.stages.len() >= 2 {
                let correlated = self.finalize_correlation(source_ip, chain.clone()).await;
                return Some(correlated);
            }
        } else {
            // Start new chain
            if attacker_chains.len() < MAX_CHAINS_PER_IP {
                let stage = AttackStage {
                    stage_number: 1,
                    stage_type,
                    timestamp: Utc::now(),
                    alerts: vec![alert.clone()],
                    confidence: alert.detection_result.confidence,
                    description: alert.detection_result.reason.clone(),
                };

                let new_chain = AttackChain {
                    stages: vec![stage],
                    created_at: Instant::now(),
                    last_activity: Instant::now(),
                    confidence: alert.detection_result.confidence,
                };

                attacker_chains.push(new_chain);
            }
        }

        None
    }

    /// Classify an alert into a kill chain stage
    fn classify_alert_stage(&self, alert: &EnrichedAlert) -> AttackStageType {
        let pattern = &alert.detection_result.pattern;
        let indicators = &alert.detection_result.indicators;

        // Pattern-based classification
        if pattern.contains("Port Scan") || pattern.contains("Scan") {
            AttackStageType::Reconnaissance
        } else if pattern.contains("Brute Force") || pattern.contains("Login") {
            AttackStageType::InitialAccess
        } else if pattern.contains("SYN Flood")
            || pattern.contains("DoS")
            || pattern.contains("Flood")
        {
            AttackStageType::Impact
        } else if pattern.contains("Anomaly") || pattern.contains("Suspicious") {
            // Check indicators for more context
            if indicators.iter().any(|i| i.contains("port")) {
                AttackStageType::Reconnaissance
            } else if indicators.iter().any(|i| i.contains("connection")) {
                AttackStageType::InitialAccess
            } else {
                AttackStageType::Collection
            }
        } else {
            AttackStageType::InitialAccess // Default
        }
    }

    /// Calculate confidence for a stage transition
    fn calculate_stage_confidence(
        &self,
        stage_type: &AttackStageType,
        alert: &EnrichedAlert,
    ) -> f64 {
        let base_confidence = alert.detection_result.confidence;

        // Boost confidence for high-severity alerts
        let severity_boost = match alert.severity {
            Severity::Critical => 0.1,
            Severity::High => 0.05,
            _ => 0.0,
        };

        // Penalize for few indicators
        let indicator_penalty = if alert.detection_result.indicators.len() < 2 {
            0.1
        } else {
            0.0
        };

        (base_confidence + severity_boost - indicator_penalty).min(1.0)
    }

    /// Calculate correlation strength between chain and new stage
    fn calculate_correlation_strength(
        &self,
        existing_stages: &[AttackStage],
        new_stage: AttackStageType,
        alert: &EnrichedAlert,
    ) -> f64 {
        let mut score: f64 = 0.0;

        // Check against known patterns
        for pattern in &self.patterns {
            if pattern.stage_sequence.len() > existing_stages.len() {
                let expected_next = &pattern.stage_sequence[existing_stages.len()];
                if *expected_next == new_stage {
                    score = score.max(pattern.confidence_boost);
                }
            }
        }

        // Boost for temporal proximity
        if let Some(last) = existing_stages.last() {
            let time_diff = Utc::now()
                .signed_duration_since(last.timestamp)
                .num_seconds();
            if time_diff < 60 {
                score += 0.1; // Within 1 minute
            } else if time_diff < 300 {
                score += 0.05; // Within 5 minutes
            }
        }

        // Boost for consistent attacker
        score += alert.detection_result.confidence * 0.2;

        score.min(1.0)
    }

    /// Finalize a correlated attack from a chain
    async fn finalize_correlation(
        &self,
        attacker_ip: IpAddr,
        chain: AttackChain,
    ) -> CorrelatedAttack {
        let start_time = chain
            .stages
            .first()
            .map(|s| s.timestamp)
            .unwrap_or_else(Utc::now);
        let end_time = chain
            .stages
            .last()
            .map(|s| s.timestamp)
            .unwrap_or_else(Utc::now);

        // Collect all affected targets and ports
        let mut affected_targets = HashSet::new();
        let mut affected_ports = HashSet::new();
        let mut all_indicators = Vec::new();

        for stage in &chain.stages {
            for alert in &stage.alerts {
                affected_targets.insert(alert.source_ip);
                affected_targets.insert(alert.destination_ip);
                if let Some(sport) = alert.source_port {
                    affected_ports.insert(sport);
                }
                if let Some(dport) = alert.destination_port {
                    affected_ports.insert(dport);
                }
                all_indicators.extend(alert.detection_result.indicators.clone());
            }
        }

        // Determine attack category
        let attack_type = self.categorize_attack(&chain);

        // Calculate combined confidence
        let combined_confidence =
            chain.confidence * (0.7 + (chain.stages.len() as f64 * 0.1)).min(1.0);

        // Determine severity
        let severity = if combined_confidence > 0.9 && chain.stages.len() >= 3 {
            Severity::Critical
        } else if combined_confidence > 0.8 {
            Severity::High
        } else if combined_confidence > 0.6 {
            Severity::Medium
        } else {
            Severity::Low
        };

        // Generate summary
        let summary = self.generate_attack_summary(&chain, &attack_type, attacker_ip);

        let correlated = CorrelatedAttack {
            id: format!(
                "CORR-{}-{}- {}",
                Utc::now().timestamp_millis(),
                attacker_ip,
                Uuid::new_v4()
            ),
            attacker_ip,
            start_time,
            end_time,
            stages: chain.stages,
            combined_confidence,
            severity,
            attack_type,
            indicators: all_indicators,
            affected_targets,
            affected_ports,
            is_ongoing: true,
            summary,
        };

        // Store in history
        let mut history = self.attack_history.write().await;
        if history.len() >= self.max_history {
            history.pop_front();
        }
        history.push_back(correlated.clone());

        correlated
    }

    /// Categorize an attack based on its stages
    fn categorize_attack(&self, chain: &AttackChain) -> AttackCategory {
        let stage_types: HashSet<_> = chain.stages.iter().map(|s| s.stage_type).collect();

        if stage_types.contains(&AttackStageType::Impact)
            && stage_types.contains(&AttackStageType::Reconnaissance)
        {
            AttackCategory::MultiStageIntrusion
        } else if stage_types.contains(&AttackStageType::Impact)
            && chain
                .stages
                .iter()
                .filter(|s| s.stage_type == AttackStageType::Impact)
                .count()
                > 1
        {
            AttackCategory::DoSCampaign
        } else if stage_types.contains(&AttackStageType::Reconnaissance)
            && stage_types.contains(&AttackStageType::InitialAccess)
        {
            AttackCategory::BruteForceCampaign
        } else if stage_types.contains(&AttackStageType::Collection)
            || stage_types.contains(&AttackStageType::Exfiltration)
        {
            AttackCategory::DataExfiltration
        } else if chain.stages.len() >= 3 {
            AttackCategory::APTActivity
        } else {
            AttackCategory::Unknown
        }
    }

    /// Generate human-readable attack summary
    fn generate_attack_summary(
        &self,
        chain: &AttackChain,
        category: &AttackCategory,
        attacker_ip: IpAddr,
    ) -> String {
        let stage_names: Vec<_> = chain.stages.iter().map(|s| s.stage_type.as_str()).collect();

        format!(
            "{} detected from {}. Kill chain: {}. {} stages over {:.1} minutes. Confidence: {:.0}%",
            category.as_str(),
            attacker_ip,
            stage_names.join(" → "),
            chain.stages.len(),
            chain.created_at.elapsed().as_secs_f64() / 60.0,
            chain.confidence * 100.0
        )
    }

    /// Clean up old attack chains
    fn cleanup_old_chains(&self, chains: &mut Vec<AttackChain>) {
        chains.retain(|chain| {
            let age = chain.last_activity.elapsed().as_secs();
            age < CORRELATION_WINDOW_SECS && chain.stages.len() < 8
        });
    }

    /// Get active correlated attacks
    pub async fn get_active_attacks(&self) -> Vec<CorrelatedAttack> {
        let history = self.attack_history.read().await;
        history.iter().filter(|a| a.is_ongoing).cloned().collect()
    }

    /// Get recent correlated attacks
    pub async fn get_recent_attacks(&self, limit: usize) -> Vec<CorrelatedAttack> {
        let history = self.attack_history.read().await;
        history.iter().rev().take(limit).cloned().collect()
    }

    /// Get attacks by source IP
    pub async fn get_attacks_by_ip(&self, ip: IpAddr) -> Vec<CorrelatedAttack> {
        let history = self.attack_history.read().await;
        history
            .iter()
            .filter(|a| a.attacker_ip == ip)
            .cloned()
            .collect()
    }

    /// Mark attack as resolved
    pub async fn resolve_attack(&self, attack_id: &str) {
        let mut history = self.attack_history.write().await;
        for attack in history.iter_mut() {
            if attack.id == attack_id {
                attack.is_ongoing = false;
                attack.end_time = Utc::now();
                break;
            }
        }
    }

    /// Get correlation statistics
    pub async fn get_stats(&self) -> CorrelationStats {
        let history = self.attack_history.read().await;
        let active = history.iter().filter(|a| a.is_ongoing).count();
        let total = history.len();

        let category_counts: HashMap<String, usize> =
            history.iter().fold(HashMap::new(), |mut acc, attack| {
                *acc.entry(attack.attack_type.as_str().to_string())
                    .or_insert(0) += 1;
                acc
            });

        CorrelationStats {
            active_attacks: active,
            total_correlated: total,
            category_breakdown: category_counts,
        }
    }
}

/// Correlation statistics
#[derive(Debug, Clone, Serialize)]
pub struct CorrelationStats {
    pub active_attacks: usize,
    pub total_correlated: usize,
    pub category_breakdown: HashMap<String, usize>,
}

impl Default for CorrelationEngine {
    fn default() -> Self {
        Self::new()
    }
}
