//! Forensics Module
//!
//! Historical alert storage, analysis, and replay capabilities.
//! Enables post-incident investigation and attack timeline reconstruction.

use crate::correlator::CorrelatedAttack;
use crate::models::{EnrichedAlert, PacketInfo};
use crate::profiler::IpProfile;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Maximum alerts to keep in memory
const MAX_ALERT_HISTORY: usize = 10000;
/// Maximum packet samples to store
const MAX_PACKET_SAMPLES: usize = 1000;
/// Time window for automatic snapshot creation
const SNAPSHOT_INTERVAL_SECS: u64 = 300; // 5 minutes

/// Forensic session for investigation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicSession {
    pub id: String,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub time_range: (DateTime<Utc>, DateTime<Utc>),
    pub filters: ForensicFilters,
    pub alerts: Vec<EnrichedAlert>,
    pub packets: Vec<PacketInfo>,
    pub correlated_attacks: Vec<CorrelatedAttack>,
    pub notes: Vec<InvestigationNote>,
    pub status: InvestigationStatus,
}

/// Investigation status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InvestigationStatus {
    Active,
    Paused,
    Completed,
    Archived,
}

/// Filters for forensic analysis
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ForensicFilters {
    pub time_start: Option<DateTime<Utc>>,
    pub time_end: Option<DateTime<Utc>>,
    pub source_ips: Vec<IpAddr>,
    pub destination_ips: Vec<IpAddr>,
    pub ports: Vec<u16>,
    pub protocols: Vec<String>,
    pub severity_min: Option<String>,
    pub alert_types: Vec<String>,
    pub keywords: Vec<String>,
}

/// Investigation note
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvestigationNote {
    pub timestamp: DateTime<Utc>,
    pub author: String,
    pub content: String,
    pub alert_ids: Vec<String>,
    pub ip_addresses: Vec<IpAddr>,
}

/// Attack timeline entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEntry {
    pub timestamp: DateTime<Utc>,
    pub entry_type: TimelineEntryType,
    pub description: String,
    pub related_alerts: Vec<String>,
    pub ip_address: Option<IpAddr>,
    pub severity: String,
}

/// Types of timeline entries
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TimelineEntryType {
    InitialContact,
    Reconnaissance,
    ExploitationAttempt,
    LateralMovement,
    DataExfiltration,
    Impact,
    ResponseAction,
    SystemEvent,
}

/// Alert snapshot for point-in-time analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertSnapshot {
    pub timestamp: DateTime<Utc>,
    pub alert_count: usize,
    pub top_threats: Vec<String>,
    pub active_ips: Vec<IpAddr>,
    pub severity_distribution: HashMap<String, u32>,
}

/// Main forensics engine
pub struct ForensicsEngine {
    /// Alert history storage
    alert_history: Arc<RwLock<VecDeque<EnrichedAlert>>>,
    /// Packet samples for detailed analysis
    packet_samples: Arc<RwLock<VecDeque<PacketInfo>>>,
    /// Active investigation sessions
    sessions: Arc<RwLock<HashMap<String, ForensicSession>>>,
    /// Time-indexed alerts for fast queries
    time_index: Arc<RwLock<BTreeMap<DateTime<Utc>, Vec<String>>>>,
    /// IP-indexed alerts
    ip_index: Arc<RwLock<HashMap<IpAddr, Vec<String>>>>,
    /// Periodic snapshots
    snapshots: Arc<RwLock<VecDeque<AlertSnapshot>>>,
    /// Last snapshot time
    last_snapshot: Arc<RwLock<Instant>>,
}

/// Replay configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayConfig {
    pub speed_multiplier: f64, // 1.0 = realtime, 2.0 = 2x speed, 0.5 = half speed
    pub pause_on_alert: bool,
    pub filter_ips: Vec<IpAddr>,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
}

impl Default for ReplayConfig {
    fn default() -> Self {
        Self {
            speed_multiplier: 1.0,
            pause_on_alert: false,
            filter_ips: Vec::new(),
            start_time: Utc::now() - chrono::Duration::hours(1),
            end_time: Utc::now(),
        }
    }
}

/// Replay state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayState {
    Playing,
    Paused,
    Stopped,
    Completed,
}

impl ForensicsEngine {
    pub fn new() -> Self {
        Self {
            alert_history: Arc::new(RwLock::new(VecDeque::with_capacity(MAX_ALERT_HISTORY))),
            packet_samples: Arc::new(RwLock::new(VecDeque::with_capacity(MAX_PACKET_SAMPLES))),
            sessions: Arc::new(RwLock::new(HashMap::new())),
            time_index: Arc::new(RwLock::new(BTreeMap::new())),
            ip_index: Arc::new(RwLock::new(HashMap::new())),
            snapshots: Arc::new(RwLock::new(VecDeque::with_capacity(100))),
            last_snapshot: Arc::new(RwLock::new(Instant::now())),
        }
    }

    /// Store an alert for forensics
    pub async fn store_alert(&self, alert: EnrichedAlert) {
        let mut history = self.alert_history.write().await;
        let mut time_index = self.time_index.write().await;
        let mut ip_index = self.ip_index.write().await;

        // Add to history
        if history.len() >= MAX_ALERT_HISTORY {
            history.pop_front();
        }

        let alert_id = alert.id.clone();
        let timestamp = alert.timestamp;

        history.push_back(alert);

        // Index by time
        time_index
            .entry(timestamp)
            .or_insert_with(Vec::new)
            .push(alert_id.clone());

        // Index by IP
        if let Some(alert) = history.back() {
            ip_index
                .entry(alert.source_ip)
                .or_insert_with(Vec::new)
                .push(alert_id.clone());
        }

        // Periodic snapshot
        let should_snapshot = {
            let last = self.last_snapshot.read().await;
            last.elapsed().as_secs() > SNAPSHOT_INTERVAL_SECS
        };

        if should_snapshot {
            drop(history);
            drop(time_index);
            drop(ip_index);
            self.create_snapshot().await;
            let mut last = self.last_snapshot.write().await;
            *last = Instant::now();
        }
    }

    /// Store packet sample
    pub async fn store_packet(&self, packet: PacketInfo) {
        let mut samples = self.packet_samples.write().await;

        if samples.len() >= MAX_PACKET_SAMPLES {
            samples.pop_front();
        }

        samples.push_back(packet);
    }

    /// Create a point-in-time snapshot
    async fn create_snapshot(&self) {
        let history = self.alert_history.read().await;

        let mut severity_dist = HashMap::new();
        let mut active_ips = HashSet::new();

        for alert in history.iter().rev().take(100) {
            *severity_dist
                .entry(alert.severity.to_string())
                .or_insert(0u32) += 1;
            active_ips.insert(alert.source_ip);
        }

        let snapshot = AlertSnapshot {
            timestamp: Utc::now(),
            alert_count: history.len(),
            top_threats: Vec::new(), // Would be populated from threat ranking
            active_ips: active_ips.into_iter().collect(),
            severity_distribution: severity_dist,
        };

        let mut snapshots = self.snapshots.write().await;
        if snapshots.len() >= 100 {
            snapshots.pop_front();
        }
        snapshots.push_back(snapshot);
    }

    /// Create new investigation session
    pub async fn create_session(&self, name: String, filters: ForensicFilters) -> ForensicSession {
        let session = ForensicSession {
            id: format!("SESS-{}", Utc::now().timestamp_millis()),
            name,
            created_at: Utc::now(),
            time_range: (
                filters
                    .time_start
                    .unwrap_or_else(|| Utc::now() - chrono::Duration::hours(24)),
                filters.time_end.unwrap_or_else(|| Utc::now()),
            ),
            filters: filters.clone(),
            alerts: Vec::new(),
            packets: Vec::new(),
            correlated_attacks: Vec::new(),
            notes: Vec::new(),
            status: InvestigationStatus::Active,
        };

        // Pre-populate with matching alerts
        let matching = self.search_alerts(&filters).await;
        let mut sessions = self.sessions.write().await;
        let mut session_with_alerts = session.clone();
        session_with_alerts.alerts = matching;

        sessions.insert(session.id.clone(), session_with_alerts.clone());
        session_with_alerts
    }

    /// Search alerts by filters
    pub async fn search_alerts(&self, filters: &ForensicFilters) -> Vec<EnrichedAlert> {
        let history = self.alert_history.read().await;

        history
            .iter()
            .filter(|alert| {
                // Time filter
                if let Some(start) = filters.time_start {
                    if alert.timestamp < start {
                        return false;
                    }
                }
                if let Some(end) = filters.time_end {
                    if alert.timestamp > end {
                        return false;
                    }
                }

                // IP filters
                if !filters.source_ips.is_empty() {
                    if !filters.source_ips.contains(&alert.source_ip) {
                        return false;
                    }
                }

                // Port filter
                if !filters.ports.is_empty() {
                    let matches_port = alert
                        .source_port
                        .map_or(false, |p| filters.ports.contains(&p))
                        || alert
                            .destination_port
                            .map_or(false, |p| filters.ports.contains(&p));
                    if !matches_port {
                        return false;
                    }
                }

                // Keyword search
                if !filters.keywords.is_empty() {
                    let alert_text = format!("{} {:?}", alert.description, alert.detection_result);
                    let matches = filters
                        .keywords
                        .iter()
                        .any(|kw| alert_text.to_lowercase().contains(&kw.to_lowercase()));
                    if !matches {
                        return false;
                    }
                }

                true
            })
            .cloned()
            .collect()
    }

    /// Get alerts for a specific IP
    pub async fn get_ip_timeline(&self, ip: IpAddr) -> Vec<EnrichedAlert> {
        let ip_index = self.ip_index.read().await;
        let history = self.alert_history.read().await;

        let alert_ids = ip_index.get(&ip).cloned().unwrap_or_default();

        history
            .iter()
            .filter(|a| alert_ids.contains(&a.id))
            .cloned()
            .collect()
    }

    /// Build attack timeline for investigation
    pub async fn build_timeline(&self, session_id: &str) -> Vec<TimelineEntry> {
        let sessions = self.sessions.read().await;
        let session = match sessions.get(session_id) {
            Some(s) => s.clone(),
            None => return Vec::new(),
        };
        drop(sessions);

        let mut timeline = Vec::new();

        // Convert alerts to timeline entries
        for alert in &session.alerts {
            let entry = TimelineEntry {
                timestamp: alert.timestamp,
                entry_type: self.classify_timeline_entry(alert),
                description: alert.description.clone(),
                related_alerts: vec![alert.id.clone()],
                ip_address: Some(alert.source_ip),
                severity: alert.severity.to_string(),
            };
            timeline.push(entry);
        }

        // Sort by timestamp
        timeline.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

        timeline
    }

    /// Classify alert into timeline entry type
    fn classify_timeline_entry(&self, alert: &EnrichedAlert) -> TimelineEntryType {
        let pattern = alert.detection_result.pattern.to_lowercase();

        if pattern.contains("scan") || pattern.contains("recon") {
            TimelineEntryType::Reconnaissance
        } else if pattern.contains("brute") || pattern.contains("exploit") {
            TimelineEntryType::ExploitationAttempt
        } else if pattern.contains("flood") || pattern.contains("dos") {
            TimelineEntryType::Impact
        } else if pattern.contains("lateral") || pattern.contains("pivot") {
            TimelineEntryType::LateralMovement
        } else if pattern.contains("exfil") || pattern.contains("data") {
            TimelineEntryType::DataExfiltration
        } else {
            TimelineEntryType::SystemEvent
        }
    }

    /// Add note to investigation
    pub async fn add_note(
        &self,
        session_id: &str,
        author: String,
        content: String,
        alert_ids: Vec<String>,
        ips: Vec<IpAddr>,
    ) -> bool {
        let mut sessions = self.sessions.write().await;

        if let Some(session) = sessions.get_mut(session_id) {
            session.notes.push(InvestigationNote {
                timestamp: Utc::now(),
                author,
                content,
                alert_ids,
                ip_addresses: ips,
            });
            true
        } else {
            false
        }
    }

    /// Start replay of historical events
    pub async fn start_replay(&self, config: ReplayConfig) -> ReplayHandle {
        let alerts = self
            .search_alerts(&ForensicFilters {
                time_start: Some(config.start_time),
                time_end: Some(config.end_time),
                source_ips: config.filter_ips.clone(),
                ..Default::default()
            })
            .await;

        let packets = if config.filter_ips.is_empty() {
            self.packet_samples
                .read()
                .await
                .iter()
                .filter(|p| p.timestamp >= config.start_time && p.timestamp <= config.end_time)
                .cloned()
                .collect()
        } else {
            Vec::new()
        };

        ReplayHandle {
            alerts,
            packets,
            config,
            current_index: 0,
            state: ReplayState::Paused,
            start_time: None,
        }
    }

    /// Get forensics statistics
    pub async fn get_stats(&self) -> ForensicsStats {
        let history = self.alert_history.read().await;
        let sessions = self.sessions.read().await;
        let snapshots = self.snapshots.read().await;

        ForensicsStats {
            total_alerts_stored: history.len(),
            active_sessions: sessions
                .values()
                .filter(|s| s.status == InvestigationStatus::Active)
                .count(),
            total_sessions: sessions.len(),
            snapshots_available: snapshots.len(),
            time_coverage_hours: self.calculate_time_coverage(&history).await,
        }
    }

    /// Calculate time coverage of stored alerts
    async fn calculate_time_coverage(&self, history: &VecDeque<EnrichedAlert>) -> f64 {
        if history.len() < 2 {
            return 0.0;
        }

        let times: Vec<_> = history.iter().map(|a| a.timestamp).collect();
        let min_time = times.iter().min().unwrap();
        let max_time = times.iter().max().unwrap();

        let duration = max_time.signed_duration_since(*min_time);
        duration.num_hours() as f64 + duration.num_minutes() as f64 / 60.0
    }

    /// Export session to JSON
    pub async fn export_session(&self, session_id: &str) -> Option<String> {
        let sessions = self.sessions.read().await;

        sessions
            .get(session_id)
            .and_then(|session| serde_json::to_string_pretty(session).ok())
    }

    /// Get session by ID
    pub async fn get_session(&self, session_id: &str) -> Option<ForensicSession> {
        let sessions = self.sessions.read().await;
        sessions.get(session_id).cloned()
    }

    /// List all sessions
    pub async fn list_sessions(&self) -> Vec<ForensicSession> {
        let sessions = self.sessions.read().await;
        sessions.values().cloned().collect()
    }

    /// Pause live capture (simulation - would stop packet capture in real impl)
    pub async fn pause_capture(&self) -> bool {
        tracing::info!("🔴 Live capture paused for forensic analysis");
        true
    }

    /// Resume live capture
    pub async fn resume_capture(&self) -> bool {
        tracing::info!("🟢 Live capture resumed");
        true
    }
}

/// Handle for controlling replay
pub struct ReplayHandle {
    pub alerts: Vec<EnrichedAlert>,
    pub packets: Vec<PacketInfo>,
    pub config: ReplayConfig,
    pub current_index: usize,
    pub state: ReplayState,
    pub start_time: Option<Instant>,
}

impl ReplayHandle {
    /// Get next event in replay
    pub fn next_event(&mut self) -> Option<ReplayEvent> {
        if self.current_index >= self.alerts.len() {
            self.state = ReplayState::Completed;
            return None;
        }

        let alert = &self.alerts[self.current_index];
        self.current_index += 1;

        Some(ReplayEvent::Alert(alert.clone()))
    }

    /// Play replay (async - would use tokio::time)
    pub async fn play(&mut self) {
        self.state = ReplayState::Playing;
        self.start_time = Some(Instant::now());
    }

    /// Pause replay
    pub fn pause(&mut self) {
        self.state = ReplayState::Paused;
    }

    /// Stop replay
    pub fn stop(&mut self) {
        self.state = ReplayState::Stopped;
        self.current_index = 0;
    }

    /// Seek to specific time
    pub fn seek_to(&mut self, timestamp: DateTime<Utc>) {
        self.current_index = self
            .alerts
            .iter()
            .position(|a| a.timestamp >= timestamp)
            .unwrap_or(0);
    }

    /// Get progress percentage
    pub fn progress(&self) -> f64 {
        if self.alerts.is_empty() {
            return 100.0;
        }
        (self.current_index as f64 / self.alerts.len() as f64) * 100.0
    }
}

/// Events during replay
#[derive(Debug, Clone)]
pub enum ReplayEvent {
    Alert(EnrichedAlert),
    Packet(PacketInfo),
    Timestamp(DateTime<Utc>),
}

/// Forensics statistics
#[derive(Debug, Clone, Serialize)]
pub struct ForensicsStats {
    pub total_alerts_stored: usize,
    pub active_sessions: usize,
    pub total_sessions: usize,
    pub snapshots_available: usize,
    pub time_coverage_hours: f64,
}

impl Default for ForensicsEngine {
    fn default() -> Self {
        Self::new()
    }
}
