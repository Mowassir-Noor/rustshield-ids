//! Real-time Response Engine
//!
//! Active defense capabilities with safe and active modes.
//! Implements automated responses to detected threats.

use crate::correlator::CorrelatedAttack;
use crate::models::{EnrichedAlert, Severity};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Response mode - determines what actions can be taken
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResponseMode {
    /// Monitoring only - no active responses
    Safe,
    /// Automatic low-impact responses only
    SemiActive,
    /// Full automatic responses enabled
    Active,
    /// Dry-run mode - log actions but don't execute
    DryRun,
}

impl ResponseMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            ResponseMode::Safe => "SAFE (Monitor Only)",
            ResponseMode::SemiActive => "SEMI-ACTIVE (Limited Response)",
            ResponseMode::Active => "ACTIVE (Full Response)",
            ResponseMode::DryRun => "DRY-RUN (Log Only)",
        }
    }

    /// Check if a response type is allowed in this mode
    pub fn allows(&self, response_type: &ResponseType) -> bool {
        match self {
            ResponseMode::Safe => false,
            ResponseMode::DryRun => true, // All allowed but not executed
            ResponseMode::SemiActive => matches!(
                response_type,
                ResponseType::RateLimit | ResponseType::LogOnly | ResponseType::Notify
            ),
            ResponseMode::Active => true, // All allowed
        }
    }
}

/// Types of response actions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ResponseType {
    /// Log the threat (always available)
    LogOnly,
    /// Send notification
    Notify,
    /// Rate limit traffic
    RateLimit,
    /// Block IP temporarily (soft block)
    TemporaryBlock,
    /// Block IP permanently (firewall rule)
    PermanentBlock,
    /// Kill suspicious connections
    KillConnections,
    /// Add to honeypot monitoring
    HoneypotRedirect,
}

impl ResponseType {
    pub fn as_str(&self) -> &'static str {
        match self {
            ResponseType::LogOnly => "Log Only",
            ResponseType::Notify => "Send Notification",
            ResponseType::RateLimit => "Rate Limit",
            ResponseType::TemporaryBlock => "Temporary Block (15 min)",
            ResponseType::PermanentBlock => "Permanent Block",
            ResponseType::KillConnections => "Kill Connections",
            ResponseType::HoneypotRedirect => "Honeypot Redirect",
        }
    }

    pub fn severity(&self) -> ResponseSeverity {
        match self {
            ResponseType::LogOnly => ResponseSeverity::None,
            ResponseType::Notify => ResponseSeverity::Low,
            ResponseType::RateLimit => ResponseSeverity::Low,
            ResponseType::KillConnections => ResponseSeverity::Medium,
            ResponseType::TemporaryBlock => ResponseSeverity::Medium,
            ResponseType::HoneypotRedirect => ResponseSeverity::Medium,
            ResponseType::PermanentBlock => ResponseSeverity::High,
        }
    }
}

/// Response severity level
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ResponseSeverity {
    None,
    Low,
    Medium,
    High,
}

/// A response action taken against a threat
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseAction {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub target_ip: IpAddr,
    pub response_type: ResponseType,
    pub triggered_by: String, // Alert ID or attack ID
    pub reason: String,
    pub mode: ResponseMode,
    pub executed: bool,
    pub success: Option<bool>,
    pub error_message: Option<String>,
    pub duration_secs: Option<u64>, // For temporary blocks
    pub expires_at: Option<DateTime<Utc>>,
}

/// Response rule defining when to trigger an action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseRule {
    pub name: String,
    pub conditions: ResponseConditions,
    pub response: ResponseType,
    pub cooldown_secs: u64,
    pub require_confirmation: bool,
}

/// Conditions for triggering a response
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResponseConditions {
    pub min_severity: Option<Severity>,
    pub min_confidence: Option<f64>,
    pub min_alerts: Option<u32>,
    pub alert_patterns: Vec<String>,
    pub attack_types: Vec<String>,
    pub is_correlated_attack: bool,
}

/// Main response engine
pub struct ResponseEngine {
    /// Current response mode
    mode: Arc<RwLock<ResponseMode>>,
    /// Active blocks/rate limits
    active_responses: Arc<RwLock<HashMap<IpAddr, Vec<ResponseAction>>>>,
    /// Response rules
    rules: Arc<RwLock<Vec<ResponseRule>>>,
    /// Action history
    history: Arc<RwLock<VecDeque<ResponseAction>>>,
    /// Last action timestamp per IP (for cooldown)
    last_action: Arc<RwLock<HashMap<(IpAddr, ResponseType), Instant>>>,
    /// Blocked IPs cache
    blocked_ips: Arc<RwLock<HashSet<IpAddr>>>,
    /// Rate limited IPs
    rate_limited: Arc<RwLock<HashMap<IpAddr, RateLimitState>>>,
}

/// Rate limiting state for an IP
#[derive(Debug, Clone)]
struct RateLimitState {
    tokens: f64,
    last_update: Instant,
    max_rate: f64,
}

/// Suggested action for an alert
#[derive(Debug, Clone, Serialize)]
pub struct SuggestedAction {
    pub action: ResponseType,
    pub reason: String,
    pub confidence: f64,
    pub risk_reduction: f64,
    pub would_execute: bool,
}

impl ResponseEngine {
    pub fn new(mode: ResponseMode) -> Self {
        let rules = Self::default_rules();

        Self {
            mode: Arc::new(RwLock::new(mode)),
            active_responses: Arc::new(RwLock::new(HashMap::new())),
            rules: Arc::new(RwLock::new(rules)),
            history: Arc::new(RwLock::new(VecDeque::with_capacity(1000))),
            last_action: Arc::new(RwLock::new(HashMap::new())),
            blocked_ips: Arc::new(RwLock::new(HashSet::new())),
            rate_limited: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create default response rules
    fn default_rules() -> Vec<ResponseRule> {
        vec![
            ResponseRule {
                name: "Critical Severity Immediate Block".to_string(),
                conditions: ResponseConditions {
                    min_severity: Some(Severity::Critical),
                    min_confidence: Some(0.9),
                    is_correlated_attack: false,
                    ..Default::default()
                },
                response: ResponseType::PermanentBlock,
                cooldown_secs: 60,
                require_confirmation: false,
            },
            ResponseRule {
                name: "Multi-Stage Attack Response".to_string(),
                conditions: ResponseConditions {
                    is_correlated_attack: true,
                    min_confidence: Some(0.8),
                    ..Default::default()
                },
                response: ResponseType::TemporaryBlock,
                cooldown_secs: 300,
                require_confirmation: false,
            },
            ResponseRule {
                name: "High Volume DoS Rate Limit".to_string(),
                conditions: ResponseConditions {
                    alert_patterns: vec!["DoS".to_string(), "Flood".to_string()],
                    min_severity: Some(Severity::High),
                    ..Default::default()
                },
                response: ResponseType::RateLimit,
                cooldown_secs: 60,
                require_confirmation: false,
            },
            ResponseRule {
                name: "Brute Force Temporary Block".to_string(),
                conditions: ResponseConditions {
                    alert_patterns: vec!["Brute Force".to_string()],
                    min_alerts: Some(5),
                    ..Default::default()
                },
                response: ResponseType::TemporaryBlock,
                cooldown_secs: 900,
                require_confirmation: false,
            },
            ResponseRule {
                name: "Suspicious Activity Notify".to_string(),
                conditions: ResponseConditions {
                    min_severity: Some(Severity::Medium),
                    min_confidence: Some(0.7),
                    ..Default::default()
                },
                response: ResponseType::Notify,
                cooldown_secs: 300,
                require_confirmation: false,
            },
        ]
    }

    /// Process an alert and determine appropriate responses
    pub async fn process_alert(&self, alert: &EnrichedAlert) -> Vec<ResponseAction> {
        let mut actions = Vec::new();
        let source_ip = alert.source_ip;

        let rules = self.rules.read().await;
        let mode = *self.mode.read().await;

        for rule in rules.iter() {
            if self.matches_conditions(alert, &rule.conditions).await {
                // Check cooldown
                if self
                    .check_cooldown(source_ip, rule.response, rule.cooldown_secs)
                    .await
                {
                    if let Some(action) = self
                        .execute_response(source_ip, rule.response, &alert.id, &rule.name, mode)
                        .await
                    {
                        actions.push(action);
                    }
                }
            }
        }

        actions
    }

    /// Process a correlated attack
    pub async fn process_correlated_attack(
        &self,
        attack: &CorrelatedAttack,
    ) -> Vec<ResponseAction> {
        let mut actions = Vec::new();
        let mode = *self.mode.read().await;

        // Always take stronger action on correlated attacks
        let response_type = if attack.severity == Severity::Critical {
            ResponseType::PermanentBlock
        } else {
            ResponseType::TemporaryBlock
        };

        if self
            .check_cooldown(attack.attacker_ip, response_type, 60)
            .await
        {
            if let Some(action) = self
                .execute_response(
                    attack.attacker_ip,
                    response_type,
                    &attack.id,
                    &format!("Correlated {} attack", attack.attack_type.as_str()),
                    mode,
                )
                .await
            {
                actions.push(action);
            }
        }

        // Also rate limit if it's a DoS campaign
        if attack.attack_type.to_string().contains("DoS") {
            if self
                .check_cooldown(attack.attacker_ip, ResponseType::RateLimit, 30)
                .await
            {
                if let Some(action) = self
                    .execute_response(
                        attack.attacker_ip,
                        ResponseType::RateLimit,
                        &attack.id,
                        "DoS protection rate limiting",
                        mode,
                    )
                    .await
                {
                    actions.push(action);
                }
            }
        }

        actions
    }

    /// Check if alert matches response conditions
    async fn matches_conditions(
        &self,
        alert: &EnrichedAlert,
        conditions: &ResponseConditions,
    ) -> bool {
        // Check severity
        if let Some(min_sev) = conditions.min_severity {
            if alert.severity < min_sev {
                return false;
            }
        }

        // Check confidence
        if let Some(min_conf) = conditions.min_confidence {
            if alert.detection_result.confidence < min_conf {
                return false;
            }
        }

        // Check pattern
        if !conditions.alert_patterns.is_empty() {
            let pattern_match = conditions
                .alert_patterns
                .iter()
                .any(|p| alert.detection_result.pattern.contains(p));
            if !pattern_match {
                return false;
            }
        }

        true
    }

    /// Check if cooldown period has elapsed
    async fn check_cooldown(
        &self,
        ip: IpAddr,
        response_type: ResponseType,
        cooldown_secs: u64,
    ) -> bool {
        let last_action = self.last_action.read().await;
        let key = (ip, response_type);

        if let Some(last_time) = last_action.get(&key) {
            if last_time.elapsed().as_secs() < cooldown_secs {
                return false; // Still in cooldown
            }
        }

        true
    }

    /// Execute a response action
    async fn execute_response(
        &self,
        target_ip: IpAddr,
        response_type: ResponseType,
        triggered_by: &str,
        reason: &str,
        mode: ResponseMode,
    ) -> Option<ResponseAction> {
        // Check if response type is allowed in current mode
        let would_execute = mode.allows(&response_type);

        let action = ResponseAction {
            id: format!(
                "RESP-{}-{}",
                Utc::now().timestamp_millis(),
                uuid::Uuid::new_v4()
            ),
            timestamp: Utc::now(),
            target_ip,
            response_type,
            triggered_by: triggered_by.to_string(),
            reason: reason.to_string(),
            mode,
            executed: false,
            success: None,
            error_message: None,
            duration_secs: None,
            expires_at: None,
        };

        if mode == ResponseMode::DryRun {
            // In dry-run, just log what would happen
            let mut action = action.clone();
            action.executed = false;
            action.success = Some(true);
            action.error_message = Some(format!("Dry-run: Would execute {:?}", response_type));
            self.record_action(action.clone()).await;
            return Some(action);
        }

        return if would_execute {
            let mut action = action.clone();
            let result = match response_type {
                ResponseType::LogOnly => {
                    action.executed = true;
                    action.success = Some(true);
                    Ok(())
                }
                ResponseType::Notify => self.send_notification(target_ip, reason).await,
                ResponseType::RateLimit => {
                    self.apply_rate_limit(target_ip, 100.0).await // 100 pps limit
                }
                ResponseType::TemporaryBlock => {
                    self.apply_block(target_ip, Duration::from_secs(900), false)
                        .await // 15 min
                }
                ResponseType::PermanentBlock => {
                    self.apply_block(target_ip, Duration::from_secs(86400 * 365), true)
                        .await // 1 year
                }
                ResponseType::KillConnections => self.kill_connections(target_ip).await,
                ResponseType::HoneypotRedirect => self.redirect_to_honeypot(target_ip).await,
            };

            match result {
                Ok(()) => {
                    action.executed = true;
                    action.success = Some(true);
                }
                Err(e) => {
                    action.executed = true;
                    action.success = Some(false);
                    action.error_message = Some(e.to_string());
                }
            }

            // Update last action timestamp
            let mut last_action = self.last_action.write().await;
            last_action.insert((target_ip, response_type), Instant::now());

            self.record_action(action.clone()).await;
            Some(action)
        } else {
            // Mode doesn't allow this action
            let mut action = action;
            action.executed = false;
            action.success = Some(false);
            action.error_message = Some(format!(
                "Mode {:?} does not allow {:?}",
                mode, response_type
            ));
            self.record_action(action.clone()).await;
            Some(action)
        };
    }

    /// Record action in history
    async fn record_action(&self, action: ResponseAction) {
        let target_ip = action.target_ip;

        let mut history = self.history.write().await;
        if history.len() >= 1000 {
            history.pop_front();
        }
        history.push_back(action);

        // Also track in active responses
        let mut active = self.active_responses.write().await;
        active
            .entry(target_ip)
            .or_insert_with(Vec::new)
            .push(history.back().unwrap().clone());
    }

    /// Get current response mode
    pub async fn get_mode(&self) -> ResponseMode {
        *self.mode.read().await
    }

    /// Set response mode
    pub async fn set_mode(&self, mode: ResponseMode) {
        let mut current = self.mode.write().await;
        *current = mode;
        tracing::info!("Response mode changed to: {}", mode.as_str());
    }
    /// Send notification about threat
    async fn send_notification(
        &self,
        ip: IpAddr,
        reason: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // In production, this would send to Slack, PagerDuty, email, etc.
        tracing::info!("🔔 SECURITY ALERT: Threat from {} - {}", ip, reason);
        Ok(())
    }

    /// Apply rate limiting to an IP
    async fn apply_rate_limit(
        &self,
        ip: IpAddr,
        max_pps: f64,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut rate_limited = self.rate_limited.write().await;
        rate_limited.insert(
            ip,
            RateLimitState {
                tokens: max_pps,
                last_update: Instant::now(),
                max_rate: max_pps,
            },
        );

        tracing::info!("⏱️  Rate limit applied to {}: {} pps", ip, max_pps);
        Ok(())
    }

    /// Apply IP block (simulated - would integrate with iptables/nftables)
    async fn apply_block(
        &self,
        ip: IpAddr,
        duration: Duration,
        permanent: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut blocked = self.blocked_ips.write().await;
        blocked.insert(ip);

        let block_type = if permanent { "PERMANENT" } else { "TEMPORARY" };
        let duration_str = if permanent {
            "permanent".to_string()
        } else {
            format!("{:?}", duration)
        };

        // In production, this would execute:
        // iptables -A INPUT -s <ip> -j DROP
        // or nftables equivalent
        tracing::warn!(
            "🚫 {} BLOCK applied to {} (duration: {})",
            block_type,
            ip,
            duration_str
        );

        // Spawn cleanup task for temporary blocks
        if !permanent {
            let blocked_ips = self.blocked_ips.clone();
            tokio::spawn(async move {
                tokio::time::sleep(duration).await;
                let mut blocked = blocked_ips.write().await;
                blocked.remove(&ip);
                tracing::info!("🔓 Temporary block expired for {}", ip);
            });
        }

        Ok(())
    }

    /// Kill active connections from/to IP
    async fn kill_connections(&self, ip: IpAddr) -> Result<(), Box<dyn std::error::Error>> {
        // In production, this would:
        // 1. Query conntrack for connections
        // 2. Send RST packets
        // 3. Close socket connections
        tracing::info!("🔌 Connections killed for {}", ip);
        Ok(())
    }

    /// Redirect traffic to honeypot
    async fn redirect_to_honeypot(&self, ip: IpAddr) -> Result<(), Box<dyn std::error::Error>> {
        // In production, this would configure:
        // - iptables DNAT rules
        // - Routing table entries
        tracing::info!("🍯 Traffic from {} redirected to honeypot", ip);
        Ok(())
    }

    /// Check if an IP is currently blocked
    pub async fn is_blocked(&self, ip: IpAddr) -> bool {
        let blocked = self.blocked_ips.read().await;
        blocked.contains(&ip)
    }

    /// Check if an IP is rate limited
    pub async fn is_rate_limited(&self, ip: IpAddr) -> Option<f64> {
        let mut rate_limited = self.rate_limited.write().await;

        if let Some(state) = rate_limited.get_mut(&ip) {
            let now = Instant::now();
            let elapsed = now.duration_since(state.last_update).as_secs_f64();

            // Token bucket refill
            state.tokens = (state.tokens + elapsed * state.max_rate).min(state.max_rate);
            state.last_update = now;

            if state.tokens >= 1.0 {
                state.tokens -= 1.0;
                None // Not limited
            } else {
                Some(0.0) // Limited
            }
        } else {
            None
        }
    }

    /// Suggest appropriate actions for an alert
    pub async fn suggest_actions(&self, alert: &EnrichedAlert) -> Vec<SuggestedAction> {
        let mut suggestions = Vec::new();
        let mode = *self.mode.read().await;

        // Base suggestion based on severity
        let base_actions = match alert.severity {
            Severity::Critical => vec![
                (
                    ResponseType::PermanentBlock,
                    0.95,
                    "Critical severity warrants immediate block",
                ),
                (
                    ResponseType::KillConnections,
                    0.90,
                    "Terminate all active connections",
                ),
                (
                    ResponseType::Notify,
                    0.85,
                    "Alert security team immediately",
                ),
            ],
            Severity::High => vec![
                (
                    ResponseType::TemporaryBlock,
                    0.85,
                    "High severity - temporary containment",
                ),
                (
                    ResponseType::RateLimit,
                    0.80,
                    "Rate limit to prevent escalation",
                ),
                (ResponseType::Notify, 0.75, "Notify security team"),
            ],
            Severity::Medium => vec![
                (
                    ResponseType::RateLimit,
                    0.70,
                    "Medium threat - monitor and limit",
                ),
                (ResponseType::Notify, 0.65, "Log for review"),
            ],
            Severity::Low => vec![(
                ResponseType::LogOnly,
                0.60,
                "Low priority - log and monitor",
            )],
        };

        for (action, confidence, reason) in base_actions {
            suggestions.push(SuggestedAction {
                action,
                reason: reason.to_string(),
                confidence,
                risk_reduction: confidence * 0.8,
                would_execute: mode.allows(&action),
            });
        }

        suggestions
    }

    /// Get active responses
    pub async fn get_active_responses(&self) -> Vec<ResponseAction> {
        let active = self.active_responses.read().await;
        active
            .values()
            .flat_map(|v| v.iter().cloned())
            .filter(|a| a.expires_at.map_or(true, |e| e > Utc::now()))
            .collect()
    }

    /// Get response history
    pub async fn get_history(&self, limit: usize) -> Vec<ResponseAction> {
        let history = self.history.read().await;
        history.iter().rev().take(limit).cloned().collect()
    }

    /// Get engine statistics
    pub async fn get_stats(&self) -> ResponseStats {
        let active = self.active_responses.read().await;
        let history = self.history.read().await;
        let blocked = self.blocked_ips.read().await;

        ResponseStats {
            total_actions: history.len(),
            active_blocks: blocked.len(),
            active_rate_limits: active
                .values()
                .filter(|v| v.iter().any(|a| a.response_type == ResponseType::RateLimit))
                .count(),
            current_mode: *self.mode.read().await,
        }
    }

    /// Unblock an IP
    pub async fn unblock(&self, ip: IpAddr) -> bool {
        let mut blocked = self.blocked_ips.write().await;
        blocked.remove(&ip)
    }
}

/// Response engine statistics
#[derive(Debug, Clone, Serialize)]
pub struct ResponseStats {
    pub total_actions: usize,
    pub active_blocks: usize,
    pub active_rate_limits: usize,
    pub current_mode: ResponseMode,
}

impl Default for ResponseEngine {
    fn default() -> Self {
        Self::new(ResponseMode::Safe)
    }
}
