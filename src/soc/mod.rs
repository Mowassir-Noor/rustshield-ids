//! SOC Integration Layer
//!
//! Orchestrates all detection, correlation, profiling, and response components.
//! Central hub for professional-grade security operations.

use crate::engine::{DetectionEngine, Detector};
use crate::correlator::{CorrelationEngine, CorrelatedAttack};
use crate::profiler::{BehaviorProfiler, BehaviorAnalysis};
use crate::response::{ResponseEngine, ResponseMode, ResponseAction};
use crate::dpi::{DpiEngine, PayloadAnalysis};
use crate::forensics::{ForensicsEngine, ForensicSession, ForensicFilters, ReplayConfig};
use crate::ai_explainer::{AiExplainer, ThreatExplanation};
use crate::models::{EnrichedAlert, PacketInfo, Severity};
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tokio::time::{interval, Duration};
use serde::{Serialize, Deserialize};
use chrono::Utc;
use tracing::{info, warn, error};

/// SOC Engine configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocConfig {
    pub response_mode: ResponseMode,
    pub enable_correlation: bool,
    pub enable_profiling: bool,
    pub enable_dpi: bool,
    pub enable_forensics: bool,
    pub enable_ai_explanation: bool,
    pub auto_response_threshold: Severity,
}

impl Default for SocConfig {
    fn default() -> Self {
        Self {
            response_mode: ResponseMode::Safe,
            enable_correlation: true,
            enable_profiling: true,
            enable_dpi: false, // Disabled by default for performance
            enable_forensics: true,
            enable_ai_explanation: true,
            auto_response_threshold: Severity::High,
        }
    }
}

/// SOC Alert - enriched with all analysis layers
#[derive(Debug, Clone, Serialize)]
pub struct SocAlert {
    pub base_alert: EnrichedAlert,
    pub behavior_analysis: Option<BehaviorAnalysis>,
    pub payload_analysis: Option<PayloadAnalysis>,
    pub ai_explanation: Option<ThreatExplanation>,
    pub correlated_attack: Option<CorrelatedAttack>,
    pub response_actions: Vec<ResponseAction>,
    pub soc_score: f64, // Combined risk score
}

/// SOC Engine - main orchestrator
pub struct SocEngine {
    /// Configuration
    config: Arc<RwLock<SocConfig>>,
    /// Detection engine
    detection: Arc<DetectionEngine>,
    /// Correlation engine
    correlation: Arc<CorrelationEngine>,
    /// Behavior profiler
    profiler: Arc<BehaviorProfiler>,
    /// Response engine
    response: Arc<ResponseEngine>,
    /// DPI engine
    dpi: Arc<DpiEngine>,
    /// Forensics engine
    forensics: Arc<ForensicsEngine>,
    /// AI explainer
    ai_explainer: Arc<AiExplainer>,
    /// Alert channel
    alert_tx: mpsc::Sender<SocAlert>,
    alert_rx: Arc<RwLock<mpsc::Receiver<SocAlert>>>,
}

impl SocEngine {
    pub fn new(config: SocConfig) -> Self {
        let (alert_tx, alert_rx) = mpsc::channel(1000);
        
        Self {
            config: Arc::new(RwLock::new(config.clone())),
            detection: Arc::new(DetectionEngine::new()),
            correlation: Arc::new(CorrelationEngine::new()),
            profiler: Arc::new(BehaviorProfiler::new()),
            response: Arc::new(ResponseEngine::new(config.response_mode)),
            dpi: Arc::new(DpiEngine::new()),
            forensics: Arc::new(ForensicsEngine::new()),
            ai_explainer: Arc::new(AiExplainer::new()),
            alert_tx,
            alert_rx: Arc::new(RwLock::new(alert_rx)),
        }
    }
    
    /// Create with default engine
    pub fn with_defaults() -> Self {
        Self::new(SocConfig::default())
    }
    
    /// Process a single packet through all SOC layers
    pub async fn process_packet(&self, packet: PacketInfo) -> Vec<SocAlert> {
        let mut soc_alerts = Vec::new();
        let config = self.config.read().await.clone();
        
        // 1. Detection layer
        let detection_alerts = self.detection.process_packet(packet.clone()).await;
        
        for alert in detection_alerts {
            // 2. Profiling layer
            let behavior_analysis = if config.enable_profiling {
                self.profiler.process_packet(&packet).await
            } else {
                None
            };
            
            // 3. DPI layer
            let payload_analysis = if config.enable_dpi {
                self.dpi.analyze_packet(&packet).await
            } else {
                None
            };
            
            // 4. Correlation layer
            let correlated_attack = if config.enable_correlation {
                self.correlation.correlate_alert(&alert).await
            } else {
                None
            };
            
            // 5. AI Explanation
            let ai_explanation = if config.enable_ai_explanation {
                Some(self.ai_explainer.explain_alert(&alert).await)
            } else {
                None
            };
            
            // 6. Calculate SOC score
            let soc_score = self.calculate_soc_score(&alert, &behavior_analysis, &correlated_attack);
            
            // 7. Response layer
            let mut response_actions = Vec::new();
            if alert.severity >= config.auto_response_threshold {
                let actions = self.response.process_alert(&alert).await;
                response_actions.extend(actions);
            }
            
            // Also process correlated attack response
            if let Some(ref attack) = correlated_attack {
                let attack_responses = self.response.process_correlated_attack(attack).await;
                response_actions.extend(attack_responses);
            }
            
            let soc_alert = SocAlert {
                base_alert: alert.clone(),
                behavior_analysis,
                payload_analysis,
                ai_explanation,
                correlated_attack,
                response_actions,
                soc_score,
            };
            
            // 8. Store in forensics
            if config.enable_forensics {
                self.forensics.store_alert(alert.clone()).await;
                self.forensics.store_packet(packet.clone()).await;
            }
            
            // 9. Send to alert channel
            let _ = self.alert_tx.send(soc_alert.clone()).await;
            
            soc_alerts.push(soc_alert);
        }
        
        soc_alerts
    }
    
    /// Calculate combined SOC risk score
    fn calculate_soc_score(
        &self,
        alert: &EnrichedAlert,
        behavior: &Option<BehaviorAnalysis>,
        correlation: &Option<CorrelatedAttack>,
    ) -> f64 {
        let mut score = 0.0;
        
        // Base score from detection confidence and severity
        score += alert.detection_result.confidence * 40.0;
        score += match alert.severity {
            Severity::Critical => 30.0,
            Severity::High => 20.0,
            Severity::Medium => 10.0,
            Severity::Low => 5.0,
        };
        
        // Boost from behavioral analysis
        if let Some(ref beh) = behavior {
            score += beh.risk_score * 15.0;
        }
        
        // Major boost from correlation
        if let Some(ref corr) = correlation {
            score += corr.combined_confidence * 15.0;
        }
        
        score.min(100.0)
    }
    
    /// Start background maintenance tasks
    pub async fn start_background_tasks(&self) {
        let correlation = self.correlation.clone();
        let profiler = self.profiler.clone();
        let forensics = self.forensics.clone();
        
        // Periodic cleanup and analysis
        tokio::spawn(async move {
            let mut cleanup_interval = interval(Duration::from_secs(60));
            
            loop {
                cleanup_interval.tick().await;
                
                // Cleanup old correlation chains
                let active = correlation.get_active_attacks().await;
                info!("Active correlated attacks: {}", active.len());
                
                // Update profiler baselines
                let stats = profiler.get_stats().await;
                info!("Profiler stats: {} profiles, {} high-risk", stats.total_profiles, stats.high_risk);
            }
        });
    }
    
    /// Create forensic investigation session
    pub async fn create_forensic_session(
        &self,
        name: String,
        filters: ForensicFilters,
    ) -> ForensicSession {
        self.forensics.create_session(name, filters).await
    }
    
    /// Start replay of historical data
    pub async fn start_replay(&self, config: ReplayConfig) -> crate::forensics::ReplayHandle {
        self.forensics.start_replay(config).await
    }
    
    /// Get executive summary
    pub async fn get_executive_summary(&self) -> String {
        // Get recent alerts from forensics
        let recent_alerts = vec![]; // Would fetch from forensics
        let active_attacks = self.correlation.get_active_attacks().await;
        
        self.ai_explainer.generate_executive_summary(&recent_alerts, &active_attacks).await
    }
    
    /// Update configuration
    pub async fn update_config(&self, new_config: SocConfig) {
        let mut config = self.config.write().await;
        *config = new_config.clone();
        
        // Update response mode
        self.response.set_mode(new_config.response_mode).await;
        
        info!("SOC configuration updated");
    }
    
    /// Get current configuration
    pub async fn get_config(&self) -> SocConfig {
        self.config.read().await.clone()
    }
    
    /// Get response mode
    pub async fn get_response_mode(&self) -> ResponseMode {
        self.response.get_mode().await
    }
    
    /// Set response mode
    pub async fn set_response_mode(&self, mode: ResponseMode) {
        self.response.set_mode(mode).await;
        let mut config = self.config.write().await;
        config.response_mode = mode;
    }
    
    /// Get component statistics
    pub async fn get_stats(&self) -> SocStats {
        SocStats {
            correlation: self.correlation.get_stats().await,
            profiler: self.profiler.get_stats().await,
            response: self.response.get_stats().await,
            forensics: self.forensics.get_stats().await,
            dpi: self.dpi.get_stats().await,
        }
    }
    
    /// Subscribe to alerts
    pub async fn subscribe_alerts(&self) -> mpsc::Receiver<SocAlert> {
        let (tx, rx) = mpsc::channel(100);
        
        let alert_rx = self.alert_rx.clone();
        tokio::spawn(async move {
            let mut alert_rx = alert_rx.write().await;
            while let Some(alert) = alert_rx.recv().await {
                if tx.send(alert).await.is_err() {
                    break;
                }
            }
        });
        
        rx
    }
    
    /// Get high-priority alerts (SOC score > 70)
    pub async fn get_high_priority_alerts(&self, limit: usize) -> Vec<SocAlert> {
        // Would query from forensics with soc_score filter
        vec![]
    }
    
    /// Generate threat intelligence report
    pub async fn generate_threat_report(&self) -> ThreatReport {
        let now = Utc::now();
        let active_attacks = self.correlation.get_active_attacks().await;
        let recent_attacks = self.correlation.get_recent_attacks(50).await;
        
        let mut attack_types = std::collections::HashMap::new();
        for attack in &recent_attacks {
            *attack_types.entry(attack.attack_type.as_str().to_string()).or_insert(0) += 1;
        }
        
        ThreatReport {
            generated_at: now,
            active_threats: active_attacks.len(),
            threats_neutralized: recent_attacks.iter().filter(|a| !a.is_ongoing).count(),
            top_attack_types: attack_types,
            summary: self.get_executive_summary().await,
            recommendations: self.generate_recommendations().await,
        }
    }
    
    /// Generate security recommendations
    async fn generate_recommendations(&self) -> Vec<String> {
        let mut recommendations = Vec::new();
        
        let active_attacks = self.correlation.get_active_attacks().await;
        let stats = self.profiler.get_stats().await;
        
        if !active_attacks.is_empty() {
            recommendations.push("IMMEDIATE: Review and respond to active multi-stage attacks".to_string());
        }
        
        if stats.high_risk > 10 {
            recommendations.push("HIGH: Significant high-risk IP activity - consider network segmentation review".to_string());
        }
        
        recommendations.push("Monitor for escalation from current medium-severity alerts".to_string());
        recommendations.push("Review authentication logs for any successful brute force attempts".to_string());
        
        recommendations
    }
}

/// SOC Statistics
#[derive(Debug, Clone, Serialize)]
pub struct SocStats {
    pub correlation: crate::correlator::CorrelationStats,
    pub profiler: crate::profiler::ProfilerStats,
    pub response: crate::response::ResponseStats,
    pub forensics: crate::forensics::ForensicsStats,
    pub dpi: crate::dpi::DpiStats,
}

/// Threat intelligence report
#[derive(Debug, Clone, Serialize)]
pub struct ThreatReport {
    pub generated_at: chrono::DateTime<Utc>,
    pub active_threats: usize,
    pub threats_neutralized: usize,
    pub top_attack_types: std::collections::HashMap<String, u32>,
    pub summary: String,
    pub recommendations: Vec<String>,
}

/// Builder for SOC Engine
pub struct SocEngineBuilder {
    config: SocConfig,
}

impl SocEngineBuilder {
    pub fn new() -> Self {
        Self {
            config: SocConfig::default(),
        }
    }
    
    pub fn response_mode(mut self, mode: ResponseMode) -> Self {
        self.config.response_mode = mode;
        self
    }
    
    pub fn enable_correlation(mut self, enable: bool) -> Self {
        self.config.enable_correlation = enable;
        self
    }
    
    pub fn enable_profiling(mut self, enable: bool) -> Self {
        self.config.enable_profiling = enable;
        self
    }
    
    pub fn enable_dpi(mut self, enable: bool) -> Self {
        self.config.enable_dpi = enable;
        self
    }
    
    pub fn auto_response_threshold(mut self, severity: Severity) -> Self {
        self.config.auto_response_threshold = severity;
        self
    }
    
    pub fn build(self) -> SocEngine {
        SocEngine::new(self.config)
    }
}

impl Default for SocEngineBuilder {
    fn default() -> Self {
        Self::new()
    }
}
