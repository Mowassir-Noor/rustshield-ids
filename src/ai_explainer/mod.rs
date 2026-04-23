//! AI Explanation Layer for RustShield IDS
//!
//! Provides intelligent threat analysis and human-readable explanations.
//! Uses rule-based templates + statistical analysis (lightweight, local).
//! No heavy ML models or cloud APIs required.

use crate::models::{EnrichedAlert, DetectionResult, Severity};
use crate::correlator::{CorrelatedAttack, AttackCategory, AttackStageType};
use crate::profiler::{BehaviorAnalysis, BehaviorType};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};

/// AI-generated threat explanation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatExplanation {
    pub alert_id: String,
    pub timestamp: DateTime<Utc>,
    pub summary: String,
    pub detailed_analysis: String,
    pub threat_assessment: String,
    pub impact_evaluation: String,
    pub recommended_actions: Vec<String>,
    pub confidence: f64,
    pub attack_chain_context: Option<String>,
    pub similar_threats: Vec<String>,
    pub historical_precedent: Option<String>,
}

/// Explanation templates for different attack patterns
#[derive(Debug, Clone)]
struct ExplanationTemplate {
    pattern_keywords: Vec<String>,
    summary_template: String,
    analysis_template: String,
    impact_template: String,
    recommendations: Vec<String>,
}

/// MITRE ATT&CK technique mapping
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreMapping {
    pub technique_id: String,
    pub technique_name: String,
    pub tactic: String,
    pub description: String,
    pub url: String,
}

/// AI Explainer engine
pub struct AiExplainer {
    /// Explanation templates database
    templates: Arc<RwLock<Vec<ExplanationTemplate>>>,
    /// Historical explanation cache
    explanation_cache: Arc<RwLock<HashMap<String, ThreatExplanation>>>,
    /// Alert frequency for prioritization
    alert_frequency: Arc<RwLock<HashMap<String, u32>>>,
    /// Known attack patterns
    known_patterns: Arc<RwLock<Vec<KnownAttackPattern>>>,
}

/// Known attack pattern with historical context
#[derive(Debug, Clone)]
struct KnownAttackPattern {
    name: String,
    indicators: Vec<String>,
    typical_duration_mins: u32,
    escalation_likely: bool,
    related_techniques: Vec<String>,
}

impl AiExplainer {
    pub fn new() -> Self {
        let templates = Self::load_templates();
        let known_patterns = Self::load_known_patterns();
        
        Self {
            templates: Arc::new(RwLock::new(templates)),
            explanation_cache: Arc::new(RwLock::new(HashMap::new())),
            alert_frequency: Arc::new(RwLock::new(HashMap::new())),
            known_patterns: Arc::new(RwLock::new(known_patterns)),
        }
    }
    
    /// Load explanation templates
    fn load_templates() -> Vec<ExplanationTemplate> {
        vec![
            // Port Scan Templates
            ExplanationTemplate {
                pattern_keywords: vec!["port scan".to_string(), "scan".to_string()],
                summary_template: "Port scanning activity detected from {source_ip}".to_string(),
                analysis_template: "The attacker is systematically probing {destination_ip} across {port_count} ports. This is typically the first stage of a multi-stage attack (reconnaissance). The scan pattern suggests {scan_type} scanning technique.".to_string(),
                impact_template: "Information disclosure - attacker is mapping network services and identifying potential entry points. Risk escalation likely if followed by exploitation attempts.".to_string(),
                recommendations: vec![
                    "Review firewall rules and consider port knocking or concealment".to_string(),
                    "Monitor for follow-up attacks from same source IP".to_string(),
                    "Consider implementing rate limiting on connection attempts".to_string(),
                ],
            },
            
            // Brute Force Templates
            ExplanationTemplate {
                pattern_keywords: vec!["brute force".to_string(), "login".to_string(), "authentication".to_string()],
                summary_template: "Brute force attack against {service} service detected".to_string(),
                analysis_template: "Systematic password guessing attempts detected: {attempt_count} failed logins to port {port} from {source_ip}. Attack pattern shows {pattern_type} technique with {confidence}% confidence.".to_string(),
                impact_template: "Account compromise risk. Successful authentication would grant attacker access to {service} service. Credential stuffing attack possible if using leaked passwords.".to_string(),
                recommendations: vec![
                    "Implement account lockout policy after failed attempts".to_string(),
                    "Enable multi-factor authentication immediately".to_string(),
                    "Block source IP at firewall if attack persists".to_string(),
                    "Review authentication logs for this service".to_string(),
                ],
            },
            
            // SYN Flood / DoS Templates
            ExplanationTemplate {
                pattern_keywords: vec!["syn flood".to_string(), "dos".to_string(), "flood".to_string()],
                summary_template: "Denial of Service attack: {attack_type} from {source_ip}".to_string(),
                analysis_template: "High volume SYN packet flood detected: {packet_count} SYN packets to port {port} in {time_window}s. Source IP may be spoofed or part of botnet. Connection table exhaustion likely.".to_string(),
                impact_template: "Service availability impact. Target service may become unresponsive. Legitimate users unable to connect. Amplification possible if reflected attack.".to_string(),
                recommendations: vec![
                    "Enable SYN cookies on target system immediately".to_string(),
                    "Implement rate limiting at network edge".to_string(),
                    "Consider upstream DDoS mitigation service".to_string(),
                    "Monitor connection table utilization".to_string(),
                ],
            },
            
            // Anomaly Templates
            ExplanationTemplate {
                pattern_keywords: vec!["anomaly".to_string(), "unusual".to_string(), "deviation".to_string()],
                summary_template: "Anomalous traffic pattern detected from {source_ip}".to_string(),
                analysis_template: "Statistical deviation detected: {deviation_details}. Traffic characteristics diverge {deviation_percent}% from established baseline. Pattern suggests {likely_cause}.".to_string(),
                impact_template: "Unknown impact - anomalous behavior may indicate novel attack vector, malware communication, or policy violation. Requires investigation.".to_string(),
                recommendations: vec![
                    "Capture and analyze full packet payload".to_string(),
                    "Cross-reference with threat intelligence feeds".to_string(),
                    "Review endpoint security on source system".to_string(),
                    "Consider network segmentation verification".to_string(),
                ],
            },
            
            // Multi-Stage Attack Templates
            ExplanationTemplate {
                pattern_keywords: vec!["multi-stage".to_string(), "correlated".to_string(), "kill chain".to_string()],
                summary_template: "Multi-stage attack campaign detected from {source_ip}".to_string(),
                analysis_template: "Sophisticated attack progression detected across {stage_count} stages: {stage_sequence}. This represents a complete kill chain execution. Attacker has demonstrated persistence and escalation capability.".to_string(),
                impact_template: "CRITICAL: Full system compromise possible. Attack has progressed through multiple phases. Immediate containment required. Assume breach mentality.".to_string(),
                recommendations: vec![
                    "ISOLATE affected systems immediately".to_string(),
                    "Initiate incident response procedure".to_string(),
                    "Capture forensic images before remediation".to_string(),
                    "Review all systems accessed by this IP".to_string(),
                    "Check for persistence mechanisms (cron, services, registry)".to_string(),
                ],
            },
        ]
    }
    
    /// Load known attack patterns
    fn load_known_patterns() -> Vec<KnownAttackPattern> {
        vec![
            KnownAttackPattern {
                name: "Reconnaissance → Exploitation".to_string(),
                indicators: vec!["scan".to_string(), "exploit".to_string()],
                typical_duration_mins: 30,
                escalation_likely: true,
                related_techniques: vec!["T1046".to_string(), "T1190".to_string()],
            },
            KnownAttackPattern {
                name: "Credential Brute Force".to_string(),
                indicators: vec!["brute".to_string(), "login".to_string()],
                typical_duration_mins: 60,
                escalation_likely: true,
                related_techniques: vec!["T1110".to_string(), "T1110.001".to_string()],
            },
            KnownAttackPattern {
                name: "DoS Campaign".to_string(),
                indicators: vec!["flood".to_string(), "dos".to_string()],
                typical_duration_mins: 120,
                escalation_likely: false,
                related_techniques: vec!["T1498".to_string(), "T1499".to_string()],
            },
        ]
    }
    
    /// Generate explanation for a single alert
    pub async fn explain_alert(&self, alert: &EnrichedAlert) -> ThreatExplanation {
        let cache_key = alert.id.clone();
        
        // Check cache
        {
            let cache = self.explanation_cache.read().await;
            if let Some(explanation) = cache.get(&cache_key) {
                return explanation.clone();
            }
        }
        
        // Update frequency counter
        {
            let mut freq = self.alert_frequency.write().await;
            let pattern = alert.detection_result.pattern.clone();
            *freq.entry(pattern).or_insert(0) += 1;
        }
        
        // Find matching template
        let template = self.find_template(&alert.detection_result.pattern).await;
        
        // Generate explanation
        let explanation = self.generate_explanation(alert, &template).await;
        
        // Cache result
        {
            let mut cache = self.explanation_cache.write().await;
            cache.insert(cache_key, explanation.clone());
        }
        
        explanation
    }
    
    /// Generate explanation for correlated attack
    pub async fn explain_correlated_attack(&self, attack: &CorrelatedAttack) -> ThreatExplanation {
        let stage_names: Vec<_> = attack.stages.iter()
            .map(|s| s.stage_type.as_str())
            .collect();
        
        let stage_sequence = stage_names.join(" → ");
        
        let summary = format!(
            "{} campaign from {}: {} stages detected",
            attack.attack_type.as_str(),
            attack.attacker_ip,
            attack.stages.len()
        );
        
        let detailed_analysis = format!(
            "Multi-stage attack progression through kill chain:\n{}\n\nCombined confidence: {:.0}%\nAffected ports: {}\nDuration: {:.1} minutes",
            stage_sequence,
            attack.combined_confidence * 100.0,
            attack.affected_ports.len(),
            (attack.end_time - attack.start_time).num_seconds() as f64 / 60.0
        );
        
        let impact = match attack.attack_type {
            crate::correlator::AttackCategory::MultiStageIntrusion => 
                "CRITICAL: Complete system compromise possible. Attack demonstrates sophisticated adversary with kill chain execution capability.".to_string(),
            crate::correlator::AttackCategory::RansomwareCampaign =>
                "CRITICAL: Ransomware deployment likely. Immediate isolation required.".to_string(),
            crate::correlator::AttackCategory::DataExfiltration =>
                "HIGH: Data theft in progress. Sensitive data may have been accessed.".to_string(),
            crate::correlator::AttackCategory::DoSCampaign =>
                "MEDIUM: Service availability impact. No data compromise indicated.".to_string(),
            _ => "Unknown impact - requires investigation".to_string(),
        };
        
        let recommendations = vec![
            "ISOLATE affected systems immediately".to_string(),
            "Block attacker IP at network perimeter".to_string(),
            "Initiate incident response".to_string(),
            "Capture forensic evidence".to_string(),
        ];
        
        ThreatExplanation {
            alert_id: attack.id.clone(),
            timestamp: Utc::now(),
            summary,
            detailed_analysis,
            threat_assessment: attack.summary.clone(),
            impact_evaluation: impact,
            recommended_actions: recommendations,
            confidence: attack.combined_confidence,
            attack_chain_context: Some(stage_sequence),
            similar_threats: self.find_similar_patterns(&attack.attack_type.to_string()).await,
            historical_precedent: self.check_historical_precedent(&attack.attack_type.to_string()).await,
        }
    }
    
    /// Explain behavior analysis
    pub async fn explain_behavior(&self, analysis: &BehaviorAnalysis) -> String {
        if analysis.flags.is_empty() {
            return "Normal behavior within established baseline".to_string();
        }
        
        let mut explanations = Vec::new();
        
        for flag in &analysis.flags {
            let explanation = match flag.flag_type {
                BehaviorType::NewIp => format!(
                    "First-time contact from {}. Risk Score: {:.0}% - Monitor for additional suspicious activity.",
                    analysis.ip,
                    analysis.risk_score * 100.0
                ),
                BehaviorType::TrafficSpike => format!(
                    "Traffic volume anomaly: {}. Deviation: {:.1} standard deviations above baseline.",
                    flag.description,
                    analysis.z_scores.get("pps").unwrap_or(&0.0)
                ),
                BehaviorType::PortScanBehavior => format!(
                    "Port scanning behavior detected: {}. This may indicate reconnaissance activity.",
                    flag.description
                ),
                _ => flag.description.clone(),
            };
            explanations.push(explanation);
        }
        
        format!(
            "Behavioral Analysis for {}:\n{}\n\nOverall Risk: {:.0}%\nRecommendation: {}",
            analysis.ip,
            explanations.join("\n"),
            analysis.risk_score * 100.0,
            analysis.recommendation
        )
    }
    
    /// Find matching template
    async fn find_template(&self, pattern: &str) -> ExplanationTemplate {
        let templates = self.templates.read().await;
        let pattern_lower = pattern.to_lowercase();
        
        templates.iter()
            .find(|t| t.pattern_keywords.iter().any(|kw| pattern_lower.contains(kw)))
            .cloned()
            .unwrap_or_else(|| ExplanationTemplate {
                pattern_keywords: vec![],
                summary_template: "Suspicious activity detected from {source_ip}".to_string(),
                analysis_template: "Pattern '{pattern}' detected with {confidence}% confidence.".to_string(),
                impact_template: "Unknown - requires investigation".to_string(),
                recommendations: vec![
                    "Monitor source IP for additional activity".to_string(),
                    "Review related alerts for context".to_string(),
                ],
            })
    }
    
    /// Generate full explanation
    async fn generate_explanation(
        &self,
        alert: &EnrichedAlert,
        template: &ExplanationTemplate,
    ) -> ThreatExplanation {
        let dr = &alert.detection_result;
        
        // Fill in template variables
        let summary = template.summary_template
            .replace("{source_ip}", &alert.source_ip.to_string());
        
        let analysis = template.analysis_template
            .replace("{source_ip}", &alert.source_ip.to_string())
            .replace("{destination_ip}", &alert.destination_ip.to_string())
            .replace("{port}", &alert.destination_port.map_or("unknown".to_string(), |p| p.to_string()))
            .replace("{pattern}", &dr.pattern)
            .replace("{confidence}", &format!("{:.0}", dr.confidence * 100.0));
        
        let impact = template.impact_template.clone();
        
        // Calculate threat priority
        let priority_score = self.calculate_priority(alert).await;
        
        ThreatExplanation {
            alert_id: alert.id.clone(),
            timestamp: Utc::now(),
            summary,
            detailed_analysis: analysis,
            threat_assessment: format!("Severity: {:?} | Priority Score: {:.0}/100", alert.severity, priority_score),
            impact_evaluation: impact,
            recommended_actions: template.recommendations.clone(),
            confidence: dr.confidence,
            attack_chain_context: None,
            similar_threats: self.find_similar_patterns(&dr.pattern).await,
            historical_precedent: self.check_historical_precedent(&dr.pattern).await,
        }
    }
    
    /// Calculate threat priority score
    async fn calculate_priority(&self, alert: &EnrichedAlert) -> f64 {
        let mut score = 0.0;
        
        // Base score from severity
        score += match alert.severity {
            Severity::Critical => 40.0,
            Severity::High => 30.0,
            Severity::Medium => 20.0,
            Severity::Low => 10.0,
        };
        
        // Boost for confidence
        score += alert.detection_result.confidence * 30.0;
        
        // Boost for multiple indicators
        score += (alert.detection_result.indicators.len() as f64 * 5.0).min(20.0);
        
        // Frequency penalty (lower priority if we see it constantly)
        let freq = self.alert_frequency.read().await;
        if let Some(count) = freq.get(&alert.detection_result.pattern) {
            if *count > 100 {
                score *= 0.8; // Reduce priority for frequent alerts
            }
        }
        
        score.min(100.0)
    }
    
    /// Find similar attack patterns
    async fn find_similar_patterns(&self, pattern: &str) -> Vec<String> {
        let patterns = self.known_patterns.read().await;
        let pattern_lower = pattern.to_lowercase();
        
        patterns.iter()
            .filter(|p| p.indicators.iter().any(|i| pattern_lower.contains(i)))
            .map(|p| p.name.clone())
            .collect()
    }
    
    /// Check for historical precedent
    async fn check_historical_precedent(&self, pattern: &str) -> Option<String> {
        let freq = self.alert_frequency.read().await;
        let count = freq.get(pattern).copied().unwrap_or(0);
        
        if count > 50 {
            Some(format!("This pattern has been observed {} times previously", count))
        } else {
            None
        }
    }
    
    /// Get MITRE ATT&CK mapping for alert
    pub async fn get_mitre_mapping(&self, alert: &EnrichedAlert) -> Vec<MitreMapping> {
        let mut mappings = Vec::new();
        let pattern_lower = alert.detection_result.pattern.to_lowercase();
        
        // Port scanning
        if pattern_lower.contains("scan") {
            mappings.push(MitreMapping {
                technique_id: "T1046".to_string(),
                technique_name: "Network Service Scanning".to_string(),
                tactic: "Discovery".to_string(),
                description: "Adversaries may attempt to get a listing of services running on remote hosts".to_string(),
                url: "https://attack.mitre.org/techniques/T1046/".to_string(),
            });
        }
        
        // Brute force
        if pattern_lower.contains("brute") || pattern_lower.contains("login") {
            mappings.push(MitreMapping {
                technique_id: "T1110".to_string(),
                technique_name: "Brute Force".to_string(),
                tactic: "Credential Access".to_string(),
                description: "Adversaries may use brute force techniques to gain access to accounts".to_string(),
                url: "https://attack.mitre.org/techniques/T1110/".to_string(),
            });
        }
        
        // DoS
        if pattern_lower.contains("flood") || pattern_lower.contains("dos") {
            mappings.push(MitreMapping {
                technique_id: "T1499".to_string(),
                technique_name: "Endpoint Denial of Service".to_string(),
                tactic: "Impact".to_string(),
                description: "Adversaries may perform endpoint denial of service".to_string(),
                url: "https://attack.mitre.org/techniques/T1499/".to_string(),
            });
        }
        
        mappings
    }
    
    /// Generate executive summary
    pub async fn generate_executive_summary(
        &self,
        alerts: &[EnrichedAlert],
        attacks: &[CorrelatedAttack],
    ) -> String {
        let total_alerts = alerts.len();
        let critical_count = alerts.iter().filter(|a| a.severity == Severity::Critical).count();
        let high_count = alerts.iter().filter(|a| a.severity == Severity::High).count();
        
        let mut summary = format!(
            "Security Posture Summary ({} alerts, {} critical, {} high)\n\n",
            total_alerts, critical_count, high_count
        );
        
        if !attacks.is_empty() {
            summary.push_str("Active Multi-Stage Attacks:\n");
            for attack in attacks.iter().take(3) {
                summary.push_str(&format!(
                    "  • {} from {} ({:.0}% confidence)\n",
                    attack.attack_type.as_str(),
                    attack.attacker_ip,
                    attack.combined_confidence * 100.0
                ));
            }
            summary.push('\n');
        }
        
        // Top threat patterns
        let mut pattern_counts: HashMap<String, u32> = HashMap::new();
        for alert in alerts {
            *pattern_counts.entry(alert.detection_result.pattern.clone()).or_insert(0) += 1;
        }
        
        let mut sorted_patterns: Vec<_> = pattern_counts.iter().collect();
        sorted_patterns.sort_by(|a, b| b.1.cmp(a.1));
        
        summary.push_str("Top Threat Patterns:\n");
        for (pattern, count) in sorted_patterns.iter().take(5) {
            summary.push_str(&format!("  • {}: {} occurrences\n", pattern, count));
        }
        
        summary.push_str(&format!(
            "\nRecommendation: {}",
            if critical_count > 0 {
                "IMMEDIATE ACTION REQUIRED - Critical threats detected"
            } else if high_count > 5 {
                "Priority review recommended - Multiple high-severity alerts"
            } else {
                "Standard monitoring - No immediate action required"
            }
        ));
        
        summary
    }
    
    /// Clear explanation cache
    pub async fn clear_cache(&self) {
        let mut cache = self.explanation_cache.write().await;
        cache.clear();
    }
}

impl Default for AiExplainer {
    fn default() -> Self {
        Self::new()
    }
}
