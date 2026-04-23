//! Detection Engine with AI-assisted analysis
//!
//! Modular detector system for intelligent threat detection

use crate::models::{DetectionResult, EnrichedAlert, PacketInfo, Severity};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::RwLock;

pub mod detectors;
pub use detectors::*;

/// Core trait for all detection modules
#[async_trait::async_trait]
pub trait Detector: Send + Sync {
    /// Name of the detector
    fn name(&self) -> &str;

    /// Process a packet and return detection result
    async fn analyze(&self, packet: &PacketInfo, context: &DetectionContext) -> Option<DetectionResult>;

    /// Confidence threshold (0.0 - 1.0)
    fn threshold(&self) -> f64;
}

/// Detection context passed to all detectors
#[derive(Debug, Clone, Default)]
pub struct DetectionContext {
    /// Recent packets from same source (last N seconds)
    pub source_history: Vec<PacketInfo>,
    /// Recent packets to same destination
    pub dest_history: Vec<PacketInfo>,
    /// Connection state tracking
    pub connection_count: u32,
    /// Time window for analysis
    pub time_window_secs: u64,
}

/// Detection engine that orchestrates all detectors
pub struct DetectionEngine {
    detectors: Vec<Box<dyn Detector>>,
    alert_store: Arc<RwLock<AlertStore>>,
    stats: Arc<RwLock<EngineStats>>,
}

/// Engine statistics
#[derive(Debug, Clone, Default)]
pub struct EngineStats {
    pub packets_processed: u64,
    pub detections_triggered: u64,
    pub detector_stats: HashMap<String, u64>,
}

/// Alert store for aggregation
#[derive(Debug, Clone, Default)]
pub struct AlertStore {
    pub alerts: Vec<EnrichedAlert>,
    pub max_size: usize,
}

impl DetectionEngine {
    pub fn new() -> Self {
        Self {
            detectors: Vec::new(),
            alert_store: Arc::new(RwLock::new(AlertStore {
                alerts: Vec::new(),
                max_size: 1000,
            })),
            stats: Arc::new(RwLock::new(EngineStats::default())),
        }
    }

    pub fn add_detector(&mut self, detector: Box<dyn Detector>) {
        self.detectors.push(detector);
    }

    pub async fn process_packet(&self, packet: PacketInfo) -> Vec<EnrichedAlert> {
        let mut alerts = Vec::new();
        let context = self.build_context(&packet).await;

        for detector in &self.detectors {
            if let Some(result) = detector.analyze(&packet, &context).await {
                if result.detected && result.confidence >= detector.threshold() {
                    let alert = self.create_alert(&packet, &result, detector.name()).await;
                    alerts.push(alert.clone());
                    
                    // Store alert
                    let mut store = self.alert_store.write().await;
                    if store.alerts.len() >= store.max_size {
                        store.alerts.remove(0);
                    }
                    store.alerts.push(alert);

                    // Update stats
                    let mut stats = self.stats.write().await;
                    stats.detections_triggered += 1;
                    *stats.detector_stats.entry(detector.name().to_string()).or_insert(0) += 1;
                }
            }
        }

        // Update packet count
        let mut stats = self.stats.write().await;
        stats.packets_processed += 1;

        alerts
    }

    async fn build_context(&self, _packet: &PacketInfo) -> DetectionContext {
        // In production, this would query recent packet history
        DetectionContext {
            time_window_secs: 60,
            ..Default::default()
        }
    }

    async fn create_alert(
        &self,
        packet: &PacketInfo,
        result: &DetectionResult,
        detector_name: &str,
    ) -> EnrichedAlert {
        use chrono::Utc;
        use uuid::Uuid;

        EnrichedAlert {
            id: format!("ALERT-{}-{}", Utc::now().timestamp_millis(), Uuid::new_v4()),
            timestamp: Utc::now(),
            severity: result.severity,
            alert_type: crate::models::AlertType::RuleBased {
                rule_id: detector_name.to_string(),
                rule_name: result.pattern.clone(),
            },
            source_ip: packet.source_ip,
            destination_ip: packet.destination_ip,
            source_port: packet.source_port,
            destination_port: packet.destination_port,
            protocol: packet.protocol,
            description: result.reason.clone(),
            details: crate::models::AlertDetails {
                triggered_features: result.indicators.clone(),
                feature_deviations: vec![],
                raw_features: None,
                recommendation: format!("Investigate {} from {}", result.pattern, packet.source_ip),
            },
            detection_result: result.clone(),
            score: result.confidence,
        }
    }

    pub async fn get_stats(&self) -> EngineStats {
        self.stats.read().await.clone()
    }

    pub async fn get_recent_alerts(&self, limit: usize) -> Vec<EnrichedAlert> {
        let store = self.alert_store.read().await;
        store.alerts.iter().rev().take(limit).cloned().collect()
    }
}

/// Default engine with all detectors
pub fn create_default_engine() -> DetectionEngine {
    let mut engine = DetectionEngine::new();
    
    engine.add_detector(Box::new(PortScanDetector::new()));
    engine.add_detector(Box::new(BruteForceDetector::new()));
    engine.add_detector(Box::new(AnomalyDetector::new()));
    engine.add_detector(Box::new(DosDetector::new()));
    
    engine
}
