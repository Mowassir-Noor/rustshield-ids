use crate::ai::{AnomalyDetector, FeatureAggregator};
use crate::capture::PacketCapture;
use crate::config::Config;
use crate::detection::DetectionEngine;
use crate::logging::AlertStats;
use crate::logging::{AlertAggregator, AlertLogger};
use crate::models::{Alert, Severity};
use anyhow::Result;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, RwLock};
use tokio::time::interval;
use tracing::{error, info, warn};

/// Run the IDS in monitoring mode
pub async fn run_monitoring(config: Config, interface: String) -> Result<()> {
    info!("Starting monitoring mode on interface: {}", interface);

    let config = Arc::new(config);
    let (packet_tx, mut packet_rx) =
        mpsc::channel::<crate::models::PacketInfo>(config.general.max_packet_queue);
    let (alert_tx, mut alert_rx) = mpsc::channel::<Alert>(1000);

    // Initialize components
    let packet_capture = PacketCapture::new(config.clone(), packet_tx);
    let detection_engine = Arc::new(DetectionEngine::new(config.clone())?);
    let alert_logger = Arc::new(AlertLogger::new(Arc::new(config.logging.clone())).await?);

    let mut anomaly_detector = AnomalyDetector::new(config.clone());
    let model_path = std::path::Path::new(&config.ai.model_path);
    anomaly_detector.load_model(model_path)?;

    // Alert aggregator for deduplication
    let alert_aggregator = Arc::new(RwLock::new(AlertAggregator::new(
        config.alerting.deduplication_window_secs,
        config.alerting.rate_limit_per_minute,
    )));

    // Start packet capture
    packet_capture.start_capture(interface).await?;

    // Feature aggregator for anomaly detection
    let mut feature_aggregator = FeatureAggregator::new(config.ai.feature_window_secs);
    let mut last_feature_extraction = tokio::time::Instant::now();

    // Spawn alert processing task
    let alert_logger_clone = alert_logger.clone();
    let alert_aggregator_clone = alert_aggregator.clone();
    let min_severity = config.alerting.min_severity.clone();

    tokio::spawn(async move {
        while let Some(alert) = alert_rx.recv().await {
            // Check severity threshold
            let should_log = match (alert.severity, min_severity.as_str()) {
                (Severity::Critical, _) => true,
                (Severity::High, "CRITICAL") => false,
                (Severity::High, _) => true,
                (Severity::Medium, "CRITICAL") | (Severity::Medium, "HIGH") => false,
                (Severity::Medium, _) => true,
                (Severity::Low, "LOW") => true,
                _ => false,
            };

            if !should_log {
                continue;
            }

            // Check for suppression
            let suppress = {
                let mut aggregator = alert_aggregator_clone.write().await;
                aggregator.should_suppress(&alert)
            };

            if suppress {
                continue;
            }

            // Log the alert
            if let Err(e) = alert_logger_clone.log_alert(&alert).await {
                error!("Failed to log alert: {}", e);
            }
        }
    });

    // Main processing loop
    info!("IDS is now monitoring. Press Ctrl+C to stop.");

    let stats = AlertStats::default();
    let stats_interval = interval(Duration::from_secs(60));
    tokio::pin!(stats_interval);

    loop {
        tokio::select! {
            Some(packet) = packet_rx.recv() => {
                // Add to feature aggregator
                feature_aggregator.add_packet(&packet);

                // Rule-based detection
                let alerts = detection_engine.process_packet(&packet).await;
                for alert in alerts {
                    if let Err(e) = alert_tx.send(alert).await {
                        warn!("Failed to send alert: {}", e);
                    }
                }

                // Periodic anomaly detection
                let now = tokio::time::Instant::now();
                if now.duration_since(last_feature_extraction).as_secs() >= config.ai.feature_window_secs {
                    if let Some(features) = feature_aggregator.extract_features() {
                        let (anomaly_score, deviations) = anomaly_detector.detect(&features);

                        if anomaly_score >= config.ai.anomaly_threshold {
                            if let Some(alert) = detection_engine.analyze_traffic_features(
                                &features,
                                anomaly_score,
                                deviations
                            ).await {
                                if let Err(e) = alert_tx.send(alert).await {
                                    warn!("Failed to send anomaly alert: {}", e);
                                }
                            }
                        }
                    }
                    last_feature_extraction = now;
                }
            }
            _ = stats_interval.tick() => {
                let count = alert_logger.get_alert_count().await;
                info!("Stats: {} alerts logged", count);
            }
            else => break,
        }
    }

    Ok(())
}

/// Analyze a PCAP file and generate a report
pub async fn analyze_pcap(
    config: Config,
    pcap_file: std::path::PathBuf,
    output: Option<std::path::PathBuf>,
) -> Result<()> {
    info!("Analyzing PCAP file: {:?}", pcap_file);

    let config = Arc::new(config);
    let (packet_tx, mut packet_rx) = mpsc::channel::<crate::models::PacketInfo>(10000);
    let (alert_tx, mut alert_rx) = mpsc::channel::<Alert>(1000);

    // Initialize components
    let packet_capture = PacketCapture::new(config.clone(), packet_tx);
    let detection_engine = Arc::new(DetectionEngine::new(config.clone())?);

    let mut anomaly_detector = AnomalyDetector::new(config.clone());
    let model_path = std::path::Path::new(&config.ai.model_path);
    anomaly_detector.load_model(model_path)?;

    // Collect alerts
    let all_alerts = Arc::new(RwLock::new(Vec::new()));
    let all_alerts_clone = all_alerts.clone();

    tokio::spawn(async move {
        while let Some(alert) = alert_rx.recv().await {
            all_alerts_clone.write().await.push(alert);
        }
    });

    // Read PCAP file
    packet_capture
        .capture_from_pcap(pcap_file.to_str().unwrap())
        .await?;

    // Process all packets
    let mut feature_aggregator = FeatureAggregator::new(30);
    let mut packet_count = 0;

    while let Some(packet) = packet_rx.recv().await {
        packet_count += 1;
        feature_aggregator.add_packet(&packet);

        // Rule-based detection
        let alerts = detection_engine.process_packet(&packet).await;
        for alert in alerts {
            let _ = alert_tx.send(alert).await;
        }

        // Periodic anomaly detection
        if packet_count % 100 == 0 {
            if let Some(features) = feature_aggregator.extract_features() {
                let (anomaly_score, deviations) = anomaly_detector.detect(&features);

                if anomaly_score >= config.ai.anomaly_threshold {
                    if let Some(alert) = detection_engine
                        .analyze_traffic_features(&features, anomaly_score, deviations)
                        .await
                    {
                        let _ = alert_tx.send(alert).await;
                    }
                }
            }
        }
    }

    // Drop sender to close channel
    drop(alert_tx);

    // Wait for alert processing
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Generate report
    let alerts = all_alerts.read().await.clone();
    generate_analysis_report(&alerts, packet_count, output).await?;

    Ok(())
}

async fn generate_analysis_report(
    alerts: &[Alert],
    packet_count: usize,
    output: Option<std::path::PathBuf>,
) -> Result<()> {
    let severity_breakdown = serde_json::json!({
        "critical": alerts.iter().filter(|a| matches!(a.severity, Severity::Critical)).count(),
        "high": alerts.iter().filter(|a| matches!(a.severity, Severity::High)).count(),
        "medium": alerts.iter().filter(|a| matches!(a.severity, Severity::Medium)).count(),
        "low": alerts.iter().filter(|a| matches!(a.severity, Severity::Low)).count(),
    });

    let alerts_json: Vec<serde_json::Value> = alerts
        .iter()
        .map(|a| {
            serde_json::json!({
                "id": a.id.clone(),
                "timestamp": a.timestamp.to_rfc3339(),
                "severity": a.severity.to_string(),
                "description": a.description.clone(),
                "score": a.score,
            })
        })
        .collect();

    let report = serde_json::json!({
        "analysis_timestamp": chrono::Utc::now().to_rfc3339(),
        "total_packets": packet_count,
        "total_alerts": alerts.len(),
        "severity_breakdown": severity_breakdown,
        "alerts": alerts_json,
    });

    let report_json = serde_json::to_string_pretty(&report)?;

    if let Some(path) = output {
        tokio::fs::write(&path, report_json).await?;
        println!("Analysis report saved to: {:?}", path);
    } else {
        println!("{}", report_json);
    }

    Ok(())
}
