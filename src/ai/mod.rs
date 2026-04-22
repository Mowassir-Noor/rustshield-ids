use crate::config::Config;
use crate::models::{FeatureDeviation, TrafficFeatures};
use crate::utils::{calculate_entropy, std_deviation};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use tracing::{info, warn};

/// Anomaly detection using Isolation Forest-inspired algorithm
pub struct AnomalyDetector {
    config: Arc<Config>,
    model: Option<IsolationForestModel>,
    baseline_stats: Option<BaselineStats>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct IsolationForestModel {
    trees: Vec<IsolationTree>,
    contamination: f64,
    n_samples: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct IsolationTree {
    split_features: Vec<usize>,
    split_values: Vec<f64>,
    tree_depth: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BaselineStats {
    feature_means: Vec<f64>,
    feature_stds: Vec<f64>,
    feature_mins: Vec<f64>,
    feature_maxs: Vec<f64>,
    sample_count: usize,
}

/// Window-based feature aggregator for real-time analysis
pub struct FeatureAggregator {
    window_secs: u64,
    packets: Vec<(std::time::Instant, PacketInfo)>,
}

#[derive(Debug, Clone)]
struct PacketInfo {
    source_ip: IpAddr,
    dest_ip: IpAddr,
    source_port: Option<u16>,
    dest_port: Option<u16>,
    protocol: u8,
    size_bytes: usize,
    flags: Option<u8>,
}

impl FeatureAggregator {
    pub fn new(window_secs: u64) -> Self {
        Self {
            window_secs,
            packets: Vec::new(),
        }
    }

    pub fn add_packet(&mut self, packet: &crate::models::PacketInfo) {
        let now = std::time::Instant::now();
        
        // Remove old packets outside the window
        let window = std::time::Duration::from_secs(self.window_secs);
        self.packets.retain(|(t, _)| now.duration_since(*t) < window);
        
        // Add new packet
        self.packets.push((now, PacketInfo {
            source_ip: packet.source_ip,
            dest_ip: packet.destination_ip,
            source_port: packet.source_port,
            dest_port: packet.destination_port,
            protocol: match packet.protocol {
                crate::models::Protocol::Tcp => 6,
                crate::models::Protocol::Udp => 17,
                crate::models::Protocol::Icmp => 1,
                crate::models::Protocol::Other(n) => n,
            },
            size_bytes: packet.size_bytes,
            flags: packet.flags,
        }));
    }

    pub fn extract_features(&mut self) -> Option<TrafficFeatures> {
        let now = std::time::Instant::now();
        let window = std::time::Duration::from_secs(self.window_secs);
        
        // Clean old packets
        self.packets.retain(|(t, _)| now.duration_since(*t) < window);
        
        if self.packets.is_empty() {
            return None;
        }

        let packets: Vec<_> = self.packets.iter().map(|(_, p)| p).collect();
        
        // Calculate features
        let connection_count = self.count_unique_flows(&packets);
        let packet_count = packets.len() as u32;
        
        let sizes: Vec<f64> = packets.iter().map(|p| p.size_bytes as f64).collect();
        let avg_packet_size = sizes.iter().sum::<f64>() / sizes.len() as f64;
        let std_packet_size = std_deviation(&sizes);
        
        let unique_ports = packets.iter()
            .filter_map(|p| p.dest_port)
            .collect::<HashSet<_>>()
            .len() as u16;
        
        let unique_destinations = packets.iter()
            .map(|p| p.dest_ip)
            .collect::<HashSet<_>>()
            .len() as u32;
        
        let time_window = self.window_secs as f64;
        let bytes_per_second: f64 = sizes.iter().sum::<f64>() / time_window;
        let packets_per_second = packet_count as f64 / time_window;
        
        // TCP flag analysis
        let (syn_count, fin_count, rst_count) = packets.iter()
            .filter(|p| p.flags.is_some())
            .fold((0u32, 0u32, 0u32), |(syn, fin, rst), p| {
                let flags = p.flags.unwrap();
                (
                    syn + ((flags & 0x02) != 0) as u32,
                    fin + ((flags & 0x01) != 0) as u32,
                    rst + ((flags & 0x04) != 0) as u32,
                )
            });
        
        let tcp_count = packets.iter().filter(|p| p.protocol == 6).count() as f64;
        let syn_ratio = if tcp_count > 0.0 { syn_count as f64 / tcp_count } else { 0.0 };
        let fin_ratio = if tcp_count > 0.0 { fin_count as f64 / tcp_count } else { 0.0 };
        let rst_ratio = if tcp_count > 0.0 { rst_count as f64 / tcp_count } else { 0.0 };
        
        // Port entropy
        let ports: Vec<u16> = packets.iter()
            .filter_map(|p| p.dest_port)
            .collect();
        let port_entropy = calculate_entropy(&ports);
        
        Some(TrafficFeatures {
            connection_count,
            packet_count,
            avg_packet_size,
            std_packet_size,
            unique_ports,
            unique_destinations,
            bytes_per_second,
            packets_per_second,
            syn_ratio,
            fin_ratio,
            rst_ratio,
            port_entropy,
            time_window_secs: self.window_secs,
        })
    }

    fn count_unique_flows(&self, packets: &[&PacketInfo]) -> u32 {
        let mut flows = HashSet::new();
        for p in packets {
            flows.insert((p.source_ip, p.dest_ip, p.dest_port));
        }
        flows.len() as u32
    }
}

impl AnomalyDetector {
    pub fn new(config: Arc<Config>) -> Self {
        Self {
            config,
            model: None,
            baseline_stats: None,
        }
    }

    pub fn load_model(&mut self, path: &Path) -> Result<()> {
        if !path.exists() {
            warn!("Model file not found at {:?}, using untrained detector", path);
            return Ok(());
        }

        let data = std::fs::read(path)?;
        let model: IsolationForestModel = bincode::deserialize(&data)
            .map_err(|e| anyhow::anyhow!("Failed to deserialize model: {}", e))?;
        
        self.model = Some(model);
        info!("Loaded anomaly detection model from {:?}", path);
        
        Ok(())
    }

    pub fn save_model(&self, path: &Path) -> Result<()> {
        if let Some(ref model) = self.model {
            let data = bincode::serialize(model)
                .map_err(|e| anyhow::anyhow!("Failed to serialize model: {}", e))?;
            std::fs::write(path, data)?;
            info!("Saved anomaly detection model to {:?}", path);
        }
        Ok(())
    }

    /// Detect anomalies in traffic features
    pub fn detect(&self, features: &TrafficFeatures) -> (f64, Vec<FeatureDeviation>) {
        let feature_vec = features.to_feature_vector();
        
        // If no model, use simple statistical thresholding
        if self.model.is_none() || self.baseline_stats.is_none() {
            return self.statistical_detection(&feature_vec);
        }

        let model = self.model.as_ref().unwrap();
        let stats = self.baseline_stats.as_ref().unwrap();
        
        // Calculate anomaly score using isolation forest approach
        let score = self.calculate_isolation_score(&feature_vec, model);
        
        // Calculate feature deviations
        let deviations = self.calculate_deviations(&feature_vec, stats);
        
        (score, deviations)
    }

    fn statistical_detection(&self, features: &[f64]) -> (f64, Vec<FeatureDeviation>) {
        // Simple z-score based detection when no model is available
        let deviations: Vec<FeatureDeviation> = features.iter().enumerate()
            .filter(|(_, &v)| v > 100.0) // Simple threshold
            .map(|(idx, &v)| FeatureDeviation {
                feature_name: format!("feature_{}", idx),
                expected_value: 50.0,
                actual_value: v,
                deviation_score: v / 50.0,
                explanation: format!("Value {} is above threshold 100", v),
            })
            .collect();
        
        let score = if deviations.is_empty() { 0.0 } else { 0.5 };
        (score, deviations)
    }

    fn calculate_isolation_score(&self, features: &[f64], model: &IsolationForestModel) -> f64 {
        // Simplified isolation score calculation
        // In a full implementation, this would traverse the trees
        let avg_depth = model.trees.len() as f64;
        let normalized_score = 1.0 - (-avg_depth / model.n_samples as f64).exp();
        
        // Use feature vector to influence score
        let feature_sum: f64 = features.iter().sum();
        let feature_penalty = (feature_sum / 1000.0).min(0.5);
        
        (normalized_score * 0.5 + feature_penalty).min(1.0)
    }

    fn calculate_deviations(&self, features: &[f64], stats: &BaselineStats) -> Vec<FeatureDeviation> {
        let feature_names = [
            "connection_count",
            "packet_count", 
            "avg_packet_size",
            "std_packet_size",
            "unique_ports",
            "unique_destinations",
            "bytes_per_second",
            "packets_per_second",
            "syn_ratio",
            "fin_ratio",
            "rst_ratio",
            "port_entropy",
        ];

        features.iter().enumerate()
            .map(|(idx, &value)| {
                let mean = stats.feature_means.get(idx).copied().unwrap_or(0.0);
                let std = stats.feature_stds.get(idx).copied().unwrap_or(1.0);
                let z_score = (value - mean) / std.max(0.001);
                
                FeatureDeviation {
                    feature_name: feature_names.get(idx).copied().unwrap_or("unknown").to_string(),
                    expected_value: mean,
                    actual_value: value,
                    deviation_score: z_score.abs(),
                    explanation: self.explain_deviation(feature_names.get(idx).copied().unwrap_or("unknown"), z_score),
                }
            })
            .filter(|d| d.deviation_score > 2.0) // Only significant deviations
            .collect()
    }

    fn explain_deviation(&self, feature_name: &str, z_score: f64) -> String {
        let direction = if z_score > 0.0 { "higher" } else { "lower" };
        
        match feature_name {
            "connection_count" => format!("Connection frequency is {} than baseline", direction),
            "packet_count" => format!("Packet volume is {} than expected", direction),
            "avg_packet_size" => format!("Average packet size is {} than typical", direction),
            "bytes_per_second" => format!("Bandwidth usage is {} than baseline", direction),
            "packets_per_second" => format!("Traffic rate is {} than normal", direction),
            "unique_ports" => "Scanning behavior detected".to_string(),
            "port_entropy" => "Unusual port distribution".to_string(),
            "syn_ratio" => "High proportion of SYN packets (possible scan/flood)".to_string(),
            "rst_ratio" => "High connection reset rate".to_string(),
            _ => format!("Value is {} than expected", direction),
        }
    }
}

/// Train a baseline model on normal traffic
pub async fn train_baseline_model(
    config: &Config,
    data_file: Option<std::path::PathBuf>,
    output_path: &std::path::Path,
) -> Result<()> {
    info!("Starting baseline model training");
    
    // Create output directory if needed
    if let Some(parent) = output_path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }

    // In a real implementation, this would:
    // 1. Load training data from PCAP or feature file
    // 2. Extract features from multiple time windows
    // 3. Calculate baseline statistics
    // 4. Train Isolation Forest model
    
    // For this implementation, we create a placeholder model
    let model = IsolationForestModel {
        trees: vec![IsolationTree {
            split_features: vec![0, 1, 2],
            split_values: vec![50.0, 100.0, 200.0],
            tree_depth: 10,
        }],
        contamination: config.ai.isolation_forest_contamination,
        n_samples: 1000,
    };

    let stats = BaselineStats {
        feature_means: vec![10.0, 100.0, 500.0, 100.0, 5.0, 10.0, 10000.0, 100.0, 0.1, 0.1, 0.05, 2.0],
        feature_stds: vec![5.0, 50.0, 200.0, 50.0, 3.0, 5.0, 5000.0, 50.0, 0.05, 0.05, 0.02, 0.5],
        feature_mins: vec![0.0; 12],
        feature_maxs: vec![100.0, 1000.0, 5000.0, 1000.0, 50.0, 100.0, 100000.0, 1000.0, 1.0, 1.0, 1.0, 5.0],
        sample_count: 1000,
    };

    // Serialize and save
    let model_data = bincode::serialize(&(model, stats))
        .map_err(|e| anyhow::anyhow!("Failed to serialize model: {}", e))?;
    
    tokio::fs::write(output_path, model_data).await?;
    
    info!("Baseline model trained and saved to {:?}", output_path);
    Ok(())
}
