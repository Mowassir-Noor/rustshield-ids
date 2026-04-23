//! Deep Packet Inspection (Simplified)
//!
//! Analyzes packet payloads for suspicious patterns.
//! Lightweight implementation for detecting common attack signatures.

use crate::models::{PacketInfo, Protocol, DetectionResult, Severity};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Serialize, Deserialize};

/// Maximum payload size to analyze (avoid processing huge packets)
const MAX_PAYLOAD_SIZE: usize = 8192;
/// Minimum payload size to be interesting
const MIN_PAYLOAD_SIZE: usize = 10;

/// Suspicious payload patterns
const SUSPICIOUS_STRINGS: &[&str] = &[
    // SQL Injection patterns
    "' OR '1'='1",
    "' OR 1=1--",
    "UNION SELECT",
    "INSERT INTO",
    "DELETE FROM",
    "DROP TABLE",
    
    // Command injection
    "; rm -rf ",
    "| /bin/sh",
    "| bash",
    "$(",
    "`",
    
    // XSS patterns
    "<script>",
    "javascript:",
    "onerror=",
    "onload=",
    "alert(",
    "document.cookie",
    
    // Directory traversal
    "../",
    "..\\",
    "/etc/passwd",
    "C:\\\\Windows",
    "boot.ini",
    
    // Malware/scanning signatures
    "nmap",
    "masscan",
    "zgrab",
    "nikto",
    "sqlmap",
    
    // Buffer overflow indicators
    "AAAAAAA", // Repeated characters (simplified heuristic)
];

/// Entropy threshold for detecting encrypted/encoded payloads
const HIGH_ENTROPY_THRESHOLD: f64 = 7.0;
const LOW_ENTROPY_THRESHOLD: f64 = 2.0;

/// Payload analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadAnalysis {
    pub detected: bool,
    pub confidence: f64,
    pub pattern_type: PayloadPatternType,
    pub matched_signatures: Vec<String>,
    pub entropy: f64,
    pub printable_ratio: f64,
    pub payload_sample: String, // First N bytes
    pub severity: Severity,
    pub reason: String,
}

/// Types of payload patterns
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PayloadPatternType {
    SuspiciousString,
    HighEntropy,      // Possibly encrypted/encoded
    LowEntropy,       // Possibly padding/malformed
    RepeatedPattern,  // Buffer overflow candidate
    ExecutableContent, // Contains executable code signatures
    ScanningSignature, // Known scanner fingerprint
    EncodedPayload,   // Base64, hex encoded
    Compressed,       // Compressed data
    Unknown,
}

impl PayloadPatternType {
    pub fn as_str(&self) -> &'static str {
        match self {
            PayloadPatternType::SuspiciousString => "Suspicious String Pattern",
            PayloadPatternType::HighEntropy => "High Entropy (Encrypted/Encoded)",
            PayloadPatternType::LowEntropy => "Low Entropy (Padding/Malformed)",
            PayloadPatternType::RepeatedPattern => "Repeated Pattern (Overflow)",
            PayloadPatternType::ExecutableContent => "Executable Content",
            PayloadPatternType::ScanningSignature => "Scanner Fingerprint",
            PayloadPatternType::EncodedPayload => "Encoded Payload",
            PayloadPatternType::Compressed => "Compressed Data",
            PayloadPatternType::Unknown => "Unknown Pattern",
        }
    }
}

/// DPI Engine for payload inspection
pub struct DpiEngine {
    /// Custom signatures loaded from config
    custom_signatures: Arc<RwLock<Vec<String>>>,
    /// IP reputation for payload analysis
    suspicious_ips: Arc<RwLock<HashSet<IpAddr>>>,
    /// Protocol-specific analyzers
    protocol_analyzers: HashMap<Protocol, Box<dyn ProtocolAnalyzer + Send + Sync>>,
    /// Statistics
    stats: Arc<RwLock<DpiStats>>,
}

use std::net::IpAddr;

/// Protocol-specific analyzer trait
trait ProtocolAnalyzer {
    fn analyze(&self, packet: &PacketInfo, payload: &[u8]) -> Option<PayloadAnalysis>;
}

/// Statistics for DPI
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DpiStats {
    pub packets_analyzed: u64,
    pub payloads_flagged: u64,
    pub signatures_matched: u64,
    pub avg_entropy: f64,
}

impl DpiEngine {
    pub fn new() -> Self {
        let mut protocol_analyzers: HashMap<Protocol, Box<dyn ProtocolAnalyzer + Send + Sync>> = HashMap::new();
        
        // Add protocol analyzers
        protocol_analyzers.insert(Protocol::Tcp, Box::new(TcpAnalyzer));
        protocol_analyzers.insert(Protocol::Udp, Box::new(UdpAnalyzer));
        protocol_analyzers.insert(Protocol::Icmp, Box::new(IcmpAnalyzer));
        
        Self {
            custom_signatures: Arc::new(RwLock::new(Vec::new())),
            suspicious_ips: Arc::new(RwLock::new(HashSet::new())),
            protocol_analyzers,
            stats: Arc::new(RwLock::new(DpiStats::default())),
        }
    }
    
    /// Analyze a packet's payload
    pub async fn analyze_packet(&self, packet: &PacketInfo) -> Option<PayloadAnalysis> {
        // Update stats
        let mut stats = self.stats.write().await;
        stats.packets_analyzed += 1;
        
        // Only analyze if we have payload data
        // In real implementation, this would come from packet parsing
        let payload = self.extract_payload(packet)?;
        
        if payload.len() < MIN_PAYLOAD_SIZE || payload.len() > MAX_PAYLOAD_SIZE {
            return None;
        }
        
        // Protocol-specific analysis
        let protocol_result = if let Some(analyzer) = self.protocol_analyzers.get(&packet.protocol) {
            analyzer.analyze(packet, &payload)
        } else {
            None
        };
        
        if protocol_result.is_some() {
            stats.payloads_flagged += 1;
            return protocol_result;
        }
        
        // General payload analysis
        let analysis = self.analyze_payload(&payload).await;
        
        if analysis.detected {
            stats.payloads_flagged += 1;
            stats.signatures_matched += analysis.matched_signatures.len() as u64;
        }
        
        Some(analysis)
    }
    
    /// Extract payload from packet (placeholder - real implementation would parse actual payload)
    fn extract_payload(&self, packet: &PacketInfo) -> Option<Vec<u8>> {
        // In production, this would extract actual payload from packet data
        // For now, we simulate based on packet characteristics
        if packet.size_bytes > 60 {
            // Simulate payload extraction
            Some(vec![0u8; packet.size_bytes - 60])
        } else {
            None
        }
    }
    
    /// Analyze payload content
    async fn analyze_payload(&self, payload: &[u8]) -> PayloadAnalysis {
        let mut matched_signatures = Vec::new();
        let payload_str = String::from_utf8_lossy(payload);
        
        // Check for suspicious strings
        for pattern in SUSPICIOUS_STRINGS {
            if payload_str.to_lowercase().contains(&pattern.to_lowercase()) {
                matched_signatures.push(pattern.to_string());
            }
        }
        
        // Check custom signatures
        let custom = self.custom_signatures.read().await;
        for pattern in custom.iter() {
            if payload_str.contains(pattern) {
                matched_signatures.push(format!("custom:{}", pattern));
            }
        }
        drop(custom);
        
        // Calculate entropy
        let entropy = self.calculate_entropy(payload);
        
        // Calculate printable character ratio
        let printable_count = payload.iter()
            .filter(|&&b| b.is_ascii_graphic() || b == b' ' || b == b'\n' || b == b'\r' || b == b'\t')
            .count();
        let printable_ratio = printable_count as f64 / payload.len() as f64;
        
        // Detect repeated patterns (buffer overflow heuristic)
        let has_repeated_pattern = self.detect_repeated_pattern(payload);
        
        // Determine pattern type
        let pattern_type = if !matched_signatures.is_empty() {
            PayloadPatternType::SuspiciousString
        } else if entropy > HIGH_ENTROPY_THRESHOLD {
            PayloadPatternType::HighEntropy
        } else if entropy < LOW_ENTROPY_THRESHOLD {
            PayloadPatternType::LowEntropy
        } else if has_repeated_pattern {
            PayloadPatternType::RepeatedPattern
        } else if self.is_likely_encoded(payload) {
            PayloadPatternType::EncodedPayload
        } else {
            PayloadPatternType::Unknown
        };
        
        // Calculate confidence
        let confidence = self.calculate_confidence(
            &matched_signatures,
            entropy,
            printable_ratio,
            has_repeated_pattern
        );
        
        // Determine severity
        let severity = if !matched_signatures.is_empty() {
            Severity::High
        } else if entropy > HIGH_ENTROPY_THRESHOLD {
            Severity::Medium
        } else if has_repeated_pattern {
            Severity::Medium
        } else {
            Severity::Low
        };
        
        // Generate sample
        let sample_len = payload.len().min(100);
        let sample = String::from_utf8_lossy(&payload[..sample_len])
            .chars()
            .map(|c| if c.is_ascii_graphic() || c.is_ascii_whitespace() { c } else { '.' })
            .collect();
        
        // Generate reason
        let reason = if !matched_signatures.is_empty() {
            format!("Matched {} suspicious patterns: {}", 
                matched_signatures.len(),
                matched_signatures.join(", ")
            )
        } else {
            format!("{} detected (entropy: {:.2}, printable: {:.0}%)",
                pattern_type.as_str(),
                entropy,
                printable_ratio * 100.0
            )
        };
        
        PayloadAnalysis {
            detected: confidence > 0.6,
            confidence,
            pattern_type,
            matched_signatures,
            entropy,
            printable_ratio,
            payload_sample: sample,
            severity,
            reason,
        }
    }
    
    /// Calculate Shannon entropy of payload
    fn calculate_entropy(&self, data: &[u8]) -> f64 {
        let mut frequency = [0u64; 256];
        
        for &byte in data {
            frequency[byte as usize] += 1;
        }
        
        let len = data.len() as f64;
        let mut entropy = 0.0;
        
        for &count in frequency.iter() {
            if count > 0 {
                let probability = count as f64 / len;
                entropy -= probability * probability.log2();
            }
        }
        
        entropy
    }
    
    /// Detect repeated byte patterns (overflow detection)
    fn detect_repeated_pattern(&self, data: &[u8]) -> bool {
        if data.len() < 20 {
            return false;
        }
        
        // Check for runs of same character
        let mut current_run = 1;
        let mut max_run = 1;
        
        for i in 1..data.len() {
            if data[i] == data[i-1] {
                current_run += 1;
                max_run = max_run.max(current_run);
            } else {
                current_run = 1;
            }
        }
        
        // If any run is > 50% of payload, it's suspicious
        max_run > data.len() / 2
    }
    
    /// Check if payload appears to be encoded
    fn is_likely_encoded(&self, data: &[u8]) -> bool {
        // Check for Base64 patterns (printable, ends with = or ==)
        let all_printable = data.iter().all(|&b| {
            b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=' || b.is_ascii_whitespace()
        });
        
        if all_printable && data.len() % 4 == 0 {
            // Likely Base64
            return true;
        }
        
        // Check for hex encoding
        if data.len() % 2 == 0 {
            let all_hex = data.iter().all(|&b| {
                b.is_ascii_hexdigit()
            });
            if all_hex {
                return true;
            }
        }
        
        false
    }
    
    /// Calculate overall confidence score
    fn calculate_confidence(
        &self,
        signatures: &[String],
        entropy: f64,
        printable_ratio: f64,
        has_repeated: bool
    ) -> f64 {
        let mut score = 0.0;
        
        // Signature matches
        score += (signatures.len() as f64) * 0.3;
        
        // High entropy
        if entropy > HIGH_ENTROPY_THRESHOLD {
            score += 0.2;
        }
        
        // Low printable ratio
        if printable_ratio < 0.5 {
            score += 0.2;
        }
        
        // Repeated pattern
        if has_repeated {
            score += 0.3;
        }
        
        score.min(1.0)
    }
    
    /// Add custom signature
    pub async fn add_signature(&self, pattern: String) {
        let mut signatures = self.custom_signatures.write().await;
        signatures.push(pattern);
    }
    
    /// Get DPI statistics
    pub async fn get_stats(&self) -> DpiStats {
        self.stats.read().await.clone()
    }
}

/// TCP protocol analyzer
struct TcpAnalyzer;

impl ProtocolAnalyzer for TcpAnalyzer {
    fn analyze(&self, packet: &PacketInfo, payload: &[u8]) -> Option<PayloadAnalysis> {
        // Check for HTTP requests
        let payload_str = String::from_utf8_lossy(payload);
        
        if payload_str.starts_with("GET ") || payload_str.starts_with("POST ") {
            // Check for suspicious HTTP patterns
            let suspicious = [
                "../", "..\\", ";", "|", "`", "$(",
            ];
            
            let mut found = Vec::new();
            for &pattern in &suspicious {
                if payload_str.contains(pattern) {
                    found.push(pattern.to_string());
                }
            }
            
            if !found.is_empty() {
                return Some(PayloadAnalysis {
                    detected: true,
                    confidence: 0.7 + (found.len() as f64 * 0.1).min(0.3),
                    pattern_type: PayloadPatternType::SuspiciousString,
                    matched_signatures: found,
                    entropy: 0.0,
                    printable_ratio: 1.0,
                    payload_sample: payload_str.chars().take(100).collect(),
                    severity: Severity::High,
                    reason: "Suspicious characters in HTTP request".to_string(),
                });
            }
        }
        
        None
    }
}

/// UDP protocol analyzer
struct UdpAnalyzer;

impl ProtocolAnalyzer for UdpAnalyzer {
    fn analyze(&self, _packet: &PacketInfo, _payload: &[u8]) -> Option<PayloadAnalysis> {
        // UDP-specific analysis (DNS, SNMP, etc.)
        None
    }
}

/// ICMP protocol analyzer
struct IcmpAnalyzer;

impl ProtocolAnalyzer for IcmpAnalyzer {
    fn analyze(&self, _packet: &PacketInfo, payload: &[u8]) -> Option<PayloadAnalysis> {
        // Check for ICMP tunneling (data in ICMP payload)
        if payload.len() > 56 { // Normal ICMP payload is small
            let entropy = {
                let mut freq = [0u64; 256];
                for &b in payload {
                    freq[b as usize] += 1;
                }
                let len = payload.len() as f64;
                let mut e = 0.0;
                for &c in freq.iter() {
                    if c > 0 {
                        let p = c as f64 / len;
                        e -= p * p.log2();
                    }
                }
                e
            };
            
            if entropy > 6.0 {
                return Some(PayloadAnalysis {
                    detected: true,
                    confidence: 0.75,
                    pattern_type: PayloadPatternType::HighEntropy,
                    matched_signatures: vec!["Large ICMP payload".to_string()],
                    entropy,
                    printable_ratio: 0.5,
                    payload_sample: String::from_utf8_lossy(&payload[..payload.len().min(50)])
                        .to_string(),
                    severity: Severity::Medium,
                    reason: "Possible ICMP tunneling detected".to_string(),
                });
            }
        }
        
        None
    }
}

impl Default for DpiEngine {
    fn default() -> Self {
        Self::new()
    }
}
