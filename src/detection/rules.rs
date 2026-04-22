use crate::models::{PacketInfo, Protocol, Severity};
use serde::{Deserialize, Serialize};

/// A detection rule for signature-based detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub severity: Severity,
    pub enabled: bool,
    pub conditions: Vec<RuleCondition>,
    pub action: RuleAction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RuleCondition {
    Protocol { protocol: Protocol },
    SourcePort { port: u16 },
    DestinationPort { port: u16 },
    SourceIp { ip: String },
    DestinationIp { ip: String },
    PayloadContains { pattern: String },
    PacketSizeRange { min: usize, max: usize },
    TcpFlags { flags: u8 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RuleAction {
    Alert,
    Log,
    Ignore,
}

/// Rule matching result
pub struct RuleMatch {
    pub rule: Rule,
    pub matched_conditions: Vec<RuleCondition>,
}

/// Engine for managing and matching rules
pub struct RuleEngine {
    rules: Vec<Rule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RulesFile {
    rules: Vec<Rule>,
}

impl RuleEngine {
    pub fn load(path: &str) -> anyhow::Result<Self> {
        // Try to load from file, or use default rules
        let rules = if std::path::Path::new(path).exists() {
            let content = std::fs::read_to_string(path)?;
            let rules_file: RulesFile = serde_yaml::from_str(&content)?;
            rules_file.rules
        } else {
            Self::default_rules()
        };

        Ok(Self { rules })
    }

    pub fn rule_count(&self) -> usize {
        self.rules.iter().filter(|r| r.enabled).count()
    }

    pub fn match_packet(&self, packet: &PacketInfo) -> Option<RuleMatch> {
        for rule in &self.rules {
            if !rule.enabled {
                continue;
            }

            let matched_conditions: Vec<RuleCondition> = rule
                .conditions
                .iter()
                .filter(|condition| Self::check_condition(condition, packet))
                .cloned()
                .collect();

            // All conditions must match
            if matched_conditions.len() == rule.conditions.len() {
                return Some(RuleMatch {
                    rule: rule.clone(),
                    matched_conditions,
                });
            }
        }

        None
    }

    fn check_condition(condition: &RuleCondition, packet: &PacketInfo) -> bool {
        match condition {
            RuleCondition::Protocol { protocol } => packet.protocol == *protocol,
            RuleCondition::SourcePort { port } => packet.source_port == Some(*port),
            RuleCondition::DestinationPort { port } => packet.destination_port == Some(*port),
            RuleCondition::SourceIp { ip } => Self::ip_matches(&packet.source_ip.to_string(), ip),
            RuleCondition::DestinationIp { ip } => {
                Self::ip_matches(&packet.destination_ip.to_string(), ip)
            }
            RuleCondition::PayloadContains { pattern } => {
                // In a real implementation, we'd check the actual payload
                // For now, we use the hash as a proxy
                packet
                    .payload_hash
                    .as_ref()
                    .map(|h| h.contains(pattern))
                    .unwrap_or(false)
            }
            RuleCondition::PacketSizeRange { min, max } => {
                packet.size_bytes >= *min && packet.size_bytes <= *max
            }
            RuleCondition::TcpFlags { flags } => {
                packet.flags.map(|f| f & *flags == *flags).unwrap_or(false)
            }
        }
    }

    fn ip_matches(ip: &str, pattern: &str) -> bool {
        // Simple exact match or CIDR match
        if ip == pattern {
            return true;
        }

        // Check if pattern contains / for CIDR
        if pattern.contains('/') {
            // Parse CIDR and check (simplified)
            if let Ok(network) = pattern.parse::<ipnetwork::IpNetwork>() {
                if let Ok(addr) = ip.parse::<std::net::IpAddr>() {
                    return network.contains(addr);
                }
            }
        }

        false
    }

    fn default_rules() -> Vec<Rule> {
        vec![
            Rule {
                id: "RULE-001".to_string(),
                name: "SSH Brute Force".to_string(),
                description: "Detects potential SSH brute force attacks".to_string(),
                severity: Severity::High,
                enabled: true,
                conditions: vec![
                    RuleCondition::DestinationPort { port: 22 },
                    RuleCondition::Protocol {
                        protocol: Protocol::Tcp,
                    },
                ],
                action: RuleAction::Alert,
            },
            Rule {
                id: "RULE-002".to_string(),
                name: "Telnet Plaintext".to_string(),
                description: "Detects Telnet connections (insecure protocol)".to_string(),
                severity: Severity::Medium,
                enabled: true,
                conditions: vec![
                    RuleCondition::DestinationPort { port: 23 },
                    RuleCondition::Protocol {
                        protocol: Protocol::Tcp,
                    },
                ],
                action: RuleAction::Alert,
            },
            Rule {
                id: "RULE-003".to_string(),
                name: "DNS over TCP Large Query".to_string(),
                description: "Detects unusually large DNS queries over TCP".to_string(),
                severity: Severity::Medium,
                enabled: true,
                conditions: vec![
                    RuleCondition::DestinationPort { port: 53 },
                    RuleCondition::Protocol {
                        protocol: Protocol::Tcp,
                    },
                    RuleCondition::PacketSizeRange {
                        min: 1000,
                        max: 65535,
                    },
                ],
                action: RuleAction::Alert,
            },
            Rule {
                id: "RULE-004".to_string(),
                name: "SMB External Access".to_string(),
                description: "Detects SMB traffic from external sources".to_string(),
                severity: Severity::High,
                enabled: true,
                conditions: vec![
                    RuleCondition::DestinationPort { port: 445 },
                    RuleCondition::Protocol {
                        protocol: Protocol::Tcp,
                    },
                ],
                action: RuleAction::Alert,
            },
            Rule {
                id: "RULE-005".to_string(),
                name: "RDP Connection".to_string(),
                description: "Detects Remote Desktop Protocol connections".to_string(),
                severity: Severity::Low,
                enabled: true,
                conditions: vec![
                    RuleCondition::DestinationPort { port: 3389 },
                    RuleCondition::Protocol {
                        protocol: Protocol::Tcp,
                    },
                ],
                action: RuleAction::Log,
            },
            Rule {
                id: "RULE-006".to_string(),
                name: "ICMP Tunnel Large Packet".to_string(),
                description: "Detects potential ICMP tunneling via large packets".to_string(),
                severity: Severity::Medium,
                enabled: true,
                conditions: vec![
                    RuleCondition::Protocol {
                        protocol: Protocol::Icmp,
                    },
                    RuleCondition::PacketSizeRange {
                        min: 1000,
                        max: 65535,
                    },
                ],
                action: RuleAction::Alert,
            },
            Rule {
                id: "RULE-007".to_string(),
                name: "MySQL External Access".to_string(),
                description: "Detects MySQL connections from external sources".to_string(),
                severity: Severity::High,
                enabled: true,
                conditions: vec![
                    RuleCondition::DestinationPort { port: 3306 },
                    RuleCondition::Protocol {
                        protocol: Protocol::Tcp,
                    },
                ],
                action: RuleAction::Alert,
            },
            Rule {
                id: "RULE-008".to_string(),
                name: "Redis Unauthenticated".to_string(),
                description: "Detects Redis connections (often unauthenticated)".to_string(),
                severity: Severity::High,
                enabled: true,
                conditions: vec![
                    RuleCondition::DestinationPort { port: 6379 },
                    RuleCondition::Protocol {
                        protocol: Protocol::Tcp,
                    },
                ],
                action: RuleAction::Alert,
            },
        ]
    }
}

impl RuleMatcher for RuleEngine {
    fn match_packet(&self, packet: &PacketInfo) -> Option<RuleMatch> {
        self.match_packet(packet)
    }
}

pub trait RuleMatcher: Send + Sync {
    fn match_packet(&self, packet: &PacketInfo) -> Option<RuleMatch>;
}
