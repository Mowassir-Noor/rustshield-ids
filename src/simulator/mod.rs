//! Attack Simulation Module
//!
//! Generates synthetic attack traffic for testing and demonstration.
//! Supports port scans, brute force, and DoS attacks.

use crate::models::{PacketInfo, Protocol};
use chrono::Utc;
use std::net::{IpAddr, Ipv4Addr};
use tokio::sync::mpsc;
use tokio::time::{interval, Duration};

/// Types of attacks that can be simulated
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AttackType {
    /// Port scan across multiple ports
    PortScan { intensity: ScanIntensity },
    /// SSH/Service brute force
    BruteForce { service_port: u16 },
    /// Volume-based DoS
    Dos { duration_secs: u64 },
    /// SYN flood
    SynFlood { intensity: ScanIntensity },
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ScanIntensity {
    Low,      // ~10 ports/packets per second
    Medium,   // ~50 ports/packets per second
    High,     // ~200 ports/packets per second
    Extreme,  // ~1000 ports/packets per second
}

impl ScanIntensity {
    pub fn rate(&self) -> u64 {
        match self {
            ScanIntensity::Low => 10,
            ScanIntensity::Medium => 50,
            ScanIntensity::High => 200,
            ScanIntensity::Extreme => 1000,
        }
    }

    pub fn port_count(&self) -> u16 {
        match self {
            ScanIntensity::Low => 20,
            ScanIntensity::Medium => 100,
            ScanIntensity::High => 500,
            ScanIntensity::Extreme => 2000,
        }
    }
}

/// Attack simulator for generating synthetic traffic
pub struct AttackSimulator {
    tx: mpsc::Sender<PacketInfo>,
    attacker_ip: IpAddr,
    target_ip: IpAddr,
}

impl AttackSimulator {
    pub fn new(tx: mpsc::Sender<PacketInfo>, target_ip: IpAddr) -> Self {
        let attacker_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 100, 50));
        Self { tx, attacker_ip, target_ip }
    }

    pub fn with_attacker(tx: mpsc::Sender<PacketInfo>, attacker_ip: IpAddr, target_ip: IpAddr) -> Self {
        Self { tx, attacker_ip, target_ip }
    }

    /// Start simulating an attack
    pub async fn simulate(&self, attack: AttackType) {
        match attack {
            AttackType::PortScan { intensity } => {
                self.simulate_port_scan(intensity).await;
            }
            AttackType::BruteForce { service_port } => {
                self.simulate_brute_force(service_port).await;
            }
            AttackType::Dos { duration_secs } => {
                self.simulate_dos(duration_secs).await;
            }
            AttackType::SynFlood { intensity } => {
                self.simulate_syn_flood(intensity).await;
            }
        }
    }

    /// Simulate a port scan attack
    async fn simulate_port_scan(&self, intensity: ScanIntensity) {
        let port_count = intensity.port_count();
        let rate = intensity.rate();
        let delay = Duration::from_millis(1000 / rate);

        let mut interval = interval(delay);
        
        for port in 1..=port_count {
            interval.tick().await;
            
            let packet = PacketInfo {
                timestamp: Utc::now(),
                source_ip: self.attacker_ip,
                destination_ip: self.target_ip,
                source_port: Some(40000 + port as u16),
                destination_port: Some(port),
                protocol: Protocol::Tcp,
                size_bytes: 64,
                payload_hash: None,
                flags: Some(0x02), // SYN flag
                ttl: Some(64),
            };
            
            let _ = self.tx.send(packet).await;
        }
    }

    /// Simulate a brute force attack
    async fn simulate_brute_force(&self, service_port: u16) {
        let attempts = 20u16;
        let delay = Duration::from_millis(200); // 5 attempts per second

        let mut interval = interval(delay);

        for i in 0..attempts {
            interval.tick().await;

            // Alternate between successful-looking and failed-looking packets
            let flags = if i % 3 == 0 {
                Some(0x18) // PSH+ACK (established connection data)
            } else {
                Some(0x02) // SYN (new connection attempt)
            };

            let packet = PacketInfo {
                timestamp: Utc::now(),
                source_ip: self.attacker_ip,
                destination_ip: self.target_ip,
                source_port: Some(50000 + i),
                destination_port: Some(service_port),
                protocol: Protocol::Tcp,
                size_bytes: 60 + (i % 5) as usize * 10,
                payload_hash: None,
                flags,
                ttl: Some(64),
            };

            let _ = self.tx.send(packet).await;

            // Sometimes send RST
            if i % 4 == 0 {
                let rst_packet = PacketInfo {
                    timestamp: Utc::now(),
                    source_ip: self.target_ip,
                    destination_ip: self.attacker_ip,
                    source_port: Some(service_port),
                    destination_port: Some(50000 + i),
                    protocol: Protocol::Tcp,
                    size_bytes: 40,
                    payload_hash: None,
                    flags: Some(0x04), // RST
                    ttl: Some(64),
                };
                let _ = self.tx.send(rst_packet).await;
            }
        }
    }

    /// Simulate a DoS attack
    async fn simulate_dos(&self, duration_secs: u64) {
        let rate = 500; // packets per second
        let delay = Duration::from_millis(1000 / rate);
        let mut interval = interval(delay);
        let start = std::time::Instant::now();
        let mut counter = 0u16;

        while start.elapsed().as_secs() < duration_secs {
            interval.tick().await;

            let packet = PacketInfo {
                timestamp: Utc::now(),
                source_ip: self.attacker_ip,
                destination_ip: self.target_ip,
                source_port: Some(60000 + (counter % 1000)),
                destination_port: Some(80),
                protocol: Protocol::Tcp,
                size_bytes: 1500,
                payload_hash: None,
                flags: Some(0x18), // PSH+ACK
                ttl: Some(64),
            };

            let _ = self.tx.send(packet).await;
            counter = counter.wrapping_add(1);
        }
    }

    /// Simulate a SYN flood attack
    async fn simulate_syn_flood(&self, intensity: ScanIntensity) {
        let rate = intensity.rate();
        let duration_secs = 10;
        let delay = Duration::from_millis(1000 / rate);
        let mut interval = interval(delay);
        let start = std::time::Instant::now();
        let mut counter = 0u16;

        while start.elapsed().as_secs() < duration_secs {
            interval.tick().await;

            let packet = PacketInfo {
                timestamp: Utc::now(),
                source_ip: self.attacker_ip,
                destination_ip: self.target_ip,
                source_port: Some(30000 + (counter % 5000)),
                destination_port: Some(80),
                protocol: Protocol::Tcp,
                size_bytes: 60,
                payload_hash: None,
                flags: Some(0x02), // SYN only
                ttl: Some(64),
            };

            let _ = self.tx.send(packet).await;
            counter = counter.wrapping_add(1);
        }
    }

    /// Simulate multiple attack types in sequence
    pub async fn simulate_attack_sequence(&self) {
        // Port scan
        self.simulate(AttackType::PortScan { 
            intensity: ScanIntensity::Medium 
        }).await;

        tokio::time::sleep(Duration::from_secs(2)).await;

        // Brute force on SSH
        self.simulate(AttackType::BruteForce { 
            service_port: 22 
        }).await;

        tokio::time::sleep(Duration::from_secs(2)).await;

        // SYN flood
        self.simulate(AttackType::SynFlood { 
            intensity: ScanIntensity::High 
        }).await;
    }
}

/// Run simulation mode - generates fake traffic for testing
pub async fn run_simulation(tx: mpsc::Sender<PacketInfo>) {
    let target_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
    let simulator = AttackSimulator::new(tx, target_ip);

    loop {
        simulator.simulate_attack_sequence().await;
        tokio::time::sleep(Duration::from_secs(10)).await;
    }
}
