use crate::config::Config;
use crate::models::{PacketInfo, Protocol};
use anyhow::{Context, Result};
use chrono::Utc;
use pcap::{Capture, Device, Linktype, Packet};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

/// Packet capture engine
pub struct PacketCapture {
    config: Arc<Config>,
    tx: mpsc::Sender<PacketInfo>,
}

impl PacketCapture {
    pub fn new(config: Arc<Config>, tx: mpsc::Sender<PacketInfo>) -> Self {
        Self { config, tx }
    }

    pub async fn start_capture(&self, interface_name: String) -> Result<()> {
        info!("Starting packet capture on interface: {}", interface_name);

        let device = Device::list()?
            .into_iter()
            .find(|d| d.name == interface_name)
            .with_context(|| format!("Interface '{}' not found", interface_name))?;

        let mut capture = Capture::from_device(device)?
            .promisc(self.config.capture.promiscuous)
            .snaplen(self.config.capture.snaplen)
            .buffer_size(self.config.capture.buffer_size)
            .timeout(100)
            .open()?;

        // Apply BPF filter if specified
        if let Some(ref filter) = self.config.capture.bpf_filter {
            capture.filter(filter, true)?;
            info!("Applied BPF filter: {}", filter);
        }

        let datalink = capture.get_datalink();
        info!("Capture started with datalink: {:?}", datalink);

        // Spawn blocking packet capture on a dedicated thread
        let tx = self.tx.clone();
        let exclude_ips = self.config.capture.exclude_ips.clone();

        tokio::task::spawn_blocking(move || Self::capture_loop(capture, datalink, tx, exclude_ips));

        Ok(())
    }

    pub async fn capture_from_pcap(&self, pcap_file: &str) -> Result<()> {
        info!("Reading packets from PCAP file: {}", pcap_file);

        let mut capture = Capture::from_file(pcap_file)?;
        let datalink = capture.get_datalink();
        let exclude_ips = self.config.capture.exclude_ips.clone();

        // Process all packets in the file
        while let Ok(packet) = capture.next_packet() {
            if let Some(packet_info) = Self::parse_packet(&packet, datalink, &exclude_ips) {
                if let Err(e) = self.tx.try_send(packet_info) {
                    warn!("Failed to send packet: {}", e);
                }
            }
        }

        info!("Finished reading PCAP file");
        Ok(())
    }

    fn capture_loop(
        mut capture: Capture<pcap::Active>,
        datalink: Linktype,
        tx: mpsc::Sender<PacketInfo>,
        exclude_ips: Vec<std::net::IpAddr>,
    ) {
        loop {
            match capture.next_packet() {
                Ok(packet) => {
                    if let Some(packet_info) = Self::parse_packet(&packet, datalink, &exclude_ips) {
                        match tx.try_send(packet_info) {
                            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                                warn!("Packet queue full, dropping packet");
                            }
                            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                                error!("Channel closed");
                                break;
                            }
                            Ok(()) => {}
                        }
                    }
                }
                Err(pcap::Error::TimeoutExpired) => continue,
                Err(e) => {
                    error!("Capture error: {}", e);
                    break;
                }
            }
        }
    }

    fn parse_packet(
        packet: &Packet,
        datalink: Linktype,
        exclude_ips: &[std::net::IpAddr],
    ) -> Option<PacketInfo> {
        let timestamp = Utc::now();
        let data = packet.data;

        // Parse based on datalink type
        let (source_ip, dest_ip, protocol, payload_data, ttl) = match datalink.0 {
            1 => Self::parse_ethernet(data)?,   // Ethernet
            228 => Self::parse_ipv4_raw(data)?, // Raw IPv4 on Linux
            229 => Self::parse_ipv6_raw(data)?, // Raw IPv6 on Linux
            _ => {
                debug!("Unsupported datalink type: {}", datalink.0);
                return None;
            }
        };

        // Skip excluded IPs
        if exclude_ips.contains(&source_ip) || exclude_ips.contains(&dest_ip) {
            return None;
        }

        // Parse transport layer
        let (source_port, dest_port, flags) = match protocol {
            Protocol::Tcp => {
                if let Some(tcp) = TcpPacket::new(payload_data) {
                    let flags = tcp.get_flags();
                    let flag_byte = Self::tcp_flags_to_byte(flags);
                    (
                        Some(tcp.get_source()),
                        Some(tcp.get_destination()),
                        Some(flag_byte),
                    )
                } else {
                    (None, None, None)
                }
            }
            Protocol::Udp => {
                if let Some(udp) = UdpPacket::new(payload_data) {
                    (Some(udp.get_source()), Some(udp.get_destination()), None)
                } else {
                    (None, None, None)
                }
            }
            _ => (None, None, None),
        };

        let size_bytes = packet.data.len();
        let payload_hash = if payload_data.len() > 20 {
            Some(blake3::hash(payload_data).to_hex().to_string())
        } else {
            None
        };

        Some(PacketInfo {
            timestamp,
            source_ip,
            destination_ip: dest_ip,
            source_port,
            destination_port: dest_port,
            protocol,
            size_bytes,
            payload_hash,
            flags,
            ttl,
        })
    }

    fn parse_ethernet(data: &[u8]) -> Option<(IpAddr, IpAddr, Protocol, &[u8], Option<u8>)> {
        // Ethernet header is 14 bytes (6 dst + 6 src + 2 type)
        if data.len() < 14 {
            return None;
        }
        let ethertype = u16::from_be_bytes([data[12], data[13]]);
        let payload = &data[14..];

        match ethertype {
            0x0800 => {
                // IPv4
                let packet = Ipv4Packet::new(payload)?;
                let source_ip = IpAddr::V4(packet.get_source());
                let dest_ip = IpAddr::V4(packet.get_destination());
                let ttl = Some(packet.get_ttl());
                let protocol = match packet.get_next_level_protocol() {
                    IpNextHeaderProtocols::Tcp => Protocol::Tcp,
                    IpNextHeaderProtocols::Udp => Protocol::Udp,
                    IpNextHeaderProtocols::Icmp => Protocol::Icmp,
                    other => Protocol::Other(other.0),
                };
                // Get actual IP payload (skip IP header)
                let ip_header_len = ((data[14] & 0x0F) * 4) as usize;
                let ip_payload = &data[14 + ip_header_len..];
                Some((source_ip, dest_ip, protocol, ip_payload, ttl))
            }
            0x86DD => {
                // IPv6
                let packet = Ipv6Packet::new(payload)?;
                let source_ip = IpAddr::V6(packet.get_source());
                let dest_ip = IpAddr::V6(packet.get_destination());
                let ttl = Some(packet.get_hop_limit());
                let protocol = match packet.get_next_header() {
                    IpNextHeaderProtocols::Tcp => Protocol::Tcp,
                    IpNextHeaderProtocols::Udp => Protocol::Udp,
                    IpNextHeaderProtocols::Icmpv6 => Protocol::Icmp,
                    other => Protocol::Other(other.0),
                };
                // IPv6 header is fixed 40 bytes
                let ip_payload = &data[54..];
                Some((source_ip, dest_ip, protocol, ip_payload, ttl))
            }
            _ => None,
        }
    }

    fn parse_ipv4_raw(data: &[u8]) -> Option<(IpAddr, IpAddr, Protocol, &[u8], Option<u8>)> {
        let packet = Ipv4Packet::new(data)?;
        let source_ip = IpAddr::V4(packet.get_source());
        let dest_ip = IpAddr::V4(packet.get_destination());
        let ttl = Some(packet.get_ttl());
        let payload_start = 20; // Standard IPv4 header size without options
        let payload = &data[payload_start.min(data.len())..];

        let protocol = match packet.get_next_level_protocol() {
            IpNextHeaderProtocols::Tcp => Protocol::Tcp,
            IpNextHeaderProtocols::Udp => Protocol::Udp,
            IpNextHeaderProtocols::Icmp => Protocol::Icmp,
            other => Protocol::Other(other.0),
        };

        Some((source_ip, dest_ip, protocol, payload, ttl))
    }

    fn parse_ipv6_raw(data: &[u8]) -> Option<(IpAddr, IpAddr, Protocol, &[u8], Option<u8>)> {
        let packet = Ipv6Packet::new(data)?;
        let source_ip = IpAddr::V6(packet.get_source());
        let dest_ip = IpAddr::V6(packet.get_destination());
        let ttl = Some(packet.get_hop_limit());
        let payload_start = 40; // IPv6 header is fixed 40 bytes
        let payload = &data[payload_start.min(data.len())..];

        let protocol = match packet.get_next_header() {
            IpNextHeaderProtocols::Tcp => Protocol::Tcp,
            IpNextHeaderProtocols::Udp => Protocol::Udp,
            IpNextHeaderProtocols::Icmpv6 => Protocol::Icmp,
            other => Protocol::Other(other.0),
        };

        Some((source_ip, dest_ip, protocol, payload, ttl))
    }

    fn tcp_flags_to_byte(flags: u8) -> u8 {
        // Simplified flag representation
        flags & 0x3F // Keep only the 6 standard TCP flags
    }
}

/// List available network interfaces
pub fn list_interfaces() -> Result<Vec<String>> {
    let devices = Device::list()?;
    Ok(devices.into_iter().map(|d| d.name).collect())
}
