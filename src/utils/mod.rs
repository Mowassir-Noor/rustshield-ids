use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Sliding window counter for rate limiting and tracking
pub struct SlidingWindowCounter {
    windows: HashMap<IpAddr, Vec<Instant>>,
    window_duration: Duration,
    max_entries: usize,
}

impl SlidingWindowCounter {
    pub fn new(window_secs: u64) -> Self {
        Self {
            windows: HashMap::new(),
            window_duration: Duration::from_secs(window_secs),
            max_entries: 10000,
        }
    }

    pub fn add_event(&mut self, ip: IpAddr) -> usize {
        let now = Instant::now();
        let window_duration = self.window_duration;
        let max_entries = self.max_entries;

        // Get or insert entry
        let entries = self.windows.entry(ip).or_insert_with(Vec::new);

        // Remove old entries outside the window
        entries.retain(|&t| now.duration_since(t) < window_duration);

        // Add new entry
        entries.push(now);
        let count = entries.len();

        // Cleanup if too many entries (drop the borrow first)
        drop(entries);
        if self.windows.len() > max_entries {
            self.cleanup_old_entries(now);
        }

        count
    }

    pub fn count(&mut self, ip: IpAddr) -> usize {
        let now = Instant::now();
        if let Some(entries) = self.windows.get_mut(&ip) {
            entries.retain(|&t| now.duration_since(t) < self.window_duration);
            entries.len()
        } else {
            0
        }
    }

    fn cleanup_old_entries(&mut self, now: Instant) {
        let keys_to_remove: Vec<IpAddr> = self
            .windows
            .iter()
            .filter(|(_, entries)| {
                entries
                    .iter()
                    .all(|&t| now.duration_since(t) >= self.window_duration)
            })
            .map(|(k, _)| *k)
            .collect();

        for key in keys_to_remove {
            self.windows.remove(&key);
        }
    }
}

/// Calculate entropy of a distribution
pub fn calculate_entropy(values: &[u16]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }

    let mut frequency_map: HashMap<u16, usize> = HashMap::new();
    for &value in values {
        *frequency_map.entry(value).or_insert(0) += 1;
    }

    let total = values.len() as f64;
    let mut entropy = 0.0;

    for &count in frequency_map.values() {
        let probability = count as f64 / total;
        if probability > 0.0 {
            entropy -= probability * probability.log2();
        }
    }

    entropy
}

/// Calculate standard deviation
pub fn std_deviation(values: &[f64]) -> f64 {
    if values.len() < 2 {
        return 0.0;
    }

    let mean = values.iter().sum::<f64>() / values.len() as f64;
    let variance = values.iter().map(|&x| (x - mean).powi(2)).sum::<f64>() / values.len() as f64;

    variance.sqrt()
}

/// Generate a unique alert ID
pub fn generate_alert_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let random = rand::random::<u16>();
    format!("ALERT-{}-{}", timestamp, random)
}

/// Check if an IP is private/internal
pub fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();
            // 10.0.0.0/8
            octets[0] == 10
            // 172.16.0.0/12
            || (octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31)
            // 192.168.0.0/16
            || (octets[0] == 192 && octets[1] == 168)
            // 127.0.0.0/8 (loopback)
            || octets[0] == 127
        }
        IpAddr::V6(ipv6) => {
            // ::1 (loopback)
            ipv6.is_loopback()
            // fc00::/7 (ULA)
            || (ipv6.octets()[0] & 0xfe) == 0xfc
        }
    }
}

/// Time window tracker for event aggregation
pub struct TimeWindow<T> {
    data: Vec<(Instant, T)>,
    window_duration: Duration,
}

impl<T: Clone> TimeWindow<T> {
    pub fn new(window_secs: u64) -> Self {
        Self {
            data: Vec::new(),
            window_duration: Duration::from_secs(window_secs),
        }
    }

    pub fn add(&mut self, item: T) {
        let now = Instant::now();
        self.data
            .retain(|(t, _)| now.duration_since(*t) < self.window_duration);
        self.data.push((now, item));
    }

    pub fn get_all(&mut self) -> Vec<T> {
        let now = Instant::now();
        self.data
            .retain(|(t, _)| now.duration_since(*t) < self.window_duration);
        self.data.iter().map(|(_, item)| item.clone()).collect()
    }

    pub fn len(&mut self) -> usize {
        let now = Instant::now();
        self.data
            .retain(|(t, _)| now.duration_since(*t) < self.window_duration);
        self.data.len()
    }
}
