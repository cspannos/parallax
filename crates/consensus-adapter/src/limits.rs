//! Admission limits for the unauthenticated listeners: the cert server
//! (ADR 0031), the intent-gossip handshake (ADR 0030) and the PQ tunnel
//! handshake (ADR 0034). A handshake costs ~0.7 ms CPU before the peer is
//! known, and a `RECOLLECT` makes a validator re-send ~3.4 KB, so each
//! listener bounds concurrent connections, connection rate per source IP, and
//! how long an unauthenticated peer may take.
//!
//! All validators share 127.0.0.1 in tests, so the per-IP defaults are sized
//! for a full localhost mesh (n·(n−1) tunnel dials at start).

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// An unauthenticated peer must finish the handshake (or its request) in this long.
pub const HANDSHAKE_WAIT: Duration = Duration::from_secs(5);

/// Source IPs tracked per listener before idle (full) buckets are dropped.
const MAX_TRACKED: usize = 4096;

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Connections being served (or handshaking) at once.
    pub slots: usize,
    /// Per source IP: burst size and refill per second.
    pub burst: f64,
    pub per_sec: f64,
}

impl Limits {
    pub const HANDSHAKE: Self = Self { slots: 64, burst: 512.0, per_sec: 64.0 };
    pub const CERT_SERVER: Self = Self { slots: 256, burst: 512.0, per_sec: 256.0 };
}

#[derive(Clone, Copy, Debug)]
pub struct TokenBucket {
    tokens: f64,
    last: Instant,
}

impl TokenBucket {
    pub fn full(burst: f64) -> Self {
        Self { tokens: burst, last: Instant::now() }
    }

    fn refill(&mut self, burst: f64, per_sec: f64, now: Instant) {
        let dt = now.saturating_duration_since(self.last).as_secs_f64();
        self.tokens = (self.tokens + dt * per_sec).min(burst);
        self.last = now;
    }

    /// Take one token if available.
    pub fn take(&mut self, burst: f64, per_sec: f64) -> bool {
        self.refill(burst, per_sec, Instant::now());
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Per-listener gate: a connection is served only with a free slot and a
/// token from its source IP's bucket. The permit is held while serving.
pub struct Admission {
    limits: Limits,
    slots: Arc<Semaphore>,
    per_ip: Mutex<HashMap<IpAddr, TokenBucket>>,
}

impl Admission {
    pub fn new(limits: Limits) -> Arc<Self> {
        Arc::new(Self {
            limits,
            slots: Arc::new(Semaphore::new(limits.slots)),
            per_ip: Mutex::new(HashMap::new()),
        })
    }

    pub fn admit(&self, ip: IpAddr) -> Option<OwnedSemaphorePermit> {
        let Limits { burst, per_sec, .. } = self.limits;
        {
            let mut map = self.per_ip.lock().unwrap();
            if !map.contains_key(&ip) && map.len() >= MAX_TRACKED {
                let now = Instant::now();
                map.retain(|_, b| {
                    b.refill(burst, per_sec, now);
                    b.tokens < burst
                });
                if map.len() >= MAX_TRACKED {
                    return None;
                }
            }
            if !map.entry(ip).or_insert_with(|| TokenBucket::full(burst)).take(burst, per_sec) {
                return None;
            }
        }
        self.slots.clone().try_acquire_owned().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn per_ip_burst_then_refuse() {
        let gate = Admission::new(Limits { slots: 100, burst: 3.0, per_sec: 0.001 });
        let a: IpAddr = [10, 0, 0, 1].into();
        let b: IpAddr = [10, 0, 0, 2].into();
        let held: Vec<_> = (0..3).map(|_| gate.admit(a).expect("within burst")).collect();
        assert!(gate.admit(a).is_none(), "bucket empty");
        assert!(gate.admit(b).is_some(), "other IPs unaffected");
        drop(held);
    }

    #[test]
    fn slots_bound_concurrency() {
        let gate = Admission::new(Limits { slots: 2, burst: 100.0, per_sec: 100.0 });
        let ip: IpAddr = [10, 0, 0, 1].into();
        let p1 = gate.admit(ip).unwrap();
        let _p2 = gate.admit(ip).unwrap();
        assert!(gate.admit(ip).is_none(), "no free slot");
        drop(p1);
        assert!(gate.admit(ip).is_some(), "slot freed");
    }

    #[test]
    fn bucket_refills() {
        let mut b = TokenBucket::full(1.0);
        assert!(b.take(1.0, 1000.0));
        std::thread::sleep(Duration::from_millis(5));
        assert!(b.take(1.0, 1000.0));
    }
}
