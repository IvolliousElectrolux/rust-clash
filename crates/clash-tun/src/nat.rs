use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::{Duration, Instant};

use parking_lot::Mutex;

pub struct TcpSession {
    pub source: SocketAddrV4,
    pub destination: SocketAddrV4,
    last: Instant,
}

pub struct TcpNat {
    timeout: Duration,
    gate: Mutex<Inner>,
}

struct Inner {
    addr_map: HashMap<SocketAddrV4, u16>,
    port_map: HashMap<u16, TcpSession>,
    port_index: u16,
}

impl TcpNat {
    pub fn new(timeout: Duration) -> Self {
        Self {
            timeout,
            gate: Mutex::new(Inner {
                addr_map: HashMap::new(),
                port_map: HashMap::new(),
                port_index: 10000,
            }),
        }
    }

    pub fn lookup(&self, source: SocketAddrV4, destination: SocketAddrV4) -> Option<u16> {
        let mut g = self.gate.lock();
        if let Some(existing) = g.addr_map.get(&source).copied() {
            let dest_changed = g
                .port_map
                .get(&existing)
                .is_some_and(|s| s.destination != destination);
            if dest_changed {
                let src = g.port_map.get(&existing).map(|s| s.source).unwrap_or(source);
                g.port_map.insert(
                    existing,
                    TcpSession {
                        source: src,
                        destination,
                        last: Instant::now(),
                    },
                );
            } else if let Some(s) = g.port_map.get_mut(&existing) {
                s.last = Instant::now();
            }
            return Some(existing);
        }
        let mut next = 0u16;
        for _ in 0..55535 {
            next = g.port_index;
            if next == 0 {
                next = 10000;
                g.port_index = 10001;
            } else {
                g.port_index = g.port_index.wrapping_add(1);
            }
            if !g.port_map.contains_key(&next) {
                break;
            }
        }
        if next == 0 || g.port_map.contains_key(&next) {
            return None;
        }
        g.addr_map.insert(source, next);
        g.port_map.insert(
            next,
            TcpSession {
                source,
                destination,
                last: Instant::now(),
            },
        );
        Some(next)
    }

    pub fn lookup_back(&self, port: u16) -> Option<(SocketAddrV4, SocketAddrV4)> {
        let mut g = self.gate.lock();
        let s = g.port_map.get_mut(&port)?;
        s.last = Instant::now();
        Some((s.source, s.destination))
    }

    pub fn has_destination(&self, ip: Ipv4Addr) -> bool {
        let g = self.gate.lock();
        g.port_map.values().any(|s| s.destination.ip() == &ip)
    }

    pub fn sweep(&self) {
        let now = Instant::now();
        let mut g = self.gate.lock();
        let dead: Vec<u16> = g
            .port_map
            .iter()
            .filter(|(_, s)| now.duration_since(s.last) > self.timeout)
            .map(|(p, _)| *p)
            .collect();
        for p in dead {
            if let Some(s) = g.port_map.remove(&p) {
                g.addr_map.remove(&s.source);
            }
        }
    }
}
