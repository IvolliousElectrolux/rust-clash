use std::collections::HashMap;
use std::ffi::OsStr;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

/// Spawn a helper process without flashing a console window on Windows.
pub fn hidden_command(program: impl AsRef<OsStr>) -> std::process::Command {
    let mut cmd = std::process::Command::new(program);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    cmd
}

pub fn domain_to_ascii(host: &str) -> String {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() || host.bytes().all(|b| b < 128) {
        return host;
    }
    idna::domain_to_ascii(&host).unwrap_or(host)
}

pub struct TtlLru<T: Clone> {
    inner: Mutex<HashMap<String, Entry<T>>>,
    capacity: usize,
}

struct Entry<T> {
    value: T,
    expire: Instant,
}

impl<T: Clone> TtlLru<T> {
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            capacity: capacity.max(16),
        }
    }

    pub fn get(&self, key: &str) -> Option<T> {
        let mut map = self.inner.lock();
        let e = map.get(key)?;
        if Instant::now() > e.expire {
            map.remove(key);
            return None;
        }
        Some(e.value.clone())
    }

    pub fn set(&self, key: String, value: T, ttl: Option<Duration>) {
        let expire = Instant::now() + ttl.unwrap_or(Duration::from_mins_compat(10));
        let mut map = self.inner.lock();
        map.insert(key, Entry { value, expire });
        if map.len() > self.capacity {
            let now = Instant::now();
            map.retain(|_, e| now <= e.expire);
            if map.len() > self.capacity {
                let extra = map.len() - self.capacity;
                let keys: Vec<String> = map.keys().take(extra).cloned().collect();
                for k in keys {
                    map.remove(&k);
                }
            }
        }
    }
}

trait DurationExt {
    fn from_mins_compat(m: u64) -> Duration;
}

impl DurationExt for Duration {
    fn from_mins_compat(m: u64) -> Duration {
        Duration::from_secs(m * 60)
    }
}
