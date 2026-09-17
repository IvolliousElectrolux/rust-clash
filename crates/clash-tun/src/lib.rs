use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::Result;
use clash_core::{OutboundDialer, ProxyNode, RuleDb};
use parking_lot::Mutex;

pub struct TunService {
    running: AtomicBool,
    starting: AtomicBool,
    rules: Mutex<Option<Arc<RuleDb>>>,
    outbound: Mutex<Option<Arc<OutboundDialer>>>,
    #[cfg(windows)]
    runtime: tokio::sync::Mutex<Option<win::WinRuntime>>,
}

impl TunService {
    pub fn new() -> Self {
        Self {
            running: AtomicBool::new(false),
            starting: AtomicBool::new(false),
            rules: Mutex::new(None),
            outbound: Mutex::new(None),
            #[cfg(windows)]
            runtime: tokio::sync::Mutex::new(None),
        }
    }

    pub fn configure(&self, rules: Arc<RuleDb>, outbound: Arc<OutboundDialer>) {
        *self.rules.lock() = Some(rules);
        *self.outbound.lock() = Some(outbound);
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    pub async fn start(&self) -> Result<()> {
        if !cfg!(windows) {
            anyhow::bail!("Enhance mode (TUN) is only supported on Windows.");
        }
        if self.is_running() {
            return Ok(());
        }
        if self
            .starting
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            while self.starting.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            if self.is_running() {
                return Ok(());
            }
            anyhow::bail!("enhance start already in progress");
        }
        let r = {
            #[cfg(windows)]
            {
                win::start(self).await
            }
            #[cfg(not(windows))]
            {
                Ok(())
            }
        };
        self.starting.store(false, Ordering::SeqCst);
        r
    }

    pub async fn stop(&self) {
        #[cfg(windows)]
        {
            win::stop(self).await;
        }
        self.running.store(false, Ordering::Relaxed);
        clash_core::InterfaceBinder::clear();
    }

    pub async fn on_node_changed(&self, node: Option<&ProxyNode>) -> bool {
        if !self.is_running() {
            return true;
        }
        #[cfg(windows)]
        {
            win::on_node_changed(self, node).await
        }
        #[cfg(not(windows))]
        {
            let _ = node;
            true
        }
    }
}

impl Default for TunService {
    fn default() -> Self {
        Self::new()
    }
}

pub fn recover_orphaned_os_state() {
    #[cfg(windows)]
    win::recover();
}

pub fn ensure_wintun_extracted() {
    #[cfg(windows)]
    win::ensure_wintun();
}

#[cfg(windows)]
mod packet;
#[cfg(windows)]
mod nat;
#[cfg(windows)]
mod wintun;
#[cfg(windows)]
mod probe;
#[cfg(windows)]
mod routes;
#[cfg(windows)]
mod stack;
#[cfg(windows)]
mod win;
