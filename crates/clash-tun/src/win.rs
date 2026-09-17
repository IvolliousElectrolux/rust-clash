use std::net::IpAddr;
use std::sync::atomic::Ordering;

use anyhow::Result;
use clash_core::paths::AppPaths;
use clash_core::ProxyNode;

use crate::probe;
use crate::routes::{self, TunRoutes};
use crate::stack::SystemTcpStack;
use crate::wintun::{WintunDevice, WintunNative};
use crate::TunService;

pub const WINTUN_BYTES: &[u8] = include_bytes!("../../../res/wintun/wintun.dll");

pub struct WinRuntime {
    stack: SystemTcpStack,
    routes: TunRoutes,
    _device: (),
}

pub fn ensure_wintun() {
    let path = AppPaths::wintun_dll();
    if path.exists() {
        if let Ok(on) = std::fs::read(&path) {
            if on == WINTUN_BYTES {
                return;
            }
        }
    }
    let _ = std::fs::create_dir_all(AppPaths::user_data_dir());
    let _ = std::fs::write(path, WINTUN_BYTES);
}

pub async fn start(svc: &TunService) -> Result<()> {
    if svc.runtime.lock().await.is_some() {
        return Ok(());
    }
    match start_inner(svc).await {
        Ok(()) => Ok(()),
        Err(e) => {
            stop(svc).await;
            routes::recover();
            clash_core::InterfaceBinder::clear();
            Err(e)
        }
    }
}

async fn start_inner(svc: &TunService) -> Result<()> {
    let outbound = svc
        .outbound
        .lock()
        .clone()
        .ok_or_else(|| anyhow::anyhow!("TunService not configured"))?;
    let rules = svc
        .rules
        .lock()
        .clone()
        .ok_or_else(|| anyhow::anyhow!("TunService not configured"))?;
    let node = outbound
        .current()
        .filter(|n| !n.is_subscription_info())
        .ok_or_else(|| anyhow::anyhow!("Select a proxy node before enabling enhance mode"))?;
    let ip = outbound
        .resolve_node_ipv4(Some(&node))
        .await
        .ok_or_else(|| anyhow::anyhow!("Could not resolve node IPv4 for anti-loop route"))?;
    let IpAddr::V4(node_ip) = ip else {
        anyhow::bail!("IPv4 required for anti-loop route");
    };

    ensure_wintun();
    let physical = probe::probe()?;
    clash_core::InterfaceBinder::set_physical(Some(physical.clone()));

    let api = WintunNative::load(&AppPaths::wintun_dll())?;
    let device = WintunDevice::create(api)?;
    let mut routes = TunRoutes::configure_interface(physical)?;
    routes.install_anti_loop(node_ip)?;
    routes.disable_ipv6();

    let stack = SystemTcpStack::start(device, rules, outbound).await?;
    routes.install_split_default()?;
    routes.configure_dns_hijack()?;

    *svc.runtime.lock().await = Some(WinRuntime {
        stack,
        routes,
        _device: (),
    });
    svc.running.store(true, Ordering::Relaxed);
    Ok(())
}

pub async fn stop(svc: &TunService) {
    if let Some(mut rt) = svc.runtime.lock().await.take() {
        rt.stack.request_stop();
        rt.routes.uninstall();
    }
    routes::remove_firewall();
    clash_core::InterfaceBinder::clear();
    svc.running.store(false, Ordering::Relaxed);
}

pub async fn on_node_changed(svc: &TunService, node: Option<&ProxyNode>) -> bool {
    let outbound = {
        let g = svc.outbound.lock();
        g.clone()
    };
    let Some(outbound) = outbound else {
        return true;
    };
    let Some(node) = node.filter(|n| !n.is_subscription_info()) else {
        return true;
    };
    let Some(ip) = outbound.resolve_node_ipv4(Some(node)).await else {
        return false;
    };
    let std::net::IpAddr::V4(v4) = ip else {
        return false;
    };
    let mut g = svc.runtime.lock().await;
    let Some(rt) = g.as_mut() else {
        return false;
    };
    if rt.routes.set_node_host_route(v4).is_err() {
        return false;
    }
    rt.stack.bump_generation();
    true
}

pub fn recover() {
    routes::recover();
}
