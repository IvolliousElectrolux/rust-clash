use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use parking_lot::Mutex as SyncMutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, Semaphore};
use tokio_util::sync::CancellationToken;

use crate::io::{DirectDial, Relay, TlsHelloCoalesce, TrafficCounters};
use crate::outbound::OutboundDialer;
use crate::rules::{RuleAction, RuleDb};
use crate::INBOUND_PORT;

pub struct ProxyService {
    rules: Arc<RuleDb>,
    outbound: Arc<OutboundDialer>,
    listening: AtomicBool,
    system_proxy: AtomicBool,
    last_error: SyncMutex<Option<String>>,
    listen: SyncMutex<CancellationToken>,
    conn: Arc<SyncMutex<CancellationToken>>,
    handle: Mutex<Option<tokio::task::JoinHandle<()>>>,
    slots: Arc<Semaphore>,
}

impl ProxyService {
    pub fn new(rules: Arc<RuleDb>, outbound: Arc<OutboundDialer>) -> Self {
        Self {
            rules,
            outbound,
            listening: AtomicBool::new(false),
            system_proxy: AtomicBool::new(false),
            last_error: SyncMutex::new(None),
            listen: SyncMutex::new(CancellationToken::new()),
            conn: Arc::new(SyncMutex::new(CancellationToken::new())),
            handle: Mutex::new(None),
            slots: Arc::new(Semaphore::new(256)),
        }
    }

    pub async fn start(&self) -> anyhow::Result<()> {
        self.set_listening(true).await
    }

    pub async fn stop(&self) {
        let _ = self.set_listening(false).await;
        self.set_system_proxy(false);
    }

    pub fn last_error(&self) -> Option<String> {
        self.last_error.lock().clone()
    }

    pub fn total_speed_kbps(&self) -> i32 {
        TrafficCounters::snapshot_total_kbps()
    }

    /// Cancel in-flight tunnels without dropping the :7887 listener.
    pub fn abort_active(&self) {
        let mut g = self.conn.lock();
        g.cancel();
        *g = CancellationToken::new();
    }

    pub async fn set_listening(&self, on: bool) -> anyhow::Result<()> {
        if on == self.listening.load(Ordering::Relaxed) && on {
            return Ok(());
        }
        if !on {
            self.listening.store(false, Ordering::Relaxed);
            self.listen.lock().cancel();
            self.abort_active();
            if let Some(h) = self.handle.lock().await.take() {
                h.abort();
            }
            return Ok(());
        }
        let listener = TcpListener::bind(("127.0.0.1", INBOUND_PORT)).await?;
        self.listening.store(true, Ordering::Relaxed);
        let listen = CancellationToken::new();
        *self.listen.lock() = listen.clone();
        let rules = self.rules.clone();
        let outbound = self.outbound.clone();
        let conn = self.conn.clone();
        let slots = self.slots.clone();
        let h = tokio::spawn(async move {
            loop {
                let (s, _) = tokio::select! {
                    _ = listen.cancelled() => break,
                    r = listener.accept() => match r {
                        Ok(x) => x,
                        Err(_) => continue,
                    },
                };
                let Ok(permit) = slots.clone().try_acquire_owned() else {
                    tokio::spawn(async move {
                        let mut s = s;
                        Relay::write_http_error(&mut s, 503, "Too many connections").await;
                    });
                    continue;
                };
                let rules = rules.clone();
                let outbound = outbound.clone();
                let abort = conn.lock().clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    let _ = handle_client(s, rules, outbound, abort).await;
                });
            }
        });
        *self.handle.lock().await = Some(h);
        Ok(())
    }

    pub fn set_system_proxy(&self, on: bool) {
        match sysproxy::set_enabled(on) {
            Ok(()) => {
                self.system_proxy.store(on, Ordering::Relaxed);
                *self.last_error.lock() = None;
            }
            Err(e) => {
                *self.last_error.lock() = Some(e);
            }
        }
    }

    pub fn system_proxy_on(&self) -> bool {
        self.system_proxy.load(Ordering::Relaxed)
    }
}

async fn handle_client(
    mut client: TcpStream,
    rules: Arc<RuleDb>,
    outbound: Arc<OutboundDialer>,
    abort: CancellationToken,
) -> anyhow::Result<()> {
    let _ = client.set_nodelay(true);
    let parsed = match tokio::time::timeout(Duration::from_secs(10), read_http_request(&mut client)).await
    {
        Ok(Ok(p)) => p,
        Ok(Err(_)) | Err(_) => {
            Relay::write_http_error(&mut client, 400, "bad request").await;
            return Ok(());
        }
    };
    let HttpRequest {
        method,
        target,
        headers,
        leftover,
    } = parsed;

    if method.eq_ignore_ascii_case("CONNECT") {
        let Some(host_port) = crate::rules::with_port(&target, "443") else {
            Relay::write_http_error(&mut client, 400, "Invalid host").await;
            return Ok(());
        };
        return handle_connect(&mut client, &host_port, leftover, rules, outbound, abort).await;
    }

    if target.to_ascii_lowercase().starts_with("https://") {
        Relay::write_http_error(&mut client, 400, "HTTPS requires CONNECT").await;
        return Ok(());
    }

    let (host_header, path) = match forward_target(&target, &headers) {
        Some(v) => v,
        None => {
            Relay::write_http_error(&mut client, 400, "Invalid host").await;
            return Ok(());
        }
    };
    let Some(host_port) = crate::rules::with_port(&host_header, "80") else {
        Relay::write_http_error(&mut client, 400, "Invalid host").await;
        return Ok(());
    };

    match rules.decide_route(&host_port) {
        RuleAction::Reject => {
            Relay::write_http_error(&mut client, 403, "Forbidden by rules").await;
            return Ok(());
        }
        RuleAction::Direct => {
            let mut remote = tokio::select! {
                _ = abort.cancelled() => return Ok(()),
                r = DirectDial::connect_with(&host_port, Some(outbound.as_ref())) => match r {
                    Ok(s) => s,
                    Err(_) => {
                        Relay::write_http_error(&mut client, 503, "Failed to reach destination").await;
                        return Ok(());
                    }
                },
            };
            let rewritten = rewrite_forward(&method, &path, &host_header, &headers, &leftover);
            remote.write_all(&rewritten).await?;
            tokio::select! {
                _ = abort.cancelled() => {}
                _ = Relay::copy_bidirectional(&mut client, &mut remote) => {}
            }
        }
        RuleAction::Proxy => {
            let mut remote = tokio::select! {
                _ = abort.cancelled() => return Ok(()),
                r = outbound.dial_async(&host_port) => match r {
                    Ok(s) => s,
                    Err(_) => {
                        Relay::write_http_error(&mut client, 503, "Failed to reach destination").await;
                        return Ok(());
                    }
                },
            };
            let rewritten = rewrite_forward(&method, &path, &host_header, &headers, &leftover);
            remote.write_all(&rewritten).await?;
            tokio::select! {
                _ = abort.cancelled() => {}
                _ = Relay::copy_bidirectional(&mut client, &mut remote) => {}
            }
        }
    }
    Ok(())
}

async fn handle_connect(
    client: &mut TcpStream,
    host_port: &str,
    leftover: Vec<u8>,
    rules: Arc<RuleDb>,
    outbound: Arc<OutboundDialer>,
    abort: CancellationToken,
) -> anyhow::Result<()> {
    match rules.decide_route(host_port) {
        RuleAction::Reject => {
            Relay::write_http_error(client, 403, "Forbidden by rules").await;
            Ok(())
        }
        RuleAction::Direct => {
            let host = host_port.to_string();
            let outbound = outbound.clone();
            tunnel_connect(
                client,
                leftover,
                async move {
                    DirectDial::connect_with(&host, Some(outbound.as_ref()))
                        .await
                        .map(|s| Box::pin(s) as clash_proxynet::BoxedStream)
                        .map_err(|e| anyhow::anyhow!(e))
                },
                abort,
            )
            .await
        }
        RuleAction::Proxy => {
            let host = host_port.to_string();
            tunnel_connect(
                client,
                leftover,
                async move { outbound.dial_async(&host).await.map_err(|e| anyhow::anyhow!(e)) },
                abort,
            )
            .await
        }
    }
}

async fn tunnel_connect<F>(
    client: &mut TcpStream,
    leftover: Vec<u8>,
    dial: F,
    abort: CancellationToken,
) -> anyhow::Result<()>
where
    F: std::future::Future<Output = anyhow::Result<clash_proxynet::BoxedStream>>,
{
    const MAX_EARLY: usize = 256 * 1024;
    let mut early = leftover;
    if early.len() > MAX_EARLY {
        Relay::write_http_error(client, 400, "CONNECT early buffer limit exceeded").await;
        return Ok(());
    }
    tokio::pin!(dial);
    let mut tmp = [0u8; 16384];
    let dest = loop {
        tokio::select! {
            _ = abort.cancelled() => return Ok(()),
            r = &mut dial => match r {
                Ok(s) => break s,
                Err(_) => {
                    Relay::write_http_error(client, 503, "Failed to reach destination").await;
                    return Ok(());
                }
            },
            n = client.read(&mut tmp) => {
                match n {
                    Ok(0) => return Ok(()),
                    Ok(n) => {
                        if early.len() + n > MAX_EARLY {
                            Relay::write_http_error(client, 400, "CONNECT early buffer limit exceeded").await;
                            return Ok(());
                        }
                        early.extend_from_slice(&tmp[..n]);
                    }
                    Err(e) => return Err(e.into()),
                }
            }
        }
    };
    let mut dest = dest;
    client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;
    client.flush().await?;
    let _ = TlsHelloCoalesce::flush_first_record(client, &mut dest, &early).await;
    tokio::select! {
        _ = abort.cancelled() => {}
        _ = Relay::copy_bidirectional(client, &mut dest) => {}
    }
    Ok(())
}

struct HttpRequest {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
    leftover: Vec<u8>,
}

async fn read_http_request(client: &mut TcpStream) -> anyhow::Result<HttpRequest> {
    let mut ms = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let n = client.read(&mut buf).await?;
        if n == 0 {
            anyhow::bail!("client closed before headers");
        }
        ms.extend_from_slice(&buf[..n]);
        if let Some(idx) = find_header_end(&ms) {
            if idx > 64 * 1024 {
                anyhow::bail!("headers too large");
            }
            let header = &ms[..idx];
            let leftover = ms[idx + 4..].to_vec();
            let text = String::from_utf8_lossy(header);
            let mut lines = text.split("\r\n");
            let first = lines.next().unwrap_or("");
            let mut parts = first.splitn(3, ' ').filter(|s| !s.is_empty());
            let method = parts.next().unwrap_or("").to_string();
            let target = parts.next().unwrap_or("").to_string();
            if method.is_empty() || target.is_empty() {
                anyhow::bail!("bad request line");
            }
            let mut headers: Vec<(String, String)> = Vec::new();
            for line in lines {
                if line.is_empty() {
                    continue;
                }
                let Some((name, value)) = line.split_once(':') else {
                    continue;
                };
                let name = name.trim().to_string();
                let value = value.trim().to_string();
                if name.eq_ignore_ascii_case("Cookie") {
                    if let Some(existing) = headers.iter_mut().find(|h| h.0.eq_ignore_ascii_case("Cookie"))
                    {
                        existing.1.push_str("; ");
                        existing.1.push_str(&value);
                        continue;
                    }
                }
                headers.push((name, value));
            }
            return Ok(HttpRequest {
                method,
                target,
                headers,
                leftover,
            });
        }
        if ms.len() > 64 * 1024 {
            anyhow::bail!("headers too large");
        }
    }
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn forward_target(target: &str, headers: &[(String, String)]) -> Option<(String, String)> {
    if target.to_ascii_lowercase().starts_with("http://") {
        let u = url::Url::parse(target).ok()?;
        let host = if u.port().is_some() {
            format!("{}:{}", u.host_str()?, u.port()?)
        } else {
            u.host_str()?.to_string()
        };
        let mut path = u.path().to_string();
        if path.is_empty() {
            path = "/".into();
        }
        if let Some(q) = u.query() {
            path.push('?');
            path.push_str(q);
        }
        return Some((host, path));
    }
    let host = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("Host"))
        .map(|(_, v)| v.clone())
        .filter(|s| !s.is_empty())?;
    let path = if target.starts_with('/') {
        target.to_string()
    } else {
        format!("/{target}")
    };
    Some((host, path))
}

fn rewrite_forward(
    method: &str,
    path: &str,
    host: &str,
    headers: &[(String, String)],
    leftover: &[u8],
) -> Vec<u8> {
    let hop = [
        "host",
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "trailers",
        "transfer-encoding",
        "upgrade",
        "proxy-connection",
    ];
    let mut out = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\n");
    for (k, v) in headers {
        if hop.iter().any(|h| k.eq_ignore_ascii_case(h)) {
            continue;
        }
        out.push_str(k);
        out.push_str(": ");
        out.push_str(v);
        out.push_str("\r\n");
    }
    out.push_str("Connection: close\r\n\r\n");
    let mut bytes = out.into_bytes();
    bytes.extend_from_slice(leftover);
    bytes
}

#[cfg(test)]
fn rewrite_http_request(raw: &[u8]) -> Vec<u8> {
    let text = String::from_utf8_lossy(raw);
    let mut lines = text.split("\r\n");
    let first = lines.next().unwrap_or("");
    let parts: Vec<&str> = first.split_whitespace().collect();
    let method = parts.first().copied().unwrap_or("GET");
    let target = parts.get(1).copied().unwrap_or("/");
    let ver = parts.get(2).copied().unwrap_or("HTTP/1.1");
    let (path, host_from_uri) = split_forward_target(target);
    let hop = [
        "host",
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "trailers",
        "transfer-encoding",
        "upgrade",
        "proxy-connection",
    ];
    let mut host = host_from_uri;
    let mut kept = Vec::new();
    let mut body = "";
    for line in lines {
        if line.is_empty() {
            let rest = text.split("\r\n\r\n").nth(1).unwrap_or("");
            body = rest;
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("host") {
                if host.is_none() {
                    host = Some(value.trim().to_string());
                }
                continue;
            }
            if hop.iter().any(|h| name.eq_ignore_ascii_case(h)) {
                continue;
            }
            kept.push((name.trim().to_string(), value.trim().to_string()));
        }
    }
    let mut out = format!("{method} {path} {ver}\r\n");
    if let Some(h) = host {
        out.push_str("Host: ");
        out.push_str(&h);
        out.push_str("\r\n");
    }
    for (k, v) in kept {
        out.push_str(&k);
        out.push_str(": ");
        out.push_str(&v);
        out.push_str("\r\n");
    }
    out.push_str("Connection: close\r\n\r\n");
    out.push_str(body);
    out.into_bytes()
}

#[cfg(test)]
fn split_forward_target(target: &str) -> (String, Option<String>) {
    if let Ok(u) = url::Url::parse(target) {
        if u.scheme() == "http" || u.scheme() == "https" {
            let mut path = u.path().to_string();
            if path.is_empty() {
                path = "/".into();
            }
            if let Some(q) = u.query() {
                path.push('?');
                path.push_str(q);
            }
            let host = u.host_str().map(|h| match u.port() {
                Some(p) => format!("{h}:{p}"),
                None => h.to_string(),
            });
            return (path, host);
        }
    }
    (if target.is_empty() { "/".into() } else { target.to_string() }, None)
}

pub fn recover_orphaned_proxy() {
    sysproxy::recover();
}

pub fn force_restore() {
    let _ = sysproxy::set_enabled(false);
}

pub fn is_administrator() -> bool {
    sysproxy::is_admin()
}

pub fn try_relaunch_elevated() -> bool {
    try_relaunch_elevated_with("")
}

pub fn try_relaunch_elevated_with(args: &str) -> bool {
    sysproxy::relaunch_elevated(args)
}

pub fn wait_for_pid(pid: u32, timeout: Duration) {
    sysproxy::wait_for_pid(pid, timeout);
}

mod sysproxy {
    use std::time::Duration;

    use crate::paths::AppPaths;
    use crate::INBOUND_PORT;

    pub fn set_enabled(on: bool) -> Result<(), String> {
        #[cfg(windows)]
        {
            return windows::set(on);
        }
        #[cfg(target_os = "macos")]
        {
            return macos::set(on);
        }
        #[cfg(target_os = "linux")]
        {
            return gnome::set(on);
        }
        #[allow(unreachable_code)]
        Err("unsupported".into())
    }

    pub fn recover() {
        #[cfg(windows)]
        windows::recover_orphaned();
        #[cfg(target_os = "macos")]
        macos::recover_orphaned();
        #[cfg(target_os = "linux")]
        gnome::recover_orphaned();
    }

    pub fn is_admin() -> bool {
        #[cfg(windows)]
        {
            return windows::is_admin();
        }
        #[cfg(not(windows))]
        true
    }

    pub fn relaunch_elevated(args: &str) -> bool {
        #[cfg(windows)]
        {
            return windows::relaunch(args);
        }
        #[cfg(not(windows))]
        {
            let _ = args;
            false
        }
    }

    pub fn wait_for_pid(pid: u32, timeout: Duration) {
        #[cfg(windows)]
        windows::wait_pid(pid, timeout);
        #[cfg(not(windows))]
        let _ = (pid, timeout);
    }

    #[cfg(windows)]
    mod windows {
        use super::*;
        use std::fs;
        use std::sync::Once;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::time::Duration;
        use windows_sys::Win32::System::Registry::*;
        use windows_sys::Win32::UI::Shell::ShellExecuteW;
        use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

        const KEY: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";
        const BYPASS: &str = "localhost;127.*;::1;[::1];10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;192.168.*;169.254.*;<local>;<loopback>";
        static APPLIED: parking_lot::Mutex<bool> = parking_lot::Mutex::new(false);
        static KEEPALIVE: AtomicBool = AtomicBool::new(false);
        static KEEP_ONCE: Once = Once::new();

        pub fn set(on: bool) -> Result<(), String> {
            if on {
                {
                    let mut applied = APPLIED.lock();
                    if !*applied {
                        save_undo();
                        apply_on()?;
                        *applied = true;
                    }
                }
                commit_on()?;
                std::thread::sleep(Duration::from_millis(200));
                if !currently_ours() {
                    commit_on()?;
                }
                if !currently_ours() {
                    *APPLIED.lock() = false;
                    KEEPALIVE.store(false, Ordering::Relaxed);
                    return Err(stolen_msg());
                }
                KEEPALIVE.store(true, Ordering::Relaxed);
                start_keepalive();
            } else {
                KEEPALIVE.store(false, Ordering::Relaxed);
                let mut applied = APPLIED.lock();
                if *applied || currently_ours() {
                    restore_undo();
                    if currently_ours() {
                        apply_off()?;
                    }
                    *applied = false;
                }
                let _ = notify();
            }
            Ok(())
        }

        fn commit_on() -> Result<(), String> {
            apply_on()
        }

        fn stolen_msg() -> String {
            let server = read_str("ProxyServer").unwrap_or_default();
            if server.contains(":7890") {
                "系统代理被 Clash Party 覆盖. 请先退出 Clash Party, 再开代理模式.".into()
            } else {
                format!(
                    "系统代理被其他程序覆盖 (enable={} server={server})",
                    read_dword("ProxyEnable").unwrap_or(0)
                )
            }
        }

        fn start_keepalive() {
            KEEP_ONCE.call_once(|| {
                let _ = std::thread::Builder::new()
                    .name("sysproxy-keep".into())
                    .spawn(|| loop {
                        std::thread::sleep(Duration::from_millis(800));
                        if !KEEPALIVE.load(Ordering::Relaxed) {
                            continue;
                        }
                        if currently_ours() {
                            continue;
                        }
                        if !KEEPALIVE.load(Ordering::Relaxed) {
                            continue;
                        }
                        let _ = commit_on();
                    });
            });
        }

        pub fn recover_orphaned() {
            KEEPALIVE.store(false, Ordering::Relaxed);
            if !currently_ours() {
                let _ = fs::remove_file(AppPaths::proxy_undo_file());
                *APPLIED.lock() = false;
                return;
            }
            *APPLIED.lock() = true;
            restore_undo();
            if currently_ours() {
                let _ = apply_off();
            }
            *APPLIED.lock() = false;
            let _ = notify();
        }

        fn apply_on() -> Result<(), String> {
            let server = format!("127.0.0.1:{INBOUND_PORT}");
            set_values(1, &server, BYPASS)?;
            set_dword(KEY, "AutoDetect", 0);
            delete_value(KEY, "AutoConfigURL");
            apply_wininet(true, &server, BYPASS);
            notify()?;
            Ok(())
        }

        fn apply_off() -> Result<(), String> {
            set_values(0, "", "")?;
            apply_wininet(false, "", "");
            Ok(())
        }

        fn currently_ours() -> bool {
            read_dword("ProxyEnable").unwrap_or(0) == 1
                && read_str("ProxyServer")
                    .unwrap_or_default()
                    .contains(&format!("127.0.0.1:{INBOUND_PORT}"))
        }

        fn save_undo() {
            let enable = read_dword("ProxyEnable").unwrap_or(0);
            let server = read_str("ProxyServer").unwrap_or_default();
            let ov = read_str("ProxyOverride").unwrap_or_default();
            let json = format!(
                "{{\"enable\":{enable},\"server\":{},\"override\":{}}}",
                serde_json::to_string(&server).unwrap_or("\"\"".into()),
                serde_json::to_string(&ov).unwrap_or("\"\"".into())
            );
            let _ = fs::write(AppPaths::proxy_undo_file(), json);
        }

        fn restore_undo() {
            if let Ok(text) = fs::read_to_string(AppPaths::proxy_undo_file()) {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
                    let enable = v.get("enable").and_then(|x| x.as_i64()).unwrap_or(0) as u32;
                    let server = v.get("server").and_then(|x| x.as_str()).unwrap_or("");
                    let ov = v.get("override").and_then(|x| x.as_str()).unwrap_or("");
                    let _ = set_values(enable, server, ov);
                    apply_wininet(enable == 1, server, ov);
                }
                let _ = fs::remove_file(AppPaths::proxy_undo_file());
            }
        }

        fn set_values(enable: u32, server: &str, ov: &str) -> Result<(), String> {
            unsafe {
                let mut h: HKEY = std::ptr::null_mut();
                let sub: Vec<u16> = KEY.encode_utf16().chain([0]).collect();
                let mut disp = 0u32;
                let st = RegCreateKeyExW(
                    HKEY_CURRENT_USER,
                    sub.as_ptr(),
                    0,
                    std::ptr::null(),
                    0,
                    KEY_WRITE | KEY_QUERY_VALUE,
                    std::ptr::null(),
                    &mut h,
                    &mut disp,
                );
                if st != 0 {
                    return Err(format!("RegCreateKeyEx {st}"));
                }
                let e = enable;
                let name_en = w("ProxyEnable");
                let st = RegSetValueExW(
                    h,
                    name_en.as_ptr(),
                    0,
                    REG_DWORD,
                    &e as *const u32 as *const u8,
                    4,
                );
                if st != 0 {
                    RegCloseKey(h);
                    return Err(format!("RegSetValueEx ProxyEnable {st}"));
                }
                set_str(h, "ProxyServer", server)?;
                set_str(h, "ProxyOverride", ov)?;
                RegCloseKey(h);
            }
            Ok(())
        }

        fn set_str(h: HKEY, name: &str, val: &str) -> Result<(), String> {
            let wide: Vec<u16> = val.encode_utf16().chain([0]).collect();
            let name_w = w(name);
            let st = unsafe {
                RegSetValueExW(
                    h,
                    name_w.as_ptr(),
                    0,
                    REG_SZ,
                    wide.as_ptr() as *const u8,
                    (wide.len() * 2) as u32,
                )
            };
            if st != 0 {
                Err(format!("RegSetValueEx {name} {st}"))
            } else {
                Ok(())
            }
        }

        fn read_dword(name: &str) -> Option<u32> {
            unsafe {
                let mut h: HKEY = std::ptr::null_mut();
                let sub: Vec<u16> = KEY.encode_utf16().chain([0]).collect();
                if RegOpenKeyExW(HKEY_CURRENT_USER, sub.as_ptr(), 0, KEY_QUERY_VALUE, &mut h) != 0 {
                    return None;
                }
                let mut ty = 0u32;
                let mut data = 0u32;
                let mut sz = 4u32;
                let st = RegQueryValueExW(h, w(name).as_ptr(), std::ptr::null_mut(), &mut ty, &mut data as *mut u32 as *mut u8, &mut sz);
                RegCloseKey(h);
                (st == 0).then_some(data)
            }
        }

        fn read_str(name: &str) -> Option<String> {
            unsafe {
                let mut h: HKEY = std::ptr::null_mut();
                let sub: Vec<u16> = KEY.encode_utf16().chain([0]).collect();
                if RegOpenKeyExW(HKEY_CURRENT_USER, sub.as_ptr(), 0, KEY_QUERY_VALUE, &mut h) != 0 {
                    return None;
                }
                let mut ty = 0u32;
                let mut sz = 0u32;
                RegQueryValueExW(h, w(name).as_ptr(), std::ptr::null_mut(), &mut ty, std::ptr::null_mut(), &mut sz);
                let mut buf = vec![0u16; (sz as usize / 2) + 1];
                let st = RegQueryValueExW(h, w(name).as_ptr(), std::ptr::null_mut(), &mut ty, buf.as_mut_ptr() as *mut u8, &mut sz);
                RegCloseKey(h);
                if st != 0 {
                    return None;
                }
                Some(String::from_utf16_lossy(&buf).trim_end_matches('\0').to_string())
            }
        }

        fn set_dword(sub: &str, name: &str, value: u32) {
            unsafe {
                let mut h: HKEY = std::ptr::null_mut();
                let path: Vec<u16> = sub.encode_utf16().chain([0]).collect();
                let mut disp = 0u32;
                if RegCreateKeyExW(
                    HKEY_CURRENT_USER,
                    path.as_ptr(),
                    0,
                    std::ptr::null(),
                    0,
                    KEY_WRITE | KEY_QUERY_VALUE,
                    std::ptr::null(),
                    &mut h,
                    &mut disp,
                ) != 0
                {
                    return;
                }
                let name_w = w(name);
                let _ = RegSetValueExW(
                    h,
                    name_w.as_ptr(),
                    0,
                    REG_DWORD,
                    &value as *const u32 as *const u8,
                    4,
                );
                RegCloseKey(h);
            }
        }

        fn delete_value(sub: &str, name: &str) {
            unsafe {
                let mut h: HKEY = std::ptr::null_mut();
                let path: Vec<u16> = sub.encode_utf16().chain([0]).collect();
                if RegOpenKeyExW(HKEY_CURRENT_USER, path.as_ptr(), 0, KEY_WRITE, &mut h) != 0 {
                    return;
                }
                let name_w = w(name);
                let _ = RegDeleteValueW(h, name_w.as_ptr());
                RegCloseKey(h);
            }
        }

        fn write_binary(sub: &str, name: &str, data: &[u8]) {
            unsafe {
                let mut h: HKEY = std::ptr::null_mut();
                let path: Vec<u16> = sub.encode_utf16().chain([0]).collect();
                let mut disp = 0u32;
                if RegCreateKeyExW(
                    HKEY_CURRENT_USER,
                    path.as_ptr(),
                    0,
                    std::ptr::null(),
                    0,
                    KEY_WRITE | KEY_QUERY_VALUE,
                    std::ptr::null(),
                    &mut h,
                    &mut disp,
                ) != 0
                {
                    return;
                }
                let name_w = w(name);
                let _ = RegSetValueExW(
                    h,
                    name_w.as_ptr(),
                    0,
                    REG_BINARY,
                    data.as_ptr(),
                    data.len() as u32,
                );
                RegCloseKey(h);
            }
        }

        fn read_binary(sub: &str, name: &str) -> Option<Vec<u8>> {
            unsafe {
                let mut h: HKEY = std::ptr::null_mut();
                let path: Vec<u16> = sub.encode_utf16().chain([0]).collect();
                if RegOpenKeyExW(HKEY_CURRENT_USER, path.as_ptr(), 0, KEY_QUERY_VALUE, &mut h) != 0 {
                    return None;
                }
                let name_w = w(name);
                let mut ty = 0u32;
                let mut sz = 0u32;
                RegQueryValueExW(
                    h,
                    name_w.as_ptr(),
                    std::ptr::null_mut(),
                    &mut ty,
                    std::ptr::null_mut(),
                    &mut sz,
                );
                if sz == 0 {
                    RegCloseKey(h);
                    return None;
                }
                let mut buf = vec![0u8; sz as usize];
                let st = RegQueryValueExW(
                    h,
                    name_w.as_ptr(),
                    std::ptr::null_mut(),
                    &mut ty,
                    buf.as_mut_ptr(),
                    &mut sz,
                );
                RegCloseKey(h);
                (st == 0).then_some(buf)
            }
        }

        #[allow(dead_code)]
        const CONNECTIONS: &str =
            "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Connections";

        #[allow(dead_code)]
        fn write_connection_blobs(enable: bool, server: &str, bypass: &str) {
            for name in ["DefaultConnectionSettings", "SavedLegacySettings"] {
                let old = read_binary(CONNECTIONS, name);
                let blob = build_connection_blob(enable, server, bypass, old.as_deref());
                write_binary(CONNECTIONS, name, &blob);
            }
        }

        #[allow(dead_code)]
        fn build_connection_blob(
            enable: bool,
            server: &str,
            bypass: &str,
            old: Option<&[u8]>,
        ) -> Vec<u8> {
            // Win11 blob: version @0 (0x47), counter @4, flags @8, then len-prefixed ASCII strings.
            let version = old
                .and_then(|o| o.get(0..4))
                .and_then(|b| b.try_into().ok())
                .map(u32::from_le_bytes)
                .filter(|v| *v >= 0x40 && *v <= 0x50)
                .unwrap_or(0x47);
            let counter = old
                .and_then(|o| o.get(4..8))
                .and_then(|b| b.try_into().ok())
                .map(u32::from_le_bytes)
                .unwrap_or(0)
                .wrapping_add(1);
            let flags: u32 = if enable { 0x03 } else { 0x01 };
            let proxy = server.as_bytes();
            let bypass_b = bypass.as_bytes();
            let mut out = Vec::with_capacity(64 + proxy.len() + bypass_b.len());
            out.extend_from_slice(&version.to_le_bytes());
            out.extend_from_slice(&counter.to_le_bytes());
            out.extend_from_slice(&flags.to_le_bytes());
            out.extend_from_slice(&(proxy.len() as u32).to_le_bytes());
            out.extend_from_slice(proxy);
            out.extend_from_slice(&(bypass_b.len() as u32).to_le_bytes());
            out.extend_from_slice(bypass_b);
            out.extend_from_slice(&0u32.to_le_bytes());
            let min_len = old.map(|o| o.len()).unwrap_or(56).max(out.len() + 32);
            out.resize(min_len, 0);
            out
        }

        fn apply_wininet(on: bool, server: &str, bypass: &str) {
            use windows_sys::Win32::Networking::WinInet::*;
            let flags = if on {
                PROXY_TYPE_DIRECT | PROXY_TYPE_PROXY
            } else {
                PROXY_TYPE_DIRECT
            };
            if !set_per_conn(flags, server, bypass) {
                let _ = set_per_conn_legacy(flags, server, bypass);
            }
        }

        fn set_per_conn(flags: u32, server: &str, bypass: &str) -> bool {
            use windows_sys::Win32::Networking::WinInet::*;
            let mut server_w: Vec<u16> = server.encode_utf16().chain([0]).collect();
            let mut bypass_w: Vec<u16> = bypass.encode_utf16().chain([0]).collect();
            let mut opts = [
                INTERNET_PER_CONN_OPTIONW {
                    dwOption: INTERNET_PER_CONN_FLAGS_UI,
                    Value: INTERNET_PER_CONN_OPTIONW_0 { dwValue: flags },
                },
                INTERNET_PER_CONN_OPTIONW {
                    dwOption: INTERNET_PER_CONN_FLAGS,
                    Value: INTERNET_PER_CONN_OPTIONW_0 { dwValue: flags },
                },
                INTERNET_PER_CONN_OPTIONW {
                    dwOption: INTERNET_PER_CONN_PROXY_SERVER,
                    Value: INTERNET_PER_CONN_OPTIONW_0 {
                        pszValue: server_w.as_mut_ptr(),
                    },
                },
                INTERNET_PER_CONN_OPTIONW {
                    dwOption: INTERNET_PER_CONN_PROXY_BYPASS,
                    Value: INTERNET_PER_CONN_OPTIONW_0 {
                        pszValue: bypass_w.as_mut_ptr(),
                    },
                },
            ];
            let mut list = INTERNET_PER_CONN_OPTION_LISTW {
                dwSize: std::mem::size_of::<INTERNET_PER_CONN_OPTION_LISTW>() as u32,
                pszConnection: std::ptr::null_mut(),
                dwOptionCount: opts.len() as u32,
                dwOptionError: 0,
                pOptions: opts.as_mut_ptr(),
            };
            unsafe {
                InternetSetOptionW(
                    std::ptr::null(),
                    INTERNET_OPTION_PER_CONNECTION_OPTION,
                    (&raw mut list).cast(),
                    list.dwSize,
                ) != 0
            }
        }

        fn set_per_conn_legacy(flags: u32, server: &str, bypass: &str) -> bool {
            use windows_sys::Win32::Networking::WinInet::*;
            let mut server_w: Vec<u16> = server.encode_utf16().chain([0]).collect();
            let mut bypass_w: Vec<u16> = bypass.encode_utf16().chain([0]).collect();
            let mut opts = [
                INTERNET_PER_CONN_OPTIONW {
                    dwOption: INTERNET_PER_CONN_FLAGS,
                    Value: INTERNET_PER_CONN_OPTIONW_0 { dwValue: flags },
                },
                INTERNET_PER_CONN_OPTIONW {
                    dwOption: INTERNET_PER_CONN_PROXY_SERVER,
                    Value: INTERNET_PER_CONN_OPTIONW_0 {
                        pszValue: server_w.as_mut_ptr(),
                    },
                },
                INTERNET_PER_CONN_OPTIONW {
                    dwOption: INTERNET_PER_CONN_PROXY_BYPASS,
                    Value: INTERNET_PER_CONN_OPTIONW_0 {
                        pszValue: bypass_w.as_mut_ptr(),
                    },
                },
            ];
            let mut list = INTERNET_PER_CONN_OPTION_LISTW {
                dwSize: std::mem::size_of::<INTERNET_PER_CONN_OPTION_LISTW>() as u32,
                pszConnection: std::ptr::null_mut(),
                dwOptionCount: opts.len() as u32,
                dwOptionError: 0,
                pOptions: opts.as_mut_ptr(),
            };
            unsafe {
                InternetSetOptionW(
                    std::ptr::null(),
                    INTERNET_OPTION_PER_CONNECTION_OPTION,
                    (&raw mut list).cast(),
                    list.dwSize,
                ) != 0
            }
        }

        fn notify() -> Result<(), String> {
            use windows_sys::Win32::Networking::WinInet::*;
            unsafe {
                if InternetSetOptionW(
                    std::ptr::null(),
                    INTERNET_OPTION_SETTINGS_CHANGED,
                    std::ptr::null(),
                    0,
                ) == 0
                {
                    return Err("InternetSetOption SETTINGS_CHANGED failed".into());
                }
                let _ = InternetSetOptionW(
                    std::ptr::null(),
                    INTERNET_OPTION_PROXY_SETTINGS_CHANGED,
                    std::ptr::null(),
                    0,
                );
                let _ = InternetSetOptionW(
                    std::ptr::null(),
                    INTERNET_OPTION_REFRESH,
                    std::ptr::null(),
                    0,
                );
            }
            Ok(())
        }

        fn w(s: &str) -> Vec<u16> {
            s.encode_utf16().chain([0]).collect()
        }

        pub fn is_admin() -> bool {
            unsafe {
                let mut token = std::ptr::null_mut();
                if windows_sys::Win32::System::Threading::OpenProcessToken(
                    windows_sys::Win32::System::Threading::GetCurrentProcess(),
                    0x0008,
                    &mut token,
                ) == 0
                {
                    return false;
                }
                #[repr(C)]
                struct Elevation { token_is_elevated: u32 }
                let mut elev = Elevation { token_is_elevated: 0 };
                let mut sz = std::mem::size_of::<Elevation>() as u32;
                windows_sys::Win32::Security::GetTokenInformation(
                    token,
                    20, // TokenElevation
                    &mut elev as *mut _ as *mut _,
                    sz,
                    &mut sz,
                );
                windows_sys::Win32::Foundation::CloseHandle(token);
                elev.token_is_elevated != 0
            }
        }

        pub fn relaunch(args: &str) -> bool {
            let Ok(exe) = std::env::current_exe() else {
                return false;
            };
            let exe_w: Vec<u16> = exe.to_string_lossy().encode_utf16().chain([0]).collect();
            let op: Vec<u16> = "runas".encode_utf16().chain([0]).collect();
            let params_w: Vec<u16> = if args.is_empty() {
                Vec::new()
            } else {
                args.encode_utf16().chain([0]).collect()
            };
            let params_ptr = if params_w.is_empty() {
                std::ptr::null()
            } else {
                params_w.as_ptr()
            };
            // ShellExecuteW must not run on the GPUI UI thread: UAC blocks it and
            // the window stops pumping, so Windows shows "已停止运行".
            unsafe {
                let _ = windows_sys::Win32::System::Com::CoInitializeEx(
                    std::ptr::null(),
                    windows_sys::Win32::System::Com::COINIT_APARTMENTTHREADED as u32,
                );
                let r = ShellExecuteW(
                    std::ptr::null_mut(),
                    op.as_ptr(),
                    exe_w.as_ptr(),
                    params_ptr,
                    std::ptr::null(),
                    SW_SHOWNORMAL,
                );
                windows_sys::Win32::System::Com::CoUninitialize();
                r as usize > 32
            }
        }

        pub fn wait_pid(pid: u32, timeout: Duration) {
            if pid == 0 {
                return;
            }
            unsafe {
                const SYNCHRONIZE: u32 = 0x0010_0000;
                let h = windows_sys::Win32::System::Threading::OpenProcess(SYNCHRONIZE, 0, pid);
                if h.is_null() {
                    return;
                }
                let ms = timeout.as_millis().min(u32::MAX as u128) as u32;
                windows_sys::Win32::System::Threading::WaitForSingleObject(h, ms);
                windows_sys::Win32::Foundation::CloseHandle(h);
            }
        }

        #[cfg(test)]
        mod blob_tests {
            use super::*;

            #[test]
            fn win11_blob_keeps_version_increments_counter() {
                let mut old = vec![0u8; 32];
                old[0] = 0x47;
                old[4] = 0xB8;
                old[5] = 0x15;
                old[8] = 0x01;
                let b = build_connection_blob(true, "127.0.0.1:7887", "localhost", Some(&old));
                assert_eq!(&b[0..4], &[0x47, 0, 0, 0]);
                assert_eq!(&b[4..8], &[0xB9, 0x15, 0, 0]);
                assert_eq!(&b[8..12], &[3, 0, 0, 0]);
                assert_eq!(&b[12..16], &[14, 0, 0, 0]);
                assert_eq!(&b[16..30], b"127.0.0.1:7887");
            }

            #[test]
            fn per_conn_structs_match_win64() {
                use std::mem::size_of;
                use windows_sys::Win32::Networking::WinInet::{
                    INTERNET_PER_CONN_OPTION_LISTW, INTERNET_PER_CONN_OPTIONW,
                };
                assert_eq!(size_of::<INTERNET_PER_CONN_OPTIONW>(), 16);
                assert_eq!(size_of::<INTERNET_PER_CONN_OPTION_LISTW>(), 32);
            }

            #[test]
            fn set_enabled_writes_7887() {
                let prev_en = read_dword("ProxyEnable");
                let prev_srv = read_str("ProxyServer");
                let prev_ov = read_str("ProxyOverride");
                let prev_blob = read_binary(CONNECTIONS, "DefaultConnectionSettings");
                apply_on().expect("apply_on");
                let enable = read_dword("ProxyEnable");
                let server = read_str("ProxyServer");
                if let Some(en) = prev_en {
                    let _ = set_values(
                        en,
                        prev_srv.as_deref().unwrap_or(""),
                        prev_ov.as_deref().unwrap_or(""),
                    );
                }
                if let Some(blob) = prev_blob {
                    write_binary(CONNECTIONS, "DefaultConnectionSettings", &blob);
                }
                let _ = notify();
                *APPLIED.lock() = false;
                KEEPALIVE.store(false, Ordering::Relaxed);
                assert_eq!(enable, Some(1), "server={server:?}");
                assert!(
                    server.as_deref().unwrap_or("").contains("127.0.0.1:7887"),
                    "server={server:?}"
                );
            }
        }
    }

    #[cfg(target_os = "macos")]
    mod macos {
        use super::*;
        use std::fs;

        pub fn set(on: bool) -> Result<(), String> {
            if on {
                apply()
            } else {
                restore();
                Ok(())
            }
        }

        pub fn recover_orphaned() {
            let Some(snaps) = load_undo() else {
                return;
            };
            if !currently_ours() {
                let _ = fs::remove_file(AppPaths::proxy_undo_mac());
                return;
            }
            for s in snaps {
                restore_service(&s);
            }
            let _ = fs::remove_file(AppPaths::proxy_undo_mac());
        }

        fn currently_ours() -> bool {
            list_services().iter().any(|svc| {
                let st = capture(svc, "getwebproxy");
                st.enabled && st.server == "127.0.0.1" && st.port.to_string() == INBOUND_PORT.to_string()
            })
        }

        fn apply() -> Result<(), String> {
            let services = list_services();
            if services.is_empty() {
                return Err("No network services found for networksetup".into());
            }
            let snaps: Vec<ServiceSnap> = services
                .iter()
                .map(|s| ServiceSnap {
                    name: s.clone(),
                    web: capture(s, "getwebproxy"),
                    secure: capture(s, "getsecurewebproxy"),
                })
                .collect();
            write_undo(&snaps);
            for svc in &services {
                run(&["-setwebproxy", svc, "127.0.0.1", &INBOUND_PORT.to_string()])?;
                run(&["-setsecurewebproxy", svc, "127.0.0.1", &INBOUND_PORT.to_string()])?;
                run(&["-setwebproxystate", svc, "on"])?;
                run(&["-setsecurewebproxystate", svc, "on"])?;
            }
            Ok(())
        }

        fn restore() {
            if let Some(snaps) = load_undo() {
                for s in snaps {
                    restore_service(&s);
                }
            }
            let _ = fs::remove_file(AppPaths::proxy_undo_mac());
        }

        fn restore_service(s: &ServiceSnap) {
            restore_one(&s.name, "-setwebproxy", "-setwebproxystate", &s.web);
            restore_one(&s.name, "-setsecurewebproxy", "-setsecurewebproxystate", &s.secure);
        }

        fn restore_one(svc: &str, set_cmd: &str, state_cmd: &str, st: &ProxyState) {
            if st.enabled && !st.server.is_empty() && st.port > 0 {
                let _ = run(&[set_cmd, svc, &st.server, &st.port.to_string()]);
                let _ = run(&[state_cmd, svc, "on"]);
            } else {
                let _ = run(&[state_cmd, svc, "off"]);
            }
        }

        fn list_services() -> Vec<String> {
            let out = std::process::Command::new("/usr/sbin/networksetup")
                .arg("-listallnetworkservices")
                .output();
            let Ok(out) = out else {
                return Vec::new();
            };
            let text = String::from_utf8_lossy(&out.stdout);
            let mut list = Vec::new();
            for line in text.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with("An asterisk") {
                    continue;
                }
                if let Some(rest) = line.strip_prefix("* ") {
                    let _ = rest;
                    continue;
                }
                list.push(line.to_string());
            }
            list
        }

        fn capture(svc: &str, cmd: &str) -> ProxyState {
            let out = std::process::Command::new("/usr/sbin/networksetup")
                .args([cmd, svc])
                .output();
            let Ok(out) = out else {
                return ProxyState::default();
            };
            let text = String::from_utf8_lossy(&out.stdout);
            let mut st = ProxyState::default();
            for line in text.lines() {
                let (k, v) = match line.split_once(':') {
                    Some(x) => x,
                    None => continue,
                };
                let v = v.trim();
                match k.trim() {
                    "Enabled" => st.enabled = v.eq_ignore_ascii_case("yes") || v == "1",
                    "Server" => st.server = v.to_string(),
                    "Port" => st.port = v.parse().unwrap_or(0),
                    _ => {}
                }
            }
            st
        }

        fn run(args: &[&str]) -> Result<(), String> {
            let st = std::process::Command::new("/usr/sbin/networksetup")
                .args(args)
                .status()
                .map_err(|e| e.to_string())?;
            if st.success() {
                Ok(())
            } else {
                Err(format!("networksetup {} failed", args.join(" ")))
            }
        }

        fn write_undo(snaps: &[ServiceSnap]) {
            let mut s = String::new();
            for x in snaps {
                s.push_str(&format!(
                    "{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
                    x.name, x.web.enabled, x.web.server, x.web.port, x.secure.enabled, x.secure.server, x.secure.port
                ));
            }
            let _ = fs::write(AppPaths::proxy_undo_mac(), s);
        }

        fn load_undo() -> Option<Vec<ServiceSnap>> {
            let text = fs::read_to_string(AppPaths::proxy_undo_mac()).ok()?;
            let mut list = Vec::new();
            for line in text.lines() {
                let p: Vec<&str> = line.split('\t').collect();
                if p.len() < 7 {
                    continue;
                }
                list.push(ServiceSnap {
                    name: p[0].to_string(),
                    web: ProxyState {
                        enabled: p[1].eq_ignore_ascii_case("true"),
                        server: p[2].to_string(),
                        port: p[3].parse().unwrap_or(0),
                    },
                    secure: ProxyState {
                        enabled: p[4].eq_ignore_ascii_case("true"),
                        server: p[5].to_string(),
                        port: p[6].parse().unwrap_or(0),
                    },
                });
            }
            Some(list)
        }

        #[derive(Default)]
        struct ProxyState {
            enabled: bool,
            server: String,
            port: i32,
        }
        struct ServiceSnap {
            name: String,
            web: ProxyState,
            secure: ProxyState,
        }
    }

    #[cfg(target_os = "linux")]
    mod gnome {
        use super::*;
        use std::fs;

        pub fn set(on: bool) -> Result<(), String> {
            if on {
                apply()
            } else {
                restore();
                Ok(())
            }
        }

        pub fn recover_orphaned() {
            let Some(snap) = load_undo() else {
                return;
            };
            let host = gget("org.gnome.system.proxy.http", "host").unwrap_or_default();
            let port = gget("org.gnome.system.proxy.http", "port").unwrap_or_default();
            let mode = gget("org.gnome.system.proxy", "mode").unwrap_or_default();
            if !mode.contains("manual")
                || !host.contains("127.0.0.1")
                || port.trim() != INBOUND_PORT.to_string()
            {
                let _ = fs::remove_file(AppPaths::proxy_undo_gnome());
                return;
            }
            apply_snap(&snap);
            let _ = fs::remove_file(AppPaths::proxy_undo_gnome());
        }

        fn apply() -> Result<(), String> {
            let snap = Snap {
                mode: gget("org.gnome.system.proxy", "mode").unwrap_or_else(|| "none".into()),
                use_same: gget("org.gnome.system.proxy", "use-same-proxy").unwrap_or_else(|| "true".into()),
                http_host: gget("org.gnome.system.proxy.http", "host").unwrap_or_default(),
                http_port: gget("org.gnome.system.proxy.http", "port").unwrap_or_else(|| "0".into()),
                http_enabled: gget("org.gnome.system.proxy.http", "enabled").unwrap_or_else(|| "false".into()),
                https_host: gget("org.gnome.system.proxy.https", "host").unwrap_or_default(),
                https_port: gget("org.gnome.system.proxy.https", "port").unwrap_or_else(|| "0".into()),
            };
            write_undo(&snap);
            gset("org.gnome.system.proxy", "mode", "manual")?;
            gset("org.gnome.system.proxy", "use-same-proxy", "true")?;
            gset("org.gnome.system.proxy.http", "enabled", "true")?;
            gset("org.gnome.system.proxy.http", "host", "127.0.0.1")?;
            gset("org.gnome.system.proxy.http", "port", &INBOUND_PORT.to_string())?;
            gset("org.gnome.system.proxy.https", "host", "127.0.0.1")?;
            gset("org.gnome.system.proxy.https", "port", &INBOUND_PORT.to_string())?;
            Ok(())
        }

        fn restore() {
            if let Some(snap) = load_undo() {
                apply_snap(&snap);
            }
            let _ = fs::remove_file(AppPaths::proxy_undo_gnome());
        }

        fn apply_snap(s: &Snap) {
            let _ = gset("org.gnome.system.proxy", "mode", &s.mode);
            let _ = gset("org.gnome.system.proxy", "use-same-proxy", &s.use_same);
            let _ = gset("org.gnome.system.proxy.http", "enabled", &s.http_enabled);
            let _ = gset("org.gnome.system.proxy.http", "host", &s.http_host);
            let _ = gset("org.gnome.system.proxy.http", "port", &s.http_port);
            let _ = gset("org.gnome.system.proxy.https", "host", &s.https_host);
            let _ = gset("org.gnome.system.proxy.https", "port", &s.https_port);
        }

        fn gget(schema: &str, key: &str) -> Option<String> {
            let out = std::process::Command::new("gsettings")
                .args(["get", schema, key])
                .output()
                .ok()?;
            if !out.status.success() {
                return None;
            }
            let mut t = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if t.starts_with('\'') && t.ends_with('\'') && t.len() >= 2 {
                t = t[1..t.len() - 1].to_string();
            }
            Some(t)
        }

        fn gset(schema: &str, key: &str, value: &str) -> Result<(), String> {
            let formatted = if value == "true" || value == "false" || value.parse::<i32>().is_ok() {
                value.to_string()
            } else {
                format!("'{}'", value.replace('\\', "\\\\").replace('\'', "\\'"))
            };
            let st = std::process::Command::new("gsettings")
                .args(["set", schema, key, &formatted])
                .status()
                .map_err(|e| e.to_string())?;
            if st.success() {
                Ok(())
            } else {
                Err("gsettings failed (non-GNOME desktop?)".into())
            }
        }

        fn write_undo(s: &Snap) {
            let line = format!(
                "{}\t{}\t{}\t{}\t{}\t{}\t{}",
                s.mode, s.use_same, s.http_host, s.http_port, s.http_enabled, s.https_host, s.https_port
            );
            let _ = fs::write(AppPaths::proxy_undo_gnome(), line);
        }

        fn load_undo() -> Option<Snap> {
            let text = fs::read_to_string(AppPaths::proxy_undo_gnome()).ok()?;
            let p: Vec<&str> = text.split('\t').collect();
            if p.len() < 7 {
                return None;
            }
            Some(Snap {
                mode: p[0].to_string(),
                use_same: p[1].to_string(),
                http_host: p[2].to_string(),
                http_port: p[3].to_string(),
                http_enabled: p[4].to_string(),
                https_host: p[5].to_string(),
                https_port: p[6].trim().to_string(),
            })
        }

        struct Snap {
            mode: String,
            use_same: String,
            http_host: String,
            http_port: String,
            http_enabled: String,
            https_host: String,
            https_port: String,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::rewrite_http_request;

    #[test]
    fn strips_hop_by_hop_and_rewrites_absolute_uri() {
        let raw = b"GET http://example.com/foo?q=1 HTTP/1.1\r\nHost: example.com\r\nProxy-Connection: keep-alive\r\nUser-Agent: x\r\n\r\nbody";
        let out = String::from_utf8(rewrite_http_request(raw)).unwrap();
        assert!(out.starts_with("GET /foo?q=1 HTTP/1.1\r\n"));
        assert!(out.to_ascii_lowercase().contains("host: example.com"));
        assert!(out.contains("User-Agent: x"));
        assert!(!out.to_ascii_lowercase().contains("proxy-connection"));
        assert!(out.ends_with("body"));
    }
}
