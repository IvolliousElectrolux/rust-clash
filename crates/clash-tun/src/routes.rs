use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use anyhow::Result;
use clash_core::hidden_command;
use clash_core::PhysicalEndpoint;
use clash_core::paths::AppPaths;

pub const ADAPTER: &str = "NanoClash";
pub const TUN_SERVER: Ipv4Addr = Ipv4Addr::new(172, 19, 0, 1);
pub const TUN_CLIENT: Ipv4Addr = Ipv4Addr::new(172, 19, 0, 2);
pub const FAKE_DNS: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 2);
pub const MTU: u16 = 1400;

pub struct TunRoutes {
    physical: PhysicalEndpoint,
    node: Option<Ipv4Addr>,
    ipv6_disabled: Option<String>,
}

impl TunRoutes {
    pub fn configure_interface(physical: PhysicalEndpoint) -> Result<Self> {
        wait_adapter_listed(Duration::from_secs(8))?;
        let mut last = None;
        for _ in 0..30 {
            if tun_addr_bindable() {
                last = None;
                break;
            }
            match set_tun_address() {
                Ok(()) => {
                    last = None;
                    break;
                }
                Err(e) => {
                    last = Some(e);
                    if tun_addr_bindable() {
                        last = None;
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(200));
                }
            }
        }
        if let Some(e) = last {
            if !tun_addr_bindable() {
                return Err(e);
            }
        }
        let _ = run_netsh(&format!(
            "interface ipv4 set subinterface \"{ADAPTER}\" mtu={MTU} store=active"
        ));
        let _ = run_netsh(&format!("interface ip set interface name=\"{ADAPTER}\" metric=1"));
        wait_bindable(Duration::from_secs(15))?;
        Ok(Self {
            physical,
            node: None,
            ipv6_disabled: None,
        })
    }

    pub fn install_anti_loop(&mut self, node: Ipv4Addr) -> Result<()> {
        self.set_node_host_route(node)
    }

    pub fn set_node_host_route(&mut self, node: Ipv4Addr) -> Result<()> {
        let previous = self.node;
        let gw = self.physical.gateway;
        let idx = self.physical.interface_index;
        let r = run("route", &[
            "add",
            &node.to_string(),
            "mask",
            "255.255.255.255",
            &gw.to_string(),
            "if",
            &idx.to_string(),
        ]);
        if r.is_err() {
            let _ = run("route", &["delete", &node.to_string(), "mask", "255.255.255.255"]);
            run("route", &[
                "add",
                &node.to_string(),
                "mask",
                "255.255.255.255",
                &gw.to_string(),
                "if",
                &idx.to_string(),
            ])?;
        }
        self.node = Some(node);
        if let Some(old) = previous {
            if old != node {
                let _ = run("route", &[
                    "delete",
                    &old.to_string(),
                    "mask",
                    "255.255.255.255",
                    &gw.to_string(),
                ]);
            }
        }
        write_undo(&self.physical.name, Some(node), self.ipv6_disabled.is_some())?;
        Ok(())
    }

    pub fn disable_ipv6(&mut self) {
        let name = self.physical.name.clone();
        if run_netsh(&format!("interface ipv6 set interface name=\"{name}\" admin=disabled")).is_ok() {
            self.ipv6_disabled = Some(name);
        }
        let _ = write_undo(&self.physical.name, self.node, self.ipv6_disabled.is_some());
    }

    pub fn install_split_default(&self) -> Result<()> {
        run("route", &["add", "0.0.0.0", "mask", "128.0.0.0", &TUN_SERVER.to_string()])?;
        run("route", &["add", "128.0.0.0", "mask", "128.0.0.0", &TUN_SERVER.to_string()])?;
        Ok(())
    }

    pub fn configure_dns_hijack(&self) -> Result<()> {
        run_netsh(&format!(
            "interface ip set dns name=\"{ADAPTER}\" static addr={FAKE_DNS} register=none"
        ))?;
        run_netsh(&format!(
            "interface ip set dns name=\"{}\" static addr={FAKE_DNS} register=none",
            self.physical.name
        ))?;
        let _ = hidden_command("ipconfig").arg("/flushdns").status();
        Ok(())
    }

    pub fn uninstall(&mut self) {
        let _ = run("route", &["delete", "0.0.0.0", "mask", "128.0.0.0"]);
        let _ = run("route", &["delete", "128.0.0.0", "mask", "128.0.0.0"]);
        if let Some(node) = self.node.take() {
            let _ = run("route", &[
                "delete",
                &node.to_string(),
                "mask",
                "255.255.255.255",
                &self.physical.gateway.to_string(),
            ]);
        }
        let _ = run_netsh(&format!("interface ip set dns name=\"{ADAPTER}\" dhcp"));
        let _ = run_netsh(&format!(
            "interface ip set dns name=\"{}\" dhcp",
            self.physical.name
        ));
        if let Some(name) = self.ipv6_disabled.take() {
            let _ = run_netsh(&format!("interface ipv6 set interface name=\"{name}\" admin=enabled"));
        }
        let _ = std::fs::remove_file(AppPaths::tun_undo_file());
    }
}

pub fn write_undo(ifname: &str, node: Option<Ipv4Addr>, ipv6: bool) -> Result<()> {
    let json = serde_json::json!({
        "ifname": ifname,
        "node": node.map(|n| n.to_string()),
        "ipv6": ipv6
    });
    std::fs::write(AppPaths::tun_undo_file(), json.to_string())?;
    Ok(())
}

pub fn recover() {
    if let Ok(text) = std::fs::read_to_string(AppPaths::tun_undo_file()) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
            if let Some(name) = v.get("ifname").and_then(|x| x.as_str()) {
                let _ = run_netsh(&format!("interface ip set dns name=\"{name}\" dhcp"));
                if v.get("ipv6").and_then(|x| x.as_bool()).unwrap_or(false) {
                    let _ = run_netsh(&format!("interface ipv6 set interface name=\"{name}\" admin=enabled"));
                }
            }
            if let Some(node) = v.get("node").and_then(|x| x.as_str()) {
                let _ = run("route", &["delete", node, "mask", "255.255.255.255"]);
            }
        }
        let _ = std::fs::remove_file(AppPaths::tun_undo_file());
    }
    let _ = run("route", &["delete", "0.0.0.0", "mask", "128.0.0.0"]);
    let _ = run("route", &["delete", "128.0.0.0", "mask", "128.0.0.0"]);
    let _ = run_netsh(&format!("interface ip set dns name=\"{ADAPTER}\" dhcp"));
    restore_fake_dns_nics();
    let _ = hidden_command("ipconfig").arg("/flushdns").status();
    remove_firewall();
}

fn restore_fake_dns_nics() {
    let mut names = crate::probe::fake_dns_interface_names();
    names.extend(parse_fake_dns_names_from_netsh());
    names.sort();
    names.dedup();
    for n in names {
        if n.eq_ignore_ascii_case(ADAPTER) {
            continue;
        }
        let _ = run_netsh(&format!("interface ip set dns name=\"{n}\" dhcp"));
    }
}

fn parse_fake_dns_names_from_netsh() -> Vec<String> {
    let Ok(out) = hidden_command("netsh")
        .args(["interface", "ip", "show", "dns"])
        .output()
    else {
        return Vec::new();
    };
    let text = String::from_utf8_lossy(&out.stdout);
    let mut current: Option<String> = None;
    let mut names = Vec::new();
    for line in text.lines() {
        let t = line.trim();
        if let Some(name) = parse_netsh_if_name(t) {
            current = Some(name);
            continue;
        }
        if t.contains("198.18.") {
            if let Some(n) = current.clone() {
                if !names.contains(&n) {
                    names.push(n);
                }
            }
        }
    }
    names
}

fn parse_netsh_if_name(t: &str) -> Option<String> {
    if let Some(rest) = t.strip_prefix("Configuration for interface ") {
        return Some(rest.trim_matches(|c| c == '"' || c == '\'').to_string());
    }
    if let Some(rest) = t.strip_prefix("接口 ") {
        if let Some(name) = rest.strip_suffix(" 的配置") {
            return Some(name.trim_matches(|c| c == '"' || c == '\'').to_string());
        }
    }
    None
}

pub fn allow_firewall() {
    if let Ok(exe) = std::env::current_exe() {
        let _ = hidden_command("netsh")
            .args([
                "advfirewall",
                "firewall",
                "add",
                "rule",
                "name=NanoClash",
                "dir=in",
                "action=allow",
                &format!("program={}", exe.display()),
                "enable=yes",
            ])
            .status();
    }
}

pub fn remove_firewall() {
    let _ = hidden_command("netsh")
        .args(["advfirewall", "firewall", "delete", "rule", "name=NanoClash"])
        .status();
}

fn wait_bindable(timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    let mut last = None;
    while Instant::now() < deadline {
        match std::net::TcpListener::bind((TUN_SERVER, 0)) {
            Ok(_) => return Ok(()),
            Err(e) => last = Some(e),
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    anyhow::bail!("TUN address {TUN_SERVER} not bindable: {:?}", last)
}

fn tun_addr_bindable() -> bool {
    std::net::TcpListener::bind((TUN_SERVER, 0)).is_ok()
}

fn wait_adapter_listed(timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if adapter_listed() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    anyhow::bail!("adapter {ADAPTER} not listed")
}

fn adapter_listed() -> bool {
    let Ok(out) = hidden_command("netsh")
        .args(["interface", "show", "interface"])
        .output()
    else {
        return false;
    };
    String::from_utf8_lossy(&out.stdout).contains(ADAPTER)
}

fn set_tun_address() -> Result<()> {
    let cmds = [
        format!(
            "interface ip set address name=\"{ADAPTER}\" source=static addr={TUN_SERVER} mask=255.255.255.252 gateway=none"
        ),
        format!(
            "interface ipv4 set address name=\"{ADAPTER}\" source=static address={TUN_SERVER} mask=255.255.255.252 gateway=none"
        ),
        format!(
            "interface ip set address name=\"{ADAPTER}\" source=static addr={TUN_SERVER} mask=255.255.255.252"
        ),
    ];
    let mut last = None;
    for cmd in cmds {
        match run_netsh(&cmd) {
            Ok(()) => return Ok(()),
            Err(e) => last = Some(e),
        }
        if tun_addr_bindable() {
            return Ok(());
        }
    }
    Err(last.unwrap_or_else(|| anyhow::anyhow!("set TUN address failed")))
}

fn run_netsh(args: &str) -> Result<()> {
    // netsh needs one Windows command line so quoted names stay intact.
    use std::os::windows::process::CommandExt;
    let mut cmd = hidden_command("netsh");
    cmd.raw_arg(args);
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());
    let out = cmd.output()?;
    if out.status.success() {
        Ok(())
    } else {
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        anyhow::bail!(
            "netsh {args} => {} {} {}",
            out.status,
            stdout.trim(),
            stderr.trim()
        )
    }
}

fn run(file: &str, args: &[&str]) -> Result<()> {
    let st = hidden_command(file).args(args).status()?;
    if st.success() {
        Ok(())
    } else {
        anyhow::bail!("{file} {:?} => {st}", args)
    }
}
