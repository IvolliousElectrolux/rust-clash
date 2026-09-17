use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::ptr;

use anyhow::Result;
use clash_core::PhysicalEndpoint;
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetAdaptersAddresses, GAA_FLAG_INCLUDE_GATEWAYS, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_MULTICAST,
    IP_ADAPTER_ADDRESSES_LH,
};
use windows_sys::Win32::Networking::WinSock::AF_INET;

use crate::routes::{ADAPTER, TUN_SERVER};

const IF_TYPE_SOFTWARE_LOOPBACK: u32 = 24;
const IF_OPER_STATUS_UP: i32 = 1;
const ERROR_BUFFER_OVERFLOW: u32 = 111;

#[derive(Clone)]
struct Nic {
    name: String,
    index: u32,
    local: Ipv4Addr,
    gateway: Option<Ipv4Addr>,
    dns: Vec<IpAddr>,
    if_type: u32,
}

pub fn probe() -> Result<PhysicalEndpoint> {
    let nics = list_nics()?;
    let preferred = udp_preferred_local();
    let mut fallback = None;
    for nic in &nics {
        if !usable_physical(nic) {
            continue;
        }
        let Some(gw) = nic.gateway else {
            continue;
        };
        let ep = PhysicalEndpoint {
            interface_index: nic.index as i32,
            local_address: nic.local,
            gateway: gw,
            name: nic.name.clone(),
            dns_servers: nic.dns.clone(),
        };
        if preferred.is_some_and(|p| p == nic.local) {
            return Ok(ep);
        }
        if fallback.is_none() {
            fallback = Some(ep);
        }
    }
    fallback.ok_or_else(|| anyhow::anyhow!("No usable physical IPv4 default interface found"))
}

pub fn fake_dns_interface_names() -> Vec<String> {
    list_nics()
        .unwrap_or_default()
        .into_iter()
        .filter(|n| n.dns.iter().any(|d| is_fake_dns(*d)))
        .filter(|n| !is_tun_name(&n.name))
        .map(|n| n.name)
        .collect()
}

fn usable_physical(nic: &Nic) -> bool {
    if is_tun_name(&nic.name) || nic.if_type == IF_TYPE_SOFTWARE_LOOPBACK {
        return false;
    }
    if nic.index == 0 {
        return false;
    }
    if is_tun_addr(nic.local) {
        return false;
    }
    nic.gateway.is_some_and(|g| !is_tun_addr(g) && g != Ipv4Addr::UNSPECIFIED)
}

fn is_tun_name(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.contains("nanoclash") || n.contains("wintun") || n.contains(&ADAPTER.to_ascii_lowercase())
}

fn is_tun_addr(ip: Ipv4Addr) -> bool {
    ip == TUN_SERVER || ip == crate::routes::TUN_CLIENT
}

fn is_fake_dns(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            let b = v.octets();
            b[0] == 198 && b[1] == 18
        }
        IpAddr::V6(_) => false,
    }
}

fn udp_preferred_local() -> Option<Ipv4Addr> {
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect("1.1.1.1:53").ok()?;
    match sock.local_addr().ok()?.ip() {
        IpAddr::V4(v) if !is_tun_addr(v) => Some(v),
        _ => None,
    }
}

fn list_nics() -> Result<Vec<Nic>> {
    unsafe {
        let flags = GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST;
        let mut size = 0u32;
        let st = GetAdaptersAddresses(AF_INET as u32, flags, ptr::null_mut(), ptr::null_mut(), &mut size);
        if st != ERROR_BUFFER_OVERFLOW && st != 0 {
            anyhow::bail!("GetAdaptersAddresses size {st}");
        }
        if size == 0 {
            return Ok(Vec::new());
        }
        let mut buf = vec![0u8; size as usize];
        let st = GetAdaptersAddresses(
            AF_INET as u32,
            flags,
            ptr::null_mut(),
            buf.as_mut_ptr().cast(),
            &mut size,
        );
        if st != 0 {
            anyhow::bail!("GetAdaptersAddresses {st}");
        }
        let mut out = Vec::new();
        let mut p = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
        while !p.is_null() {
            let a = &*p;
            if a.OperStatus == IF_OPER_STATUS_UP {
                if let Some(nic) = parse_nic(a) {
                    out.push(nic);
                }
            }
            p = a.Next;
        }
        Ok(out)
    }
}

fn parse_nic(a: &IP_ADAPTER_ADDRESSES_LH) -> Option<Nic> {
    unsafe {
        let name = wide_ptr(a.FriendlyName);
        if name.is_empty() {
            return None;
        }
        let index = a.Anonymous1.Anonymous.IfIndex;
        let mut local = None;
        let mut ua = a.FirstUnicastAddress;
        while !ua.is_null() {
            if let Some(ip) = sockaddr_v4((*ua).Address.lpSockaddr) {
                if !ip.is_loopback() && !ip.is_unspecified() && !ip.is_link_local() {
                    local = Some(ip);
                    break;
                }
            }
            ua = (*ua).Next;
        }
        let local = local?;
        let mut gateway = None;
        let mut ga = a.FirstGatewayAddress;
        while !ga.is_null() {
            if let Some(ip) = sockaddr_v4((*ga).Address.lpSockaddr) {
                if !ip.is_unspecified() {
                    gateway = Some(ip);
                    break;
                }
            }
            ga = (*ga).Next;
        }
        let mut dns = Vec::new();
        let mut da = a.FirstDnsServerAddress;
        while !da.is_null() {
            if let Some(ip) = sockaddr_v4((*da).Address.lpSockaddr) {
                let v = IpAddr::V4(ip);
                if !dns.contains(&v) && !ip.is_loopback() && !ip.is_unspecified() {
                    dns.push(v);
                }
            }
            da = (*da).Next;
        }
        Some(Nic {
            name,
            index,
            local,
            gateway,
            dns,
            if_type: a.IfType,
        })
    }
}

fn wide_ptr(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    unsafe {
        while *p.add(len) != 0 {
            len += 1;
            if len > 512 {
                break;
            }
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(p, len))
    }
}

fn sockaddr_v4(sa: *const windows_sys::Win32::Networking::WinSock::SOCKADDR) -> Option<Ipv4Addr> {
    if sa.is_null() {
        return None;
    }
    unsafe {
        let family = (*sa).sa_family;
        if family != AF_INET as u16 {
            return None;
        }
        let bytes = std::ptr::read_unaligned(sa as *const [u8; 16]);
        Some(Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7]))
    }
}
