use clash_core::{action_for_ip, FakeIpPool, NodeCatalog, NodeFilter, ProxyNode, RuleAction, RuleDb};
use std::net::{IpAddr, Ipv4Addr};

#[test]
fn clash_yaml_filters_unsupported_and_keeps_vless_trojan() {
    let yaml = r#"
proxies:
  - name: ok-vless
    type: vless
    server: 1.2.3.4
    port: 443
    uuid: 11111111-1111-1111-1111-111111111111
    tls: true
    network: tcp
  - name: drop-grpc
    type: vless
    server: 1.2.3.4
    port: 443
    uuid: 11111111-1111-1111-1111-111111111111
    tls: true
    network: grpc
  - name: ok-trojan
    type: trojan
    server: 5.6.7.8
    port: 443
    password: secret
    network: ws
  - name: drop-ss
    type: ss
    server: 9.9.9.9
    port: 8388
    password: x
"#;
    let nodes = NodeCatalog::parse(yaml.as_bytes());
    let names: Vec<_> = nodes.iter().map(|n| n.name.as_str()).collect();
    assert!(names.contains(&"ok-vless"));
    assert!(names.contains(&"ok-trojan"));
    assert!(!names.contains(&"drop-grpc"));
    assert!(!names.contains(&"drop-ss"));
}

#[test]
fn share_link_vless_and_trojan() {
    let vless = "vless://11111111-1111-1111-1111-111111111111@example.com:443?type=tcp&security=tls&sni=example.com#node-a";
    let trojan = "trojan://secret@example.com:443?sni=example.com#node-b";
    let nodes = NodeCatalog::parse(format!("{vless}\n{trojan}").as_bytes());
    assert_eq!(nodes.len(), 2);
    assert!(nodes.iter().any(|n| n.type_name == "vless" && n.server == "example.com"));
    assert!(nodes.iter().any(|n| n.type_name == "trojan"));
}

#[test]
fn node_filter_rejects_bad_flow() {
    let n = ProxyNode {
        name: "x".into(),
        type_name: "vless".into(),
        server: "1.1.1.1".into(),
        port: 443,
        uuid: Some("11111111-1111-1111-1111-111111111111".into()),
        password: None,
        tls: true,
        server_name: None,
        flow: Some("xtls-rprx-vision-udp443".into()),
        network: "tcp".into(),
        client_fingerprint: None,
        reality_public_key: None,
        reality_short_id: None,
        skip_cert_verify: false,
        ws_path: None,
        ws_host: None,
        security: Some("tls".into()),
    };
    assert!(!NodeFilter::accept(&n));
}

#[test]
fn fake_ip_pool_allocates_from_dot4() {
    let mut pool = FakeIpPool::new();
    let ip = pool.lookup("www.example.com");
    assert_eq!(ip, Ipv4Addr::new(198, 18, 0, 4));
    assert_eq!(pool.lookback(ip).as_deref(), Some("www.example.com"));
    assert!(FakeIpPool::is_fake_ip_v4(ip));
    assert!(!FakeIpPool::is_fake_ip(IpAddr::V4(FakeIpPool::DNS)));
}

#[test]
fn private_ip_is_direct() {
    assert_eq!(
        action_for_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
        RuleAction::Direct
    );
    assert_eq!(
        action_for_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
        RuleAction::Proxy
    );
}

#[test]
fn rules_bin_gz_self_check() {
    use std::io::Read;
    let mut d = flate2::read::GzDecoder::new(clash_core::RULES_GZ);
    let mut plain = Vec::new();
    d.read_to_end(&mut plain).unwrap();
    let db = RuleDb::load_bytes(&plain).expect("embedded rules");
    assert_eq!(db.match_domain("www.baidu.com"), RuleAction::Direct);
    assert_eq!(db.match_domain("www.google.com"), RuleAction::Proxy);
}

#[test]
fn with_port_connect_defaults_to_443() {
    use clash_core::with_port;
    assert_eq!(with_port("example.com", "443").as_deref(), Some("example.com:443"));
    assert_eq!(with_port("example.com:8443", "443").as_deref(), Some("example.com:8443"));
    assert_eq!(with_port("[::1]", "443").as_deref(), Some("[::1]:443"));
}
