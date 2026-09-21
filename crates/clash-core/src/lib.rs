pub mod config;
pub mod dns;
pub mod inbound;
pub mod io;
pub mod net;
pub mod outbound;
pub mod paths;
pub mod rules;
pub mod ui_state;
pub mod utils;

pub use clash_proxynet::install_crypto_provider;
pub use config::{
    ContentStore, NodeCatalog, NodeFilter, ProfileEntry, ProfileKind, ProfileStore, ProxyNode,
    SubscriptionClient, SubscriptionFetchResult, SubscriptionUserInfo,
};
pub use dns::{
    build_a_response, build_empty_dns, build_named_a_response, parse_dns_query, DohBlocklist,
    DohResolver, FakeIpPool,
};
pub use inbound::ProxyService;
pub use io::{DirectDial, Relay, TrafficCounters, TlsHelloCoalesce};
pub use net::{DirectNetwork, InterfaceBinder, PhysicalEndpoint};
pub use outbound::{HealthCheckResult, HealthChecker, HealthStatus, OutboundDialer};
pub use paths::AppPaths;
pub use ui_state::{LaunchFlags, SavedNode, UiMode, UiState, UiTheme};
pub use rules::{action_for_ip, join_host_port, try_split_host_port, with_port, RuleAction, RuleDb};
pub use utils::hidden_command;

pub const INBOUND_PORT: u16 = 7887;
pub const RULES_GZ: &[u8] = include_bytes!("../../../res/Rules.bin.gz");
