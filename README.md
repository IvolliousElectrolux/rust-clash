# rust-clash

Native rewrite of NanoClash: GPUI desktop UI, tokio networking, self-contained VLESS/Trojan/REALITY/Vision stack, Windows System-TCP TUN.

User data, inbound port, TUN adapter name and undo files stay **NanoClash**-compatible (`ArrorMeo/NanoClash`, `127.0.0.1:7887`, adapter `NanoClash`).

## Build

```
cargo build --release -p rust-clash
```

Windows needs the files under `res/` (`Rules.bin.gz`, `icon/icon.ico`, `wintun/wintun.dll`).

## Check

- Start: HTTP inbound listens on `:7887`; system proxy unchanged until 代理模式 is on
- Cloud/local subscriptions write `config.yaml` interchangeable with NanoClash
- Node ingest matches NanoClash filters; subscription-info rows are not selectable
- 代理模式 points at `:7887` and restores on exit / crash (`proxy-undo.json` and OS-specific undo)
- 增强模式 is Windows + Administrator only; other OS show 不可用; mutually exclusive with 代理模式
- Rules: Proxy / Direct / Reject; sidecar `Rules.bin` overrides the embedded database
- VLESS none/tls/reality + Vision; Trojan TLS; tcp/ws
- Health check copy, sort-after-finish, cancel
- Speed refreshes every 1s; switching nodes aborts tunnels
- Crash recovery clears system proxy and TUN routes / DNS / IPv6 / firewall
