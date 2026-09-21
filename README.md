# rust-clash

Windows 上的原生 Clash 风格客户端: GPUI 桌面 UI, tokio 网络, 系统代理与 WinTUN 增强模式.

版本 **1.0.0**.

## 致谢与参考

本项目不是从零发明的协议栈, 实现时对照了下列作品. 协议代码是自行移植的, 没有把这些项目当作 crate 依赖进来.

### NanoClash (霜龙)

rust-clash 是 **霜龙** 所写 [NanoClash](https://github.com/ArrowMeo2088/NanoClash) 的原生重写, 目标是在 Windows 上复用同一套使用习惯和本地数据.

兼容性 (可与 NanoClash 共用同一份用户数据, 不要两个进程同时开):

- 用户目录: `%AppData%\ArrorMeo\NanoClash` (`config.yaml`, 订阅缓存, `Rules.bin`, 撤销文件)
- HTTP 入站: `127.0.0.1:7887`
- TUN 适配器名: `NanoClash`
- 订阅与节点过滤、系统代理 / 增强模式互斥, 以及退出或崩溃后的代理 / 路由还原, 都按 NanoClash 的行为对齐

没有霜龙的 NanoClash, 就不会有这个重写.

### leaf (eycorsican)

Shadowsocks AEAD, VMess, SOCKS5, HTTP CONNECT, simple-obfs 的 outbound 实现对照了 [leaf](https://github.com/eycorsican/leaf) 的协议与握手逻辑, 按 leaf 的路子在本仓库里重写, **不是** `leaf-core` 一类的 crate 依赖.

### 其他参考

- [GPUI](https://github.com/zed-industries/zed) / [gpui-component](https://github.com/longbridge/gpui-component): 桌面 UI
- [WinTUN](https://www.wintun.net/): Windows TUN (`res/wintun/wintun.dll`)
- Clash Meta: 拉取订阅时的 User-Agent (`clash.meta`)
- Clash Party: 托盘菜单与藏到托盘的交互对标

VLESS / Trojan / REALITY / Vision 是本仓库里已有的 outbound 实现, 不是从 leaf 搬的.

## 功能

- 入站 HTTP `127.0.0.1:7887`; 代理模式才改系统代理, 退出或崩溃会还原
- 增强模式: Windows + 管理员, 与代理模式互斥
- 出站: VLESS (none/tls/reality + Vision), Trojan TLS, Shadowsocks AEAD, VMess, SOCKS5, HTTP CONNECT; 传输 tcp / ws / httpupgrade, 以及 simple-obfs
- 托盘常驻, 叉掉窗口是隐藏; 主题 (托盘右键, 不进主窗口)
- 规则: Proxy / Direct / Reject; 旁路 `Rules.bin` 可覆盖内置库

当前未做: Hysteria, TUIC, WireGuard, gRPC.

## 构建

```
cargo build --release -p rust-clash
upx --best --lzma -f target\release\rust-clash.exe
```

Windows 需要 `res/` 下的 `Rules.bin.gz`, `icon/icon.ico`, `wintun/wintun.dll`.
