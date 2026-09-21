//! rust-clash desktop entry (GPUI).

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod tray;
mod theme;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use clash_core::{
    inbound, AppPaths, ContentStore, DirectNetwork, DohResolver, HealthCheckResult, HealthChecker,
    HealthStatus, LaunchFlags, NodeCatalog, OutboundDialer, ProfileKind, ProfileStore, ProxyNode,
    ProxyService, RuleDb, SavedNode, SubscriptionClient, UiMode, UiState,
};
use clash_tun::{ensure_wintun_extracted, recover_orphaned_os_state, TunService};
use gpui::prelude::*;
use gpui::{
    actions, div, px, rgb, size, App, Application, Bounds, ClickEvent, ClipboardItem, Context,
    Entity, KeyBinding, MouseButton, SharedString, TitlebarOptions, Window, WindowBounds,
    WindowControlArea, WindowOptions,
};
use gpui_component::input::{Input, InputState};
use gpui_component::Root;

actions!(app, [Quit]);

static ALLOW_QUIT: AtomicBool = AtomicBool::new(false);

const TITLE_BAR_H: f32 = 34.;
use parking_lot::Mutex;

struct AppCore {
    proxy: Arc<ProxyService>,
    outbound: Arc<OutboundDialer>,
    tun: Arc<TunService>,
    profiles: Mutex<ProfileStore>,
    health: Arc<HealthChecker>,
    rt: tokio::runtime::Handle,
}

struct NodeVm {
    node: ProxyNode,
    latency: SharedString,
    health: HealthStatus,
    latency_ms: Option<i32>,
}

struct MainView {
    core: Arc<AppCore>,
    nodes: Vec<NodeVm>,
    selected: Option<usize>,
    proxy_on: bool,
    enhance_on: bool,
    health_running: bool,
    health_cancel: Arc<std::sync::atomic::AtomicBool>,
    speed: SharedString,
    error: SharedString,
    quota: SharedString,
    expire: SharedString,
    show_dialog: bool,
    dialog_cloud: bool,
    dialog_path: SharedString,
    dialog_status: SharedString,
    show_profiles: bool,
    show_elevate: bool,
    enhance_busy: bool,
    name_input: Entity<InputState>,
    url_input: Entity<InputState>,
    tray: tray::Tray,
    window_visible: bool,
}

impl MainView {
    fn new(
        core: Arc<AppCore>,
        force_enhance: bool,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        let name_input = cx.new(|cx| InputState::new(window, cx).placeholder("可留空"));
        let url_input = cx.new(|cx| InputState::new(window, cx).placeholder("https://..."));
        let saved = UiState::load();
        let (tray, mut tray_rx) = tray::Tray::spawn();
        let mut this = Self {
            core,
            nodes: Vec::new(),
            selected: None,
            proxy_on: false,
            enhance_on: false,
            health_running: false,
            health_cancel: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            speed: "传输速度 0 KB/s".into(),
            error: "".into(),
            quota: "".into(),
            expire: "".into(),
            show_dialog: false,
            dialog_cloud: true,
            dialog_path: "".into(),
            dialog_status: "".into(),
            show_profiles: false,
            show_elevate: false,
            enhance_busy: false,
            name_input,
            url_input,
            tray,
            window_visible: true,
        };
        this.reload_nodes();
        this.apply_saved_node(&saved);
        this.refresh_quota();
        let mode = if force_enhance {
            UiMode::Enhance
        } else {
            saved.mode
        };
        this.restore_mode(mode, cx);
        this.sync_tray();
        window.on_window_should_close(cx, {
            let view = cx.weak_entity();
            move |window, cx| {
                view.update(cx, |this, cx| this.on_close_requested(window, cx))
                    .unwrap_or(true)
            }
        });
        cx.spawn_in(window, async move |this, cx| {
            while let Some(ev) = tray_rx.recv().await {
                let _ = cx.update(|window, cx| {
                    let _ = this.update(cx, |this, cx| this.handle_tray(ev, window, cx));
                });
            }
        })
        .detach();
        cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor().timer(Duration::from_secs(1)).await;
                this.update(cx, |this, cx| {
                    let kb = this.core.proxy.total_speed_kbps();
                    this.speed = format!("传输速度 {kb} KB/s").into();
                    cx.notify();
                })
                .ok();
            }
        })
        .detach();
        this
    }

    fn reload_nodes(&mut self) {
        let prev = self.saved_node();
        self.nodes.clear();
        let profiles = self.core.profiles.lock();
        if let Some(active) = profiles.active() {
            if let Some(raw) = ContentStore::try_read(&active.hash) {
                for n in NodeCatalog::parse(&raw) {
                    self.nodes.push(NodeVm {
                        node: n,
                        latency: "-".into(),
                        health: HealthStatus::Idle,
                        latency_ms: None,
                    });
                }
            }
        }
        self.selected = prev
            .as_ref()
            .and_then(|want| find_saved_node(&self.nodes, want))
            .or_else(|| {
                self.nodes
                    .iter()
                    .position(|n| !n.node.is_subscription_info())
            });
        if let Some(i) = self.selected {
            self.core
                .outbound
                .set_current(Some(self.nodes[i].node.clone()));
        } else {
            self.core.outbound.set_current(None);
        }
    }

    fn refresh_quota(&mut self) {
        let profiles = self.core.profiles.lock();
        let Some(active) = profiles.active() else {
            self.quota = "".into();
            self.expire = "".into();
            return;
        };
        if active.kind != ProfileKind::Cloud {
            self.quota = "".into();
            self.expire = "".into();
            return;
        }
        self.quota = format_quota(active.used_bytes, active.total_bytes).into();
        self.expire = format_expire(active.expire_unix).into();
    }
}

impl Render for MainView {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let enhance_ok = cfg!(windows);
        let p = theme::current(cx);
        div()
            .relative()
            .flex()
            .flex_col()
            .size_full()
            .bg(rgb(p.bg))
            .text_color(rgb(p.fg))
            .child(title_bar(window.is_maximized(), cx))
            .child(
                div()
                    .flex()
                    .flex_col()
                    .p_3()
                    .gap_2()
                    .flex_1()
                    .min_h(px(0.))
                    .child(
                        div()
                            .w_full()
                            .flex()
                            .flex_row()
                            .flex_wrap()
                            .items_center()
                            .gap_2()
                            .child(self.row_profiles(cx))
                            .child(self.row_modes(enhance_ok, cx)),
                    )
                    .child(self.row_nodes(window, cx)),
            )
            .when(self.show_profiles, |d| d.child(self.profile_menu(cx)))
            .when(self.show_dialog, |d| d.child(self.dialog(cx)))
            .when(self.show_elevate, |d| d.child(self.elevate_dialog(cx)))
    }
}

impl MainView {
    fn row_profiles(&mut self, cx: &mut Context<Self>) -> impl IntoElement {
        let names: Vec<String> = self
            .core
            .profiles
            .lock()
            .profiles()
            .iter()
            .map(|p| p.name.clone())
            .collect();
        let active = self
            .core
            .profiles
            .lock()
            .active()
            .map(|p| p.name.clone())
            .unwrap_or_else(|| "(无)".into());
        let cloud = self
            .core
            .profiles
            .lock()
            .active()
            .map(|p| p.kind == ProfileKind::Cloud)
            .unwrap_or(false);
        let p = theme::current(cx);
        div()
            .flex()
            .flex_row()
            .flex_none()
            .flex_nowrap()
            .items_center()
            .gap_2()
            .child(chip(
                "添加订阅",
                cx.listener(|this, _, window, cx| {
                    this.show_dialog = true;
                    this.dialog_status = "".into();
                    this.dialog_path = "".into();
                    this.name_input.update(cx, |s, cx| s.set_value("", window, cx));
                    this.url_input.update(cx, |s, cx| s.set_value("", window, cx));
                    cx.notify();
                }),
                cx,
            ))
            .child(chip_label(
                "profile-select",
                active,
                cx.listener(|this, _, _, cx| {
                    this.show_profiles = !this.show_profiles;
                    cx.notify();
                }),
                cx,
            ))
            .when(cloud, |d| {
                d.child(chip(
                    "更新订阅",
                    cx.listener(|this, _, _, cx| this.update_profile(cx)),
                    cx,
                ))
            })
            .when(!names.is_empty(), |d| {
                d.child(chip(
                    "删除",
                    cx.listener(|this, _, _, cx| this.delete_profile(cx)),
                    cx,
                ))
            })
            .child(
                div()
                    .text_sm()
                    .text_color(rgb(p.muted))
                    .child(self.quota.clone()),
            )
            .child(
                div()
                    .text_sm()
                    .text_color(rgb(p.muted))
                    .child(self.expire.clone()),
            )
    }

    fn profile_menu(&mut self, cx: &mut Context<Self>) -> impl IntoElement {
        let names: Vec<String> = self
            .core
            .profiles
            .lock()
            .profiles()
            .iter()
            .map(|p| p.name.clone())
            .collect();
        let p = theme::current(cx);
        div()
            .id("profile-overlay")
            .absolute()
            .inset_0()
            .occlude()
            .on_mouse_down(
                MouseButton::Left,
                cx.listener(|this, _, _, cx| {
                    this.show_profiles = false;
                    cx.notify();
                }),
            )
            .child(
                div()
                    .id("profile-menu")
                    .absolute()
                    .top(px(TITLE_BAR_H + 12. + 30.))
                    .left(px(12.))
                    .min_w(px(180.))
                    .max_h(px(280.))
                    .overflow_y_scroll()
                    .bg(rgb(p.card))
                    .border_1()
                    .border_color(rgb(p.border))
                    .rounded_md()
                    .text_color(rgb(p.fg))
                    .occlude()
                    .on_mouse_down(MouseButton::Left, |_, _, cx| cx.stop_propagation())
                    .children(names.into_iter().enumerate().map(|(i, n)| {
                        let name = n.clone();
                        div()
                            .id(("prof", i))
                            .px_3()
                            .py_1()
                            .cursor_pointer()
                            .hover(move |s| s.bg(rgb(p.bg)))
                            .on_click(cx.listener(move |this, _, _, cx| {
                                this.switch_profile(&name, cx);
                            }))
                            .child(n)
                    })),
            )
    }

    fn row_modes(&mut self, enhance_ok: bool, cx: &mut Context<Self>) -> impl IntoElement {
        let health_label = if self.health_running {
            "取消检查"
        } else {
            "健康检查"
        };
        let proxy_state = if self.proxy_on {
            format!("开启 127.0.0.1:{}", clash_core::INBOUND_PORT)
        } else {
            "关闭".into()
        };
        let enhance_state = if !enhance_ok {
            "不可用"
        } else if self.enhance_on {
            "开启"
        } else {
            "关闭"
        };
        let p = theme::current(cx);
        let proxy_color = if self.proxy_on {
            rgb(p.success)
        } else {
            rgb(p.danger)
        };
        let enhance_color = if !enhance_ok {
            rgb(p.muted)
        } else if self.enhance_on {
            rgb(p.success)
        } else {
            rgb(p.danger)
        };
        div()
            .flex()
            .flex_row()
            .flex_none()
            .flex_nowrap()
            .items_center()
            .gap_3()
            .child(chip_label(
                "health-check",
                health_label,
                cx.listener(|this, _, _, cx| this.toggle_health(cx)),
                cx,
            ))
            .child(
                div()
                    .id("proxy-mode")
                    .flex()
                    .flex_row()
                    .items_center()
                    .gap_1()
                    .cursor_pointer()
                    .on_click(cx.listener(|this, _, _, cx| this.toggle_proxy(cx)))
                    .child(div().text_color(rgb(p.fg)).child("代理模式"))
                    .child(toggle_knob("proxy-toggle", self.proxy_on, cx))
                    .child(div().text_color(proxy_color).child(proxy_state)),
            )
            .child(
                div()
                    .id("enhance-mode")
                    .flex()
                    .flex_row()
                    .items_center()
                    .gap_1()
                    .cursor_pointer()
                    .on_click(cx.listener(move |this, _, _, cx| {
                        if enhance_ok {
                            this.toggle_enhance(cx);
                        }
                    }))
                    .child(div().text_color(rgb(p.fg)).child("增强模式"))
                    .child(toggle_knob(
                        "enhance-toggle",
                        self.enhance_on && enhance_ok,
                        cx,
                    ))
                    .child(div().text_color(enhance_color).child(enhance_state)),
            )
            .child(
                div()
                    .text_color(rgb(p.danger))
                    .child(self.error.clone()),
            )
            .child(
                div()
                    .text_sm()
                    .text_color(rgb(p.muted))
                    .child(self.speed.clone()),
            )
    }

    fn row_nodes(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let card_w = node_card_width(window);
        let p = theme::current(cx);
        div()
            .id("node-list")
            .flex_1()
            .min_h(px(0.))
            .overflow_y_scroll()
            .flex()
            .flex_row()
            .flex_wrap()
            .gap_2()
            .children(self.nodes.iter().enumerate().map(|(i, n)| {
                let selected = self.selected == Some(i);
                let info = n.node.is_subscription_info();
                let proto = if n
                    .node
                    .client_fingerprint
                    .as_deref()
                    .is_some_and(|s| !s.is_empty())
                {
                    format!("{} (fp 未生效)", n.node.type_name)
                } else {
                    n.node.type_name.clone()
                };
                let name = n.node.name.clone();
                let lat = n.latency.clone();
                let lat_color = latency_color(n.health, p.muted);
                div()
                    .id(("node", i))
                    .w(card_w)
                    .h(px(36.))
                    .px_2()
                    .border_1()
                    .border_color(if selected {
                        rgb(p.accent)
                    } else {
                        rgb(p.border)
                    })
                    .rounded_md()
                    .bg(rgb(p.card))
                    .flex()
                    .flex_row()
                    .items_center()
                    .justify_between()
                    .text_sm()
                    .text_color(rgb(p.fg))
                    .when(!info, |d| {
                        d.cursor_pointer()
                            .on_click(cx.listener(move |this, _, _, cx| this.select_node(i, cx)))
                    })
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .min_w(px(0.))
                            .child(
                                div()
                                    .text_color(rgb(p.fg))
                                    .overflow_hidden()
                                    .text_ellipsis()
                                    .child(name),
                            )
                            .child(div().text_xs().text_color(rgb(p.proto)).child(proto)),
                    )
                    .child(div().text_xs().text_color(rgb(lat_color)).child(lat))
            }))
    }

    fn dialog(&mut self, cx: &mut Context<Self>) -> impl IntoElement {
        let p = theme::current(cx);
        div()
            .absolute()
            .inset_0()
            .flex()
            .items_center()
            .justify_center()
            .bg(gpui::Rgba {
                r: 0.,
                g: 0.,
                b: 0.,
                a: 0.35,
            })
            .child(
                div()
                    .w(px(440.))
                    .h(px(260.))
                    .p_4()
                    .bg(rgb(p.card))
                    .rounded_md()
                    .text_color(rgb(p.fg))
                    .flex()
                    .flex_col()
                    .gap_2()
                    .child("添加订阅")
                    .child(
                        div()
                            .flex()
                            .gap_3()
                            .child(chip(
                                "云端订阅",
                                cx.listener(|this, _, _, cx| {
                                    this.dialog_cloud = true;
                                    cx.notify();
                                }),
                                cx,
                            ))
                            .child(chip(
                                "本地订阅",
                                cx.listener(|this, _, _, cx| {
                                    this.dialog_cloud = false;
                                    cx.notify();
                                }),
                                cx,
                            )),
                    )
                    .child("订阅名称（可留空）")
                    .child(Input::new(&self.name_input).h(px(28.)))
                    .when(self.dialog_cloud, |d| {
                        d.child("订阅地址")
                            .child(Input::new(&self.url_input).h(px(28.)))
                    })
                    .when(!self.dialog_cloud, |d| {
                        d.child(chip_label(
                            "pick-file",
                            if self.dialog_path.is_empty() {
                                "选择文件"
                            } else {
                                "已选文件"
                            },
                            cx.listener(|this, _, _, cx| {
                                if let Some(path) = rfd::FileDialog::new()
                                    .add_filter(
                                        "Config",
                                        &["yaml", "yml", "json", "conf", "txt"],
                                    )
                                    .pick_file()
                                {
                                    this.dialog_path = path.to_string_lossy().to_string().into();
                                }
                                cx.notify();
                            }),
                            cx,
                        ))
                    })
                    .child(div().text_color(rgb(p.danger)).child(self.dialog_status.clone()))
                    .child(
                        div()
                            .flex()
                            .gap_2()
                            .child(chip(
                                "确定",
                                cx.listener(|this, _, _, cx| this.confirm_dialog(cx)),
                                cx,
                            ))
                            .child(chip(
                                "取消",
                                cx.listener(|this, _, _, cx| {
                                    this.show_dialog = false;
                                    cx.notify();
                                }),
                                cx,
                            )),
                    ),
            )
    }

    fn confirm_dialog(&mut self, cx: &mut Context<Self>) {
        if self.dialog_cloud {
            let url = self.url_input.read(cx).value().to_string();
            let url = url.trim().to_string();
            if url.is_empty() {
                self.dialog_status = "请输入订阅地址".into();
                cx.notify();
                return;
            }
            if !url.starts_with("http://") && !url.starts_with("https://") {
                self.dialog_status = "订阅地址仅支持 http/https".into();
                cx.notify();
                return;
            }
            self.dialog_status = "处理中…".into();
            let name = self.name_input.read(cx).value().to_string();
            let core = self.core.clone();
            cx.spawn(async move |this, cx| {
                let r = on_tokio(&core.rt, {
                    let client = SubscriptionClient;
                    let url = url.clone();
                    async move { client.fetch(&url).await }
                })
                .await
                .unwrap_or_else(|| Err("runtime".into()));
                this.update(cx, |this, cx| {
                    match r {
                        Ok(fetched) => {
                            let n = if name.trim().is_empty() {
                                fetched.suggested_name.as_deref()
                            } else {
                                Some(name.trim())
                            };
                            let added = core.profiles.lock().add_cloud(
                                n,
                                &url,
                                &fetched.body,
                                fetched.user_info.as_ref(),
                            );
                            match added {
                                Ok(_) => {
                                    this.show_dialog = false;
                                    this.reload_nodes();
                                    this.refresh_quota();
                                    this.persist();
                                }
                                Err(e) => this.dialog_status = format!("失败: {e}").into(),
                            }
                        }
                        Err(e) => this.dialog_status = format!("失败: {e}").into(),
                    }
                    cx.notify();
                })
                .ok();
            })
            .detach();
        } else {
            let path = self.dialog_path.to_string();
            if path.trim().is_empty() || !std::path::Path::new(&path).exists() {
                self.dialog_status = "请选择有效的本地文件".into();
                cx.notify();
                return;
            }
            match std::fs::metadata(&path) {
                Ok(m) if m.len() as usize > SubscriptionClient::MAX_BODY => {
                    self.dialog_status = "本地文件超过 16 MB".into();
                    cx.notify();
                    return;
                }
                Err(_) => {
                    self.dialog_status = "请选择有效的本地文件".into();
                    cx.notify();
                    return;
                }
                _ => {}
            }
            match std::fs::read(&path) {
                Ok(bytes) => {
                    let typed = self.name_input.read(cx).value().to_string();
                    let stem = if typed.trim().is_empty() {
                        std::path::Path::new(&path)
                            .file_stem()
                            .and_then(|s| s.to_str())
                    } else {
                        Some(typed.trim())
                    };
                    self.core.profiles.lock().add_local(stem, &bytes);
                    self.show_dialog = false;
                    self.reload_nodes();
                    self.refresh_quota();
                    self.persist();
                }
                Err(e) => self.dialog_status = format!("失败: {e}").into(),
            }
        }
        cx.notify();
    }

    fn select_node(&mut self, i: usize, cx: &mut Context<Self>) {
        if self.nodes.get(i).is_some_and(|n| n.node.is_subscription_info()) {
            return;
        }
        let node = self.nodes[i].node.clone();
        self.selected = Some(i);
        let core = self.core.clone();
        cx.spawn(async move |this, cx| {
            let probe = node.clone();
            let ok = on_tokio(&core.rt, {
                let tun = core.tun.clone();
                async move { tun.on_node_changed(Some(&probe)).await }
            })
            .await
            .unwrap_or(false);
            this.update(cx, |this, cx| {
                if ok {
                    this.core.outbound.set_current(Some(node));
                    this.core.proxy.abort_active();
                    this.error = "".into();
                    this.persist();
                } else {
                    this.error = "节点路由更新失败".into();
                }
                cx.notify();
            })
            .ok();
        })
        .detach();
        cx.notify();
    }

    fn toggle_proxy(&mut self, cx: &mut Context<Self>) {
        let on = !self.proxy_on;
        if on && self.enhance_on {
            self.enhance_on = false;
            let core = self.core.clone();
            cx.spawn(async move |_, _| {
                let _ = on_tokio(&core.rt, {
                    let core = core.clone();
                    async move {
                        core.tun.stop().await;
                        let _ = core.proxy.set_listening(true).await;
                    }
                })
                .await;
            })
            .detach();
        }
        if on {
            self.core.proxy.abort_active();
        }
        self.core.proxy.set_system_proxy(on);
        self.proxy_on = self.core.proxy.system_proxy_on();
        if let Some(e) = self.core.proxy.last_error() {
            self.error = e.into();
            self.proxy_on = false;
        } else {
            self.error = "".into();
        }
        self.persist();
        cx.notify();
    }

    fn toggle_enhance(&mut self, cx: &mut Context<Self>) {
        if self.nodes.iter().all(|n| n.node.is_subscription_info()) {
            self.error = "无可用节点, 已关闭增强模式".into();
            cx.notify();
            return;
        }
        if !inbound::is_administrator() {
            self.show_elevate = true;
            cx.notify();
            return;
        }
        let on = !self.enhance_on;
        if on {
            self.start_enhance(cx);
        } else {
            self.stop_enhance(cx);
        }
        cx.notify();
    }

    fn start_enhance(&mut self, cx: &mut Context<Self>) {
        self.begin_enhance(cx, 1, false);
    }

    fn begin_enhance(&mut self, cx: &mut Context<Self>, attempts: u32, keep_intent: bool) {
        if self.core.tun.is_running() {
            self.enhance_on = true;
            self.enhance_busy = false;
            self.error = "".into();
            self.persist();
            cx.notify();
            return;
        }
        if self.enhance_busy {
            return;
        }
        self.enhance_busy = true;
        self.proxy_on = false;
        self.core.proxy.set_system_proxy(false);
        let core = self.core.clone();
        let attempts = attempts.max(1);
        cx.spawn(async move |this, cx| {
            let mut last_err: Option<String> = None;
            let mut ok = false;
            for i in 0..attempts {
                let r = on_tokio(&core.rt, {
                    let core = core.clone();
                    async move {
                        let _ = core.proxy.set_listening(false).await;
                        match core.tun.start().await {
                            Ok(()) => Ok(()),
                            Err(e) => {
                                let _ = core.proxy.set_listening(true).await;
                                Err(e)
                            }
                        }
                    }
                })
                .await
                .unwrap_or_else(|| Err(anyhow::anyhow!("runtime")));
                match r {
                    Ok(()) => {
                        ok = true;
                        last_err = None;
                        break;
                    }
                    Err(e) => {
                        last_err = Some(e.to_string());
                        if i + 1 < attempts {
                            cx.background_executor()
                                .timer(Duration::from_millis(400))
                                .await;
                        }
                    }
                }
            }
            this.update(cx, |this, cx| {
                if ok {
                    this.enhance_on = true;
                    this.error = "".into();
                    this.persist();
                } else {
                    this.enhance_on = false;
                    this.error = last_err.unwrap_or_else(|| "enhance failed".into()).into();
                    if keep_intent {
                        UiState::patch(|s| {
                            s.mode = UiMode::Enhance;
                            s.node = this.saved_node();
                        });
                        this.sync_tray();
                    } else {
                        this.persist();
                    }
                }
                this.enhance_busy = false;
                cx.notify();
            })
            .ok();
        })
        .detach();
    }

    fn stop_enhance(&mut self, cx: &mut Context<Self>) {
        let core = self.core.clone();
        cx.spawn(async move |this, cx| {
            let _ = on_tokio(&core.rt, {
                let core = core.clone();
                async move {
                    core.tun.stop().await;
                    let _ = core.proxy.set_listening(true).await;
                }
            })
            .await;
            this.update(cx, |this, cx| {
                this.enhance_on = false;
                this.enhance_busy = false;
                this.persist();
                cx.notify();
            })
            .ok();
        })
        .detach();
    }

    fn toggle_health(&mut self, cx: &mut Context<Self>) {
        if self.health_running {
            self.health_cancel
                .store(true, std::sync::atomic::Ordering::Relaxed);
            self.health_running = false;
            cx.notify();
            return;
        }
        self.health_running = true;
        self.health_cancel
            .store(false, std::sync::atomic::Ordering::Relaxed);
        let mut pending = 0usize;
        for n in &mut self.nodes {
            if !n.node.is_subscription_info() {
                n.latency = "…".into();
                n.health = HealthStatus::Checking;
                n.latency_ms = None;
                pending += 1;
            }
        }
        self.sort_health_partial();
        let nodes: Vec<ProxyNode> = self.nodes.iter().map(|n| n.node.clone()).collect();
        let core = self.core.clone();
        let cancel = self.health_cancel.clone();
        cx.spawn(async move |this, cx| {
            let (tx, rx) = std::sync::mpsc::channel();
            core.rt.spawn({
                let health = core.health.clone();
                let cancel = cancel.clone();
                async move {
                    let (out_tx, mut out_rx) = tokio::sync::mpsc::unbounded_channel();
                    let runner = tokio::spawn(async move {
                        health.check_stream(nodes, cancel, out_tx).await;
                    });
                    while let Some(item) = out_rx.recv().await {
                        if tx.send(item).is_err() {
                            break;
                        }
                    }
                    let _ = runner.await;
                }
            });
            let mut got = 0usize;
            while got < pending {
                if cancel.load(std::sync::atomic::Ordering::Relaxed) {
                    break;
                }
                let mut batch = Vec::new();
                while let Ok(item) = rx.try_recv() {
                    batch.push(item);
                }
                if batch.is_empty() {
                    cx.background_executor()
                        .timer(Duration::from_millis(20))
                        .await;
                    continue;
                }
                got += batch.len();
                this.update(cx, |this, cx| {
                    if cancel.load(std::sync::atomic::Ordering::Relaxed) {
                        return;
                    }
                    for (name, server, port, r) in batch {
                        this.apply_health_result(&name, &server, port, r);
                    }
                    this.sort_health_partial();
                    cx.notify();
                })
                .ok();
            }
            this.update(cx, |this, cx| {
                this.health_running = false;
                cx.notify();
            })
            .ok();
        })
        .detach();
        cx.notify();
    }

    fn apply_health_result(
        &mut self,
        name: &str,
        server: &str,
        port: u16,
        r: HealthCheckResult,
    ) {
        if let Some(vm) = self.nodes.iter_mut().find(|n| {
            n.node.name == name && n.node.server == server && n.node.port == port
        }) {
            vm.health = r.status;
            vm.latency_ms = r.latency_ms;
            vm.latency = if r.latency_ok {
                format!("{}ms", r.latency_ms.unwrap_or(0)).into()
            } else {
                "timeout".into()
            };
        }
    }

    fn sort_health_partial(&mut self) {
        let key = self.saved_node();
        self.nodes.sort_by(|a, b| health_rank(a).cmp(&health_rank(b)));
        self.selected = key
            .as_ref()
            .and_then(|want| find_saved_node(&self.nodes, want));
    }

    fn update_profile(&mut self, cx: &mut Context<Self>) {
        let (url, name) = {
            let p = self.core.profiles.lock();
            match p.active() {
                Some(a) => (a.url.clone(), a.name.clone()),
                None => return,
            }
        };
        let Some(url) = url else {
            return;
        };
        let core = self.core.clone();
        cx.spawn(async move |this, cx| {
            let r = on_tokio(&core.rt, {
                let client = SubscriptionClient;
                let url = url.clone();
                async move { client.fetch(&url).await }
            })
            .await
            .unwrap_or_else(|| Err("runtime".into()));
            this.update(cx, |this, cx| {
                if let Ok(fetched) = r {
                    let _ = core.profiles.lock().update_cloud(
                        &name,
                        &fetched.body,
                        fetched.user_info.as_ref(),
                    );
                    this.reload_nodes();
                    this.refresh_quota();
                    this.core.proxy.abort_active();
                    if this.enhance_on {
                        if let Some(node) = this
                            .selected
                            .and_then(|i| this.nodes.get(i))
                            .filter(|n| !n.node.is_subscription_info())
                            .map(|n| n.node.clone())
                        {
                            this.core.outbound.set_current(Some(node.clone()));
                            let tun = core.tun.clone();
                            let rt = core.rt.clone();
                            cx.spawn(async move |this, cx| {
                                let probe = node;
                                let ok = on_tokio(&rt, async move {
                                    tun.on_node_changed(Some(&probe)).await
                                })
                                .await
                                .unwrap_or(false);
                                this.update(cx, |this, cx| {
                                    if !ok {
                                        this.error = "节点路由更新失败".into();
                                    }
                                    cx.notify();
                                })
                                .ok();
                            })
                            .detach();
                        }
                    }
                    this.persist();
                }
                cx.notify();
            })
            .ok();
        })
        .detach();
    }

    fn delete_profile(&mut self, cx: &mut Context<Self>) {
        let name = {
            let profiles = self.core.profiles.lock();
            profiles.active().map(|p| p.name.clone())
        };
        if let Some(name) = name {
            self.core.profiles.lock().remove(&name);
        }
        self.reload_nodes();
        self.refresh_quota();
        self.core.proxy.abort_active();
        self.persist();
        cx.notify();
    }

    fn apply_saved_node(&mut self, saved: &UiState) {
        let Some(want) = saved.node.as_ref() else {
            return;
        };
        let Some(i) = find_saved_node(&self.nodes, want) else {
            return;
        };
        self.selected = Some(i);
        self.core
            .outbound
            .set_current(Some(self.nodes[i].node.clone()));
    }

    fn restore_mode(&mut self, mode: UiMode, cx: &mut Context<Self>) {
        match mode {
            UiMode::Off => {}
            UiMode::Proxy => {
                self.core.proxy.abort_active();
                self.core.proxy.set_system_proxy(true);
                self.proxy_on = self.core.proxy.system_proxy_on();
                if let Some(e) = self.core.proxy.last_error() {
                    self.error = e.into();
                    self.proxy_on = false;
                    self.persist();
                }
            }
            UiMode::Enhance => {
                if !cfg!(windows) {
                    return;
                }
                if self.nodes.iter().all(|n| n.node.is_subscription_info()) {
                    self.error = "无可用节点, 已关闭增强模式".into();
                    return;
                }
                if !inbound::is_administrator() {
                    return;
                }
                self.begin_enhance(cx, 6, true);
            }
        }
    }

    fn saved_node(&self) -> Option<SavedNode> {
        let i = self.selected?;
        let n = self.nodes.get(i)?;
        if n.node.is_subscription_info() {
            return None;
        }
        Some(SavedNode {
            name: n.node.name.clone(),
            server: n.node.server.clone(),
            port: n.node.port,
        })
    }

    fn persist(&self) {
        UiState::patch(|s| {
            s.mode = if self.enhance_on {
                UiMode::Enhance
            } else if self.proxy_on {
                UiMode::Proxy
            } else {
                UiMode::Off
            };
            s.node = self.saved_node();
            s.window_visible = self.window_visible;
        });
        self.sync_tray();
    }

    fn sync_tray(&self) {
        let profiles = self.core.profiles.lock();
        self.tray.update_menu(tray::TrayMenuState {
            proxy_on: self.proxy_on,
            enhance_on: self.enhance_on,
            enhance_ok: cfg!(windows),
            profiles: profiles.profiles().iter().map(|p| p.name.clone()).collect(),
            active_profile: profiles.active().map(|p| p.name.clone()),
        });
    }

    fn on_close_requested(&mut self, window: &mut Window, cx: &mut Context<Self>) -> bool {
        if ALLOW_QUIT.load(Ordering::SeqCst) {
            return true;
        }
        self.set_window_visible(false, window, cx);
        false
    }

    fn set_window_visible(&mut self, show: bool, window: &mut Window, cx: &mut Context<Self>) {
        tray::apply_window_shown(window, show);
        self.window_visible = show;
        self.persist();
        cx.notify();
    }

    fn handle_tray(&mut self, ev: tray::TrayEvent, window: &mut Window, cx: &mut Context<Self>) {
        match ev {
            tray::TrayEvent::ToggleWindow => {
                let show = !tray::window_is_shown(window);
                self.set_window_visible(show, window, cx);
            }
            tray::TrayEvent::ShowWindow => self.set_window_visible(true, window, cx),
            tray::TrayEvent::ToggleProxy => self.toggle_proxy(cx),
            tray::TrayEvent::ToggleTun => {
                if !tray::window_is_shown(window) {
                    self.set_window_visible(true, window, cx);
                }
                self.toggle_enhance(cx);
            }
            tray::TrayEvent::SwitchProfile(name) => self.switch_profile(&name, cx),
            tray::TrayEvent::OpenDataDir => cx.open_with_system(&AppPaths::user_data_dir()),
            tray::TrayEvent::OpenAppDir => cx.open_with_system(&AppPaths::base_dir()),
            tray::TrayEvent::CopyEnv => {
                let port = clash_core::INBOUND_PORT;
                let text = format!(
                    "set http_proxy=http://127.0.0.1:{port}\r\nset https_proxy=http://127.0.0.1:{port}\r\nset ALL_PROXY=http://127.0.0.1:{port}"
                );
                cx.write_to_clipboard(ClipboardItem::new_string(text));
            }
            tray::TrayEvent::OpenTheme => theme::open_picker(cx),
            tray::TrayEvent::Restart => request_restart(cx),
            tray::TrayEvent::Quit => request_quit(cx),
        }
    }

    fn switch_profile(&mut self, name: &str, cx: &mut Context<Self>) {
        self.core.profiles.lock().set_default(name);
        self.show_profiles = false;
        self.reload_nodes();
        self.refresh_quota();
        self.core.proxy.abort_active();
        self.persist();
        cx.notify();
    }

    fn elevate_dialog(&mut self, cx: &mut Context<Self>) -> impl IntoElement {
        let p = theme::current(cx);
        div()
            .id("elevate-overlay")
            .absolute()
            .inset_0()
            .flex()
            .items_center()
            .justify_center()
            .occlude()
            .bg(gpui::Rgba {
                r: 0.,
                g: 0.,
                b: 0.,
                a: 0.35,
            })
            .child(
                div()
                    .id("elevate-dialog")
                    .w(px(400.))
                    .p_4()
                    .bg(rgb(p.card))
                    .rounded_md()
                    .text_color(rgb(p.fg))
                    .flex()
                    .flex_col()
                    .gap_3()
                    .occlude()
                    .on_mouse_down(MouseButton::Left, |_, _, cx| cx.stop_propagation())
                    .child("需要管理员权限")
                    .child(
                        div()
                            .text_sm()
                            .text_color(rgb(p.muted))
                            .child("增强模式需要管理员权限, 是否重启并以管理员权限启动?"),
                    )
                    .child(
                        div()
                            .flex()
                            .gap_2()
                            .child(chip_label(
                                "elevate-ok",
                                "确定",
                                cx.listener(|this, _, _, cx| this.confirm_elevate(cx)),
                                cx,
                            ))
                            .child(chip_label(
                                "elevate-cancel",
                                "取消",
                                cx.listener(|this, _, _, cx| {
                                    this.show_elevate = false;
                                    cx.notify();
                                }),
                                cx,
                            )),
                    ),
            )
    }

    fn confirm_elevate(&mut self, cx: &mut Context<Self>) {
        UiState::patch(|s| {
            s.mode = UiMode::Enhance;
            s.node = self.saved_node();
        });
        self.show_elevate = false;
        cx.notify();
        let core = self.core.clone();
        cx.spawn(async move |this, cx| {
            let _ = on_tokio(&core.rt, {
                let proxy = core.proxy.clone();
                let tun = core.tun.clone();
                async move {
                    let _ = proxy.set_listening(false).await;
                    tun.stop().await;
                    inbound::force_restore();
                }
            })
            .await;

            let (tx, rx) = std::sync::mpsc::sync_channel(1);
            let args = LaunchFlags::elevate_relaunch_args();
            std::thread::spawn(move || {
                let _ = tx.send(inbound::try_relaunch_elevated_with(&args));
            });
            let ok = loop {
                match rx.try_recv() {
                    Ok(v) => break v,
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => break false,
                    Err(std::sync::mpsc::TryRecvError::Empty) => {
                        cx.background_executor()
                            .timer(Duration::from_millis(20))
                            .await;
                    }
                }
            };

            if ok {
                std::thread::spawn(|| {
                    std::thread::sleep(Duration::from_millis(1500));
                    std::process::exit(0);
                });
                this.update(cx, |_, cx| cx.quit()).ok();
                return;
            }

            let _ = on_tokio(&core.rt, {
                let proxy = core.proxy.clone();
                async move { proxy.set_listening(true).await }
            })
            .await;
            this.update(cx, |this, cx| {
                this.persist();
                this.error = "已取消或无法获取管理员权限".into();
                cx.notify();
            })
            .ok();
        })
        .detach();
    }
}

async fn on_tokio<T: Send + 'static>(
    rt: &tokio::runtime::Handle,
    fut: impl std::future::Future<Output = T> + Send + 'static,
) -> Option<T> {
    rt.spawn(fut).await.ok()
}

fn health_rank(n: &NodeVm) -> (u8, i32) {
    if n.node.is_subscription_info() {
        return (0, 0);
    }
    match n.health {
        HealthStatus::Ok | HealthStatus::Slow => (1, n.latency_ms.unwrap_or(i32::MAX)),
        HealthStatus::LatencyFailed => (2, i32::MAX),
        HealthStatus::Checking | HealthStatus::Idle => (3, i32::MAX),
    }
}

fn latency_color(health: HealthStatus, muted: u32) -> u32 {
    match health {
        HealthStatus::Ok => 0x16a34a,
        HealthStatus::Slow => 0xca8a04,
        HealthStatus::LatencyFailed => 0xdc2626,
        _ => muted,
    }
}

fn node_card_width(window: &Window) -> gpui::Pixels {
    let pad = 24.0;
    let gap = 8.0;
    let min_card = 186.0;
    let inner = (f32::from(window.bounds().size.width) - pad).max(min_card);
    let cols = ((inner + gap) / (min_card + gap)).floor().max(1.0);
    px((inner - gap * (cols - 1.0)) / cols)
}

fn find_saved_node(nodes: &[NodeVm], want: &SavedNode) -> Option<usize> {
    nodes
        .iter()
        .position(|n| {
            n.node.name == want.name && n.node.server == want.server && n.node.port == want.port
        })
        .or_else(|| {
            nodes
                .iter()
                .position(|n| n.node.name == want.name && !n.node.is_subscription_info())
        })
}

fn title_bar(maximized: bool, cx: &App) -> impl IntoElement {
    let p = theme::current(cx);
    div()
        .id("title-bar")
        .h(px(TITLE_BAR_H))
        .flex_shrink_0()
        .flex()
        .flex_row()
        .items_center()
        .bg(rgb(p.chip))
        .border_b_1()
        .border_color(rgb(p.border))
        .text_color(rgb(p.fg))
        .child(
            div()
                .id("title-drag")
                .flex_1()
                .h_full()
                .px_3()
                .flex()
                .items_center()
                .window_control_area(WindowControlArea::Drag)
                .child("rust-clash"),
        )
        .child(win_ctrl("win-min", "─", WindowControlArea::Min, false, cx))
        .child(win_ctrl(
            "win-max",
            if maximized { "❐" } else { "□" },
            WindowControlArea::Max,
            false,
            cx,
        ))
        .child(win_ctrl("win-close", "×", WindowControlArea::Close, true, cx))
}

fn win_ctrl(
    id: &'static str,
    label: &'static str,
    area: WindowControlArea,
    close: bool,
    cx: &App,
) -> impl IntoElement {
    let p = theme::current(cx);
    div()
        .id(id)
        .w(px(46.))
        .h_full()
        .flex()
        .items_center()
        .justify_center()
        .text_color(rgb(p.fg))
        .window_control_area(area)
        .hover(move |s| {
            if close {
                s.bg(rgb(0xdc2626)).text_color(rgb(0xffffff))
            } else {
                s.bg(rgb(p.chip_hover))
            }
        })
        .child(label)
}

fn chip(
    label: &'static str,
    on: impl Fn(&ClickEvent, &mut Window, &mut App) + 'static,
    cx: &App,
) -> impl IntoElement {
    let p = theme::current(cx);
    div()
        .id(label)
        .flex_none()
        .px_2()
        .py_1()
        .rounded_md()
        .bg(rgb(p.chip))
        .text_color(rgb(p.fg))
        .cursor_pointer()
        .hover(move |s| s.bg(rgb(p.chip_hover)))
        .on_click(on)
        .child(label)
}

fn chip_label(
    id: &'static str,
    label: impl Into<SharedString>,
    on: impl Fn(&ClickEvent, &mut Window, &mut App) + 'static,
    cx: &App,
) -> impl IntoElement {
    let p = theme::current(cx);
    div()
        .id(id)
        .flex_none()
        .px_2()
        .py_1()
        .rounded_md()
        .bg(rgb(p.chip))
        .text_color(rgb(p.fg))
        .cursor_pointer()
        .hover(move |s| s.bg(rgb(p.chip_hover)))
        .on_click(on)
        .child(label.into())
}

fn toggle_knob(id: &'static str, on: bool, cx: &App) -> impl IntoElement {
    let p = theme::current(cx);
    div()
        .id(id)
        .w(px(36.))
        .h(px(20.))
        .rounded_full()
        .bg(if on { rgb(p.success) } else { rgb(p.muted) })
        .flex()
        .items_center()
        .px(px(2.))
        .when(on, |d| d.justify_end())
        .when(!on, |d| d.justify_start())
        .child(
            div()
                .w(px(16.))
                .h(px(16.))
                .rounded_full()
                .bg(rgb(0xffffff)),
        )
}

fn format_quota(used: Option<i64>, total: Option<i64>) -> String {
    if used.is_none() && total.is_none() {
        return "-".into();
    }
    let used_str = used.map(format_bytes).unwrap_or_else(|| "-".into());
    match total {
        None | Some(0) => format!("{used_str}/不限"),
        Some(t) => {
            let pct = used
                .map(|u| ((u as f64) * 100.0 / (t as f64)).clamp(0.0, 100.0))
                .unwrap_or(0.0);
            format!("{pct:.2}%  {used_str}/{}", format_bytes(t))
        }
    }
}

fn format_bytes(bytes: i64) -> String {
    let b = bytes as f64;
    if b >= 1_000_000_000.0 {
        format!("{:.2} GB", b / 1_000_000_000.0)
    } else if b >= 1_000_000.0 {
        format!("{:.2} MB", b / 1_000_000.0)
    } else {
        format!("{:.2} KB", b / 1000.0)
    }
}

fn format_expire(unix: Option<i64>) -> String {
    let Some(t) = unix.filter(|t| *t > 0) else {
        return "到期 -".into();
    };
    let (y, m, d) = civil_from_unix(t);
    format!("到期 {y:04}-{m:02}-{d:02}")
}

fn civil_from_unix(unix: i64) -> (i32, u32, u32) {
    let z = unix.div_euclid(86400) + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i32 + era as i32 * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

fn main() {
    clash_core::install_crypto_provider();
    std::panic::set_hook(Box::new(|info| {
        let thread = std::thread::current()
            .name()
            .unwrap_or("unnamed")
            .to_string();
        let loc = info
            .location()
            .map(|l| format!("{}:{}", l.file(), l.line()))
            .unwrap_or_else(|| "?".into());
        let msg = info.to_string();
        let line = format!("{thread} {loc}\n{msg}\n");
        let path = clash_core::AppPaths::user_data_dir().join("panic.log");
        let _ = std::fs::write(path, line);
        eprintln!("{msg}");
    }));
    DirectNetwork::configure();
    clash_core::AppPaths::ensure_user_data();
    let flags = LaunchFlags::from_env();
    if let Some(pid) = flags.wait_pid {
        inbound::wait_for_pid(pid, Duration::from_secs(15));
    }
    if flags.start_enhance {
        let mut s = UiState::load();
        s.mode = UiMode::Enhance;
        s.save();
    }
    let saved = UiState::load();
    if saved.mode == UiMode::Enhance && cfg!(windows) && !inbound::is_administrator() {
        if inbound::try_relaunch_elevated_with(&LaunchFlags::elevate_relaunch_args()) {
            return;
        }
    }
    ensure_wintun_extracted();
    recover_orphaned_os_state();
    inbound::recover_orphaned_proxy();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio");
    let rules = Arc::new(RuleDb::load_default().expect("rules"));
    let mut profiles = ProfileStore::new();
    profiles.load_or_migrate();
    let doh = DohResolver::new();
    let outbound = Arc::new(OutboundDialer::new(doh));
    let proxy = Arc::new(ProxyService::new(rules.clone(), outbound.clone()));
    let mut listen_err = None;
    for attempt in 0..25 {
        match rt.block_on(proxy.start()) {
            Ok(()) => {
                listen_err = None;
                break;
            }
            Err(e) => {
                listen_err = Some(e);
                std::thread::sleep(Duration::from_millis(200));
                if attempt == 24 {
                    break;
                }
            }
        }
    }
    if let Some(e) = listen_err {
        let _ = std::fs::write(
            clash_core::AppPaths::user_data_dir().join("panic.log"),
            format!("listen :7887: {e}\n"),
        );
        eprintln!("listen :7887: {e}");
    }
    let tun = Arc::new(TunService::new());
    tun.configure(rules, outbound.clone());
    let health = Arc::new(HealthChecker::new(outbound.clone()));
    let core = Arc::new(AppCore {
        proxy: proxy.clone(),
        outbound,
        tun: tun.clone(),
        profiles: Mutex::new(profiles),
        health,
        rt: rt.handle().clone(),
    });

    let _enter = rt.enter();
    let core_ui = core.clone();
    let force_enhance = flags.start_enhance;
    Application::new().run(move |cx: &mut App| {
        let _ = gpui_component::init(cx);
        theme::apply(saved.theme, None, cx);
        cx.on_action(quit_action);
        cx.bind_keys([KeyBinding::new("ctrl-q", Quit, None)]);
        let bounds = Bounds::centered(None, size(px(706.), px(494.)), cx);
        cx.open_window(
            WindowOptions {
                window_bounds: Some(WindowBounds::Windowed(bounds)),
                titlebar: Some(TitlebarOptions {
                    title: Some("rust-clash".into()),
                    appears_transparent: true,
                    ..Default::default()
                }),
                is_resizable: true,
                window_min_size: Some(size(px(706.), px(494.))),
                show: true,
                focus: true,
                ..Default::default()
            },
            move |window, cx| {
                let view = cx.new(|cx| MainView::new(core_ui.clone(), force_enhance, window, cx));
                cx.new(|cx| Root::new(view, window, cx))
            },
        )
        .unwrap();
    });

    drop(_enter);
    rt.block_on(async {
        tun.stop().await;
        proxy.stop().await;
        inbound::force_restore();
    });
}

fn request_quit(cx: &mut App) {
    ALLOW_QUIT.store(true, Ordering::SeqCst);
    cx.quit();
}

fn request_restart(cx: &mut App) {
    ALLOW_QUIT.store(true, Ordering::SeqCst);
    cx.restart();
}

fn quit_action(_: &Quit, cx: &mut App) {
    request_quit(cx);
}
