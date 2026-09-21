use clash_core::{UiState, UiTheme};
use gpui::prelude::*;
use gpui::{
    div, px, rgb, size, App, Bounds, Context, Global, Hsla, SharedString, TitlebarOptions, Window,
    WindowBounds, WindowControlArea, WindowOptions,
};
use gpui_component::{Theme, ThemeMode};

const TITLE_H: f32 = 34.;

#[derive(Clone, Copy)]
pub struct Palette {
    pub bg: u32,
    pub fg: u32,
    pub muted: u32,
    pub chip: u32,
    pub chip_hover: u32,
    pub card: u32,
    pub border: u32,
    pub accent: u32,
    pub danger: u32,
    pub success: u32,
    pub proto: u32,
}

impl Palette {
    pub fn of(theme: UiTheme) -> Self {
        match theme {
            UiTheme::OneDark => Self {
                bg: 0x282c34,
                fg: 0xabb2bf,
                muted: 0x5c6370,
                chip: 0x3e4451,
                chip_hover: 0x4b5263,
                card: 0x21252b,
                border: 0x181a1f,
                accent: 0x61afef,
                danger: 0xe06c75,
                success: 0x98c379,
                proto: 0x5c6370,
            },
            UiTheme::Dracula => Self {
                bg: 0x282a36,
                fg: 0xf8f8f2,
                muted: 0x6272a4,
                chip: 0x44475a,
                chip_hover: 0x4d5068,
                card: 0x21222c,
                border: 0x191a21,
                accent: 0xbd93f9,
                danger: 0xff5555,
                success: 0x50fa7b,
                proto: 0x6272a4,
            },
            UiTheme::CatppuccinMocha => Self {
                bg: 0x1e1e2e,
                fg: 0xcdd6f4,
                muted: 0xa6adc8,
                chip: 0x313244,
                chip_hover: 0x45475a,
                card: 0x181825,
                border: 0x11111b,
                accent: 0x89b4fa,
                danger: 0xf38ba8,
                success: 0xa6e3a1,
                proto: 0x6c7086,
            },
            UiTheme::LightModern => Self {
                bg: 0xf8f8f8,
                fg: 0x3b3b3b,
                muted: 0x616161,
                chip: 0xe8e8e8,
                chip_hover: 0xe0e0e0,
                card: 0xffffff,
                border: 0xe5e5e5,
                accent: 0x005fb8,
                danger: 0xf85149,
                success: 0x2ea043,
                proto: 0x6e7681,
            },
            UiTheme::CatppuccinLatte => Self {
                bg: 0xeff1f5,
                fg: 0x4c4f69,
                muted: 0x6c6f85,
                chip: 0xccd0da,
                chip_hover: 0xbcc0cc,
                card: 0xe6e9ef,
                border: 0xdce0e8,
                accent: 0x1e66f5,
                danger: 0xd20f39,
                success: 0x40a02b,
                proto: 0x9ca0b0,
            },
            UiTheme::GithubLight => Self {
                bg: 0xf6f8fa,
                fg: 0x1f2328,
                muted: 0x656d76,
                chip: 0xeaeef2,
                chip_hover: 0xd0d7de,
                card: 0xffffff,
                border: 0xd0d7de,
                accent: 0x0969da,
                danger: 0xcf222e,
                success: 0x1a7f37,
                proto: 0x656d76,
            },
        }
    }
}

#[derive(Clone, Copy, Default)]
struct ActiveUiTheme(UiTheme);

impl Global for ActiveUiTheme {}

pub fn current_id(cx: &App) -> UiTheme {
    cx.try_global::<ActiveUiTheme>()
        .map(|t| t.0)
        .unwrap_or_default()
}

pub fn current(cx: &App) -> Palette {
    Palette::of(current_id(cx))
}

pub fn apply(theme: UiTheme, window: Option<&mut Window>, cx: &mut App) {
    let p = Palette::of(theme);
    let mode = if theme.is_dark() {
        ThemeMode::Dark
    } else {
        ThemeMode::Light
    };
    Theme::change(mode, window, cx);
    let t = Theme::global_mut(cx);
    t.font_size = px(13.);
    t.background = hsla(p.bg);
    t.foreground = hsla(p.fg);
    t.border = hsla(p.border);
    t.muted = hsla(p.chip);
    t.muted_foreground = hsla(p.muted);
    t.popover = hsla(p.card);
    t.popover_foreground = hsla(p.fg);
    t.input = hsla(p.border);
    t.caret = hsla(p.fg);
    t.primary = hsla(p.accent);
    t.primary_hover = hsla(p.accent);
    t.primary_active = hsla(p.accent);
    t.primary_foreground = hsla(0xffffff);
    t.secondary = hsla(p.chip);
    t.secondary_hover = hsla(p.chip_hover);
    t.secondary_foreground = hsla(p.fg);
    t.accent = hsla(p.chip_hover);
    t.accent_foreground = hsla(p.fg);
    t.list = hsla(p.bg);
    t.list_hover = hsla(p.chip_hover);
    t.list_active = hsla(p.chip);
    t.list_active_border = hsla(p.accent);
    t.danger = hsla(p.danger);
    t.danger_foreground = hsla(0xffffff);
    t.success = hsla(p.success);
    t.success_foreground = hsla(0xffffff);
    t.ring = hsla(p.accent);
    t.selection = hsla(p.accent);
    cx.set_global(ActiveUiTheme(theme));
    cx.refresh_windows();
}

pub fn select(theme: UiTheme, window: &mut Window, cx: &mut App) {
    UiState::patch(|s| s.theme = theme);
    apply(theme, Some(window), cx);
}

pub fn open_picker(cx: &mut App) {
    for handle in cx.windows() {
        if handle.downcast::<ThemePicker>().is_some() {
            let _ = handle.update(cx, |_, window, _| {
                crate::tray::apply_window_shown(window, true);
            });
            return;
        }
    }
    let bounds = Bounds::centered(None, size(px(380.), px(468.)), cx);
    let _ = cx.open_window(
        WindowOptions {
            window_bounds: Some(WindowBounds::Windowed(bounds)),
            titlebar: Some(TitlebarOptions {
                title: Some("主题".into()),
                appears_transparent: true,
                ..Default::default()
            }),
            is_resizable: false,
            window_min_size: Some(size(px(360.), px(420.))),
            ..Default::default()
        },
        |_, cx| cx.new(|_| ThemePicker),
    );
}

fn hsla(hex: u32) -> Hsla {
    Hsla::from(rgb(hex))
}

struct ThemePicker;

impl Render for ThemePicker {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let p = current(cx);
        let selected = current_id(cx);
        let maximized = window.is_maximized();
        div()
            .flex()
            .flex_col()
            .size_full()
            .bg(rgb(p.bg))
            .text_color(rgb(p.fg))
            .child(picker_title(maximized, &p))
            .child(
                div()
                    .flex()
                    .flex_col()
                    .p_3()
                    .gap_3()
                    .flex_1()
                    .child(section("暗色", dark_themes(), selected, &p, cx))
                    .child(section("浅色", light_themes(), selected, &p, cx)),
            )
    }
}

fn dark_themes() -> &'static [UiTheme] {
    &[
        UiTheme::OneDark,
        UiTheme::Dracula,
        UiTheme::CatppuccinMocha,
    ]
}

fn light_themes() -> &'static [UiTheme] {
    &[
        UiTheme::LightModern,
        UiTheme::CatppuccinLatte,
        UiTheme::GithubLight,
    ]
}

fn section(
    title: &'static str,
    items: &'static [UiTheme],
    selected: UiTheme,
    p: &Palette,
    cx: &mut Context<ThemePicker>,
) -> impl IntoElement {
    let p = *p;
    div()
        .flex()
        .flex_col()
        .gap_1()
        .child(
            div()
                .text_xs()
                .text_color(rgb(p.muted))
                .child(title),
        )
        .children(items.iter().copied().map(move |id| {
            let on = id == selected;
            let sw = Palette::of(id);
            div()
                .id(SharedString::from(id.label()))
                .flex()
                .flex_row()
                .items_center()
                .gap_2()
                .px_2()
                .py_1()
                .rounded_md()
                .cursor_pointer()
                .bg(if on { rgb(p.chip) } else { rgb(p.card) })
                .border_1()
                .border_color(if on { rgb(p.accent) } else { rgb(p.border) })
                .hover(move |s| s.bg(rgb(p.chip_hover)))
                .on_click(cx.listener(move |_, _, window, cx| select(id, window, cx)))
                .child(radio(on, &p))
                .child(
                    div()
                        .flex_1()
                        .text_sm()
                        .child(id.label()),
                )
                .child(swatch(sw.bg, p.border))
                .child(swatch(sw.card, p.border))
                .child(swatch(sw.accent, p.border))
                .child(swatch(sw.fg, p.border))
        }))
}

fn radio(on: bool, p: &Palette) -> impl IntoElement {
    div()
        .w(px(14.))
        .h(px(14.))
        .rounded_full()
        .border_1()
        .border_color(rgb(if on { p.accent } else { p.border }))
        .flex()
        .items_center()
        .justify_center()
        .when(on, |d| {
            d.child(
                div()
                    .w(px(8.))
                    .h(px(8.))
                    .rounded_full()
                    .bg(rgb(p.accent)),
            )
        })
}

fn swatch(fill: u32, border: u32) -> impl IntoElement {
    div()
        .w(px(14.))
        .h(px(14.))
        .rounded_sm()
        .bg(rgb(fill))
        .border_1()
        .border_color(rgb(border))
}

fn picker_title(maximized: bool, p: &Palette) -> impl IntoElement {
    let _ = maximized;
    let p = *p;
    div()
        .id("theme-title")
        .h(px(TITLE_H))
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
                .id("theme-drag")
                .flex_1()
                .h_full()
                .px_3()
                .flex()
                .items_center()
                .window_control_area(WindowControlArea::Drag)
                .child("主题"),
        )
        .child(
            div()
                .id("theme-close")
                .w(px(46.))
                .h_full()
                .flex()
                .items_center()
                .justify_center()
                .window_control_area(WindowControlArea::Close)
                .hover(|s| s.bg(rgb(0xdc2626)).text_color(rgb(0xffffff)))
                .child("×"),
        )
}
