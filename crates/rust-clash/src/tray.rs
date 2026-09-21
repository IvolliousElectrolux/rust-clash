use std::sync::Arc;

use parking_lot::Mutex;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

#[derive(Clone, Debug)]
pub enum TrayEvent {
    ToggleWindow,
    ShowWindow,
    ToggleProxy,
    ToggleTun,
    SwitchProfile(String),
    OpenDataDir,
    OpenAppDir,
    CopyEnv,
    OpenTheme,
    Restart,
    Quit,
}

#[derive(Clone, Debug, Default)]
pub struct TrayMenuState {
    pub proxy_on: bool,
    pub enhance_on: bool,
    pub enhance_ok: bool,
    pub profiles: Vec<String>,
    pub active_profile: Option<String>,
}

#[derive(Clone)]
pub struct Tray {
    inner: Arc<Inner>,
}

struct Inner {
    menu: Mutex<TrayMenuState>,
    events: UnboundedSender<TrayEvent>,
}

impl Tray {
    pub fn spawn() -> (Self, UnboundedReceiver<TrayEvent>) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let tray = Self {
            inner: Arc::new(Inner {
                menu: Mutex::new(TrayMenuState::default()),
                events: tx.clone(),
            }),
        };
        #[cfg(windows)]
        win::start(tray.inner.clone());
        (tray, rx)
    }

    pub fn update_menu(&self, state: TrayMenuState) {
        *self.inner.menu.lock() = state;
    }
}

#[cfg(windows)]
mod win {
    use super::*;
    use std::mem::size_of;
    use std::os::windows::ffi::OsStrExt;
    use std::sync::OnceLock;

    use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, POINT, RECT, WPARAM};
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows_sys::Win32::UI::Shell::{
        ExtractIconW, Shell_NotifyIconW, NIF_ICON, NIF_MESSAGE, NIF_TIP, NIM_ADD, NIM_DELETE,
        NOTIFYICONDATAW,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        AppendMenuW, CreatePopupMenu, CreateWindowExW, DefWindowProcW, DestroyMenu,
        DispatchMessageW, GetCursorPos, GetMessageW, LoadIconW, PostMessageW, PostQuitMessage,
        RegisterClassW, SetForegroundWindow, SetMenuDefaultItem, TrackPopupMenu, TranslateMessage,
        HICON, HMENU, MSG, TPM_BOTTOMALIGN, TPM_LEFTALIGN, TPM_RIGHTBUTTON, WM_APP, WM_COMMAND,
        WM_CONTEXTMENU, WM_CREATE, WM_DESTROY, WM_LBUTTONUP, WM_RBUTTONUP, WNDCLASSW, WS_OVERLAPPED,
        MF_CHECKED, MF_GRAYED, MF_POPUP, MF_SEPARATOR, MF_STRING, MF_UNCHECKED,
    };

    const WM_TRAY: u32 = WM_APP + 32;
    const ID_SHOW: u16 = 1001;
    const ID_PROXY: u16 = 1002;
    const ID_TUN: u16 = 1003;
    const ID_DIR_DATA: u16 = 1004;
    const ID_DIR_APP: u16 = 1005;
    const ID_COPY_ENV: u16 = 1006;
    const ID_THEME: u16 = 1009;
    const ID_RESTART: u16 = 1007;
    const ID_QUIT: u16 = 1008;
    const ID_PROFILE_BASE: u16 = 2000;

    static INNER: OnceLock<Arc<Inner>> = OnceLock::new();

    pub fn start(inner: Arc<Inner>) {
        let _ = INNER.set(inner.clone());
        std::thread::Builder::new()
            .name("tray".into())
            .spawn(move || message_loop(inner))
            .expect("tray thread");
    }

    fn message_loop(_inner: Arc<Inner>) {
        unsafe {
            let class = wide("RustClashTray");
            let wc = WNDCLASSW {
                lpfnWndProc: Some(wndproc),
                hInstance: GetModuleHandleW(std::ptr::null()),
                lpszClassName: class.as_ptr(),
                ..std::mem::zeroed()
            };
            RegisterClassW(&wc);
            let hwnd = CreateWindowExW(
                0,
                class.as_ptr(),
                wide("rust-clash").as_ptr(),
                WS_OVERLAPPED,
                0,
                0,
                0,
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                GetModuleHandleW(std::ptr::null()),
                std::ptr::null(),
            );
            if hwnd.is_null() {
                return;
            }
            let mut msg = std::mem::zeroed::<MSG>();
            while GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) > 0 {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
    }

    unsafe extern "system" fn wndproc(
        hwnd: HWND,
        msg: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        match msg {
            WM_CREATE => {
                add_icon(hwnd);
                0
            }
            WM_DESTROY => {
                remove_icon(hwnd);
                unsafe { PostQuitMessage(0) };
                0
            }
            WM_TRAY => {
                let mouse = lparam as u32;
                if mouse == WM_LBUTTONUP {
                    emit(TrayEvent::ToggleWindow);
                } else if mouse == WM_RBUTTONUP || mouse == WM_CONTEXTMENU {
                    show_menu(hwnd);
                }
                0
            }
            WM_COMMAND => {
                handle_command(wparam as u16);
                0
            }
            _ => unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) },
        }
    }

    fn add_icon(hwnd: HWND) {
        unsafe {
            let mut nid: NOTIFYICONDATAW = std::mem::zeroed();
            nid.cbSize = size_of::<NOTIFYICONDATAW>() as u32;
            nid.hWnd = hwnd;
            nid.uID = 1;
            nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
            nid.uCallbackMessage = WM_TRAY;
            nid.hIcon = load_icon();
            copy_tip(&mut nid.szTip, "rust-clash");
            Shell_NotifyIconW(NIM_ADD, &nid);
        }
    }

    fn remove_icon(hwnd: HWND) {
        unsafe {
            let mut nid: NOTIFYICONDATAW = std::mem::zeroed();
            nid.cbSize = size_of::<NOTIFYICONDATAW>() as u32;
            nid.hWnd = hwnd;
            nid.uID = 1;
            Shell_NotifyIconW(NIM_DELETE, &nid);
        }
    }

    fn load_icon() -> HICON {
        unsafe {
            let module = GetModuleHandleW(std::ptr::null());
            let from_res = LoadIconW(module, 1 as *const u16);
            if from_res != std::ptr::null_mut() {
                return from_res;
            }
            if let Ok(exe) = std::env::current_exe() {
                let path = wide_os(exe.as_os_str());
                let icon = ExtractIconW(module, path.as_ptr(), 0);
                if icon != std::ptr::null_mut() {
                    return icon;
                }
            }
            LoadIconW(std::ptr::null_mut(), 32512 as *const u16)
        }
    }

    fn show_menu(hwnd: HWND) {
        let state = INNER
            .get()
            .map(|i| i.menu.lock().clone())
            .unwrap_or_default();
        unsafe {
            let menu = CreatePopupMenu();
            if menu.is_null() {
                return;
            }
            append(menu, ID_SHOW, "显示窗口", false, true);
            append_sep(menu);
            append(menu, ID_PROXY, "系统代理", state.proxy_on, true);
            append(
                menu,
                ID_TUN,
                "虚拟网卡",
                state.enhance_on,
                state.enhance_ok,
            );
            let profiles = CreatePopupMenu();
            if state.profiles.is_empty() {
                append(profiles, 0, "(无)", false, false);
            } else {
                for (i, name) in state.profiles.iter().enumerate() {
                    let id = ID_PROFILE_BASE.saturating_add(i as u16);
                    let on = state.active_profile.as_deref() == Some(name.as_str());
                    append(profiles, id, name, on, true);
                }
            }
            append_popup(menu, profiles, "订阅配置");
            let dirs = CreatePopupMenu();
            append(dirs, ID_DIR_DATA, "数据目录", false, true);
            append(dirs, ID_DIR_APP, "程序目录", false, true);
            append_popup(menu, dirs, "打开目录");
            append(menu, ID_COPY_ENV, "复制环境变量", false, true);
            append(menu, ID_THEME, "主题", false, true);
            append_sep(menu);
            append(menu, ID_RESTART, "重启应用", false, true);
            append(menu, ID_QUIT, "退出应用\tCtrl+Q", false, true);
            SetMenuDefaultItem(menu, ID_SHOW as u32, 0);

            let mut pt = POINT { x: 0, y: 0 };
            GetCursorPos(&mut pt);
            SetForegroundWindow(hwnd);
            TrackPopupMenu(
                menu,
                TPM_LEFTALIGN | TPM_BOTTOMALIGN | TPM_RIGHTBUTTON,
                pt.x,
                pt.y,
                0,
                hwnd,
                std::ptr::null::<RECT>(),
            );
            PostMessageW(hwnd, 0, 0, 0);
            DestroyMenu(menu);
        }
    }

    fn handle_command(id: u16) {
        match id {
            ID_SHOW => emit(TrayEvent::ShowWindow),
            ID_PROXY => emit(TrayEvent::ToggleProxy),
            ID_TUN => emit(TrayEvent::ToggleTun),
            ID_DIR_DATA => emit(TrayEvent::OpenDataDir),
            ID_DIR_APP => emit(TrayEvent::OpenAppDir),
            ID_COPY_ENV => emit(TrayEvent::CopyEnv),
            ID_THEME => emit(TrayEvent::OpenTheme),
            ID_RESTART => emit(TrayEvent::Restart),
            ID_QUIT => emit(TrayEvent::Quit),
            id if id >= ID_PROFILE_BASE => {
                let idx = (id - ID_PROFILE_BASE) as usize;
                if let Some(inner) = INNER.get() {
                    let name = inner.menu.lock().profiles.get(idx).cloned();
                    if let Some(name) = name {
                        emit(TrayEvent::SwitchProfile(name));
                    }
                }
            }
            _ => {}
        }
    }

    fn emit(ev: TrayEvent) {
        if let Some(inner) = INNER.get() {
            let _ = inner.events.send(ev);
        }
    }

    fn append(menu: HMENU, id: u16, text: &str, checked: bool, enabled: bool) {
        let mut flags = MF_STRING;
        flags |= if checked { MF_CHECKED } else { MF_UNCHECKED };
        if !enabled {
            flags |= MF_GRAYED;
        }
        let label = wide(&text.replace('&', "&&"));
        unsafe {
            AppendMenuW(menu, flags, id as usize, label.as_ptr());
        }
    }

    fn append_sep(menu: HMENU) {
        unsafe {
            AppendMenuW(menu, MF_SEPARATOR, 0, std::ptr::null());
        }
    }

    fn append_popup(parent: HMENU, child: HMENU, text: &str) {
        let label = wide(text);
        unsafe {
            AppendMenuW(parent, MF_POPUP | MF_STRING, child as usize, label.as_ptr());
        }
    }

    fn copy_tip(buf: &mut [u16], text: &str) {
        let mut encoded: Vec<u16> = text.encode_utf16().collect();
        encoded.push(0);
        let n = encoded.len().min(buf.len());
        buf[..n].copy_from_slice(&encoded[..n]);
        if n < buf.len() {
            buf[n] = 0;
        } else if let Some(last) = buf.last_mut() {
            *last = 0;
        }
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn wide_os(s: &std::ffi::OsStr) -> Vec<u16> {
        s.encode_wide().chain(std::iter::once(0)).collect()
    }
}

pub fn hwnd_from_window(window: &gpui::Window) -> Option<isize> {
    #[cfg(windows)]
    {
        use raw_window_handle::{HasWindowHandle, RawWindowHandle};
        let handle = HasWindowHandle::window_handle(window).ok()?;
        match handle.as_raw() {
            RawWindowHandle::Win32(h) => Some(h.hwnd.get()),
            _ => None,
        }
    }
    #[cfg(not(windows))]
    {
        let _ = window;
        None
    }
}

pub fn window_is_shown(window: &gpui::Window) -> bool {
    #[cfg(windows)]
    {
        use windows_sys::Win32::UI::WindowsAndMessaging::{IsIconic, IsWindowVisible};
        let Some(hwnd) = hwnd_from_window(window) else {
            return true;
        };
        let hwnd = hwnd as windows_sys::Win32::Foundation::HWND;
        unsafe { IsWindowVisible(hwnd) != 0 && IsIconic(hwnd) == 0 }
    }
    #[cfg(not(windows))]
    {
        let _ = window;
        true
    }
}

pub fn apply_window_shown(window: &gpui::Window, show: bool) {
    #[cfg(windows)]
    {
        use windows_sys::Win32::UI::WindowsAndMessaging::{
            IsIconic, SetForegroundWindow, ShowWindow, SW_HIDE, SW_RESTORE, SW_SHOW,
        };
        let Some(hwnd) = hwnd_from_window(window) else {
            return;
        };
        let hwnd = hwnd as windows_sys::Win32::Foundation::HWND;
        unsafe {
            if show {
                if IsIconic(hwnd) != 0 {
                    ShowWindow(hwnd, SW_RESTORE);
                } else {
                    ShowWindow(hwnd, SW_SHOW);
                }
                SetForegroundWindow(hwnd);
            } else {
                ShowWindow(hwnd, SW_HIDE);
            }
        }
        if show {
            window.activate_window();
        }
    }
    #[cfg(not(windows))]
    {
        let _ = (window, show);
    }
}
