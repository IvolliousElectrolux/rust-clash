use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::paths::AppPaths;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UiMode {
    #[default]
    Off,
    Proxy,
    Enhance,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedNode {
    pub name: String,
    pub server: String,
    pub port: u16,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UiState {
    #[serde(default)]
    pub mode: UiMode,
    #[serde(default)]
    pub node: Option<SavedNode>,
}

/// Flags passed when relaunching elevated so TUN starts after UAC without
/// depending on the unelevated process still writing `ui-state.json`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LaunchFlags {
    pub start_enhance: bool,
    pub wait_pid: Option<u32>,
}

impl LaunchFlags {
    pub fn from_args<I, S>(args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut flags = Self::default();
        for a in args {
            let a = a.as_ref();
            if a == "--start-enhance" {
                flags.start_enhance = true;
            } else if let Some(p) = a.strip_prefix("--wait-pid=") {
                flags.wait_pid = p.parse().ok();
            }
        }
        flags
    }

    pub fn from_env() -> Self {
        Self::from_args(std::env::args().skip(1))
    }

    pub fn elevate_relaunch_args() -> String {
        format!("--start-enhance --wait-pid={}", std::process::id())
    }
}

impl UiState {
    pub fn load() -> Self {
        Self::load_from(&AppPaths::ui_state_file())
    }

    pub fn save(&self) {
        self.save_to(&AppPaths::ui_state_file());
    }

    pub fn load_from(path: &Path) -> Self {
        let Ok(text) = std::fs::read_to_string(path) else {
            return Self::default();
        };
        serde_json::from_str(&text).unwrap_or_default()
    }

    pub fn save_to(&self, path: &Path) {
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        if let Ok(text) = serde_json::to_string(self) {
            let _ = std::fs::write(path, text);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_enhance_and_node() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ui-state.json");
        let state = UiState {
            mode: UiMode::Enhance,
            node: Some(SavedNode {
                name: "hk".into(),
                server: "example.com".into(),
                port: 443,
            }),
        };
        state.save_to(&path);
        let loaded = UiState::load_from(&path);
        assert_eq!(loaded, state);
    }

    #[test]
    fn missing_file_is_off() {
        let dir = tempfile::tempdir().unwrap();
        let loaded = UiState::load_from(&dir.path().join("missing.json"));
        assert_eq!(loaded, UiState::default());
        assert_eq!(loaded.mode, UiMode::Off);
    }

    #[test]
    fn garbage_file_is_off() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ui-state.json");
        std::fs::write(&path, "{not json").unwrap();
        assert_eq!(UiState::load_from(&path).mode, UiMode::Off);
    }

    #[test]
    fn launch_flags_parse_enhance_and_pid() {
        let f = LaunchFlags::from_args(["--start-enhance", "--wait-pid=4242"]);
        assert!(f.start_enhance);
        assert_eq!(f.wait_pid, Some(4242));
        let empty = LaunchFlags::from_args(["--help"]);
        assert!(!empty.start_enhance);
        assert_eq!(empty.wait_pid, None);
    }
}
