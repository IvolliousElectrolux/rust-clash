use std::fs;
use std::path::{Path, PathBuf};

pub struct AppPaths;

impl AppPaths {
    pub fn base_dir() -> PathBuf {
        std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|p| p.to_path_buf()))
            .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")))
    }

    pub fn user_data_dir() -> PathBuf {
        let root = dirs_appdata();
        root.join("ArrorMeo").join("NanoClash")
    }

    pub fn rules_bin_sidecar() -> PathBuf {
        Self::base_dir().join("Rules.bin")
    }

    pub fn user_rules_bin() -> PathBuf {
        Self::user_data_dir().join("Rules.bin")
    }

    pub fn data_dir() -> PathBuf {
        Self::user_data_dir().join("data")
    }

    pub fn app_config_yaml() -> PathBuf {
        Self::user_data_dir().join("config.yaml")
    }

    pub fn wintun_dll() -> PathBuf {
        Self::user_data_dir().join("wintun.dll")
    }

    pub fn proxy_undo_file() -> PathBuf {
        Self::user_data_dir().join("proxy-undo.json")
    }

    pub fn proxy_undo_mac() -> PathBuf {
        Self::user_data_dir().join("proxy-undo-mac.txt")
    }

    pub fn proxy_undo_gnome() -> PathBuf {
        Self::user_data_dir().join("proxy-undo-gnome.txt")
    }

    pub fn tun_undo_file() -> PathBuf {
        Self::user_data_dir().join("tun-undo.json")
    }

    pub fn ui_state_file() -> PathBuf {
        Self::user_data_dir().join("ui-state.json")
    }

    pub fn ensure_user_data() {
        let _ = fs::create_dir_all(Self::user_data_dir());
        let _ = fs::create_dir_all(Self::data_dir());
        if Self::app_config_yaml().exists() {
            return;
        }
        let legacy = Self::base_dir().join("config.yaml");
        if !legacy.exists() {
            return;
        }
        let _ = fs::copy(&legacy, Self::app_config_yaml());
        let legacy_data = Self::base_dir().join("data");
        if let Ok(rd) = fs::read_dir(legacy_data) {
            for e in rd.flatten() {
                let dest = Self::data_dir().join(e.file_name());
                if !dest.exists() {
                    let _ = fs::copy(e.path(), dest);
                }
            }
        }
    }
}

fn dirs_appdata() -> PathBuf {
    if cfg!(windows) {
        std::env::var_os("APPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."))
    } else if cfg!(target_os = "macos") {
        dirs_home().join("Library").join("Application Support")
    } else {
        std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| dirs_home().join(".config"))
    }
}

fn dirs_home() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

pub fn path_starts_with(path: &Path, root: &Path) -> bool {
    let path = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    path.starts_with(root)
}
