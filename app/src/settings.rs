//! Settings (K7) and the user's own labels and notes for systems (R3).

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct SystemNote {
    pub label: Option<String>,
    pub notes: Option<String>,
    /// Override of the guessed kind (router, printer, nas, phone, tv, pi, ...).
    pub kind: Option<String>,
    pub trusted: bool,
    /// Shell to use when opening a terminal on this system.
    pub shell: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase", default)]
pub struct Settings {
    /// Shell id for new terminals; empty = first found.
    pub default_shell: String,
    /// Which "Copy path" form Ctrl+Shift+C copies (label as returned by vfs forms).
    pub default_path_form: String,
    /// Extra subnets to sweep, e.g. "192.168.50.0/24".
    pub extra_subnets: Vec<String>,
    /// Minutes between background scans; 0 = only when asked.
    pub scan_interval_min: u32,
    /// "system" | "light" | "dark"
    pub theme: String,
    pub show_hidden: bool,
    pub show_tree: bool,
    /// Show the left sidebar (sections list); toggled from the toolbar (Ctrl+B).
    pub show_sidebar: bool,
    /// Keep the bottom dock (terminal/transfers/probes...) collapsed until needed.
    pub dock_collapsed: bool,
    /// Width of the left sidebar in pixels (drag-to-resize).
    pub sidebar_width: u32,
    /// Check every copy against the source with SHA-256 (E9).
    pub verify_copies: bool,
    pub write_manifest: bool,
    /// Phone drop page.
    pub drop_enabled: bool,
    pub drop_port: u16,
    pub drop_expiry_hours: u64,
    /// Notes per system record id.
    pub systems: BTreeMap<String, SystemNote>,
    pub favourites: Vec<Favourite>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct Favourite {
    pub name: String,
    /// A location (vfs URI) or a system record id prefixed with "sys:".
    pub target: String,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            default_shell: String::new(),
            default_path_form: String::new(),
            extra_subnets: Vec::new(),
            scan_interval_min: 15,
            theme: "system".into(),
            show_hidden: true,
            show_tree: true,
            show_sidebar: true,
            dock_collapsed: false,
            sidebar_width: 210,
            verify_copies: true,
            write_manifest: false,
            drop_enabled: true,
            drop_port: 8765,
            drop_expiry_hours: 24,
            systems: BTreeMap::new(),
            favourites: Vec::new(),
        }
    }
}

pub fn data_dir() -> PathBuf {
    let base = dirs::data_dir().unwrap_or_else(std::env::temp_dir);
    let d = base.join("narada");
    // Carry settings over from the previous name ("navsuite") on the first run after the rename.
    if !d.exists() {
        let old = base.join("navsuite");
        if old.is_dir() {
            let _ = std::fs::rename(&old, &d);
        }
    }
    let _ = std::fs::create_dir_all(&d);
    d
}

fn path() -> PathBuf {
    data_dir().join("settings.json")
}

pub fn load() -> Settings {
    std::fs::read(path()).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
}

pub fn save(s: &Settings) -> Result<(), String> {
    let tmp = path().with_extension("json.tmp");
    let bytes = serde_json::to_vec_pretty(s).map_err(|e| e.to_string())?;
    std::fs::write(&tmp, bytes).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, path()).map_err(|e| e.to_string())
}
