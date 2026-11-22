#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    let args: Vec<String> = std::env::args().collect();
    // Elevated raw-disk helper: serve read-only partition requests, then exit (never starts a window).
    if args.get(1).map(|s| s == "--disk-helper").unwrap_or(false) {
        navsuite_lib::disk_helper(&args);
    }
    navsuite_lib::run()
}
