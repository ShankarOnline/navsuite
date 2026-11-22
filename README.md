# Navsuite

[![CI](https://github.com/ShankarOnline/navsuite/actions/workflows/ci.yml/badge.svg)](https://github.com/ShankarOnline/navsuite/actions/workflows/ci.yml)

**One explorer for files, networks, phones and drives.** A single window that shows every system on
your home network and tailnet as one record, browses files across local disks, SMB, SFTP and FTP,
passes files to any phone through a browser, reads other operating systems' drives safely, and plays
media — the same on Windows, macOS and Linux (Raspberry Pi included).

Navsuite is a family hobby project by Toggle Minds. It is early, and built in the open.

## Why

The built-in "network neighbourhood" views have broken down (SMB1 is gone, each OS uses a different
discovery protocol, mesh VPNs like Tailscale don't carry Bonjour), and good tools exist only for
slices of the problem, each tied to one OS. Navsuite joins the slices: one record per system across
every channel it can be reached through, and one file view for every kind of location.

## What works today (early MVP)

- **Network:** discovery over ARP, a port sweep, Bonjour/Avahi, SSDP/UPnP, NetBIOS and Tailscale,
  merged into one record per system, with a section per channel.
- **Files:** local disks, SMB and SFTP in one view, with copy-path in every form, open-containing-folder,
  and open-terminal-here.
- **Transfers:** one queue with a copy preview, pause/resume, and a SHA-256 check on every file.
- **Phones:** an AirDrop-style drop page a phone joins by scanning a QR code — no app on the phone.
- **Drives & dual boot:** every drive and partition listed; another operating system's partitions open
  **read-only**, always; mount and safe eject; a built-in read-only ext4/NTFS reader.
- **Media:** play video and music in the window, streamed with seek support from anywhere the app can
  reach, with music tags and cover art.
- **Probes:** ping, traceroute, port, DNS and HTTP checks, with no admin rights.
- **A built-in terminal** with the shell you choose (PowerShell, cmd, bash, zsh…).

The full feature list and design notes live in the project's planning docs.

## Build

Requires a recent Rust toolchain. Navsuite is [Tauri 2](https://tauri.app) with a plain HTML/JS
frontend — no Node build step, no bundler.

```sh
cargo run -p navsuite          # run the app
cargo test                     # run the crate tests
cargo run -p netscan --example scan   # a standalone network scan
```

## Layout

| Crate | Does |
|---|---|
| `crates/netscan` | discovery and one record per system |
| `crates/vfs` | one file layer for local disks, SMB and SFTP |
| `crates/xfer` | the transfer queue with SHA-256 checks |
| `crates/dropsrv` | the phone drop page |
| `crates/probe` | ping, traceroute, port, DNS and HTTP |
| `crates/disks` | drives, mount and eject, read-only ext4/NTFS/HFS+ |
| `app` | the Tauri window and UI |

## Safety

Navsuite never writes to another operating system's partitions or to a raw device; they are opened
read-only. It does not disable, evade or work around antivirus software. Sign-ins are kept in the
operating system's keychain and never leave the machine.

## License

[Apache License 2.0](LICENSE).
