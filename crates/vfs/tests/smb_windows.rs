//! Windows SMB smoke tests (native client). Network-free except localhost.
#![cfg(windows)]

use std::time::{Duration, Instant};
use vfs::{ErrorKind, Loc, Vfs};

#[tokio::test]
async fn unreachable_smb_host_fails_fast() {
    let tmp = tempfile::tempdir().unwrap();
    let v = Vfs::new(tmp.path().to_path_buf());
    let t0 = Instant::now();
    let e = v
        .list(&Loc::parse(r"\\192.0.2.1\share").unwrap())
        .await
        .unwrap_err();
    assert_eq!(e.kind, ErrorKind::Offline, "{e:?}");
    assert!(t0.elapsed() < Duration::from_secs(6), "{:?}", t0.elapsed());
    // cached negative result: instant
    let t1 = Instant::now();
    assert_eq!(
        v.list(&Loc::parse("smb://192.0.2.1").unwrap())
            .await
            .unwrap_err()
            .kind,
        ErrorKind::Offline
    );
    assert!(t1.elapsed() < Duration::from_millis(500));
}

#[tokio::test]
async fn localhost_shares() {
    let tmp = tempfile::tempdir().unwrap();
    let v = Vfs::new(tmp.path().to_path_buf());
    match v.list(&Loc::parse("smb://localhost").unwrap()).await {
        Ok(shares) => {
            eprintln!(
                "localhost shares: {:?}",
                shares.iter().map(|s| &s.name).collect::<Vec<_>>()
            );
            for s in shares {
                assert_eq!(s.kind, vfs::EntryKind::Share);
                assert!(!s.name.ends_with('$'));
            }
        }
        // Server service disabled / no SMB listener: acceptable
        Err(e) => eprintln!("localhost share listing unavailable: {e:?}"),
    }
}

#[tokio::test]
async fn admin_share_via_unc() {
    let tmp = tempfile::tempdir().unwrap();
    let v = Vfs::new(tmp.path().to_path_buf());
    let l = Loc::parse("smb://localhost/C$/Windows").unwrap();
    match v.list(&l).await {
        Ok(entries) => {
            assert!(
                entries
                    .iter()
                    .any(|e| e.name.eq_ignore_ascii_case("System32"))
            );
            let e = entries
                .iter()
                .find(|e| e.name.eq_ignore_ascii_case("System32"))
                .unwrap();
            assert!(
                e.loc.starts_with("smb://localhost/C$/Windows/"),
                "{}",
                e.loc
            );
            assert!(v.free_space(&l).await.is_some());
            let forms = l.forms();
            assert_eq!(forms[0].value, r"\\localhost\C$\Windows");
        }
        Err(e) => eprintln!("admin share not accessible here: {e:?}"),
    }
}
