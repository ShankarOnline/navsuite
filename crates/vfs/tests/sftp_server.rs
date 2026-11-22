//! End-to-end SFTP test against an in-process russh server backed by a temp dir.
//! Exercises host-key trust, password auth from the keyring, pooling and
//! file operations. Skips (with a message) if the OS keyring is unavailable.

use russh::keys::ssh_key::private::Ed25519Keypair;
use russh::keys::{PrivateKey, PublicKey};
use russh::server::{Auth, Msg, Session};
use russh::{Channel, ChannelId};
use russh_sftp::protocol::{
    Attrs, Data, File, FileAttributes, Handle, Name, OpenFlags, SftpHandle, SftpString, Status,
    StatusCode,
};
use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use vfs::{ErrorKind, Loc, Vfs, WriteMode};

const USER: &str = "tester";
const PASS: &str = "s3cret-navsuite-test";

fn host_key(seed: u8) -> PrivateKey {
    PrivateKey::from(Ed25519Keypair::from_seed(&[seed; 32]))
}

// ------------------------------------------------------------------ server

struct SshHandler {
    root: PathBuf,
    chans: Arc<Mutex<HashMap<ChannelId, Channel<Msg>>>>,
}

impl russh::server::Handler for SshHandler {
    type Error = russh::Error;

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        Ok(if user == USER && password == PASS {
            Auth::Accept
        } else {
            Auth::reject()
        })
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: russh::server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.chans.lock().await.insert(channel.id(), channel);
        reply.accept().await;
        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        id: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let ch = self.chans.lock().await.remove(&id);
        match (name, ch) {
            ("sftp", Some(ch)) => {
                session.channel_success(id)?;
                let h = SftpFs {
                    root: self.root.clone(),
                    handles: HashMap::new(),
                    n: 0,
                };
                tokio::spawn(russh_sftp::server::run(ch.into_stream(), h));
            }
            _ => session.channel_failure(id)?,
        }
        Ok(())
    }
}

enum H {
    F(std::fs::File),
    D(Option<Vec<File>>),
}

struct SftpFs {
    root: PathBuf,
    handles: HashMap<Vec<u8>, H>,
    n: u64,
}

fn io_code(e: std::io::Error) -> StatusCode {
    match e.kind() {
        std::io::ErrorKind::NotFound => StatusCode::NoSuchFile,
        std::io::ErrorKind::PermissionDenied => StatusCode::PermissionDenied,
        _ => StatusCode::Failure,
    }
}

fn attrs(md: &std::fs::Metadata) -> FileAttributes {
    let ty = if md.is_dir() {
        0o040000
    } else if md.file_type().is_symlink() {
        0o120000
    } else {
        0o100000
    };
    FileAttributes {
        size: Some(md.len()),
        permissions: Some(ty | 0o644),
        mtime: md
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as u32),
        ..Default::default()
    }
}

fn ok(id: u32) -> Status {
    Status {
        id,
        status_code: StatusCode::Ok,
        error_message: "Ok".into(),
        language_tag: "en-US".into(),
    }
}

impl SftpFs {
    /// Virtual path ("/a/b", "a", ".") -> (real path, canonical virtual path)
    fn map(&self, p: &SftpString) -> (PathBuf, String) {
        let s = p.as_str();
        let mut comps: Vec<String> = Vec::new();
        for c in s.split('/') {
            match c {
                "" | "." => {}
                ".." => {
                    comps.pop();
                }
                c => comps.push(c.to_string()),
            }
        }
        let mut real = self.root.clone();
        for c in &comps {
            real.push(c);
        }
        (real, format!("/{}", comps.join("/")))
    }
    fn handle(&mut self, h: H) -> SftpHandle {
        self.n += 1;
        let k = format!("h{}", self.n).into_bytes();
        self.handles.insert(k.clone(), h);
        SftpHandle::from(String::from_utf8(k).unwrap())
    }
    fn file(&mut self, h: &SftpHandle) -> Result<&mut std::fs::File, StatusCode> {
        match self.handles.get_mut(h.as_bytes()) {
            Some(H::F(f)) => Ok(f),
            _ => Err(StatusCode::Failure),
        }
    }
}

impl russh_sftp::server::Handler for SftpFs {
    type Error = StatusCode;

    fn unimplemented(&self) -> Self::Error {
        StatusCode::OpUnsupported
    }

    async fn open(
        &mut self,
        id: u32,
        filename: SftpString,
        pflags: OpenFlags,
        _a: FileAttributes,
    ) -> Result<Handle, Self::Error> {
        let (real, _) = self.map(&filename);
        let mut o = std::fs::OpenOptions::new();
        o.read(pflags.contains(OpenFlags::READ))
            .write(pflags.contains(OpenFlags::WRITE) || pflags.contains(OpenFlags::APPEND));
        if pflags.contains(OpenFlags::CREATE) {
            if pflags.contains(OpenFlags::EXCLUDE) {
                o.create_new(true);
            } else {
                o.create(true);
            }
        }
        if pflags.contains(OpenFlags::TRUNCATE) {
            o.truncate(true);
        }
        let f = o.open(real).map_err(io_code)?;
        Ok(Handle {
            id,
            handle: self.handle(H::F(f)),
        })
    }

    async fn close(&mut self, id: u32, handle: SftpHandle) -> Result<Status, Self::Error> {
        self.handles.remove(handle.as_bytes());
        Ok(ok(id))
    }

    async fn read(
        &mut self,
        id: u32,
        handle: SftpHandle,
        offset: u64,
        len: u32,
    ) -> Result<Data, Self::Error> {
        let f = self.file(&handle)?;
        f.seek(SeekFrom::Start(offset)).map_err(io_code)?;
        let mut buf = vec![0u8; len as usize];
        let n = f.read(&mut buf).map_err(io_code)?;
        if n == 0 {
            return Err(StatusCode::Eof);
        }
        buf.truncate(n);
        Ok(Data { id, data: buf })
    }

    async fn write(
        &mut self,
        id: u32,
        handle: SftpHandle,
        offset: u64,
        data: Vec<u8>,
    ) -> Result<Status, Self::Error> {
        let f = self.file(&handle)?;
        f.seek(SeekFrom::Start(offset)).map_err(io_code)?;
        f.write_all(&data).map_err(io_code)?;
        Ok(ok(id))
    }

    async fn lstat(&mut self, id: u32, path: SftpString) -> Result<Attrs, Self::Error> {
        let md = std::fs::symlink_metadata(self.map(&path).0).map_err(io_code)?;
        Ok(Attrs {
            id,
            attrs: attrs(&md),
        })
    }

    async fn stat(&mut self, id: u32, path: SftpString) -> Result<Attrs, Self::Error> {
        let md = std::fs::metadata(self.map(&path).0).map_err(io_code)?;
        Ok(Attrs {
            id,
            attrs: attrs(&md),
        })
    }

    async fn fstat(&mut self, id: u32, handle: SftpHandle) -> Result<Attrs, Self::Error> {
        let md = self.file(&handle)?.metadata().map_err(io_code)?;
        Ok(Attrs {
            id,
            attrs: attrs(&md),
        })
    }

    async fn fsetstat(
        &mut self,
        id: u32,
        handle: SftpHandle,
        a: FileAttributes,
    ) -> Result<Status, Self::Error> {
        if let Some(sz) = a.size {
            self.file(&handle)?.set_len(sz).map_err(io_code)?;
        }
        Ok(ok(id))
    }

    async fn setstat(
        &mut self,
        id: u32,
        path: SftpString,
        a: FileAttributes,
    ) -> Result<Status, Self::Error> {
        if let Some(sz) = a.size {
            std::fs::OpenOptions::new()
                .write(true)
                .open(self.map(&path).0)
                .and_then(|f| f.set_len(sz))
                .map_err(io_code)?;
        }
        Ok(ok(id))
    }

    async fn opendir(&mut self, id: u32, path: SftpString) -> Result<Handle, Self::Error> {
        let rd = std::fs::read_dir(self.map(&path).0).map_err(io_code)?;
        let mut files = Vec::new();
        for e in rd.flatten() {
            if let Ok(md) = e.metadata() {
                files.push(File::new(
                    e.file_name().to_string_lossy().into_owned(),
                    attrs(&md),
                ));
            }
        }
        Ok(Handle {
            id,
            handle: self.handle(H::D(Some(files))),
        })
    }

    async fn readdir(&mut self, id: u32, handle: SftpHandle) -> Result<Name, Self::Error> {
        match self.handles.get_mut(handle.as_bytes()) {
            Some(H::D(files)) => match files.take() {
                Some(files) => Ok(Name { id, files }),
                None => Err(StatusCode::Eof),
            },
            _ => Err(StatusCode::Failure),
        }
    }

    async fn remove(&mut self, id: u32, filename: SftpString) -> Result<Status, Self::Error> {
        std::fs::remove_file(self.map(&filename).0).map_err(io_code)?;
        Ok(ok(id))
    }

    async fn mkdir(
        &mut self,
        id: u32,
        path: SftpString,
        _a: FileAttributes,
    ) -> Result<Status, Self::Error> {
        std::fs::create_dir(self.map(&path).0).map_err(io_code)?;
        Ok(ok(id))
    }

    async fn rmdir(&mut self, id: u32, path: SftpString) -> Result<Status, Self::Error> {
        std::fs::remove_dir(self.map(&path).0).map_err(io_code)?;
        Ok(ok(id))
    }

    async fn rename(
        &mut self,
        id: u32,
        oldpath: SftpString,
        newpath: SftpString,
    ) -> Result<Status, Self::Error> {
        let (a, b) = (self.map(&oldpath).0, self.map(&newpath).0);
        if b.exists() {
            return Err(StatusCode::Failure); // SFTP v3 semantics: no overwrite
        }
        std::fs::rename(a, b).map_err(io_code)?;
        Ok(ok(id))
    }

    async fn realpath(&mut self, id: u32, path: SftpString) -> Result<Name, Self::Error> {
        let (_, v) = self.map(&path);
        Ok(Name {
            id,
            files: vec![File::dummy(v)],
        })
    }
}

/// Start a server on 127.0.0.1:<random>; returns the port.
async fn start_server(root: &Path, key: PrivateKey) -> u16 {
    let config = Arc::new(russh::server::Config {
        auth_rejection_time: Duration::from_millis(10),
        auth_rejection_time_initial: Some(Duration::ZERO),
        keys: vec![key],
        ..Default::default()
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let root = root.to_path_buf();
    tokio::spawn(async move {
        while let Ok((sock, _)) = listener.accept().await {
            let h = SshHandler {
                root: root.clone(),
                chans: Arc::default(),
            };
            let cfg = config.clone();
            tokio::spawn(async move {
                if let Ok(s) = russh::server::run_stream(cfg, sock, h).await {
                    let _ = s.await;
                }
            });
        }
    });
    port
}

// ------------------------------------------------------------------ test

#[tokio::test(flavor = "multi_thread")]
async fn sftp_end_to_end() {
    let tmp = tempfile::tempdir().unwrap();
    let served = tmp.path().join("served");
    std::fs::create_dir_all(&served).unwrap();
    let port = start_server(&served, host_key(1)).await;
    let vfs = Arc::new(Vfs::new(tmp.path().join("data")));
    let root = Loc::parse(&format!("sftp://{USER}@127.0.0.1:{port}/")).unwrap();

    // 1. unknown host key
    let e = vfs.list(&root).await.unwrap_err();
    let ErrorKind::HostKeyUnknown {
        host,
        port: p,
        fingerprint,
        key_openssh,
    } = e.kind.clone()
    else {
        panic!("expected HostKeyUnknown, got {e:?}");
    };
    assert_eq!((host.as_str(), p), ("127.0.0.1", port));
    let expected = host_key(1)
        .public_key()
        .fingerprint(russh::keys::HashAlg::Sha256)
        .to_string();
    assert_eq!(fingerprint, expected);
    vfs.trust_host_key(&host, p, &key_openssh).await.unwrap();

    // 2. no password stored -> AuthRequired (unless the keyring is unusable here)
    let e = vfs.list(&root).await.unwrap_err();
    assert!(matches!(e.kind, ErrorKind::AuthRequired { .. }), "{e:?}");
    if let Err(err) = vfs.set_credentials("127.0.0.1", USER, "wrong").await {
        eprintln!("SKIPPING rest of SFTP test: keyring unavailable: {err}");
        return;
    }
    let e = vfs.list(&root).await.unwrap_err();
    assert!(
        matches!(e.kind, ErrorKind::AuthRequired { .. }) && e.message.contains("rejected"),
        "{e:?}"
    );
    vfs.set_credentials("127.0.0.1", USER, PASS).await.unwrap();

    let (vfs2, served2, root2) = (vfs.clone(), served.clone(), root.clone());
    let result = async move {
        let (vfs, served, root) = (vfs2, served2, root2);
        // 3. file operations
        assert!(vfs.list(&root).await.unwrap().is_empty());
        let home = vfs
            .canonicalize(&Loc::parse(&format!("sftp://{USER}@127.0.0.1:{port}")).unwrap())
            .await
            .unwrap();
        assert_eq!(home.path, "/");
        let d = root.join("a").join("b c");
        vfs.mkdir(&d).await.unwrap();
        vfs.mkdir(&d).await.unwrap();
        assert!(served.join("a").join("b c").is_dir());
        let f = d.join("data.bin");
        let bytes: Vec<u8> = (0..300_000u32).map(|i| (i * 7 % 251) as u8).collect();
        let h = vfs.open_write(&f, WriteMode::Create).await.unwrap();
        for (i, c) in bytes.chunks(64 * 1024).enumerate() {
            h.write_at((i * 64 * 1024) as u64, c).await.unwrap();
        }
        h.close().await.unwrap();
        assert_eq!(std::fs::read(served.join("a/b c/data.bin")).unwrap(), bytes);
        assert_eq!(
            vfs.open_write(&f, WriteMode::Create)
                .await
                .unwrap_err()
                .kind,
            ErrorKind::Conflict
        );
        assert_eq!(vfs.read_at(&f, 1000, 10).await.unwrap(), &bytes[1000..1010]);
        let h = vfs.open_read(&f).await.unwrap();
        assert_eq!(h.len().await.unwrap(), 300_000);
        assert_eq!(h.read_at(299_995, 100).await.unwrap(), &bytes[299_995..]);
        h.close().await.unwrap();
        // resume truncates
        let h = vfs.open_write(&f, WriteMode::ResumeAt(1000)).await.unwrap();
        assert_eq!(h.len().await.unwrap(), 1000);
        h.close().await.unwrap();

        let st = vfs.stat(&f).await.unwrap();
        assert_eq!(st.size, Some(1000));
        assert!(!st.is_dir);
        let list = vfs.list(&d).await.unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(Loc::parse(&list[0].loc).unwrap(), f);
        assert_eq!(
            vfs.stat(&d.join("nope")).await.unwrap_err().kind,
            ErrorKind::NotFound
        );

        let g = d.join("renamed.bin");
        vfs.rename(&f, &g).await.unwrap();
        let h = vfs.open_write(&f, WriteMode::Truncate).await.unwrap();
        h.write_at(0, b"new").await.unwrap();
        h.close().await.unwrap();
        assert_eq!(
            vfs.rename(&f, &g).await.unwrap_err().kind,
            ErrorKind::Conflict
        );
        vfs.rename_over(&f, &g).await.unwrap();
        assert_eq!(vfs.read_at(&g, 0, 10).await.unwrap(), b"new");
        assert!(
            vfs.walk(&root)
                .await
                .unwrap()
                .iter()
                .any(|e| e.name == "renamed.bin")
        );
        assert!(vfs.same_volume(&root, &g).await);

        let out = vfs.remove(&root.join("a"), true).await.unwrap();
        assert!(!out.trashed);
        assert!(!served.join("a").exists());

        // 4. changed host key is a hard error
        let port2 = start_server(&served, host_key(2)).await;
        let other: PublicKey = host_key(1).public_key().clone();
        vfs.trust_host_key("127.0.0.1", port2, &other.to_openssh().unwrap())
            .await
            .unwrap();
        let e = vfs
            .list(&Loc::parse(&format!("sftp://{USER}@127.0.0.1:{port2}/")).unwrap())
            .await
            .unwrap_err();
        assert_eq!(e.kind, ErrorKind::Conflict, "{e:?}");
        assert!(e.message.contains("CHANGED"));

        // 5. unreachable port fails fast as Offline
        let dead = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_port = dead.local_addr().unwrap().port();
        drop(dead);
        let e = vfs
            .list(&Loc::parse(&format!("sftp://{USER}@127.0.0.1:{dead_port}/")).unwrap())
            .await
            .unwrap_err();
        assert_eq!(e.kind, ErrorKind::Offline);
    };
    // AssertUnwindSafe-free cleanup: run, then always forget the test credential
    let r = tokio::spawn(result).await;
    vfs.forget_credentials("127.0.0.1", Some(USER))
        .await
        .unwrap();
    if let Err(e) = r {
        std::panic::resume_unwind(e.into_panic());
    }
}
