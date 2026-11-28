//! Credentials: passwords in the OS keyring (service "narada", account
//! "user@host"), plus a small host -> user map in the data dir so we know
//! which account to look up for SMB hosts.

use crate::error::{Result, VfsError};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

const SERVICE: &str = "narada";

pub(crate) struct Creds {
    users_file: PathBuf,
    users: Mutex<HashMap<String, String>>,
    cache: Mutex<HashMap<String, Option<String>>>,
}

fn account(host: &str, user: &str) -> String {
    format!("{user}@{}", host.to_ascii_lowercase())
}

impl Creds {
    pub fn new(data_dir: &std::path::Path) -> Creds {
        let users_file = data_dir.join("hosts.json");
        let users = std::fs::read(&users_file)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        Creds {
            users_file,
            users: Mutex::new(users),
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// The user last stored for `host`, if any.
    pub fn user_for(&self, host: &str) -> Option<String> {
        self.users
            .lock()
            .unwrap()
            .get(&host.to_ascii_lowercase())
            .cloned()
    }

    fn save_users(&self) {
        let snapshot = self.users.lock().unwrap().clone();
        if let Some(d) = self.users_file.parent() {
            let _ = std::fs::create_dir_all(d);
        }
        if let Ok(b) = serde_json::to_vec_pretty(&snapshot) {
            let _ = std::fs::write(&self.users_file, b);
        }
    }

    pub async fn password(&self, host: &str, user: &str) -> Option<String> {
        let acct = account(host, user);
        if let Some(v) = self.cache.lock().unwrap().get(&acct) {
            return v.clone();
        }
        let a = acct.clone();
        let pw = tokio::task::spawn_blocking(move || {
            keyring::Entry::new(SERVICE, &a)
                .ok()
                .and_then(|e| e.get_password().ok())
        })
        .await
        .ok()
        .flatten();
        self.cache.lock().unwrap().insert(acct, pw.clone());
        pw
    }

    pub async fn set(&self, host: &str, user: &str, password: &str) -> Result<()> {
        let acct = account(host, user);
        let (a, p) = (acct.clone(), password.to_string());
        tokio::task::spawn_blocking(move || {
            keyring::Entry::new(SERVICE, &a)
                .and_then(|e| e.set_password(&p))
                .map_err(|e| VfsError::other(format!("keyring: {e}")))
        })
        .await??;
        self.cache
            .lock()
            .unwrap()
            .insert(acct, Some(password.to_string()));
        self.users
            .lock()
            .unwrap()
            .insert(host.to_ascii_lowercase(), user.to_string());
        self.save_users();
        Ok(())
    }

    pub async fn forget(&self, host: &str, user: Option<&str>) -> Result<()> {
        let user = match user.map(str::to_string).or_else(|| self.user_for(host)) {
            Some(u) => u,
            None => return Ok(()),
        };
        let acct = account(host, &user);
        let a = acct.clone();
        tokio::task::spawn_blocking(move || {
            if let Ok(e) = keyring::Entry::new(SERVICE, &a) {
                let _ = e.delete_credential();
            }
        })
        .await?;
        self.cache.lock().unwrap().insert(acct, None);
        let removed = {
            let mut u = self.users.lock().unwrap();
            if u.get(&host.to_ascii_lowercase()) == Some(&user) {
                u.remove(&host.to_ascii_lowercase());
                true
            } else {
                false
            }
        };
        if removed {
            self.save_users();
        }
        Ok(())
    }
}
