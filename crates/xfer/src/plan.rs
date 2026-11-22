//! Building a copy/move plan: walk sources, detect conflicts, check space.

use crate::types::*;
use std::collections::HashMap;
use vfs::{Entry, ErrorKind, Loc, Result, Scheme, Vfs, VfsError};

/// Do names on this location compare case-insensitively?
fn case_insensitive(l: &Loc) -> bool {
    l.scheme == Scheme::Smb
        || (l.scheme == Scheme::Local
            && (l.path.as_bytes().get(1) == Some(&b':') || cfg!(target_os = "macos")))
}

fn key(name: &str, ci: bool) -> String {
    if ci {
        name.to_lowercase()
    } else {
        name.to_string()
    }
}

async fn dir_index(vfs: &Vfs, dir: &Loc) -> Result<HashMap<String, Entry>> {
    let ci = case_insensitive(dir);
    match vfs.list(dir).await {
        Ok(v) => Ok(v.into_iter().map(|e| (key(&e.name, ci), e)).collect()),
        Err(e) if e.kind == ErrorKind::NotFound => Ok(HashMap::new()),
        Err(e) => Err(e),
    }
}

pub(crate) fn new_id(prefix: &str) -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    format!(
        "{prefix}{ms:x}{:03x}",
        N.fetch_add(1, Ordering::Relaxed) & 0xfff
    )
}

pub(crate) async fn plan(vfs: &Vfs, sources: Vec<Loc>, dest_dir: Loc, op: Op) -> Result<Plan> {
    let dest = vfs.stat(&dest_dir).await?;
    if !dest.is_dir {
        return Err(VfsError::new(
            ErrorKind::Conflict,
            format!("{} is not a folder", dest_dir),
        ));
    }
    let ci = case_insensitive(&dest_dir);
    let top_index = dir_index(vfs, &dest_dir).await?;
    let mut p = Plan {
        id: new_id("p"),
        op,
        dest_dir: dest_dir.to_uri(),
        items: Vec::new(),
        files: 0,
        dirs: 0,
        total_bytes: 0,
        conflicts: Vec::new(),
        free_space: None,
        enough_space: None,
        skipped: Vec::new(),
    };
    let mut all_same_volume = true;

    for src in sources {
        let su = src.to_uri();
        let skip = |p: &mut Plan, reason: &str| {
            p.skipped.push(Skipped {
                src: su.clone(),
                reason: reason.into(),
            })
        };
        if src.is_root() {
            skip(&mut p, "cannot copy a whole drive or share root");
            continue;
        }
        let st = match vfs.stat(&src).await {
            Ok(s) => s,
            Err(e) => {
                skip(&mut p, &e.message);
                continue;
            }
        };
        if st.is_dir && src.contains(&dest_dir) {
            skip(&mut p, "the destination is inside the source folder");
            continue;
        }
        let in_place = src
            .parent()
            .is_some_and(|par| par.contains(&dest_dir) && dest_dir.contains(&par));
        if op == Op::Move && in_place {
            skip(&mut p, "already in the destination folder");
            continue;
        }
        if st.is_link && st.is_dir {
            skip(&mut p, "symbolic link to a folder (not followed)");
            continue;
        }
        if op == Op::Move && !vfs.same_volume(&src, &dest_dir).await {
            all_same_volume = false;
        }
        let name = src.name();
        let dst = dest_dir.join(&name);
        let existing = top_index.get(&key(&name, ci));
        if let Some(ex) = existing
            && (!st.is_dir || !ex.is_dir)
        {
            p.conflicts.push(Conflict {
                src: su.clone(),
                dst: dst.to_uri(),
                src_size: st.size,
                dst_size: ex.size,
                src_modified: st.modified,
                dst_modified: ex.modified,
                type_mismatch: st.is_dir != ex.is_dir,
                same_file: in_place,
            });
        }
        if !st.is_dir {
            let size = st.size.unwrap_or(0);
            p.items.push(PlanItem {
                src: su,
                dst: dst.to_uri(),
                rel: name,
                size,
                is_dir: false,
            });
            p.files += 1;
            p.total_bytes += size;
            continue;
        }
        p.items.push(PlanItem {
            src: su,
            dst: dst.to_uri(),
            rel: name.clone(),
            size: 0,
            is_dir: true,
        });
        p.dirs += 1;
        // merge into an existing folder only if it is really a folder
        let merge = existing.is_some_and(|e| e.is_dir);
        // (src dir, dst dir, rel, dst exists)
        let mut stack = vec![(src.clone(), dst, name, merge, in_place)];
        while let Some((sdir, ddir, rel, dexists, same)) = stack.pop() {
            let entries = match vfs.list(&sdir).await {
                Ok(v) => v,
                Err(e) => {
                    p.skipped.push(Skipped {
                        src: sdir.to_uri(),
                        reason: e.message,
                    });
                    continue;
                }
            };
            let index = if dexists {
                dir_index(vfs, &ddir).await?
            } else {
                HashMap::new()
            };
            let mut subdirs = Vec::new();
            for e in entries {
                let s = sdir.join(&e.name);
                let d = ddir.join(&e.name);
                let r = format!("{rel}/{}", e.name);
                if e.is_dir && e.is_link {
                    p.skipped.push(Skipped {
                        src: s.to_uri(),
                        reason: "symbolic link to a folder (not followed)".into(),
                    });
                    continue;
                }
                let ex = index.get(&key(&e.name, ci));
                if let Some(ex) = ex
                    && (!e.is_dir || !ex.is_dir)
                {
                    p.conflicts.push(Conflict {
                        src: s.to_uri(),
                        dst: d.to_uri(),
                        src_size: e.size,
                        dst_size: ex.size,
                        src_modified: e.modified,
                        dst_modified: ex.modified,
                        type_mismatch: e.is_dir != ex.is_dir,
                        same_file: same,
                    });
                }
                if e.is_dir {
                    p.items.push(PlanItem {
                        src: s.to_uri(),
                        dst: d.to_uri(),
                        rel: r.clone(),
                        size: 0,
                        is_dir: true,
                    });
                    p.dirs += 1;
                    subdirs.push((s, d, r, ex.is_some_and(|x| x.is_dir), same));
                } else {
                    let size = e.size.unwrap_or(0);
                    p.items.push(PlanItem {
                        src: s.to_uri(),
                        dst: d.to_uri(),
                        rel: r,
                        size,
                        is_dir: false,
                    });
                    p.files += 1;
                    p.total_bytes += size;
                }
            }
            stack.extend(subdirs.into_iter().rev());
        }
    }
    p.free_space = vfs.free_space(&dest_dir).await;
    p.enough_space = if op == Op::Move && all_same_volume && !p.items.is_empty() {
        Some(true)
    } else {
        p.free_space.map(|f| f >= p.total_bytes)
    };
    Ok(p)
}

/// "x.ext" -> "x (n).ext"; folders and dotfiles get the suffix at the end.
pub fn keep_both_name(name: &str, n: u32, is_dir: bool) -> String {
    match name.rfind('.') {
        Some(i) if !is_dir && i > 0 => format!("{} ({n}){}", &name[..i], &name[i..]),
        _ => format!("{name} ({n})"),
    }
}
