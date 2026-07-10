//! Maildir storage. Pure std::fs. Creates new/cur/tmp automatically.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::util;

// Maildir info separator after the unique name. POSIX uses ":2,"; NTFS forbids
// ':' in filenames, so Windows uses "!2," instead.
const INFO_SEP: &str = if cfg!(windows) { "!2," } else { ":2," };

static COUNTER: AtomicU64 = AtomicU64::new(0);

pub struct Maildir {
    root: PathBuf,
}

impl Maildir {
    pub fn open(data_dir: &str, mailbox: &str) -> io::Result<Self> {
        let root = Path::new(data_dir).join(sanitize(mailbox));
        fs::create_dir_all(root.join("tmp"))?;
        fs::create_dir_all(root.join("new"))?;
        fs::create_dir_all(root.join("cur"))?;
        Ok(Self { root })
    }

    pub fn deliver(&self, raw: &[u8], from: &str) -> io::Result<PathBuf> {
        let uniq = format!(
            "{}.{}{}.{}",
            util::now_secs(),
            COUNTER.fetch_add(1, Ordering::SeqCst),
            std::process::id(),
            hostname_safe()
        );
        let tmp_path = self.root.join("tmp").join(&uniq);
        let new_path = self.root.join("new").join(&uniq);

        {
            let mut f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp_path)?;
            let received = format!(
                "Received: from desertemail by localhost; {}\r\n",
                util::rfc2822_date(util::now_secs())
            );
            f.write_all(received.as_bytes())?;
            let _ = from;
            f.write_all(raw)?;
            f.sync_all()?;
        }
        fs::rename(&tmp_path, &new_path)?;
        util::log!("delivered {} bytes to {}", raw.len(), new_path.display());
        Ok(new_path)
    }

    pub fn list_messages(&self) -> io::Result<Vec<MessageMeta>> {
        let mut msgs = Vec::new();
        for sub in &["new", "cur"] {
            let dir = self.root.join(sub);
            if !dir.exists() {
                continue;
            }
            for entry in fs::read_dir(&dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_file() {
                    let meta = entry.metadata()?;
                    let size = meta.len();
                    let name = path
                        .file_name()
                        .map(|s| s.to_string_lossy().into_owned())
                        .unwrap_or_default();
                    let flags = if *sub == "cur" {
                        if let Some(idx) = name.rfind(INFO_SEP) {
                            name[idx + INFO_SEP.len()..].to_string()
                        } else {
                            String::new()
                        }
                    } else {
                        String::new()
                    };
                    msgs.push(MessageMeta {
                        path,
                        uid: hash_name(&name),
                        size,
                        flags,
                        in_new: *sub == "new",
                    });
                }
            }
        }
        msgs.sort_by(|a, b| a.path.file_name().cmp(&b.path.file_name()));
        Ok(msgs)
    }

    pub fn read_message(&self, path: &Path) -> io::Result<Vec<u8>> {
        fs::read(path)
    }

    pub fn mark_seen(&self, meta: &MessageMeta) -> io::Result<()> {
        if !meta.in_new {
            return Ok(());
        }
        let name = meta
            .path
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let new_name = if name.contains(INFO_SEP) {
            name
        } else {
            format!("{}{}S", name, INFO_SEP)
        };
        let dest = self.root.join("cur").join(new_name);
        fs::rename(&meta.path, &dest)?;
        Ok(())
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
}

#[derive(Debug, Clone)]
pub struct MessageMeta {
    pub path: PathBuf,
    pub uid: u32,
    pub size: u64,
    pub flags: String,
    pub in_new: bool,
}

fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' || c == '.' || c == '@' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn hostname_safe() -> String {
    format!("de{}", std::process::id() % 10000)
}

fn hash_name(name: &str) -> u32 {
    let mut h: u32 = 5381;
    for b in name.bytes() {
        h = h.wrapping_mul(33).wrapping_add(b as u32);
    }
    h
}
