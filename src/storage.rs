//! Maildir storage. Pure std::fs. Creates new/cur/tmp automatically.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

use crate::util;

// Maildir info separator after the unique name. POSIX uses ":2,"; NTFS forbids
// ':' in filenames, so Windows uses "!2," instead.
pub const INFO_SEP: &str = if cfg!(windows) { "!2," } else { ":2," };

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// Short-lived cache of mailbox sizes for quota checks (avoids full rescan per msg).
struct SizeCacheEntry {
    bytes: u64,
    at: Instant,
}

fn size_cache() -> &'static Mutex<std::collections::HashMap<String, SizeCacheEntry>> {
    static C: OnceLock<Mutex<std::collections::HashMap<String, SizeCacheEntry>>> = OnceLock::new();
    C.get_or_init(|| Mutex::new(std::collections::HashMap::new()))
}

const SIZE_CACHE_TTL_SECS: u64 = 5;

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
        let uniq = unique_name();
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
        invalidate_size_cache_for_path(&self.root);
        util::log!("delivered {} bytes to {}", raw.len(), new_path.display());
        Ok(new_path)
    }

    /// Store raw octets without a Received: header (IMAP APPEND).
    /// If `seen` is true, message goes to cur with S flag; else to new.
    pub fn append_raw(&self, raw: &[u8], flags: &str) -> io::Result<PathBuf> {
        let uniq = unique_name();
        let seen = flags.contains('S') || flags.contains('s');
        let mut flag_part = normalize_flag_chars(flags);
        if seen && !flag_part.contains('S') {
            flag_part.push('S');
        }
        flag_part = sort_maildir_flags(&flag_part);
        let fname = if flag_part.is_empty() && !seen {
            uniq.clone()
        } else {
            format!("{}{}{}", uniq, INFO_SEP, flag_part)
        };
        let tmp_path = self.root.join("tmp").join(&uniq);
        let dest = if seen || !flag_part.is_empty() {
            self.root.join("cur").join(&fname)
        } else {
            self.root.join("new").join(&uniq)
        };

        {
            let mut f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp_path)?;
            f.write_all(raw)?;
            f.sync_all()?;
        }
        fs::rename(&tmp_path, &dest)?;
        invalidate_size_cache_for_path(&self.root);
        util::log!("appended {} bytes to {}", raw.len(), dest.display());
        Ok(dest)
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
                        uid: hash_name(&base_name(&name)),
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
            // ensure S present
            let base = base_name(&name);
            let mut flags = flags_from_name(&name);
            if !flags.contains('S') {
                flags.push('S');
            }
            flags = sort_maildir_flags(&flags);
            format!("{}{}{}", base, INFO_SEP, flags)
        } else {
            format!("{}{}S", name, INFO_SEP)
        };
        let dest = self.root.join("cur").join(new_name);
        fs::rename(&meta.path, &dest)?;
        invalidate_size_cache_for_path(&self.root);
        Ok(())
    }

    /// Update flags on a message. Returns new MessageMeta (path may change).
    /// `mode`: "FLAGS" (replace), "+FLAGS" (add), "-FLAGS" (remove).
    /// `imap_flags` is a list like ["\\Seen", "\\Deleted"].
    pub fn store_flags(
        &self,
        meta: &MessageMeta,
        mode: &str,
        imap_flags: &[String],
    ) -> io::Result<MessageMeta> {
        let name = meta
            .path
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        let base = base_name(&name);
        let chars = if meta.in_new {
            String::new()
        } else {
            flags_from_name(&name)
        };

        let mut want: Vec<char> = chars.chars().collect();
        let mode_u = mode.to_uppercase();
        if mode_u == "FLAGS" {
            want.clear();
        }
        for f in imap_flags {
            let c = imap_flag_to_char(f);
            if c == '\0' {
                continue;
            }
            match mode_u.as_str() {
                "FLAGS" | "+FLAGS" => {
                    if !want.contains(&c) {
                        want.push(c);
                    }
                }
                "-FLAGS" => {
                    want.retain(|&x| x != c);
                }
                _ => {}
            }
        }
        let flag_str = sort_maildir_flags(&want.into_iter().collect::<String>());
        let seen = flag_str.contains('S');
        // Messages with any flag go to cur; without and not seen stay in new if was new
        // and we're not setting flags that require cur. Maildir convention: flagged => cur.
        let go_cur = seen || !flag_str.is_empty() || !meta.in_new || mode_u == "FLAGS";
        let new_name = if go_cur {
            if flag_str.is_empty() {
                format!("{}{}", base, INFO_SEP)
            } else {
                format!("{}{}{}", base, INFO_SEP, flag_str)
            }
        } else {
            base.clone()
        };
        let dest = if go_cur {
            self.root.join("cur").join(&new_name)
        } else {
            self.root.join("new").join(&new_name)
        };
        if dest != meta.path {
            fs::rename(&meta.path, &dest)?;
            invalidate_size_cache_for_path(&self.root);
        }
        Ok(MessageMeta {
            path: dest,
            uid: meta.uid, // stable: based on base name only
            size: meta.size,
            flags: flag_str,
            in_new: !go_cur,
        })
    }

    /// Delete message file (EXPUNGE).
    pub fn expunge(&self, meta: &MessageMeta) -> io::Result<()> {
        fs::remove_file(&meta.path)?;
        invalidate_size_cache_for_path(&self.root);
        Ok(())
    }

    /// Atomically move a message into this maildir (same-filesystem rename).
    /// Preserves the unique base name and Maildir flags; destination uses
    /// `cur` when the source had flags or was already in cur, otherwise `new`.
    pub fn take_message(&self, meta: &MessageMeta) -> io::Result<MessageMeta> {
        let name = meta
            .path
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        if name.is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "empty name"));
        }
        let base = base_name(&name);
        let flags = if meta.in_new {
            String::new()
        } else {
            flags_from_name(&name)
        };
        let go_cur = !meta.in_new || !flags.is_empty();
        let dest_name = if go_cur {
            if flags.is_empty() {
                format!("{}{}", base, INFO_SEP)
            } else {
                format!("{}{}{}", base, INFO_SEP, flags)
            }
        } else {
            base.clone()
        };
        let dest = if go_cur {
            self.root.join("cur").join(&dest_name)
        } else {
            self.root.join("new").join(&dest_name)
        };
        // Avoid clobbering an existing file with the same name.
        let dest = if dest.exists() {
            let uniq = unique_name();
            let alt_name = if go_cur {
                if flags.is_empty() {
                    format!("{}{}", uniq, INFO_SEP)
                } else {
                    format!("{}{}{}", uniq, INFO_SEP, flags)
                }
            } else {
                uniq
            };
            if go_cur {
                self.root.join("cur").join(alt_name)
            } else {
                self.root.join("new").join(alt_name)
            }
        } else {
            dest
        };
        fs::rename(&meta.path, &dest)?;
        invalidate_size_cache_for_path(&self.root);
        if let Some(parent) = meta.path.parent().and_then(|p| p.parent()) {
            invalidate_size_cache_for_path(parent);
        }
        let new_name = dest
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        Ok(MessageMeta {
            path: dest,
            uid: hash_name(&base_name(&new_name)),
            size: meta.size,
            flags,
            in_new: !go_cur,
        })
    }

    /// Move message into another maildir folder (e.g. Trash). Creates dest dirs.
    pub fn move_to(&self, meta: &MessageMeta, dest: &Maildir) -> io::Result<MessageMeta> {
        dest.take_message(meta)
    }

    /// Snapshot for IDLE change detection: (mtime of new/ or root, file count).
    pub fn idle_snapshot(&self) -> (u64, u64) {
        let mut count = 0u64;
        let mut mtime = 0u64;
        for sub in &["new", "cur"] {
            let dir = self.root.join(sub);
            if let Ok(md) = fs::metadata(&dir) {
                if let Ok(t) = md.modified() {
                    if let Ok(d) = t.duration_since(std::time::UNIX_EPOCH) {
                        mtime = mtime.max(d.as_secs());
                    }
                }
            }
            if let Ok(rd) = fs::read_dir(&dir) {
                for e in rd.flatten() {
                    if e.path().is_file() {
                        count += 1;
                        if let Ok(md) = e.metadata() {
                            if let Ok(t) = md.modified() {
                                if let Ok(d) = t.duration_since(std::time::UNIX_EPOCH) {
                                    mtime = mtime.max(d.as_secs());
                                }
                            }
                        }
                    }
                }
            }
        }
        (mtime, count)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Sum file sizes under a user's Maildir tree (all subfolders).
    pub fn mailbox_size(data_dir: &str, user: &str) -> io::Result<u64> {
        let key = format!("{}|{}", data_dir, sanitize(user));
        if let Ok(cache) = size_cache().lock() {
            if let Some(ent) = cache.get(&key) {
                if ent.at.elapsed().as_secs() < SIZE_CACHE_TTL_SECS {
                    return Ok(ent.bytes);
                }
            }
        }
        let root = Path::new(data_dir).join(sanitize(user));
        let bytes = dir_size_recursive(&root)?;
        if let Ok(mut cache) = size_cache().lock() {
            cache.insert(
                key,
                SizeCacheEntry {
                    bytes,
                    at: Instant::now(),
                },
            );
        }
        Ok(bytes)
    }

    /// Invalidate size cache for a user (after delivery/expunge).
    pub fn invalidate_quota_cache(data_dir: &str, user: &str) {
        let key = format!("{}|{}", data_dir, sanitize(user));
        if let Ok(mut cache) = size_cache().lock() {
            cache.remove(&key);
        }
    }

    /// Check whether adding `extra` bytes would exceed quota.
    /// `quota_bytes` 0 = unlimited. Returns true if over quota.
    pub fn would_exceed_quota(current: u64, extra: u64, quota_bytes: u64) -> bool {
        if quota_bytes == 0 {
            return false;
        }
        current.saturating_add(extra) > quota_bytes
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

impl MessageMeta {
    /// IMAP FLAGS atom list, e.g. `(\\Seen \\Deleted)`.
    pub fn imap_flags_str(&self) -> String {
        let mut parts = Vec::new();
        if self.in_new {
            parts.push("\\Recent");
        }
        for c in self.flags.chars() {
            if let Some(f) = char_to_imap_flag(c) {
                parts.push(f);
            }
        }
        // Messages in cur without S are still "not recent" and not necessarily unseen in
        // the sense of \Seen absent — report \Seen only when S present.
        format!("({})", parts.join(" "))
    }

    pub fn has_flag(&self, imap: &str) -> bool {
        let c = imap_flag_to_char(imap);
        if c == '\0' {
            return false;
        }
        if imap.eq_ignore_ascii_case("\\Recent") {
            return self.in_new;
        }
        self.flags.contains(c)
    }

    pub fn is_seen(&self) -> bool {
        self.flags.contains('S')
    }
}

fn unique_name() -> String {
    format!(
        "{}.{}{}.{}",
        util::now_secs(),
        COUNTER.fetch_add(1, Ordering::SeqCst),
        std::process::id(),
        hostname_safe()
    )
}

fn invalidate_size_cache_for_path(root: &Path) {
    // Best-effort: clear any cache key whose path prefix matches.
    if let Ok(mut cache) = size_cache().lock() {
        let root_s = root.to_string_lossy();
        cache.retain(|k, _| !k.contains(root_s.as_ref()));
        // Also clear parent user key if root is data_dir/user or nested
        if let Some(parent) = root.parent() {
            let p = parent.to_string_lossy();
            cache.retain(|k, _| !k.contains(p.as_ref()));
        }
    }
}

fn dir_size_recursive(path: &Path) -> io::Result<u64> {
    if !path.exists() {
        return Ok(0);
    }
    let mut total = 0u64;
    let mut stack = vec![path.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let rd = match fs::read_dir(&dir) {
            Ok(r) => r,
            Err(_) => continue,
        };
        for entry in rd.flatten() {
            let p = entry.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.is_file() {
                if let Ok(md) = entry.metadata() {
                    total = total.saturating_add(md.len());
                }
            }
        }
    }
    Ok(total)
}

/// Base unique name without Maildir info suffix.
pub fn base_name(name: &str) -> String {
    if let Some(idx) = name.rfind(INFO_SEP) {
        name[..idx].to_string()
    } else {
        name.to_string()
    }
}

fn flags_from_name(name: &str) -> String {
    if let Some(idx) = name.rfind(INFO_SEP) {
        name[idx + INFO_SEP.len()..].to_string()
    } else {
        String::new()
    }
}

/// Convert IMAP flag token to Maildir char (0 if unknown).
pub fn imap_flag_to_char(f: &str) -> char {
    let f = f.trim().trim_matches('\\');
    match f.to_ascii_lowercase().as_str() {
        "seen" => 'S',
        "answered" => 'R',
        "flagged" => 'F',
        "deleted" => 'T', // trashed
        "draft" => 'D',
        "recent" => '\0', // not stored in filename
        _ => '\0',
    }
}

fn char_to_imap_flag(c: char) -> Option<&'static str> {
    match c {
        'S' => Some("\\Seen"),
        'R' => Some("\\Answered"),
        'F' => Some("\\Flagged"),
        'T' => Some("\\Deleted"),
        'D' => Some("\\Draft"),
        'P' => Some("\\Passed"),
        _ => None,
    }
}

fn normalize_flag_chars(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        if "DFPRST".contains(c) && !out.contains(c) {
            out.push(c);
        }
    }
    sort_maildir_flags(&out)
}

/// Serialize IMAP flag list into Maildir flag chars (for tests / STORE).
pub fn flags_to_maildir(imap_flags: &[String]) -> String {
    let mut s = String::new();
    for f in imap_flags {
        let c = imap_flag_to_char(f);
        if c != '\0' && !s.contains(c) {
            s.push(c);
        }
    }
    sort_maildir_flags(&s)
}

/// Parse Maildir flag chars back to IMAP flag strings.
pub fn maildir_to_imap_flags(flags: &str) -> Vec<String> {
    let mut v = Vec::new();
    for c in flags.chars() {
        if let Some(f) = char_to_imap_flag(c) {
            v.push(f.to_string());
        }
    }
    v
}

fn sort_maildir_flags(s: &str) -> String {
    const ORDER: &[char] = &['D', 'F', 'P', 'R', 'S', 'T'];
    let mut out = String::new();
    for &c in ORDER {
        if s.contains(c) {
            out.push(c);
        }
    }
    out
}

/// Sanitize a mailbox path relative to data_dir.
/// Allows `/` so folders like `user/.Trash` and `user/.Junk` nest correctly.
/// Rejects empty / `.` / `..` segments and maps other unsafe chars to `_`.
fn sanitize(s: &str) -> String {
    let mut out = String::new();
    for part in s.split(|c| c == '/' || c == '\\') {
        if part.is_empty() || part == "." || part == ".." {
            continue;
        }
        if !out.is_empty() {
            out.push('/');
        }
        for c in part.chars() {
            if c.is_alphanumeric() || c == '-' || c == '_' || c == '.' || c == '@' {
                out.push(c);
            } else {
                out.push('_');
            }
        }
    }
    out
}

fn hostname_safe() -> String {
    format!("de{}", std::process::id() % 10000)
}

/// Stable UID from the unique Maildir base name (flags stripped).
fn hash_name(name: &str) -> u32 {
    let mut h: u32 = 5381;
    for b in name.bytes() {
        h = h.wrapping_mul(33).wrapping_add(b as u32);
    }
    // Avoid UID 0 (some clients treat 0 specially)
    if h == 0 {
        1
    } else {
        h
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn flag_serialization_roundtrip() {
        let imap = vec!["\\Seen".into(), "\\Deleted".into(), "\\Flagged".into()];
        let md = flags_to_maildir(&imap);
        assert!(md.contains('S'));
        assert!(md.contains('T'));
        assert!(md.contains('F'));
        let back = maildir_to_imap_flags(&md);
        assert!(back.iter().any(|f| f == "\\Seen"));
        assert!(back.iter().any(|f| f == "\\Deleted"));
        assert!(back.iter().any(|f| f == "\\Flagged"));
    }

    #[test]
    fn uid_stable_across_flag_change() {
        let dir = std::env::temp_dir().join(format!("de_uid_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let md = Maildir::open(dir.to_str().unwrap(), "alice").unwrap();
        let path = md.deliver(b"From: a\r\n\r\nbody", "a@b").unwrap();
        let msgs = md.list_messages().unwrap();
        assert_eq!(msgs.len(), 1);
        let uid1 = msgs[0].uid;
        let updated = md
            .store_flags(&msgs[0], "+FLAGS", &["\\Seen".into()])
            .unwrap();
        assert_eq!(updated.uid, uid1);
        let msgs2 = md.list_messages().unwrap();
        assert_eq!(msgs2[0].uid, uid1);
        let _ = path;
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn mailbox_size_and_quota() {
        let dir = std::env::temp_dir().join(format!("de_quota_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let data = dir.to_str().unwrap();
        let md = Maildir::open(data, "bob").unwrap();
        assert_eq!(Maildir::mailbox_size(data, "bob").unwrap(), 0);
        md.deliver(b"0123456789", "x").unwrap(); // 10 + Received header
        let sz = Maildir::mailbox_size(data, "bob").unwrap();
        assert!(sz >= 10);
        assert!(!Maildir::would_exceed_quota(sz, 1, 0)); // unlimited
        assert!(Maildir::would_exceed_quota(sz, 1, sz)); // exactly full + 1
        assert!(!Maildir::would_exceed_quota(sz, 0, sz));
        assert!(Maildir::would_exceed_quota(sz, 100, 5));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn move_to_trash_preserves_body() {
        let dir = std::env::temp_dir().join(format!("de_move_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let data = dir.to_str().unwrap();
        let inbox = Maildir::open(data, "carol").unwrap();
        let trash = Maildir::open(data, "carol/.Trash").unwrap();
        let raw = b"From: a@b\r\nSubject: hello\r\n\r\nbody bytes 123";
        inbox.deliver(raw, "a@b").unwrap();
        let msgs = inbox.list_messages().unwrap();
        assert_eq!(msgs.len(), 1);
        let orig = inbox.read_message(&msgs[0].path).unwrap();
        let moved = inbox.move_to(&msgs[0], &trash).unwrap();
        assert!(moved.path.starts_with(trash.root()));
        assert!(trash.root().ends_with("carol/.Trash") || trash.root().to_string_lossy().contains("carol/.Trash"));
        assert_eq!(inbox.list_messages().unwrap().len(), 0);
        assert_eq!(trash.list_messages().unwrap().len(), 1);
        let after = trash.read_message(&moved.path).unwrap();
        assert_eq!(after, orig);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn sanitize_preserves_maildir_subfolders() {
        assert_eq!(sanitize("alice"), "alice");
        assert_eq!(sanitize("alice/.Junk"), "alice/.Junk");
        assert_eq!(sanitize("alice/.Trash"), "alice/.Trash");
        assert_eq!(sanitize("../evil"), "evil");
        assert_eq!(sanitize("a/../../b"), "a/b");
    }
}
