//! Minimal POSIX ustar tar writer/reader (pure std).
//! Supports regular files and directories. Long paths use ustar
//! prefix (155) + name (100) when they fit; otherwise skipped with a log.

use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

const BLOCK: usize = 512;
const NAME_MAX: usize = 100;
const PREFIX_MAX: usize = 155;
const MAX_PATH: usize = NAME_MAX + PREFIX_MAX; // 255 with '/' separator

/// Build an in-memory ustar archive. `entries` is (archive_path, filesystem_path).
/// Directories are added when encountered; files read from disk.
/// Paths that cannot fit in ustar name+prefix are skipped (logged via callback).
pub fn build_tar<F>(entries: &[(String, PathBuf)], mut on_skip: F) -> io::Result<Vec<u8>>
where
    F: FnMut(&str, &str),
{
    let mut out = Vec::new();
    let mut seen_dirs: std::collections::HashSet<String> = std::collections::HashSet::new();

    for (arc_path, fs_path) in entries {
        let arc = normalize_arc_path(arc_path);
        if arc.is_empty() {
            continue;
        }
        // Ensure parent directories exist in the archive.
        ensure_parent_dirs(&arc, &mut seen_dirs, &mut out)?;
        if fs_path.is_dir() {
            add_dir_recursive(&arc, fs_path, &mut seen_dirs, &mut out, &mut on_skip)?;
        } else if fs_path.is_file() {
            if let Err(reason) = add_file(&arc, fs_path, &mut out) {
                on_skip(&arc, &reason);
            }
        } else {
            on_skip(&arc, "not a file or directory");
        }
    }

    // Two zero blocks end the archive.
    out.extend_from_slice(&[0u8; BLOCK * 2]);
    Ok(out)
}

/// Collect backup layout paths for desertemail.
/// Returns ordered (archive_rel_path, absolute_or_relative fs path) pairs.
pub fn backup_layout(
    config_path: &Path,
    data_dir: &Path,
    dkim_key: Option<&Path>,
    tls_cert: Option<&Path>,
    tls_key: Option<&Path>,
) -> Vec<(String, PathBuf)> {
    let mut v = Vec::new();
    v.push((
        "desertemail-backup/config.toml".into(),
        config_path.to_path_buf(),
    ));
    if let Some(p) = dkim_key {
        if p.exists() {
            let base = p
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| "dkim.pem".into());
            v.push((format!("desertemail-backup/extras/{}", base), p.to_path_buf()));
        }
    }
    if let Some(p) = tls_cert {
        if p.exists() {
            let base = p
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| "tls.crt".into());
            v.push((format!("desertemail-backup/extras/{}", base), p.to_path_buf()));
        }
    }
    if let Some(p) = tls_key {
        if p.exists() {
            let base = p
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| "tls.key".into());
            v.push((format!("desertemail-backup/extras/{}", base), p.to_path_buf()));
        }
    }
    if data_dir.exists() {
        v.push((
            "desertemail-backup/data".into(),
            data_dir.to_path_buf(),
        ));
    }
    v
}

/// Whether a path component under data should be excluded (maildir tmp/).
fn is_excluded_relative(rel: &str) -> bool {
    // Exclude any path segment that is exactly "tmp" under a maildir
    // (…/new, …/cur, …/tmp). Match `/tmp/` or ending `/tmp` or `tmp/` prefix.
    let parts: Vec<&str> = rel.split('/').filter(|p| !p.is_empty()).collect();
    parts.iter().any(|p| *p == "tmp")
}

fn add_dir_recursive<F>(
    arc_prefix: &str,
    fs_dir: &Path,
    seen_dirs: &mut std::collections::HashSet<String>,
    out: &mut Vec<u8>,
    on_skip: &mut F,
) -> io::Result<()>
where
    F: FnMut(&str, &str),
{
    let dir_arc = if arc_prefix.ends_with('/') {
        arc_prefix.to_string()
    } else {
        format!("{}/", arc_prefix)
    };
    if !seen_dirs.contains(&dir_arc) {
        if let Err(reason) = write_header(out, &dir_arc, 0, b'5', 0o755) {
            on_skip(&dir_arc, &reason);
            return Ok(());
        }
        seen_dirs.insert(dir_arc.clone());
    }

    let mut entries: Vec<_> = fs::read_dir(fs_dir)?
        .filter_map(|e| e.ok())
        .collect();
    entries.sort_by_key(|e| e.file_name());

    for ent in entries {
        let name = ent.file_name().to_string_lossy().into_owned();
        if name == "." || name == ".." {
            continue;
        }
        let child_fs = ent.path();
        let child_arc = format!("{}{}", dir_arc, name);
        // Relative to data root for exclusion: strip desertemail-backup/data/
        let rel_for_excl = child_arc
            .strip_prefix("desertemail-backup/data/")
            .unwrap_or(child_arc.as_str());
        if is_excluded_relative(rel_for_excl) {
            continue;
        }
        let ft = ent.file_type()?;
        if ft.is_dir() {
            add_dir_recursive(&child_arc, &child_fs, seen_dirs, out, on_skip)?;
        } else if ft.is_file() {
            if let Err(reason) = add_file(&child_arc, &child_fs, out) {
                on_skip(&child_arc, &reason);
            }
        }
    }
    Ok(())
}

fn ensure_parent_dirs(
    arc: &str,
    seen: &mut std::collections::HashSet<String>,
    out: &mut Vec<u8>,
) -> io::Result<()> {
    let parts: Vec<&str> = arc.split('/').filter(|p| !p.is_empty()).collect();
    if parts.len() <= 1 {
        return Ok(());
    }
    let mut acc = String::new();
    for p in &parts[..parts.len() - 1] {
        if !acc.is_empty() {
            acc.push('/');
        }
        acc.push_str(p);
        let d = format!("{}/", acc);
        if !seen.contains(&d) {
            let _ = write_header(out, &d, 0, b'5', 0o755);
            seen.insert(d);
        }
    }
    Ok(())
}

fn add_file(arc: &str, fs: &Path, out: &mut Vec<u8>) -> Result<(), String> {
    let mut f = File::open(fs).map_err(|e| e.to_string())?;
    let mut data = Vec::new();
    f.read_to_end(&mut data).map_err(|e| e.to_string())?;
    write_header(out, arc, data.len() as u64, b'0', 0o644)?;
    out.extend_from_slice(&data);
    let pad = (BLOCK - (data.len() % BLOCK)) % BLOCK;
    out.extend(std::iter::repeat(0u8).take(pad));
    Ok(())
}

fn normalize_arc_path(s: &str) -> String {
    let s = s.replace('\\', "/");
    let s = s.trim_start_matches('/');
    // Collapse //
    let mut out = String::new();
    for part in s.split('/') {
        if part.is_empty() || part == "." {
            continue;
        }
        if part == ".." {
            continue; // refuse parent traversal in archive paths
        }
        if !out.is_empty() {
            out.push('/');
        }
        out.push_str(part);
    }
    out
}

/// Split path into ustar name (≤100) and prefix (≤155).
/// Returns Err if path cannot fit.
pub fn split_ustar_path(path: &str) -> Result<(String, String), String> {
    let path = path.trim_start_matches('/');
    if path.is_empty() {
        return Err("empty path".into());
    }
    if path.len() <= NAME_MAX {
        return Ok((path.to_string(), String::new()));
    }
    if path.len() > MAX_PATH + 1 {
        // +1 for the slash between prefix and name
        return Err(format!(
            "path too long for ustar ({} > {})",
            path.len(),
            MAX_PATH
        ));
    }
    // Find a slash such that name fits in 100 and prefix in 155.
    // Prefer: prefix = path[..split], name = path[split+1..]
    let bytes = path.as_bytes();
    let mut best: Option<usize> = None;
    for (i, &b) in bytes.iter().enumerate() {
        if b != b'/' {
            continue;
        }
        let prefix = &path[..i];
        let name = &path[i + 1..];
        if name.is_empty() {
            continue;
        }
        if name.len() <= NAME_MAX && prefix.len() <= PREFIX_MAX {
            best = Some(i);
            // keep last valid (longest prefix) so name is shorter/leaf-ish
        }
    }
    match best {
        Some(i) => Ok((path[i + 1..].to_string(), path[..i].to_string())),
        None => Err(format!(
            "cannot split path into ustar name+prefix: {}",
            path
        )),
    }
}

fn write_header(
    out: &mut Vec<u8>,
    path: &str,
    size: u64,
    typeflag: u8,
    mode: u32,
) -> Result<(), String> {
    let (name, prefix) = split_ustar_path(path)?;
    let mut hdr = [0u8; BLOCK];
    put_str(&mut hdr[0..100], &name);
    put_octal(&mut hdr[100..108], mode as u64, 7);
    put_octal(&mut hdr[108..116], 0, 7); // uid
    put_octal(&mut hdr[116..124], 0, 7); // gid
    put_octal(&mut hdr[124..136], size, 11);
    let mtime = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    put_octal(&mut hdr[136..148], mtime, 11);
    // checksum field spaces initially
    for b in &mut hdr[148..156] {
        *b = b' ';
    }
    hdr[156] = typeflag;
    // linkname left zero
    hdr[257..263].copy_from_slice(b"ustar\0");
    hdr[263..265].copy_from_slice(b"00");
    // uname/gname empty
    put_str(&mut hdr[345..500], &prefix);

    let sum: u32 = hdr.iter().map(|&b| b as u32).sum();
    put_octal(&mut hdr[148..156], sum as u64, 6);
    hdr[154] = 0;
    hdr[155] = b' ';

    out.extend_from_slice(&hdr);
    Ok(())
}

fn put_str(dest: &mut [u8], s: &str) {
    let b = s.as_bytes();
    let n = b.len().min(dest.len());
    dest[..n].copy_from_slice(&b[..n]);
}

fn put_octal(dest: &mut [u8], val: u64, digits: usize) {
    // Classic tar: digits octal digits, then NUL (or space for size sometimes).
    // We write digits null-terminated when dest len allows.
    let s = format!("{:0width$o}", val, width = digits);
    let b = s.as_bytes();
    let n = b.len().min(dest.len().saturating_sub(1));
    dest[..n].copy_from_slice(&b[..n]);
    if n < dest.len() {
        dest[n] = 0;
    }
}

// ---------------------------------------------------------------------------
// Reader
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct TarEntry {
    pub path: String,
    pub is_dir: bool,
    pub data: Vec<u8>,
}

/// Parse an in-memory ustar archive into entries (regular files + directories).
/// Unknown typeflags are skipped. Trailing zero blocks end the stream.
pub fn parse_tar(data: &[u8]) -> Result<Vec<TarEntry>, String> {
    let mut entries = Vec::new();
    let mut off = 0usize;
    while off + BLOCK <= data.len() {
        let hdr = &data[off..off + BLOCK];
        if hdr.iter().all(|&b| b == 0) {
            break;
        }
        // Verify checksum
        let stored = parse_octal(&hdr[148..156])?;
        let mut sum = 0u32;
        for (i, &b) in hdr.iter().enumerate() {
            if (148..156).contains(&i) {
                sum += b' ' as u32;
            } else {
                sum += b as u32;
            }
        }
        if sum != stored as u32 {
            return Err(format!(
                "bad tar checksum at offset {} (got {} expected {})",
                off, sum, stored
            ));
        }

        let name = cstr_field(&hdr[0..100]);
        let prefix = cstr_field(&hdr[345..500]);
        let path = if prefix.is_empty() {
            name
        } else if name.is_empty() {
            prefix
        } else {
            format!("{}/{}", prefix, name)
        };
        let size = parse_octal(&hdr[124..136])? as usize;
        let typeflag = hdr[156];
        off += BLOCK;

        let file_data = if size > 0 {
            if off + size > data.len() {
                return Err(format!("truncated tar entry: {}", path));
            }
            let d = data[off..off + size].to_vec();
            let pad = (BLOCK - (size % BLOCK)) % BLOCK;
            off += size + pad;
            d
        } else {
            Vec::new()
        };

        match typeflag {
            b'0' | b'\0' => {
                entries.push(TarEntry {
                    path,
                    is_dir: false,
                    data: file_data,
                });
            }
            b'5' => {
                entries.push(TarEntry {
                    path: if path.ends_with('/') {
                        path
                    } else {
                        format!("{}/", path)
                    },
                    is_dir: true,
                    data: Vec::new(),
                });
            }
            _ => {
                // skip unknown types (already consumed size)
            }
        }
    }
    Ok(entries)
}

/// Extract archive into a destination root, rewriting paths under
/// `desertemail-backup/` into the provided mapping:
/// - config.toml → `config_dest`
/// - extras/* → `extras_dir/<name>`
/// - data/* → `data_dir/*`
pub fn extract_backup(
    data: &[u8],
    config_dest: &Path,
    extras_dir: &Path,
    data_dir: &Path,
) -> Result<ExtractSummary, String> {
    let entries = parse_tar(data)?;
    let mut summary = ExtractSummary::default();
    for ent in entries {
        let p = ent.path.trim_start_matches("./");
        let rel = p
            .strip_prefix("desertemail-backup/")
            .unwrap_or(p);
        if rel.is_empty() || rel == "/" {
            continue;
        }
        if ent.is_dir {
            // Dirs created as needed for files.
            continue;
        }
        let dest = if rel == "config.toml" {
            config_dest.to_path_buf()
        } else if let Some(rest) = rel.strip_prefix("extras/") {
            extras_dir.join(rest)
        } else if let Some(rest) = rel.strip_prefix("data/") {
            data_dir.join(rest)
        } else if rel == "data" {
            continue;
        } else {
            // ignore unexpected
            continue;
        };
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {}", parent.display(), e))?;
        }
        fs::write(&dest, &ent.data)
            .map_err(|e| format!("write {}: {}", dest.display(), e))?;
        summary.files += 1;
        summary.bytes += ent.data.len() as u64;
    }
    Ok(summary)
}

#[derive(Debug, Default, Clone)]
pub struct ExtractSummary {
    pub files: usize,
    pub bytes: u64,
}

fn cstr_field(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).trim().to_string()
}

fn parse_octal(bytes: &[u8]) -> Result<u64, String> {
    let s = cstr_field(bytes);
    let s = s.trim().trim_end_matches(' ');
    if s.is_empty() {
        return Ok(0);
    }
    u64::from_str_radix(s, 8).map_err(|e| format!("bad octal {:?}: {}", s, e))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn split_short_and_long_paths() {
        let (n, p) = split_ustar_path("a/b.txt").unwrap();
        assert_eq!(n, "a/b.txt");
        assert!(p.is_empty());

        // Long path that needs prefix
        let leaf = "x".repeat(80);
        let mid = "dir_with_a_reasonably_long_name";
        let path = format!("desertemail-backup/data/user/{}/{}", mid, leaf);
        assert!(path.len() > 100);
        let (n, p) = split_ustar_path(&path).unwrap();
        assert!(n.len() <= 100);
        assert!(p.len() <= 155);
        assert_eq!(format!("{}/{}", p, n), path);
    }

    #[test]
    fn roundtrip_nested_and_contents() {
        let dir = std::env::temp_dir().join(format!(
            "desertemail-tar-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("nested/deep")).unwrap();
        let mut f = File::create(dir.join("nested/deep/hello.txt")).unwrap();
        f.write_all(b"hello-bytes-\x00\xff").unwrap();
        let mut f2 = File::create(dir.join("root.dat")).unwrap();
        f2.write_all(b"ROOT").unwrap();

        let long_name = "a".repeat(60);
        fs::create_dir_all(dir.join("nested").join(&long_name)).unwrap();
        let mut f3 = File::create(dir.join("nested").join(&long_name).join("payload.bin")).unwrap();
        f3.write_all(&[1u8, 2, 3, 4, 5]).unwrap();

        let entries = vec![("archive-root".into(), dir.clone())];
        let tar = build_tar(&entries, |p, r| panic!("skip {} {}", p, r)).unwrap();
        let parsed = parse_tar(&tar).unwrap();
        let files: Vec<_> = parsed.iter().filter(|e| !e.is_dir).collect();
        assert!(files.len() >= 3);

        let hello = files
            .iter()
            .find(|e| e.path.ends_with("nested/deep/hello.txt"))
            .expect("hello");
        assert_eq!(hello.data, b"hello-bytes-\x00\xff");

        let root = files
            .iter()
            .find(|e| e.path.ends_with("root.dat"))
            .expect("root");
        assert_eq!(root.data, b"ROOT");

        let payload = files
            .iter()
            .find(|e| e.path.ends_with("payload.bin"))
            .expect("payload");
        assert_eq!(payload.data, &[1, 2, 3, 4, 5]);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn backup_layout_paths() {
        let cfg = PathBuf::from("/etc/desertemail/config.toml");
        let data = PathBuf::from("/var/lib/desertemail");
        // data may not exist — still listed if exists; we only check config entry
        let layout = backup_layout(&cfg, &data, None, None, None);
        assert_eq!(layout[0].0, "desertemail-backup/config.toml");
        assert_eq!(layout[0].1, cfg);
    }

    #[test]
    fn excludes_tmp_dirs() {
        let dir = std::env::temp_dir().join(format!(
            "desertemail-tar-tmp-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("user/new")).unwrap();
        fs::create_dir_all(dir.join("user/tmp")).unwrap();
        fs::write(dir.join("user/new/msg"), b"ok").unwrap();
        fs::write(dir.join("user/tmp/scratch"), b"nope").unwrap();

        let entries = vec![("desertemail-backup/data".into(), dir.clone())];
        let tar = build_tar(&entries, |_, _| {}).unwrap();
        let parsed = parse_tar(&tar).unwrap();
        assert!(parsed.iter().any(|e| e.path.contains("user/new/msg")));
        assert!(!parsed.iter().any(|e| e.path.contains("/tmp/")));

        let _ = fs::remove_dir_all(&dir);
    }
}
