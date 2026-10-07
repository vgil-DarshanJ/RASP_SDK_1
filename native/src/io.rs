//! Bounded file reads. `std::fs` goes straight to the `openat`/`read`
//! system calls through bionic — no Java I/O stack in between. Every read
//! has a byte cap; a file larger than the cap is reported as truncated so
//! the caller can fall back to the Kotlin reader instead of judging a
//! partial file (a partial `/proc/self/maps` could hide a match).

use std::fs::File;
use std::io::Read;
use std::path::Path;

/// Largest `/proc/self/maps` accepted (a busy app process is well under 4 MB).
pub const MAX_MAPS_BYTES: usize = 16 * 1024 * 1024;
/// Largest `/proc/mounts` accepted.
pub const MAX_MOUNTS_BYTES: usize = 4 * 1024 * 1024;
/// Longest line kept from a proc file; longer lines are cut (a real maps line
/// is at most PATH_MAX plus about 100 characters).
pub const MAX_LINE_CHARS: usize = 8192;

#[derive(Debug, PartialEq, Eq)]
pub enum ReadOutcome {
    /// The whole file, decoded as UTF-8 with replacement characters (like Kotlin `readText()`).
    Complete(String),
    /// Larger than the cap: not judged.
    Truncated,
    /// Could not be opened or read.
    Unreadable,
}

/// Reads at most [cap] bytes of [path].
pub fn read_bounded(path: &Path, cap: usize) -> ReadOutcome {
    let Ok(file) = File::open(path) else {
        return ReadOutcome::Unreadable;
    };
    let mut buf = Vec::new();
    // One byte more than the cap tells "exactly at the cap" from "larger".
    let limit = u64::try_from(cap).unwrap_or(u64::MAX).saturating_add(1);
    match file.take(limit).read_to_end(&mut buf) {
        Ok(_) if buf.len() > cap => ReadOutcome::Truncated,
        Ok(_) => ReadOutcome::Complete(String::from_utf8_lossy(&buf).into_owned()),
        Err(_) => ReadOutcome::Unreadable,
    }
}

/// `true` when [path] exists (following symlinks), like Java `File.exists()`;
/// any error, including permission denied, is `false`.
pub fn exists(path: &str) -> bool {
    std::fs::metadata(path).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn caps_and_errors() {
        let dir = std::env::temp_dir().join(format!("raspshield-io-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("f.txt");
        std::fs::File::create(&file).unwrap().write_all(b"0123456789").unwrap();
        assert_eq!(read_bounded(&file, 10), ReadOutcome::Complete("0123456789".into()));
        assert_eq!(read_bounded(&file, 9), ReadOutcome::Truncated);
        assert_eq!(read_bounded(&dir.join("missing"), 10), ReadOutcome::Unreadable);
        assert!(exists(file.to_str().unwrap()));
        assert!(!exists(dir.join("missing").to_str().unwrap()));
        std::fs::File::create(&file).unwrap().write_all(&[0x61, 0xff, 0x62]).unwrap();
        assert_eq!(read_bounded(&file, 10), ReadOutcome::Complete("a\u{FFFD}b".into()));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
