//! Port of the `/proc/self/maps` rules of `RaspHookAnalysis.kt`: hooking
//! framework libraries in mapped paths, executable mappings from writable
//! locations, and RWX regions (not counting the Dart VM's `[anon:dart-code]`).
//!
//! [summarize] produces the same numbers and evidence lines as
//! `RaspHookAnalysis.summarizeMaps` in Kotlin for the same text; the verdict
//! (one hard or two soft signals) stays in Kotlin, which combines this with
//! the method-integrity reading. Lists and constants are copied verbatim.

use crate::io::MAX_LINE_CHARS;
use crate::json::{int, Object, Value};
use crate::text::{kotlin_trim, lines, lowercase, split_ws, split_ws_limit, truncate_chars, is_regex_space};

pub const HOOK_FRAMEWORK_MARKERS: [&str; 18] = [
    "xposed", "lsposed", "lspd", "edxposed", "riru", "zygisk", "yahfa", "sandhook",
    "substrate", "libsubstrate",
    "dobby", "libdobby", "whale", "libwhale", "epic", "shadowhook",
    "libinject", "injector",
];

/// Markers that match only a whole path token, never a prefix.
pub const EXACT_TOKEN_MARKERS: [&str; 8] = ["epic", "libepic", "whale", "libwhale", "riru", "lspd", "libinject", "injector"];

pub const SUSPICIOUS_CODE_DIRECTORIES: [&str; 6] =
    ["/data/local/tmp/", "/sdcard/", "/storage/emulated/", "/data/misc/", "/tmp/", "/cache/"];

pub const TRUSTED_CODE_DIRECTORIES: [&str; 1] = ["/data/misc/apexdata/com.android.art/dalvik-cache/"];

pub const RWX_MAPPING_THRESHOLD: usize = 12;
pub const EVIDENCE_LINE_MAX: usize = 80;
pub const LINES_PER_SIGNAL: usize = 3;

/// The maps-derived part of one hook scan.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct MapsSummary {
    pub frameworks: Vec<String>,
    pub framework_lines: Vec<String>,
    pub suspicious_exec_mapping_count: usize,
    pub suspicious_lines: Vec<String>,
    pub rwx_mapping_count: usize,
    pub rwx_lines: Vec<String>,
    pub dart_code_rwx_count: usize,
}

impl MapsSummary {
    /// The JSON `RaspNative.kt` parses; keys sorted, so it is byte-equal to
    /// Kotlin's canonical encoding of the same summary (parity fixtures).
    pub fn to_json(&self) -> String {
        Object::new()
            .with("dartCodeRwxCount", int(self.dart_code_rwx_count))
            .with("frameworkLines", Value::Strs(self.framework_lines.clone()))
            .with("frameworks", Value::Strs(self.frameworks.clone()))
            .with("rwxLines", Value::Strs(self.rwx_lines.clone()))
            .with("rwxMappingCount", int(self.rwx_mapping_count))
            .with("suspiciousExecMappingCount", int(self.suspicious_exec_mapping_count))
            .with("suspiciousLines", Value::Strs(self.suspicious_lines.clone()))
            .encode()
    }
}

/// Lines of a maps dump, each cut to [MAX_LINE_CHARS].
fn bounded_lines(maps: &str) -> Vec<&str> {
    lines(maps).into_iter().map(|l| truncate_chars(l, MAX_LINE_CHARS)).collect()
}

/// Lower-cased name tokens of one line's pathname (empty for anonymous memory).
pub fn path_tokens(line: &str) -> Vec<String> {
    let slash = line.find('/');
    let bracket = line.find('[');
    let start = match (slash, bracket) {
        (Some(s), Some(b)) if s < b => s,
        (Some(s), None) => s,
        (_, Some(b)) => b,
        (None, None) => return Vec::new(),
    };
    let lower = lowercase(&line[start..]);
    let raw: Vec<String> = lower
        .split(|c: char| !(c.is_ascii_lowercase() || c.is_ascii_digit()))
        .filter(|t| !t.is_empty())
        .map(str::to_owned)
        .collect();
    let stripped: Vec<String> = raw
        .iter()
        .filter(|t| t.chars().count() > 3 && t.starts_with("lib"))
        .map(|t| t["lib".len()..].to_owned())
        .collect();
    raw.into_iter().chain(stripped).collect()
}

fn frameworks_in_tokens(tokens: &std::collections::HashSet<String>) -> Vec<String> {
    HOOK_FRAMEWORK_MARKERS
        .iter()
        .filter(|marker| {
            if EXACT_TOKEN_MARKERS.contains(marker) {
                tokens.contains(**marker)
            } else {
                tokens.iter().any(|t| t.starts_with(**marker))
            }
        })
        .map(|m| (*m).to_owned())
        .collect()
}

/// Framework markers present anywhere in [maps].
pub fn hook_frameworks_in(maps: &str) -> Vec<String> {
    let tokens = bounded_lines(maps).into_iter().flat_map(path_tokens).collect();
    frameworks_in_tokens(&tokens)
}

fn line_has_framework(line: &str) -> bool {
    !frameworks_in_tokens(&path_tokens(line).into_iter().collect()).is_empty()
}

/// The mapped path of a line (6th field onwards), or `""`.
pub fn mapped_path(line: &str) -> String {
    split_ws_limit(kotlin_trim(line), 6)
        .get(5)
        .map(|p| kotlin_trim(p).to_owned())
        .unwrap_or_default()
}

pub fn is_trusted_code_path(path: &str) -> bool {
    TRUSTED_CODE_DIRECTORIES.iter().any(|dir| path.starts_with(dir) && !path.contains("/../"))
}

pub fn is_suspicious_executable_mapping(line: &str) -> bool {
    let lower = lowercase(line);
    let fields = split_ws(&lower);
    let Some(perms) = fields.get(1) else {
        return false;
    };
    if !perms.contains('x') {
        return false;
    }
    if is_trusted_code_path(&mapped_path(line)) {
        return false;
    }
    SUSPICIOUS_CODE_DIRECTORIES.iter().any(|dir| lower.contains(dir))
}

pub fn is_rwx_mapping(line: &str) -> bool {
    let fields = split_ws(kotlin_trim(line));
    let Some(perms) = fields.get(1) else {
        return false;
    };
    let mut chars = perms.chars();
    let (_, w, x) = (chars.next(), chars.next(), chars.next());
    w == Some('w') && x == Some('x')
}

pub fn is_dart_code_region(line: &str) -> bool {
    mapped_path(line) == "[anon:dart-code]"
}

pub fn is_counted_rwx_mapping(line: &str) -> bool {
    is_rwx_mapping(line) && !is_dart_code_region(line)
}

/// A line for evidence: whitespace runs collapsed, at most [EVIDENCE_LINE_MAX]
/// characters, keeping the start and the end (the path) around `…`.
pub fn evidence_line(line: &str) -> String {
    let mut collapsed = String::new();
    let mut in_space = false;
    for c in kotlin_trim(line).chars() {
        if is_regex_space(c) {
            if !in_space {
                collapsed.push(' ');
            }
            in_space = true;
        } else {
            collapsed.push(c);
            in_space = false;
        }
    }
    let count = collapsed.chars().count();
    if count <= EVIDENCE_LINE_MAX {
        return collapsed;
    }
    let head = 30;
    let tail = EVIDENCE_LINE_MAX - head - 1;
    let start: String = collapsed.chars().take(head).collect();
    let end: String = collapsed.chars().skip(count - tail).collect();
    format!("{start}…{end}")
}

/// Everything the hook scan takes from one maps dump.
pub fn summarize(maps: &str) -> MapsSummary {
    let all = bounded_lines(maps);
    let keep = |matched: Vec<&&str>| -> Vec<String> {
        matched.into_iter().take(LINES_PER_SIGNAL).map(|l| evidence_line(l)).collect()
    };

    let frameworks = hook_frameworks_in(maps);
    let framework_lines = if frameworks.is_empty() {
        Vec::new()
    } else {
        keep(all.iter().filter(|l| line_has_framework(l)).collect())
    };

    let suspicious: Vec<&&str> = all.iter().filter(|l| is_suspicious_executable_mapping(l)).collect();
    let mut distinct_paths: Vec<String> = Vec::new();
    for line in &suspicious {
        let after = match line.rfind(' ') {
            Some(i) => &line[i + 1..],
            None => line,
        };
        let path = kotlin_trim(after);
        if !path.is_empty() && !distinct_paths.iter().any(|p| p == path) {
            distinct_paths.push(path.to_owned());
        }
    }
    let suspicious_lines = keep(suspicious);

    let counted: Vec<&&str> = all.iter().filter(|l| is_counted_rwx_mapping(l)).collect();
    let rwx_mapping_count = counted.len();
    let dart_code_rwx_count = all.iter().filter(|l| is_rwx_mapping(l) && is_dart_code_region(l)).count();

    MapsSummary {
        frameworks,
        framework_lines,
        suspicious_exec_mapping_count: distinct_paths.len(),
        suspicious_lines,
        rwx_mapping_count,
        rwx_lines: keep(counted),
        dart_code_rwx_count,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLEAN: &str = "7f00000000-7f00001000 r-xp 00000000 fd:00 123 /system/lib64/libc.so\n\
        7f00001000-7f00002000 rw-p 00000000 00:00 0 [anon:libc_malloc]\n";

    #[test]
    fn clean_maps_have_no_signal() {
        let s = summarize(CLEAN);
        assert!(s.frameworks.is_empty() && s.suspicious_exec_mapping_count == 0 && s.rwx_mapping_count == 0);
    }

    #[test]
    fn framework_tokens_prefix_and_exact() {
        assert_eq!(hook_frameworks_in("7f-7f r-xp 0 0 0 /data/adb/lspd/libriru_x.so"), vec!["lspd", "riru"]);
        assert_eq!(hook_frameworks_in("7f-7f r--p 0 0 0 /system/framework/XposedBridge.jar"), vec!["xposed"]);
        assert!(hook_frameworks_in("7f-7f r--p 0 0 0 /data/app/com.epicenter/base.apk").is_empty());
    }

    #[test]
    fn suspicious_and_trusted_paths() {
        assert!(is_suspicious_executable_mapping("7f-7f r-xp 0 0 0 /data/local/tmp/x.so"));
        assert!(!is_suspicious_executable_mapping("7f-7f r--p 0 0 0 /data/local/tmp/x.so"));
        assert!(!is_suspicious_executable_mapping(
            "7f-7f r-xp 0 0 0 /data/misc/apexdata/com.android.art/dalvik-cache/arm64/boot.oat"
        ));
        assert!(is_suspicious_executable_mapping(
            "7f-7f r-xp 0 0 0 /data/misc/apexdata/com.android.art/dalvik-cache/../../x.so"
        ));
    }

    #[test]
    fn rwx_and_dart_code() {
        let mut maps = String::new();
        for _ in 0..13 {
            maps.push_str("7f-7f rwxp 0 0 0\n");
        }
        maps.push_str("7f-7f rwxp 0 0 0 [anon:dart-code]\n");
        let s = summarize(&maps);
        assert_eq!((s.rwx_mapping_count, s.dart_code_rwx_count, s.rwx_lines.len()), (13, 1, 3));
    }

    #[test]
    fn evidence_lines_are_shortened() {
        let long = format!("7f-7f r-xp 00000000 00:00 0 /data/local/tmp/{}/x.so", "a".repeat(100));
        let e = evidence_line(&long);
        assert_eq!(e.chars().count(), EVIDENCE_LINE_MAX);
        assert!(e.ends_with("/x.so") && e.contains('…'));
        assert_eq!(evidence_line("  a   b  "), "a b");
    }

    #[test]
    fn malformed_input_never_panics() {
        for input in ["", "\n\n", "x", "[", "/", "\u{0}\u{ffff}", "a b", "  rwx", "…/…[…"] {
            let _ = summarize(input);
            let _ = mapped_path(input);
        }
    }
}
