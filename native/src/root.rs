//! Port of the file and mount-table root checks of `RaspRootAnalysis.kt` /
//! `RaspDeviceIntegrityProbes.kt`: `su` binaries, Magisk/KernelSU artefacts,
//! busybox, writable protected partitions and root traces in the mount
//! table. Paths and rules are copied verbatim; nothing is added. The other
//! root signals (`which su`, installed packages, `ro.secure`) stay in Kotlin.

use std::path::Path;

use crate::io::{exists, read_bounded, ReadOutcome, MAX_LINE_CHARS, MAX_MOUNTS_BYTES};
use crate::json::{Object, Value};
use crate::text::{is_blank, kotlin_trim, lines, split_ws, truncate_chars};

pub const SU_PATHS: [&str; 13] = [
    "/sbin/su", "/system/bin/su", "/system/xbin/su", "/vendor/bin/su",
    "/system/sbin/su", "/su/bin/su", "/data/local/su",
    "/data/local/bin/su", "/data/local/xbin/su", "/system/bin/failsafe/su",
    "/system/bin/.ext/.su", "/system/usr/we-need-root/su-backup",
    "/system/xbin/mu",
];

pub const MAGISK_PATHS: [&str; 13] = [
    "/sbin/.magisk", "/sbin/.core/mirror", "/sbin/.core/img",
    "/data/adb/magisk", "/data/adb/magisk.db", "/data/adb/magisk.img",
    "/data/adb/modules", "/data/adb/ksu", "/data/adb/ap",
    "/cache/.disable_magisk", "/dev/.magisk.unblock",
    "/system/etc/init/magisk", "/data/adb/magisk_simple",
];

pub const BUSYBOX_PATHS: [&str; 3] = ["/system/xbin/busybox", "/system/bin/busybox", "/data/local/busybox"];

pub const PROTECTED_MOUNT_POINTS: [&str; 4] = ["/system", "/", "/vendor", "/product"];

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum MountState {
    ReadOnly,
    Writable,
    NotPresent,
    Unknown,
}

/// `(mountPoint, options)` of one `/proc/mounts` line, or `None` when malformed.
pub fn parse_mount_line(line: &str) -> Option<(&str, Vec<&str>)> {
    let parts = split_ws(kotlin_trim(line));
    if parts.len() < 4 {
        return None;
    }
    let mount_point = *parts.get(1)?;
    let options = parts.get(3)?.split(',').map(kotlin_trim).collect();
    if mount_point.is_empty() {
        return None;
    }
    Some((mount_point, options))
}

/// State of [mount_point] in a mount-table dump; `Unknown` when the dump is blank.
pub fn mount_state_of(mounts: &str, mount_point: &str) -> MountState {
    if is_blank(mounts) {
        return MountState::Unknown;
    }
    let mut found = false;
    for line in lines(mounts) {
        let Some((point, options)) = parse_mount_line(truncate_chars(line, MAX_LINE_CHARS)) else {
            continue;
        };
        if point != mount_point {
            continue;
        }
        found = true;
        if options.contains(&"rw") {
            return MountState::Writable;
        }
    }
    if found {
        MountState::ReadOnly
    } else {
        MountState::NotPresent
    }
}

pub fn writable_protected_partitions(mounts: &str) -> Vec<String> {
    PROTECTED_MOUNT_POINTS
        .iter()
        .filter(|p| mount_state_of(mounts, p) == MountState::Writable)
        .map(|p| (*p).to_owned())
        .collect()
}

pub fn mounts_indicate_root(mounts: &str) -> bool {
    mounts.contains("magisk") || mounts.contains("KSU") || mounts.contains("/data/adb")
}

/// The mount-table half of the root scan, for a dump already read.
#[derive(Debug, PartialEq, Eq)]
pub struct MountFindings {
    pub mounts_readable: bool,
    pub system_writable: bool,
    pub mount_namespace: bool,
    pub writable_partitions: Vec<String>,
}

pub fn analyze_mounts(mounts: &str) -> MountFindings {
    let writable_partitions = writable_protected_partitions(mounts);
    MountFindings {
        mounts_readable: !is_blank(mounts),
        system_writable: !writable_partitions.is_empty(),
        mount_namespace: mounts_indicate_root(mounts),
        writable_partitions,
    }
}

impl MountFindings {
    pub fn to_json(&self) -> String {
        self.object().encode()
    }

    /// Keys sorted, so the text equals Kotlin's canonical encoding (parity fixtures).
    fn object(&self) -> Object {
        Object::new()
            .with("mountNamespace", Value::Bool(self.mount_namespace))
            .with("mountsReadable", Value::Bool(self.mounts_readable))
            .with("systemWritable", Value::Bool(self.system_writable))
            .with("writablePartitions", Value::Strs(self.writable_partitions.clone()))
    }
}

/// One root scan of this device. `None` when `/proc/mounts` is larger than
/// the read cap (the caller uses the Kotlin scan rather than judge part of it).
pub fn scan() -> Option<String> {
    let mounts = match read_bounded(Path::new("/proc/mounts"), MAX_MOUNTS_BYTES) {
        ReadOutcome::Complete(text) => text,
        // Same as Kotlin readMounts(): unreadable is "" → mounts_readable false.
        ReadOutcome::Unreadable => String::new(),
        ReadOutcome::Truncated => return None,
    };
    let findings = analyze_mounts(&mounts);
    Some(
        findings
            .object()
            .with("suBinary", Value::Bool(SU_PATHS.iter().any(|p| exists(p))))
            .with("magiskArtifact", Value::Bool(MAGISK_PATHS.iter().any(|p| exists(p))))
            .with("busybox", Value::Bool(BUSYBOX_PATHS.iter().any(|p| exists(p))))
            .encode(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_as_root_read_only_is_clean() {
        let m = "/dev/block/dm-5 / ext4 ro,seclabel,relatime 0 0\n/dev/block/dm-6 /vendor ext4 ro 0 0\n";
        let f = analyze_mounts(m);
        assert!(f.mounts_readable && !f.system_writable && !f.mount_namespace);
        assert_eq!(mount_state_of(m, "/system"), MountState::NotPresent);
        assert_eq!(mount_state_of(m, "/"), MountState::ReadOnly);
    }

    #[test]
    fn rw_is_a_whole_option_and_last_rw_wins() {
        assert_eq!(mount_state_of("/dev/x /system ext4 ro,errors=remount-ro 0 0", "/system"), MountState::ReadOnly);
        assert_eq!(mount_state_of("/dev/x /system ext4 ro 0 0\n/dev/y /system ext4 rw 0 0", "/system"), MountState::Writable);
    }

    #[test]
    fn blank_or_traced_tables() {
        assert_eq!(mount_state_of("  \n", "/"), MountState::Unknown);
        assert!(!analyze_mounts("").mounts_readable);
        assert!(mounts_indicate_root("tmpfs /debug_ramdisk tmpfs rw 0 0\nmagisk /system/bin tmpfs ro 0 0"));
    }

    #[test]
    fn malformed_lines_never_panic() {
        for input in ["", "a", "a b c", "a  b c d", "\u{0}", ",,,, , , ,", "x /system t ,rw,"] {
            let _ = analyze_mounts(input);
            let _ = parse_mount_line(input);
        }
        assert_eq!(parse_mount_line("x /system t ,rw,").map(|p| p.1), Some(vec!["", "rw", ""]));
    }
}
