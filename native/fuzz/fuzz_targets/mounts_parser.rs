//! Any bytes as a /proc/mounts dump: the mount-table parser must never panic.
#![no_main]

use libfuzzer_sys::fuzz_target;
use raspshield::root;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let findings = root::analyze_mounts(&text);
    assert_eq!(findings.system_writable, !findings.writable_partitions.is_empty());
    let _ = findings.to_json();
});
