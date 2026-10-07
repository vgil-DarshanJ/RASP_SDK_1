//! Any bytes as a /proc/self/maps dump: the parser must never panic and
//! its summary must stay within its own limits.
#![no_main]

use libfuzzer_sys::fuzz_target;
use raspshield::maps;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let summary = maps::summarize(&text);
    assert!(summary.framework_lines.len() <= maps::LINES_PER_SIGNAL);
    assert!(summary.suspicious_lines.len() <= maps::LINES_PER_SIGNAL);
    assert!(summary.rwx_lines.len() <= maps::LINES_PER_SIGNAL);
    for line in summary.rwx_lines.iter().chain(&summary.suspicious_lines).chain(&summary.framework_lines) {
        assert!(line.chars().count() <= maps::EVIDENCE_LINE_MAX);
    }
    let _ = summary.to_json();
});
