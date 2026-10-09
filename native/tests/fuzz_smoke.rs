//! The fuzz targets' invariants (fuzz/fuzz_targets/*.rs), checked with
//! `cargo test` on any host: generated /proc/self/maps and /proc/mounts
//! dumps (random bytes, maps-shaped lines, mount-shaped lines, edge cases)
//! must never make the parsers panic or break their limits. A fixed seed
//! keeps it repeatable. The coverage-guided libFuzzer runs (Linux, nightly)
//! are in CI (.github/workflows/fuzz.yml).

use raspshield::{maps, root};

struct XorShift(u64);
impl XorShift {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
    fn pick<'a>(&mut self, items: &[&'a str]) -> &'a str {
        items[self.below(items.len() as u64) as usize]
    }
}

const PATHS: [&str; 12] = [
    "/system/lib64/libc.so", "/data/local/tmp/libfrida-gadget.so", "/data/app/x/lib/arm64/libapp.so",
    "/apex/com.android.art/lib64/libart.so", "[anon:dalvik-jit-code-cache]", "", "/dev/ashmem/dalvik",
    "/data/data/com.x/files/libinject.so", "[stack]", "/memfd:jit-cache (deleted)", "/data/misc/apexdata/com.android.art/dalvik-cache/arm64/boot.oat",
    "/data/local/tmp/re.frida.server/frida-agent-64.so",
];
const PERMS: [&str; 6] = ["r-xp", "rwxp", "rw-p", "r--p", "---p", "rwxs"];
const FS: [&str; 7] = ["ext4", "erofs", "tmpfs", "overlay", "f2fs", "proc", "sdcardfs"];
const MOUNTPOINTS: [&str; 7] = ["/system", "/vendor", "/product", "/", "/data", "/mnt/media_rw", "/system_ext"];
const OPTIONS: [&str; 5] = ["ro,seclabel", "rw,seclabel,relatime", "rw", "ro", "rw,nosuid,nodev"];

fn random_bytes(rng: &mut XorShift, max: u64) -> Vec<u8> {
    (0..rng.below(max)).map(|_| rng.next() as u8).collect()
}

fn maps_dump(rng: &mut XorShift) -> String {
    let mut out = String::new();
    for _ in 0..rng.below(60) {
        let start = rng.next() & 0xffff_ffff_f000;
        out.push_str(&format!(
            "{:x}-{:x} {} {:08x} {:02x}:{:02x} {} {}\n",
            start, start + (rng.below(1 << 20) & !0xfff), rng.pick(&PERMS), rng.below(1 << 24),
            rng.below(256), rng.below(256), rng.below(1 << 20), rng.pick(&PATHS),
        ));
        if rng.below(10) == 0 {
            out.push_str(&"x".repeat(rng.below(5000) as usize));
            out.push('\n');
        }
    }
    out
}

fn mounts_dump(rng: &mut XorShift) -> String {
    let mut out = String::new();
    for _ in 0..rng.below(40) {
        out.push_str(&format!("/dev/block/dm-{} {} {} {} 0 0\n", rng.below(9), rng.pick(&MOUNTPOINTS), rng.pick(&FS), rng.pick(&OPTIONS)));
        if rng.below(8) == 0 {
            out.push_str(&String::from_utf8_lossy(&random_bytes(rng, 200)));
            out.push('\n');
        }
    }
    out
}

fn check_maps(text: &str) {
    let summary = maps::summarize(text);
    assert!(summary.framework_lines.len() <= maps::LINES_PER_SIGNAL);
    assert!(summary.suspicious_lines.len() <= maps::LINES_PER_SIGNAL);
    assert!(summary.rwx_lines.len() <= maps::LINES_PER_SIGNAL);
    for line in summary.rwx_lines.iter().chain(&summary.suspicious_lines).chain(&summary.framework_lines) {
        assert!(line.chars().count() <= maps::EVIDENCE_LINE_MAX, "evidence line too long: {line:?}");
    }
    let _ = summary.to_json();
}

fn check_mounts(text: &str) {
    let findings = root::analyze_mounts(text);
    assert_eq!(findings.system_writable, !findings.writable_partitions.is_empty());
    let _ = findings.to_json();
}

#[test]
fn maps_parser_invariants_hold_for_generated_dumps() {
    let mut rng = XorShift(0x5eed_1234_abcd_0001);
    for _ in 0..4000 {
        check_maps(&maps_dump(&mut rng));
        check_maps(&String::from_utf8_lossy(&random_bytes(&mut rng, 2048)));
    }
}

#[test]
fn mounts_parser_invariants_hold_for_generated_dumps() {
    let mut rng = XorShift(0x5eed_1234_abcd_0002);
    for _ in 0..4000 {
        check_mounts(&mounts_dump(&mut rng));
        check_mounts(&String::from_utf8_lossy(&random_bytes(&mut rng, 2048)));
    }
}

#[test]
fn edge_cases_do_not_panic() {
    for text in [
        "", "\n", "\n\n\n", " ", "-", "--", "0-0", "0-0 rwxp", "\u{feff}", "\u{0}\u{0}\u{0}",
        "ffffffffffffffff-ffffffffffffffff rwxp ffffffff ff:ff 99999999999999999999 /data/local/tmp/frida",
        "a-b c d e f g h i j k l m n o p", "/system /system ext4 rw 0 0 extra fields here",
    ] {
        check_maps(text);
        check_mounts(text);
    }
    check_maps(&"7f00-7f01 rwxp 0 0:0 0 \u{1F600}".repeat(5000));
    check_mounts(&"/dev/x /system ext4 rw 0 0\n".repeat(20000));
}
