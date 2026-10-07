//! Parity with the Kotlin checks: the expected files in `fixtures/` are
//! written by the Kotlin side (RaspNativeParityTest, RASP_UPDATE_PARITY=1)
//! and checked there on every run; here the Rust ports must produce the
//! same text for the same inputs.

use std::fs;
use std::path::{Path, PathBuf};

use raspshield::{hashing, maps, root};

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures")
}

fn inputs(dir: &str) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = fs::read_dir(fixtures().join(dir))
        .expect("fixture directory")
        .map(|e| e.expect("entry").path())
        .filter(|p| p.extension().is_some_and(|e| e == "txt"))
        .collect();
    files.sort();
    files
}

fn expected_for(input: &Path) -> String {
    let name = input.file_stem().unwrap().to_str().unwrap();
    fs::read_to_string(input.with_file_name(format!("{name}.expected.json")))
        .unwrap_or_else(|_| panic!("no expected file for {name}; run the Kotlin parity test with RASP_UPDATE_PARITY=1"))
}

/// Kotlin `readText()`: UTF-8 with replacement characters.
fn read_text(path: &Path) -> String {
    String::from_utf8_lossy(&fs::read(path).unwrap()).into_owned()
}

#[test]
fn maps_summaries_match_kotlin() {
    let files = inputs("maps");
    assert!(files.len() >= 7);
    for file in files {
        let actual = maps::summarize(&read_text(&file)).to_json() + "\n";
        assert_eq!(actual, expected_for(&file), "{}", file.display());
    }
}

#[test]
fn mount_findings_match_kotlin() {
    let files = inputs("mounts");
    assert!(files.len() >= 5);
    for file in files {
        let actual = root::analyze_mounts(&read_text(&file)).to_json() + "\n";
        assert_eq!(actual, expected_for(&file), "{}", file.display());
    }
}

#[test]
fn root_path_lists_match_kotlin() {
    let mut lines = Vec::new();
    lines.extend(root::SU_PATHS.iter().map(|p| format!("su\t{p}")));
    lines.extend(root::MAGISK_PATHS.iter().map(|p| format!("magisk\t{p}")));
    lines.extend(root::BUSYBOX_PATHS.iter().map(|p| format!("busybox\t{p}")));
    lines.extend(root::PROTECTED_MOUNT_POINTS.iter().map(|p| format!("protected_mount\t{p}")));
    let expected = fs::read_to_string(fixtures().join("root_lists.tsv")).unwrap();
    assert_eq!(lines.join("\n") + "\n", expected);
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn utf8(s: &str) -> String {
    String::from_utf8(unhex(s)).unwrap()
}

#[test]
fn hash_helpers_match_kotlin() {
    let table = fs::read_to_string(fixtures().join("hashes.tsv")).unwrap();
    let mut checked = 0;
    for line in table.lines() {
        let cols: Vec<&str> = line.split('\t').collect();
        match cols.as_slice() {
            ["sha256", input, expected] => assert_eq!(hashing::sha256_hex(&unhex(input)), *expected),
            ["spki_pin", input, expected] => assert_eq!(hashing::spki_pin(&unhex(input)), *expected),
            ["dex", entries, expected] => {
                let owned: Vec<(String, Vec<u8>)> = entries
                    .split(';')
                    .map(|e| {
                        let (name, bytes) = e.split_once('=').unwrap();
                        (name.to_owned(), unhex(bytes))
                    })
                    .collect();
                let refs: Vec<(&str, &[u8])> = owned.iter().map(|(n, b)| (n.as_str(), b.as_slice())).collect();
                let actual = hashing::dex_sha256(&refs).unwrap().unwrap_or_else(|| "none".into());
                assert_eq!(actual, *expected, "{line}");
            }
            ["normalize_hex", input, expected] => {
                let actual = hashing::normalize_hex(&utf8(input)).unwrap_or_else(|| "none".into());
                assert_eq!(actual, *expected, "{line}");
            }
            ["is_pin", value, expected] => assert_eq!(hashing::is_pin(value).to_string(), *expected, "{line}"),
            ["hash_equals", a, b, expected] => {
                let actual = hashing::constant_time_eq(utf8(a).as_bytes(), utf8(b).as_bytes());
                assert_eq!(actual.to_string(), *expected, "{line}");
            }
            _ => panic!("unknown line: {line}"),
        }
        checked += 1;
    }
    assert!(checked >= 25, "only {checked} vectors");
}
