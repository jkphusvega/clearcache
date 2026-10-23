//! Test fixtures live only under `C:\ClearCache_TestZone\scan-tests\<random>` (SPEC test rule)
//! and are removed when the returned `TempDir` drops.

use std::fs;
use std::path::Path;
use tempfile::TempDir;

pub const BASE: &str = r"C:\ClearCache_TestZone\scan-tests";

pub fn fixture() -> TempDir {
    fs::create_dir_all(BASE).expect("create TestZone base");
    tempfile::Builder::new()
        .prefix("t")
        .tempdir_in(BASE)
        .expect("create fixture dir")
}

pub fn write_file(path: &Path, bytes: usize) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, vec![b'x'; bytes]).unwrap();
}

/// `mklink /J link target` — a junction, the reparse point a scanner must not follow.
pub fn junction(link: &Path, target: &Path) {
    let status = std::process::Command::new("cmd")
        .args(["/c", "mklink", "/J"])
        .arg(link)
        .arg(target)
        .output()
        .expect("run mklink");
    assert!(status.status.success(), "mklink /J failed: {status:?}");
}
