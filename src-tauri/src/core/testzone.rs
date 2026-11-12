//! Test fixtures live only under `C:\ClearCache_TestZone\scan-tests\<random>` (SPEC test rule)
//! and are removed when the returned `TempDir` drops.

use std::fs;
use std::path::{Path, PathBuf};
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

/// Creates a folder whose name Win32 would rewrite (trailing dot or space), through the
/// verbatim path; `TempDir` can still remove it.
pub fn odd_dir(path: &Path) {
    fs::create_dir_all(crate::core::paths::verbatim(path)).expect("create odd-named folder");
}

/// Writes a file through the verbatim path (for odd names and paths past MAX_PATH).
pub fn write_verbatim(path: &Path, bytes: usize) {
    let v = crate::core::paths::verbatim(path);
    if let Some(parent) = v.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(v, vec![b'x'; bytes]).unwrap();
}

/// Denies listing `dir` to Everyone until the guard drops (declare it after the fixture so it
/// drops first), for folders the scan cannot read.
pub struct DenyList(PathBuf);

pub fn deny_list(dir: &Path) -> DenyList {
    icacls(dir, &["/deny", "*S-1-1-0:(RD)"]);
    DenyList(dir.to_path_buf())
}

impl Drop for DenyList {
    fn drop(&mut self) {
        icacls(&self.0, &["/remove:d", "*S-1-1-0"]);
    }
}

fn icacls(path: &Path, args: &[&str]) {
    let out = std::process::Command::new("icacls")
        .arg(path)
        .args(args)
        .output()
        .expect("run icacls");
    assert!(out.status.success(), "icacls {args:?} failed: {out:?}");
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
