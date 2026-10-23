//! Phase 2: `exclusive_bytes` — how much disk space removing a folder would actually free.
//!
//! Rule: the scope is a folder and everything below it. A file's on-disk size counts toward
//! `exclusive_bytes` once, and only if the number of its links seen inside the scope equals
//! its `nNumberOfLinks`; otherwise it counts toward `shared_bytes` (a link lives outside).
//!
//! Flow (runs after the walk result is already on screen, D13):
//! ```text
//! allow-listed node ─► enumerate files (listing only)
//!   cloud attribute?  ── yes ─► never opened, 0 bytes
//!   inside sync root? ── yes ─► never opened, logical size, unverified
//!   CreateFileW(FILE_READ_ATTRIBUTES, share all, OPEN_REPARSE_POINT|BACKUP_SEMANTICS)
//!     ├ fails ─► logical size, unverified_files++
//!     └ same handle: file id + link count + EndOfFile/AllocationSize/compressed size (D11)
//!   links in scope == nNumberOfLinks ? exclusive : shared
//! ```
//! Cloud and sync-root checks happen before the opener is called; the opener is a trait so
//! tests can prove it is never called for those files.

use rayon::prelude::*;
use serde::Serialize;
use std::collections::HashMap;
use std::fs;
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};

use crate::core::paths;
use crate::core::scan::attrs::{self, EntryKind};
use crate::core::scan::progress::Progress;
use crate::core::scan::syncroots::SyncRootDetection;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileKey {
    pub volume: u32,
    pub index: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct FileInfo {
    pub key: FileKey,
    pub links: u32,
    pub end_of_file: u64,
    pub disk_bytes: u64,
}

pub trait FileOpener: Sync {
    /// Opens with the fixed flags above and reads everything from that one handle.
    fn open_info(&self, path: &Path) -> Result<FileInfo, String>;
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AccountingUpdate {
    pub node_id: u32,
    pub exclusive_bytes: u64,
    pub shared_bytes: u64,
    pub unverified_files: u32,
    /// Handle-based size (EndOfFile); a hard-linked file's listing size can be stale (D11).
    pub logical_bytes: u64,
}

/// One allow-listed subtree: the topmost node plus the result-tree nodes below it.
#[derive(Debug, Clone)]
pub struct Scope {
    pub node_id: u32,
    pub path: PathBuf,
    /// All result-tree nodes inside the scope (including the scope node), by normalized path.
    pub nodes: Vec<(u32, PathBuf)>,
}

struct FileRec {
    path: PathBuf,
    chain: Vec<u32>,
    attrs: u32,
    size: u64,
}

enum Outcome {
    Skip,
    Unverified(u64),
    Info(FileInfo),
}

pub const CANCEL_CHECK_EVERY: usize = 1000;

/// Returns `false` if cancelled (updates already sent for finished scopes stay valid).
pub fn run(
    scopes: &[Scope],
    opener: &dyn FileOpener,
    sync: &SyncRootDetection,
    max_depth: usize,
    progress: &Progress,
    on_update: &mut (dyn FnMut(AccountingUpdate) + Send),
) -> bool {
    for scope in scopes {
        if progress.is_cancelled() {
            return false;
        }
        match account_scope(scope, opener, sync, max_depth, progress) {
            Some(updates) => updates.into_iter().for_each(&mut *on_update),
            None => return false,
        }
    }
    !progress.is_cancelled()
}

fn account_scope(
    scope: &Scope,
    opener: &dyn FileOpener,
    sync: &SyncRootDetection,
    max_depth: usize,
    progress: &Progress,
) -> Option<Vec<AccountingUpdate>> {
    let by_path: HashMap<String, u32> = scope
        .nodes
        .iter()
        .map(|(id, p)| (paths::norm(p), *id))
        .collect();
    let files = enumerate(
        &scope.path,
        vec![scope.node_id],
        &by_path,
        0,
        max_depth,
        progress,
    );
    if progress.is_cancelled() {
        return None;
    }

    let outcomes: Vec<Outcome> = files
        .par_chunks(CANCEL_CHECK_EVERY)
        .map(|chunk| {
            if progress.is_cancelled() {
                return Vec::new();
            }
            let out: Vec<Outcome> = chunk
                .iter()
                .map(|f| classify_file(f, opener, sync))
                .collect();
            progress.add(chunk.len() as u64, 0);
            out
        })
        .flatten()
        .collect();
    if progress.is_cancelled() {
        return None;
    }

    #[derive(Default, Clone, Copy)]
    struct Acc {
        excl: u64,
        shared: u64,
        unverified: u32,
        logical: u64,
    }
    let mut acc: HashMap<u32, Acc> = scope
        .nodes
        .iter()
        .map(|(id, _)| (*id, Acc::default()))
        .collect();
    let mut multi: HashMap<FileKey, (FileInfo, Vec<&[u32]>)> = HashMap::new();

    for (f, o) in files.iter().zip(&outcomes) {
        match o {
            Outcome::Skip => {}
            Outcome::Unverified(size) => {
                for id in &f.chain {
                    let a = acc.entry(*id).or_default();
                    a.excl += size;
                    a.logical += size;
                    a.unverified += 1;
                }
            }
            Outcome::Info(info) => {
                for id in &f.chain {
                    acc.entry(*id).or_default().logical += info.end_of_file;
                }
                if info.links <= 1 {
                    for id in &f.chain {
                        acc.entry(*id).or_default().excl += info.disk_bytes;
                    }
                } else {
                    multi
                        .entry(info.key)
                        .or_insert_with(|| (*info, Vec::new()))
                        .1
                        .push(&f.chain);
                }
            }
        }
    }

    for (info, chains) in multi.values() {
        let mut seen: HashMap<u32, u32> = HashMap::new();
        for chain in chains {
            for id in chain.iter() {
                *seen.entry(*id).or_default() += 1;
            }
        }
        for (id, count) in seen {
            let a = acc.entry(id).or_default();
            if count >= info.links {
                a.excl += info.disk_bytes;
            } else {
                a.shared += info.disk_bytes;
            }
        }
    }

    let mut updates: Vec<AccountingUpdate> = acc
        .into_iter()
        .map(|(node_id, a)| AccountingUpdate {
            node_id,
            exclusive_bytes: a.excl,
            shared_bytes: a.shared,
            unverified_files: a.unverified,
            logical_bytes: a.logical,
        })
        .collect();
    updates.sort_by_key(|u| u.node_id);
    Some(updates)
}

fn classify_file(f: &FileRec, opener: &dyn FileOpener, sync: &SyncRootDetection) -> Outcome {
    // Both checks come before any call that could open the file.
    if attrs::is_cloud_only(f.attrs) {
        return Outcome::Skip;
    }
    if sync.contains(&f.path) {
        return Outcome::Unverified(f.size);
    }
    match opener.open_info(&f.path) {
        Ok(info) => Outcome::Info(info),
        Err(_) => Outcome::Unverified(f.size),
    }
}

/// Listing-only enumeration of files under `dir`, each tagged with the chain of
/// result-tree nodes containing it.
fn enumerate(
    dir: &Path,
    chain: Vec<u32>,
    by_path: &HashMap<String, u32>,
    depth: usize,
    max_depth: usize,
    progress: &Progress,
) -> Vec<FileRec> {
    if progress.is_cancelled() {
        return Vec::new();
    }
    let Ok(read) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut files = Vec::new();
    let mut subdirs = Vec::new();
    for entry in read.flatten() {
        let Ok(meta) = entry.metadata() else { continue };
        match attrs::classify(meta.file_attributes(), meta.file_type().is_symlink()) {
            EntryKind::Link => {}
            EntryKind::Dir => {
                if depth < max_depth {
                    subdirs.push(entry.path());
                }
            }
            EntryKind::File | EntryKind::CloudOnly => files.push(FileRec {
                path: entry.path(),
                chain: chain.clone(),
                attrs: meta.file_attributes(),
                size: meta.len(),
            }),
        }
    }
    progress.set_current(dir);
    let recurse = |p: PathBuf| {
        let mut c = chain.clone();
        if let Some(id) = by_path.get(&paths::norm(&p)) {
            c.push(*id);
        }
        enumerate(&p, c, by_path, depth + 1, max_depth, progress)
    };
    // Same stack rule as the walk: parallel only near the top.
    let nested: Vec<Vec<FileRec>> = if depth < crate::core::scan::walk::PARALLEL_DEPTH {
        subdirs.into_par_iter().map(recurse).collect()
    } else {
        subdirs.into_iter().map(recurse).collect()
    };
    files.extend(nested.into_iter().flatten());
    files
}

pub struct Win32Opener;

impl FileOpener for Win32Opener {
    fn open_info(&self, path: &Path) -> Result<FileInfo, String> {
        win::open_info(path)
    }
}

mod win {
    use super::{FileInfo, FileKey};
    use std::path::Path;
    use windows::core::HSTRING;
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FileCompressionInfo, FileStandardInfo, GetFileInformationByHandle,
        GetFileInformationByHandleEx, BY_HANDLE_FILE_INFORMATION, FILE_COMPRESSION_INFO,
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_STANDARD_INFO, OPEN_EXISTING,
    };

    struct Handle(HANDLE);
    impl Drop for Handle {
        fn drop(&mut self) {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }

    pub fn open_info(path: &Path) -> Result<FileInfo, String> {
        let wide = HSTRING::from(crate::core::paths::long_path(path).as_os_str());
        let h = unsafe {
            CreateFileW(
                &wide,
                FILE_READ_ATTRIBUTES.0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                None,
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
                None,
            )
        }
        .map_err(|e| e.message())?;
        let h = Handle(h);

        let mut bhfi = BY_HANDLE_FILE_INFORMATION::default();
        unsafe { GetFileInformationByHandle(h.0, &mut bhfi) }.map_err(|e| e.message())?;

        let mut std_info = FILE_STANDARD_INFO::default();
        unsafe {
            GetFileInformationByHandleEx(
                h.0,
                FileStandardInfo,
                (&mut std_info as *mut FILE_STANDARD_INFO).cast(),
                size_of::<FILE_STANDARD_INFO>() as u32,
            )
        }
        .map_err(|e| e.message())?;

        let mut comp = FILE_COMPRESSION_INFO::default();
        let compressed = unsafe {
            GetFileInformationByHandleEx(
                h.0,
                FileCompressionInfo,
                (&mut comp as *mut FILE_COMPRESSION_INFO).cast(),
                size_of::<FILE_COMPRESSION_INFO>() as u32,
            )
        }
        .ok()
        .filter(|_| comp.CompressionFormat.0 != 0)
        .map(|_| comp.CompressedFileSize.max(0) as u64);

        Ok(FileInfo {
            key: FileKey {
                volume: bhfi.dwVolumeSerialNumber,
                index: ((bhfi.nFileIndexHigh as u64) << 32) | bhfi.nFileIndexLow as u64,
            },
            links: bhfi.nNumberOfLinks,
            end_of_file: std_info.EndOfFile.max(0) as u64,
            disk_bytes: compressed.unwrap_or(std_info.AllocationSize.max(0) as u64),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::testzone::{fixture, write_file};
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Mutex;

    fn scope(root: &Path, nodes: &[(u32, &Path)]) -> Scope {
        Scope {
            node_id: nodes[0].0,
            path: root.to_path_buf(),
            nodes: nodes.iter().map(|(i, p)| (*i, p.to_path_buf())).collect(),
        }
    }

    fn run_collect(
        scopes: &[Scope],
        opener: &dyn FileOpener,
        sync: &SyncRootDetection,
    ) -> HashMap<u32, AccountingUpdate> {
        let progress = Progress::default();
        let mut out = HashMap::new();
        assert!(run(scopes, opener, sync, 512, &progress, &mut |u| {
            out.insert(u.node_id, u);
        }));
        out
    }

    #[test]
    fn accounting_hardlinks_all_inside_scope_count_once_as_exclusive() {
        let fx = fixture();
        let root = fx.path().join("cache");
        write_file(&root.join("a").join("blob"), 10_000);
        write_file(&root.join("solo"), 5_000);
        fs::hard_link(root.join("a").join("blob"), root.join("b_link")).unwrap();

        let r = run_collect(
            &[scope(&root, &[(1, &root)])],
            &Win32Opener,
            &SyncRootDetection::default(),
        );
        let u = &r[&1];
        assert_eq!(u.shared_bytes, 0);
        // 10 000 counted once (not twice), rounded up to clusters.
        assert!(
            u.exclusive_bytes >= 15_000 && u.exclusive_bytes < 30_000,
            "{u:?}"
        );
        assert_eq!(u.unverified_files, 0);
        assert_eq!(u.logical_bytes, 25_000); // logical counts every link, like the walk
    }

    #[test]
    fn accounting_hardlink_outside_scope_is_shared() {
        let fx = fixture();
        let root = fx.path().join("cache");
        let a = root.join("a");
        write_file(&a.join("blob"), 10_000);
        fs::hard_link(a.join("blob"), fx.path().join("outside_link")).unwrap();
        let b = root.join("b");
        write_file(&b.join("x"), 1);
        fs::hard_link(a.join("blob"), b.join("inner_link")).unwrap();

        // Nested result nodes: root (all its links but one are inside), a, b.
        let r = run_collect(
            &[scope(&root, &[(1, &root), (2, &a), (3, &b)])],
            &Win32Opener,
            &SyncRootDetection::default(),
        );
        // blob has 3 links: a/blob, b/inner_link (in scope), outside_link (not).
        assert!(r[&1].shared_bytes >= 10_000, "{:?}", r[&1]);
        assert!(
            r[&2].shared_bytes >= 10_000 && r[&2].exclusive_bytes == 0,
            "{:?}",
            r[&2]
        );
        assert!(r[&3].shared_bytes >= 10_000, "{:?}", r[&3]);
        // The blob's size is counted once per scope, not once per link.
        assert!(r[&1].shared_bytes < 20_000);
    }

    #[test]
    fn accounting_nested_scope_hardlink_exclusive_only_at_parent() {
        let fx = fixture();
        let root = fx.path().join("cache");
        let a = root.join("a");
        let b = root.join("b");
        write_file(&a.join("blob"), 10_000);
        fs::create_dir_all(&b).unwrap();
        fs::hard_link(a.join("blob"), b.join("blob2")).unwrap();
        let r = run_collect(
            &[scope(&root, &[(1, &root), (2, &a), (3, &b)])],
            &Win32Opener,
            &SyncRootDetection::default(),
        );
        assert!(
            r[&1].exclusive_bytes >= 10_000 && r[&1].shared_bytes == 0,
            "{:?}",
            r[&1]
        );
        assert!(
            r[&2].exclusive_bytes == 0 && r[&2].shared_bytes >= 10_000,
            "{:?}",
            r[&2]
        );
    }

    /// Records every path it is asked to open; returns fixed info.
    #[derive(Default)]
    struct Spy {
        calls: Mutex<Vec<PathBuf>>,
        fail_with: Option<&'static str>,
    }
    impl FileOpener for Spy {
        fn open_info(&self, path: &Path) -> Result<FileInfo, String> {
            self.calls.lock().unwrap().push(path.to_path_buf());
            if let Some(e) = self.fail_with {
                return Err(e.into());
            }
            static NEXT: AtomicU32 = AtomicU32::new(1);
            Ok(FileInfo {
                key: FileKey {
                    volume: 1,
                    index: NEXT.fetch_add(1, Ordering::Relaxed) as u64,
                },
                links: 1,
                end_of_file: 100,
                disk_bytes: 4096,
            })
        }
    }

    #[test]
    fn accounting_never_opens_cloud_files() {
        let fx = fixture();
        let root = fx.path().join("cache");
        write_file(&root.join("local.bin"), 100);
        let cloud = root.join("cloud.bin");
        write_file(&cloud, 100);
        // Mark the fixture file as a cloud placeholder (attribute only, via attrib +O = offline).
        let st = std::process::Command::new("attrib")
            .arg("+O")
            .arg(&cloud)
            .status()
            .unwrap();
        assert!(st.success());
        assert!(attrs::is_cloud_only(
            fs::metadata(&cloud).unwrap().file_attributes()
        ));

        let spy = Spy::default();
        run_collect(
            &[scope(&root, &[(1, &root)])],
            &spy,
            &SyncRootDetection::default(),
        );
        let calls = spy.calls.lock().unwrap();
        assert_eq!(calls.len(), 1, "{calls:?}");
        assert!(calls[0].ends_with("local.bin"));
        let _ = std::process::Command::new("attrib")
            .arg("-O")
            .arg(&cloud)
            .status();
    }

    #[test]
    fn accounting_never_opens_files_in_sync_root() {
        let fx = fixture();
        let root = fx.path().join("cache");
        let synced = root.join("synced");
        write_file(&synced.join("doc.txt"), 700);
        write_file(&root.join("local.bin"), 100);

        let spy = Spy::default();
        let sync = SyncRootDetection::with_roots(vec![synced.clone()]);
        let r = run_collect(&[scope(&root, &[(1, &root)])], &spy, &sync);
        let calls = spy.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert!(calls[0].ends_with("local.bin"));
        assert_eq!(r[&1].unverified_files, 1); // the sync-root file: logical, unverified
        assert_eq!(r[&1].exclusive_bytes, 4096 + 700);
    }

    #[test]
    fn accounting_open_failure_counts_logical_and_unverified() {
        for err in ["sharing violation", "access denied"] {
            let fx = fixture();
            let root = fx.path().join("cache");
            write_file(&root.join("locked.bin"), 1234);
            write_file(&root.join("other.bin"), 10);
            let spy = Spy {
                fail_with: Some(err),
                ..Default::default()
            };
            let r = run_collect(
                &[scope(&root, &[(1, &root)])],
                &spy,
                &SyncRootDetection::default(),
            );
            assert_eq!(r[&1].unverified_files, 2, "{err}");
            assert_eq!(r[&1].exclusive_bytes, 1244);
            assert_eq!(r[&1].shared_bytes, 0);
        }
    }

    #[test]
    fn accounting_cancel_returns_false() {
        let fx = fixture();
        let root = fx.path().join("cache");
        write_file(&root.join("a"), 1);
        let progress = Progress::default();
        progress.cancel();
        let mut n = 0;
        assert!(!run(
            &[scope(&root, &[(1, &root)])],
            &Win32Opener,
            &SyncRootDetection::default(),
            512,
            &progress,
            &mut |_| n += 1
        ));
        assert_eq!(n, 0);
    }

    /// Why ClearCache's WinSxS split runs ~1% above DISM: run the same accounting twice,
    /// once with on-disk size (allocation) and once with EndOfFile (no cluster rounding).
    /// Read-only. Run manually: `cargo test winsxs_rounding -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn winsxs_rounding_explains_gap_to_dism() {
        struct EofOnly;
        impl FileOpener for EofOnly {
            fn open_info(&self, path: &Path) -> Result<FileInfo, String> {
                let i = Win32Opener.open_info(path)?;
                Ok(FileInfo {
                    disk_bytes: i.end_of_file,
                    ..i
                })
            }
        }
        let root = paths::env_path("SystemRoot").unwrap().join("WinSxS");
        let s = scope(&root, &[(1, &root)]);
        let gb = |b: u64| b as f64 / 1e9; // DISM's GB
        for (name, opener) in [("disk", &Win32Opener as &dyn FileOpener), ("eof", &EofOnly)] {
            let r = run_collect(
                std::slice::from_ref(&s),
                opener,
                &SyncRootDetection::default(),
            );
            let u = &r[&1];
            println!(
                "{name}: exclusive={} ({:.2} GB) shared={} ({:.2} GB) total={:.2} GB unverified={}",
                u.exclusive_bytes,
                gb(u.exclusive_bytes),
                u.shared_bytes,
                gb(u.shared_bytes),
                gb(u.exclusive_bytes + u.shared_bytes),
                u.unverified_files
            );
        }
    }

    /// D11: compare handle-based sizes with `GetCompressedFileSizeW` on 100 WinSxS files.
    /// Read-only. Run manually: `cargo test winsxs_size_source -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn winsxs_size_source_matches_compressed_file_size() {
        use windows::core::HSTRING;
        use windows::Win32::Storage::FileSystem::GetCompressedFileSizeW;

        let root = paths::env_path("SystemRoot").unwrap().join("WinSxS");
        let mut samples = Vec::new();
        let mut stack = vec![root];
        while let Some(d) = stack.pop() {
            let Ok(rd) = fs::read_dir(&d) else { continue };
            for e in rd.flatten() {
                let Ok(m) = e.metadata() else { continue };
                if m.is_dir() && !m.file_type().is_symlink() {
                    stack.push(e.path());
                } else if m.is_file() && samples.len() < 100 {
                    samples.push((e.path(), m.len()));
                }
            }
            if samples.len() >= 100 {
                break;
            }
        }
        // gcfs equals the compressed size for compressed/WOF files and EndOfFile otherwise.
        let (mut same, mut diff, mut failed) = (0, 0, 0);
        let (mut eq_disk, mut eq_eof, mut stale_listing) = (0, 0, 0);
        for (p, listed) in &samples {
            let Ok(info) = Win32Opener.open_info(p) else {
                failed += 1;
                continue;
            };
            let mut high = 0u32;
            let low =
                unsafe { GetCompressedFileSizeW(&HSTRING::from(p.as_os_str()), Some(&mut high)) };
            let gcfs = ((high as u64) << 32) | low as u64;
            eq_disk += (gcfs == info.disk_bytes) as u32;
            eq_eof += (gcfs == info.end_of_file) as u32;
            stale_listing += (*listed != info.end_of_file) as u32;
            if gcfs == info.disk_bytes || gcfs == info.end_of_file {
                same += 1;
            } else {
                diff += 1;
                println!(
                    "DIFF {} listed={} eof={} disk={} gcfs={} links={}",
                    p.display(),
                    listed,
                    info.end_of_file,
                    info.disk_bytes,
                    gcfs,
                    info.links
                );
            }
        }
        println!(
            "samples={} same={same} diff={diff} open_failed={failed} \
             gcfs==disk:{eq_disk} gcfs==eof:{eq_eof} listing!=eof:{stale_listing}",
            samples.len()
        );
    }
}
