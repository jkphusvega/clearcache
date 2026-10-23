//! Walk + accounting on fixtures under `C:\ClearCache_TestZone\scan-tests\` (test threshold 1 KiB).

use super::*;
use crate::core::accounting::{FileInfo, FileKey, Win32Opener};
use crate::core::testzone::{fixture, junction, write_file};
use std::fs;
use std::sync::Mutex;

const KIB: u64 = 1024;

fn cfg(root: &Path) -> ScanConfig {
    ScanConfig {
        target_id: "test".into(),
        kind: TargetKind::UserHome,
        root: root.to_path_buf(),
        root_display: root.to_string_lossy().into_owned(),
        threshold: KIB,
        max_depth: MAX_DEPTH,
        policy: PolicyContext {
            drive_root: None,
            system_root: None,
        },
        accounting_roots: vec![],
        user_home: None,
        read_only_volume: false,
        drive_used_bytes: None,
    }
}

fn walk_only(c: &ScanConfig) -> (ScanResult, AccountingPlan) {
    walk_phase(c, &SyncRootDetection::default(), &Progress::default()).expect("not cancelled")
}

fn node<'a>(r: &'a ScanResult, name: &str) -> &'a FlatNode {
    r.nodes
        .iter()
        .find(|n| n.name == name)
        .unwrap_or_else(|| panic!("no node {name}"))
}

fn children(r: &ScanResult, id: u32) -> Vec<&FlatNode> {
    r.nodes.iter().filter(|n| n.parent_id == Some(id)).collect()
}

#[test]
fn scan_sums_sizes_counts_and_mtime() {
    let fx = fixture();
    let root = fx.path();
    write_file(&root.join("big").join("a.bin"), 3000);
    write_file(&root.join("big").join("sub").join("b.bin"), 2000);
    write_file(&root.join("big").join("sub").join("c.txt"), 100);
    write_file(&root.join("top.log"), 10);

    let (r, _) = walk_only(&cfg(root));
    let rootn = &r.nodes[0];
    assert_eq!(rootn.logical_bytes, Some(5110));
    assert_eq!(rootn.files, Some(4));
    assert_eq!(r.summary.total_logical_bytes, 5110);
    assert_eq!(r.summary.files, 4);
    let big = node(&r, "big");
    assert_eq!(big.logical_bytes, Some(5100));
    assert_eq!(big.files, Some(3));
    let newest = fs::metadata(root.join("top.log"))
        .unwrap()
        .modified()
        .unwrap();
    let newest = newest
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    assert!((rootn.last_modified.unwrap() - newest).abs() <= 2);
}

#[test]
fn scan_threshold_parent_child_and_sibling_order() {
    let fx = fixture();
    let root = fx.path();
    write_file(&root.join("small").join("x"), 500); // below 1 KiB: dropped
    write_file(&root.join("mid").join("x"), 2000);
    write_file(&root.join("large").join("x"), 9000);
    write_file(&root.join("large").join("inner").join("y"), 4000);

    let (r, _) = walk_only(&cfg(root));
    let top: Vec<_> = children(&r, 0).iter().map(|n| n.name.clone()).collect();
    assert_eq!(top, ["large", "mid"]);
    let large = node(&r, "large");
    let inner = node(&r, "inner");
    assert_eq!(inner.parent_id, Some(large.id));
    assert_eq!(large.logical_bytes, Some(13000));
    // Small folder still counts toward the root.
    assert_eq!(r.nodes[0].logical_bytes, Some(15500));
}

#[test]
fn scan_does_not_follow_junctions() {
    let fx = fixture();
    let root = fx.path().join("scanned");
    let outside = fx.path().join("outside");
    write_file(&outside.join("huge.bin"), 50_000);
    write_file(&root.join("real").join("f"), 2000);
    junction(&root.join("link"), &outside);

    let (r, _) = walk_only(&cfg(&root));
    assert_eq!(r.nodes[0].logical_bytes, Some(2000));
    assert!(r.nodes.iter().all(|n| n.name != "link"));
}

#[test]
fn scan_top_exts_merged_and_limited() {
    let fx = fixture();
    let root = fx.path();
    write_file(&root.join("d").join("a.bin"), 5000);
    write_file(&root.join("d").join("s").join("b.BIN"), 1000);
    for (i, ext) in ["txt", "log", "json", "csv", "md", "xml"]
        .iter()
        .enumerate()
    {
        write_file(&root.join("d").join(format!("f.{ext}")), 100 + i);
    }
    let (r, _) = walk_only(&cfg(root));
    let d = node(&r, "d");
    assert_eq!(d.top_exts.len(), 5);
    assert_eq!(d.top_exts[0].ext, ".bin");
    assert_eq!(d.top_exts[0].bytes, 6000);
    assert_eq!(d.top_exts[1].ext, ".xml");
}

#[test]
fn scan_cancel_during_walk() {
    let fx = fixture();
    write_file(&fx.path().join("a").join("b"), 10);
    let p = Progress::default();
    p.cancel();
    assert!(walk_phase(&cfg(fx.path()), &SyncRootDetection::default(), &p).is_none());
}

#[test]
fn scan_depth_600_skips_beyond_512_without_crash() {
    let fx = fixture();
    let mut deep = fx.path().to_path_buf();
    for _ in 0..600 {
        deep.push("d");
    }
    fs::create_dir_all(&deep).unwrap();
    fs::write(deep.join("leaf"), b"x").unwrap();

    let (r, _) = walk_only(&cfg(fx.path()));
    assert_eq!(r.summary.skipped_count, 1);
    assert_eq!(r.skipped[0].reason, walk::REASON_TOO_DEEP);
    assert!(r.nodes[0].partial);
    assert_eq!(r.nodes[0].skipped_descendants, 1);
    // Cleanup of a 600-deep tree: TempDir's remove_dir_all handles long paths.
}

#[test]
fn scan_depth_600_inside_accounting_scope_without_crash() {
    let fx = fixture();
    let cache = fx.path().join("uvcache");
    write_file(&cache.join("top.whl"), 2000);
    let mut deep = cache.clone();
    for _ in 0..600 {
        deep.push("d");
    }
    fs::create_dir_all(&deep).unwrap();
    fs::write(deep.join("leaf"), b"x").unwrap();
    let mut c = cfg(fx.path());
    c.accounting_roots = vec![cache];
    let r = scan_blocking(
        &c,
        &SyncRootDetection::default(),
        &Win32Opener,
        &Progress::default(),
    )
    .unwrap();
    assert_eq!(node(&r, "uvcache").accounting, AccountingState::Done);
    assert_eq!(r.summary.accounting_status, PhaseStatus::Complete);
}

#[test]
fn scan_partial_propagates_to_every_ancestor() {
    let fx = fixture();
    let root = fx.path();
    write_file(&root.join("a").join("b").join("f"), 3000);
    let locked = root.join("a").join("b").join("locked");
    let locked2 = root.join("a").join("locked2");
    fs::create_dir_all(&locked).unwrap();
    fs::create_dir_all(&locked2).unwrap();
    for d in [&locked, &locked2] {
        let out = std::process::Command::new("icacls")
            .arg(d)
            .args(["/deny", "*S-1-1-0:(RD)"])
            .output()
            .unwrap();
        assert!(out.status.success(), "{out:?}");
    }

    let (r, _) = walk_only(&cfg(root));
    for d in [&locked, &locked2] {
        let _ = std::process::Command::new("icacls")
            .arg(d)
            .args(["/remove:d", "*S-1-1-0"])
            .output();
    }
    let b = node(&r, "b");
    let a = node(&r, "a");
    assert!(b.partial && b.skipped_descendants == 1, "{b:?}");
    assert!(a.partial && a.skipped_descendants == 2, "{a:?}");
    assert!(r.nodes[0].partial && r.nodes[0].skipped_descendants == 2);
    assert_eq!(r.summary.skipped_count, 2);
}

#[test]
fn scan_system_mapping_on_fake_drive_root() {
    let fx = fixture();
    let root = fx.path();
    let win = root.join("Windows");
    write_file(&win.join("WinSxS").join("x.dll"), 4000);
    write_file(&win.join("System32").join("y.dll"), 9000);
    write_file(
        &win.join("SoftwareDistribution")
            .join("Download")
            .join("u.cab"),
        2000,
    );
    write_file(
        &win.join("SoftwareDistribution")
            .join("DataStore")
            .join("d.edb"),
        2000,
    );
    write_file(&win.join("MEMORY.DMP"), 10);
    write_file(&win.join("explorer.exe"), 3000);
    write_file(&root.join("Program Files").join("App").join("a.exe"), 100);
    write_file(&root.join("ProgramData").join("p"), 5000);
    write_file(&root.join("pagefile.sys"), 50);
    write_file(&root.join("ClearCache_Quarantine").join("q"), 7000);

    let mut c = cfg(root);
    c.kind = TargetKind::Drive;
    c.policy = PolicyContext {
        drive_root: Some(root.to_path_buf()),
        system_root: Some(win.clone()),
    };
    let (r, _) = walk_only(&c);

    let w = node(&r, "Windows");
    assert_eq!(w.tag, Some(policy::TAG_SYSTEM));
    // Measured: WinSxS 4000 + Download 2000 + MEMORY.DMP 10. System32, DataStore, loose files are not.
    assert_eq!(w.logical_bytes, Some(6010));
    let other = node(&r, "기타 Windows");
    assert_eq!(other.logical_bytes, None);
    assert_eq!(other.parent_id, Some(w.id));
    assert_eq!(node(&r, "MEMORY.DMP").logical_bytes, Some(10));
    assert!(node(&r, "Download").logical_bytes == Some(2000));
    assert_eq!(node(&r, "기타 (측정 안 함)").logical_bytes, None);
    // Pinned regardless of the 1 KiB threshold.
    let pf = node(&r, "Program Files");
    assert_eq!(
        (pf.tag, pf.logical_bytes),
        (Some(policy::TAG_SYSTEM_APPS), Some(100))
    );
    assert_eq!(node(&r, "ProgramData").logical_bytes, None);
    assert_eq!(node(&r, "pagefile.sys").logical_bytes, Some(50));
    assert!(r.nodes.iter().all(|n| n.name != "ClearCache_Quarantine"));
    assert_eq!(r.nodes[0].logical_bytes, Some(6010 + 100 + 50));
}

#[test]
fn scan_two_phase_walk_result_first_then_updates_by_node_id() {
    let fx = fixture();
    let root = fx.path();
    let cache = root.join("uvcache");
    write_file(&cache.join("pkg").join("a.whl"), 3000);
    write_file(&cache.join("b.whl"), 2000);
    let mut c = cfg(root);
    c.accounting_roots = vec![cache.clone()];

    let sync = SyncRootDetection::default();
    let progress = Progress::default();
    let (mut result, plan) = walk_phase(&c, &sync, &progress).unwrap();
    // Walk result exists before accounting: allow-listed nodes are pending.
    let cache_id = node(&result, "uvcache").id;
    let pkg_id = node(&result, "pkg").id;
    assert_eq!(
        result.nodes[cache_id as usize].accounting,
        AccountingState::Pending
    );
    assert_eq!(result.nodes[0].accounting, AccountingState::None);
    assert_eq!(result.summary.accounting_status, PhaseStatus::Running);
    assert_eq!(plan.scopes.len(), 1);

    let mut updates = Vec::new();
    assert!(accounting_phase(
        &plan,
        &Win32Opener,
        &sync,
        &progress,
        &mut |u| updates.push(u)
    ));
    let ids: Vec<_> = updates.iter().map(|u| u.node_id).collect();
    assert_eq!(ids, [cache_id, pkg_id]);
    for u in &updates {
        result.apply(u);
    }
    result.finish_accounting(true, 5);
    assert_eq!(
        result.nodes[cache_id as usize].accounting,
        AccountingState::Done
    );
    assert!(result.nodes[cache_id as usize].exclusive_bytes.unwrap() >= 5000);
    assert!(result.nodes[pkg_id as usize].exclusive_bytes.unwrap() >= 3000);
    assert_eq!(result.summary.accounting_status, PhaseStatus::Complete);
}

#[test]
fn scan_accounting_cancel_keeps_walk_result() {
    let fx = fixture();
    let root = fx.path();
    let cache = root.join("uvcache");
    write_file(&cache.join("a.whl"), 3000);
    let mut c = cfg(root);
    c.accounting_roots = vec![cache];
    let sync = SyncRootDetection::default();
    let progress = Progress::default();
    let (mut result, plan) = walk_phase(&c, &sync, &progress).unwrap();
    progress.cancel();
    let mut n = 0;
    let done = accounting_phase(&plan, &Win32Opener, &sync, &progress, &mut |_| n += 1);
    assert!(!done);
    result.finish_accounting(done, 1);
    let cache = node(&result, "uvcache");
    assert_eq!(cache.accounting, AccountingState::Cancelled);
    assert_eq!(cache.logical_bytes, Some(3000));
    assert_eq!(result.summary.accounting_status, PhaseStatus::Cancelled);
}

#[test]
fn scan_sync_root_nodes_marked_and_excluded_from_accounting() {
    let fx = fixture();
    let root = fx.path();
    let od = root.join("OneDrive");
    write_file(&od.join("uvcache").join("a.whl"), 3000);
    let mut c = cfg(root);
    c.accounting_roots = vec![od.join("uvcache")];
    let sync = SyncRootDetection::with_roots(vec![od.clone()]);
    let (r, plan) = walk_phase(&c, &sync, &Progress::default()).unwrap();
    assert!(node(&r, "OneDrive").in_sync_root);
    assert!(!r.nodes[0].in_sync_root);
    assert_eq!(node(&r, "uvcache").accounting, AccountingState::Unverified);
    assert!(plan.scopes.is_empty());
}

/// Fails the test if the opener is ever called.
struct NeverOpen(Mutex<u32>);
impl crate::core::accounting::FileOpener for NeverOpen {
    fn open_info(&self, _: &Path) -> Result<FileInfo, String> {
        *self.0.lock().unwrap() += 1;
        Ok(FileInfo {
            key: FileKey {
                volume: 0,
                index: 0,
            },
            links: 1,
            end_of_file: 0,
            disk_bytes: 0,
        })
    }
}

#[test]
fn scan_sync_detection_all_failed_skips_user_home_accounting() {
    use syncroots::SyncRootSource;
    struct Broken;
    impl SyncRootSource for Broken {
        fn name(&self) -> &'static str {
            "broken"
        }
        fn read(&self) -> Result<Vec<PathBuf>, String> {
            Err("denied".into())
        }
    }
    let fx = fixture();
    let root = fx.path();
    let cache = root.join("home").join("uvcache");
    let outside = root.join("sys").join("winsxs");
    write_file(&cache.join("a.whl"), 3000);
    write_file(&outside.join("b.dll"), 3000);
    let mut c = cfg(root);
    c.user_home = Some(root.join("home"));
    c.accounting_roots = vec![cache, outside];

    let sync = SyncRootDetection::detect(&[Box::new(Broken), Box::new(Broken)]);
    assert!(sync.all_failed);
    let progress = Progress::default();
    let (r, plan) = walk_phase(&c, &sync, &progress).unwrap();
    assert_eq!(node(&r, "uvcache").accounting, AccountingState::Unverified);
    assert_eq!(node(&r, "winsxs").accounting, AccountingState::Pending);
    assert!(r.summary.sync_root_detection.partial_failure);

    let spy = NeverOpen(Mutex::new(0));
    accounting_phase(&plan, &spy, &sync, &progress, &mut |_| {});
    assert_eq!(
        *spy.0.lock().unwrap(),
        1,
        "only the file outside the user folder is opened"
    );
}

#[test]
fn scan_unaccounted_bytes_clamps_at_zero() {
    assert_eq!(unaccounted_bytes(100, 30), 70);
    assert_eq!(unaccounted_bytes(100, 130), 0);
}

#[test]
fn scan_result_json_shape() {
    let fx = fixture();
    write_file(&fx.path().join("d").join("f"), 2000);
    let r = scan_blocking(
        &cfg(fx.path()),
        &SyncRootDetection::default(),
        &Win32Opener,
        &Progress::default(),
    )
    .unwrap();
    let v = serde_json::to_value(&r).unwrap();
    for k in ["summary", "nodes", "skipped"] {
        assert!(v.get(k).is_some(), "{k}");
    }
    for k in [
        "target_id",
        "root_display",
        "total_logical_bytes",
        "files",
        "elapsed_ms",
        "accounting_ms",
        "accounting_status",
        "skipped_count",
        "cloud_only_files",
        "drive_used_bytes",
        "unaccounted_bytes",
        "sync_root_detection",
        "threshold_bytes",
    ] {
        assert!(v["summary"].get(k).is_some(), "summary.{k}");
    }
    for k in [
        "id",
        "parent_id",
        "path",
        "name",
        "logical_bytes",
        "files",
        "exclusive_bytes",
        "shared_bytes",
        "unverified_files",
        "accounting",
        "partial",
        "skipped_descendants",
        "top_exts",
        "last_modified",
        "tag",
        "is_file",
        "is_link",
        "in_sync_root",
        "read_only_volume",
    ] {
        assert!(v["nodes"][0].get(k).is_some(), "node.{k}");
    }
    assert_eq!(v["summary"]["accounting_status"], "not_needed");
}
