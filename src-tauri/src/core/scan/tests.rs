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
        // A user folder outside every fixture: without one, accounting fails closed.
        user_home: Some(PathBuf::from(r"C:\Users\clearcache-test-nobody")),
        read_only_volume: false,
        drive_used_bytes: None,
        rules: None,
        protect: None,
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

// --- Security audit (2026-11-12): the M2 scanner had the same plain-path reads ---

/// Audit 1·9: a folder named `evil.` is listed, but a plain-path read of it opens `evil`.
/// Its bytes must be counted by the walk and by accounting, not swapped for the sibling's.
#[test]
fn audit_01_scan_reads_odd_names_through_verbatim_paths() {
    use crate::core::testzone::{odd_dir, write_verbatim};
    let fx = fixture();
    let root = fx.path();
    let cache = root.join("uvcache");
    odd_dir(&cache.join("evil."));
    write_verbatim(&cache.join("evil.").join("hidden.bin"), 3000);
    odd_dir(&cache.join("evil")); // empty decoy that a plain read would open instead
    odd_dir(&cache.join("space "));
    write_verbatim(&cache.join("space ").join("s.bin"), 2000);
    let mut c = cfg(root);
    c.accounting_roots = vec![cache.clone()];

    let sync = SyncRootDetection::default();
    let progress = Progress::default();
    let (mut r, plan) = walk_phase(&c, &sync, &progress).unwrap();
    assert_eq!(r.nodes[0].logical_bytes, Some(5000));
    assert_eq!(r.summary.skipped_count, 0);
    let mut updates = Vec::new();
    assert!(accounting_phase(
        &plan,
        &Win32Opener,
        &sync,
        &progress,
        &mut |u| updates.push(u)
    ));
    for u in &updates {
        r.apply(u);
    }
    let cache_id = node(&r, "uvcache").id as usize;
    assert!(
        r.nodes[cache_id].exclusive_bytes.unwrap() >= 5000,
        "{:?}",
        r.nodes[cache_id]
    );
}

/// Audit 1·9: paths past MAX_PATH are read, not skipped.
#[test]
fn audit_01_scan_reads_past_max_path() {
    use crate::core::testzone::write_verbatim;
    let fx = fixture();
    let root = fx.path();
    let mut deep = root.join("deep");
    while deep.to_string_lossy().len() < 300 {
        deep = deep.join("a-fairly-long-folder-name");
    }
    write_verbatim(&deep.join("f.bin"), 4000);
    let (r, _) = walk_only(&cfg(root));
    assert_eq!(r.nodes[0].logical_bytes, Some(4000));
    assert_eq!(r.summary.skipped_count, 0);
}

/// Audit 3: without a user folder there is no telling what lies inside it; accounting fails
/// closed instead of opening files that may sit in an undetected sync root.
#[test]
fn audit_03_scan_without_user_folder_skips_accounting() {
    let fx = fixture();
    let root = fx.path();
    let cache = root.join("uvcache");
    write_file(&cache.join("a.whl"), 3000);
    let mut c = cfg(root);
    c.user_home = None;
    c.accounting_roots = vec![cache];
    let (r, plan) = walk_only(&c);
    assert_eq!(node(&r, "uvcache").accounting, AccountingState::Unverified);
    assert!(plan.scopes.is_empty());
}

/// Audit 13: the scan finds Windows through the OS, not `%SystemRoot%`.
#[test]
fn audit_13_scan_config_system_root_from_the_os() {
    let t = crate::core::targets::user_home_target(PathBuf::from(r"C:\Users\x"));
    let c = ScanConfig::for_target(&t, KIB);
    assert_eq!(c.policy.system_root, crate::core::paths::windows_dir());
}

// --- 2nd audit (2026-11-12) ---

/// D1: `\\?\` is for reading only; node paths stay plain, as the UI shows them.
#[test]
fn audit2_d1_node_paths_are_plain() {
    let fx = fixture();
    let root = fx.path();
    write_file(&root.join("w").join("sub").join("f.bin"), 4 * KIB as usize);
    write_file(&root.join("w").join("g.bin"), 4 * KIB as usize);
    let (r, _) = walk_only(&cfg(root));
    assert!(r.nodes.len() > 1, "{:?}", r.nodes);
    for n in &r.nodes {
        assert!(!n.path.starts_with(r"\\?\"), "{}", n.path);
        assert!(Path::new(&n.path).starts_with(root), "{}", n.path);
    }
    assert!(r
        .nodes
        .iter()
        .any(|n| n.path == root.join("w").join("sub").to_string_lossy()));
}

/// C2: every sync source failed and the user folder is written with `..`: compared in the
/// normalized form, the user folder still blocks accounting inside it.
#[test]
fn audit2_c2_user_folder_with_dotdot_blocks_accounting() {
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
    write_file(&cache.join("a.whl"), 3000);
    let mut c = cfg(root);
    c.user_home = Some(root.join("home").join("..").join("home"));
    c.accounting_roots = vec![cache];
    let sync = SyncRootDetection::detect(&[Box::new(Broken)]);
    assert!(sync.all_failed);
    let (r, plan) = walk_phase(&c, &sync, &Progress::default()).unwrap();
    assert_eq!(node(&r, "uvcache").accounting, AccountingState::Unverified);
    assert!(plan.scopes.is_empty());
}

/// Focused review 4 (M2 regression): a sync root whose real name ends in a dot is marked and
/// kept out of accounting, as it was before the roots were stored in comparison form.
#[test]
fn review_4_sync_root_named_with_trailing_dot_is_marked() {
    use crate::core::testzone::{odd_dir, write_verbatim};
    let fx = fixture();
    let root = fx.path();
    let od = root.join("od").join("root.");
    odd_dir(&od);
    write_verbatim(&od.join("doc.bin"), 4 * KIB as usize);
    let mut c = cfg(root);
    c.accounting_roots = vec![root.join("od")];
    let sync = SyncRootDetection::with_roots(vec![od.clone()]);
    let (r, plan) = walk_phase(&c, &sync, &Progress::default()).unwrap();
    let n = node(&r, "root.");
    assert!(n.in_sync_root, "{n:?}");
    assert_eq!(n.accounting, AccountingState::Unverified);
    assert!(plan
        .scopes
        .iter()
        .all(|s| s.nodes.iter().all(|(_, p)| !p.ends_with("root."))));
}

// ===== M3 T4: rule matching, stops and protection facts in the walk =====

mod t4 {
    use super::*;
    use crate::core::protect::{ProtectContext, Protection, Reason, Stop};
    use crate::core::rules::pattern::RuleMatcher;
    use crate::core::rules::source::{BuiltinRules, RuleSource};
    use crate::core::rules::{Grade, Rule, RuleOrigin};
    use std::sync::Arc;
    use walk::{walk, TreeNode};

    /// A user folder inside the fixture, and the environment that points at it.
    fn env_for(home: &Path) -> impl Fn(&str) -> Option<PathBuf> + Clone {
        let home = home.to_path_buf();
        move |k: &str| {
            let v = match k {
                "USERPROFILE" => home.clone(),
                "LOCALAPPDATA" => home.join(r"AppData\Local"),
                "APPDATA" => home.join(r"AppData\Roaming"),
                "ProgramFiles" => home.parent()?.join("pf"),
                "ProgramFiles(x86)" => home.parent()?.join("pf86"),
                "SystemRoot" => crate::core::paths::windows_dir()?,
                _ => return None,
            };
            Some(v)
        }
    }

    fn user_rule(id: &str, pattern: &str, grade: Grade) -> Rule {
        let mut r = crate::core::rules::testenv::rule(id, pattern, grade);
        r.source = RuleOrigin::User;
        r
    }

    struct Scan {
        root: TreeNode,
        rules: Arc<RuleMatcher>,
    }

    impl Scan {
        fn node(&self, path: &Path) -> &TreeNode {
            fn find<'a>(n: &'a TreeNode, p: &Path) -> Option<&'a TreeNode> {
                if crate::core::paths::same_path(&n.path, p) {
                    return Some(n);
                }
                n.children.iter().find_map(|c| find(c, p))
            }
            find(&self.root, path).unwrap_or_else(|| panic!("no node {path:?}"))
        }

        fn has_node(&self, path: &Path) -> bool {
            fn find(n: &TreeNode, p: &Path) -> bool {
                crate::core::paths::same_path(&n.path, p) || n.children.iter().any(|c| find(c, p))
            }
            find(&self.root, path)
        }

        fn rule_id(&self, path: &Path) -> Option<&str> {
            self.node(path).rule.map(|i| self.rules.rule(i).id.as_str())
        }

        fn has_rule_below(&self, path: &Path) -> bool {
            fn any(n: &TreeNode) -> bool {
                n.rule.is_some() || n.children.iter().any(any)
            }
            self.node(path).children.iter().any(any)
        }
    }

    fn scan(root: &Path, home: &Path, threshold: u64, extra: Vec<Rule>) -> Scan {
        let env = env_for(home);
        let mut rules = BuiltinRules::embedded().rules().unwrap().rules;
        rules.extend(extra);
        let matcher = Arc::new(RuleMatcher::new(&rules, &env));
        let ctx = ProtectContext::new(env, &SyncRootDetection::with_roots(Vec::new()));
        let wcfg = WalkConfig {
            threshold,
            max_depth: MAX_DEPTH,
            policy: PolicyContext {
                drive_root: None,
                system_root: None,
            },
            rules: Some(matcher.clone()),
            protect: Some(Arc::new(ctx)),
        };
        let out = walk(root, "root", &wcfg, &Progress::default()).expect("not cancelled");
        Scan {
            root: out.root,
            rules: matcher,
        }
    }

    fn has(n: &TreeNode, p: Protection) -> bool {
        n.protections.iter().any(|x| x == p)
    }

    /// D3: `package.json` sorts after `node_modules`; matching waits for the whole listing.
    #[test]
    fn t4_rules_match_after_the_whole_listing() {
        let fx = fixture();
        let root = fx.path();
        let proj = root.join("proj");
        write_file(&proj.join(r"node_modules\pkg\index.js"), 100);
        write_file(&proj.join("package.json"), 10);
        let s = scan(root, &root.join("home"), 0, vec![]);
        let nm = proj.join("node_modules");
        assert_eq!(s.rule_id(&nm), Some("node-modules"));
        assert_eq!(s.node(&nm).stop, Some(Stop::Bounded));
        assert!(
            s.node(&nm).children.is_empty(),
            "nothing below a stopping rule folder"
        );
        assert_eq!(s.node(&nm).logical, Some(100), "sizes still measured below");
        assert!(!s.has_node(&nm.join("pkg")));
    }

    /// D9: a user-data rule (Downloads) only labels and the walk goes on; a safe rule below it
    /// stops; nothing below that becomes a node, even a rule-shaped folder.
    #[test]
    fn t4_d9_downloads_continues_and_safe_rules_stop() {
        let fx = fixture();
        let root = fx.path();
        let home = root.join("home");
        let dl = home.join("Downloads");
        write_file(&dl.join(r"proj\package.json"), 10);
        write_file(&dl.join(r"proj\node_modules\x\Cargo.toml"), 10);
        write_file(&dl.join(r"proj\node_modules\x\target\a.bin"), 10);
        write_file(&dl.join(r"stuff\a.bin"), 10);
        write_file(&dl.join(r"repo\.git\HEAD"), 10);
        write_file(&dl.join(r"repo\src\main.rs"), 10);
        let s = scan(root, &home, 0, vec![]);
        assert_eq!(s.rule_id(&dl), Some("downloads"));
        assert_eq!(s.node(&dl).stop, None);
        assert_eq!(s.rule_id(&dl.join("stuff")), None);
        let nm = dl.join(r"proj\node_modules");
        assert_eq!(s.rule_id(&nm), Some("node-modules"));
        assert!(!s.has_node(&nm.join(r"x\target")));
        assert!(s.node(&dl.join("repo")).repo_root);
        assert!(s.node(&dl).contains_repo);
        assert!(s.node(&dl.join(r"repo\src")).in_repo);
        assert!(!s.node(&dl.join("stuff")).in_repo);
    }

    /// D9 for user rules: a user-data rule goes on, a safe one stops (without bounding, D12).
    #[test]
    fn t4_user_rules_follow_the_same_stop_rule() {
        let fx = fixture();
        let root = fx.path();
        let home = root.join("home");
        let projects = home.join("Projects");
        write_file(&projects.join(r"a\package.json"), 10);
        write_file(&projects.join(r"a\node_modules\i.js"), 10);
        write_file(&projects.join(r"b\.cache\deep\c.bin"), 10);
        let extra = vec![
            user_rule("p", r"%USERPROFILE%\Projects", Grade::UserData),
            user_rule("c", r"**\.cache", Grade::Safe),
        ];
        let s = scan(root, &home, 0, extra);
        assert_eq!(s.rule_id(&projects), Some("p"));
        assert_eq!(s.node(&projects).stop, None);
        assert_eq!(
            s.rule_id(&projects.join(r"a\node_modules")),
            Some("node-modules")
        );
        let cache = projects.join(r"b\.cache");
        assert_eq!(s.rule_id(&cache), Some("c"));
        assert_eq!(s.node(&cache).stop, Some(Stop::Walk));
        assert!(!s.has_node(&cache.join("deep")));
    }

    /// `.git` inside a rule folder is no repository and goes nowhere; the project's own is.
    #[test]
    fn t4_git_inside_a_rule_folder_is_not_a_repo() {
        let fx = fixture();
        let root = fx.path();
        let proj = root.join("proj");
        write_file(&proj.join("package.json"), 10);
        write_file(&proj.join(r"node_modules\dep\.git\HEAD"), 10);
        let s = scan(root, &root.join("home"), 0, vec![]);
        assert!(!s.node(&proj).contains_repo);
        assert!(!s.node(&proj).repo_root);
        assert!(!s.node(&proj.join("node_modules")).repo_root);

        write_file(&proj.join(r".git\HEAD"), 10);
        let s = scan(root, &root.join("home"), 0, vec![]);
        assert!(s.node(&proj).repo_root);
        assert!(s.node(&proj.join("node_modules")).in_repo);
        assert!(s.root.contains_repo);
    }

    /// S2 with the D12 boundary, as `check_item` draws it: credential findings stop at a
    /// built-in stopping folder; other reasons and user rule folders do not stop them.
    #[test]
    fn t4_protection_lifts_with_the_d12_boundary() {
        let fx = fixture();
        let root = fx.path();
        let kdbx = Reason::CredentialFile { name: ".kdbx" };
        write_file(&root.join(r"plain\secrets\db.kdbx"), 10);
        write_file(&root.join(r"js\package.json"), 10);
        write_file(&root.join(r"js\node_modules\pkg\test\db.kdbx"), 10);
        write_file(&root.join(r"both\package.json"), 10);
        write_file(&root.join(r"both\node_modules\db.kdbx"), 10);
        write_file(&root.join(r"both\node_modules\pkg\disk.vhdx"), 10);
        write_file(&root.join(r"user\.cache\db.kdbx"), 10);
        let extra = vec![user_rule("c", r"**\.cache", Grade::Safe)];
        let s = scan(root, &root.join("home"), 0, extra);

        assert!(has(
            s.node(&root.join(r"plain\secrets")),
            Protection::Self_(kdbx.clone())
        ));
        assert!(has(
            s.node(&root.join("plain")),
            Protection::Contains(kdbx.clone())
        ));
        // Bounded by the built-in `node_modules`.
        assert!(has(
            s.node(&root.join(r"js\node_modules")),
            Protection::Contains(kdbx.clone())
        ));
        assert!(s.node(&root.join("js")).protections.is_empty());
        // B1 end to end: the credential stops, the disk goes on.
        let both = s.node(&root.join("both"));
        assert!(has(both, Protection::Contains(Reason::VirtualDisk)));
        assert!(!has(both, Protection::Contains(kdbx.clone())));
        // A user rule folder draws no boundary.
        assert!(has(
            s.node(&root.join("user")),
            Protection::Contains(kdbx.clone())
        ));
        // The scan root holds everything that crossed.
        assert!(has(&s.root, Protection::Contains(kdbx)));
    }

    /// Unreadable folders block their whole ancestry, also across a rule folder.
    #[test]
    fn t4_unreadable_folders_block_upward() {
        let fx = fixture();
        let root = fx.path();
        write_file(&root.join(r"js\package.json"), 10);
        write_file(&root.join(r"js\node_modules\pkg\i.js"), 10);
        write_file(&root.join(r"plain\locked\a.txt"), 10);
        let _a = crate::core::testzone::deny_list(&root.join(r"js\node_modules\pkg"));
        let _b = crate::core::testzone::deny_list(&root.join(r"plain\locked"));
        let s = scan(root, &root.join("home"), 0, vec![]);
        let unreadable = Protection::Contains(Reason::Unreadable);
        assert!(has(
            s.node(&root.join(r"js\node_modules")),
            unreadable.clone()
        ));
        assert!(has(s.node(&root.join("js")), unreadable.clone()));
        assert!(has(s.node(&root.join(r"plain\locked")), unreadable.clone()));
        assert!(has(s.node(&root.join("plain")), unreadable.clone()));
        assert!(has(&s.root, unreadable));
    }

    /// Focused review (required): below a folder holding `node.exe` no rule matches at any
    /// depth, so `C:\nodejs\node_modules\npm\node_modules` is no rule node, and findings there
    /// are not bounded.
    #[test]
    fn t4_node_install_root_matches_no_rules() {
        let fx = fixture();
        let root = fx.path();
        let nodejs = root.join(r"tools\nodejs");
        write_file(&nodejs.join("node.exe"), 10);
        write_file(&nodejs.join(r"node_modules\npm\package.json"), 10);
        write_file(&nodejs.join(r"node_modules\npm\node_modules\x\i.js"), 10);
        write_file(&nodejs.join(r"node_modules\npm\node_modules\y\db.kdbx"), 10);
        let s = scan(root, &root.join("home"), 0, vec![]);
        assert_eq!(s.rule_id(&nodejs.join("node_modules")), None);
        assert_eq!(
            s.rule_id(&nodejs.join(r"node_modules\npm\node_modules")),
            None
        );
        assert!(!s.has_rule_below(&nodejs));
        assert!(has(
            s.node(&nodejs),
            Protection::Contains(Reason::CredentialFile { name: ".kdbx" })
        ));
    }

    fn filetime(t: std::time::SystemTime) -> u64 {
        let d = t.duration_since(std::time::UNIX_EPOCH).unwrap();
        (d.as_secs() + 11_644_473_600) * 10_000_000 + u64::from(d.subsec_nanos()) / 100
    }

    fn set_times(path: &Path, created: std::time::SystemTime, modified: std::time::SystemTime) {
        use std::os::windows::fs::{FileTimesExt, OpenOptionsExt};
        const FILE_WRITE_ATTRIBUTES: u32 = 0x100;
        const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
        let f = fs::OpenOptions::new()
            .access_mode(FILE_WRITE_ATTRIBUTES)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(path)
            .unwrap();
        f.set_times(
            fs::FileTimes::new()
                .set_created(created)
                .set_modified(modified),
        )
        .unwrap();
    }

    /// D10: the touch time is the latest creation or write of the folder and everything in it.
    #[test]
    fn t4_latest_touch_counts_creation_and_folder_times() {
        use std::time::{Duration, SystemTime};
        let old = SystemTime::UNIX_EPOCH + Duration::from_secs(1_577_836_800); // 2020-01-01
        let fx = fixture();
        let root = fx.path();
        // Everything old.
        let a = root.join("old");
        write_file(&a.join("f.txt"), 10);
        set_times(&a.join("f.txt"), old, old);
        set_times(&a, old, old);
        // Written long ago, but created (copied, extracted) just now.
        let b = root.join("copied");
        write_file(&b.join("f.txt"), 10);
        set_times(&b.join("f.txt"), SystemTime::now(), old);
        set_times(&b, old, old);
        // Old files in a folder that was itself just written.
        let c = root.join("touched");
        write_file(&c.join("f.txt"), 10);
        set_times(&c.join("f.txt"), old, old);
        set_times(&c, old, SystemTime::now());
        let recent = filetime(SystemTime::now() - Duration::from_secs(3600));
        let s = scan(root, &root.join("home"), 0, vec![]);
        assert!(s.node(&a).latest_touch < filetime(old + Duration::from_secs(60)));
        assert!(s.node(&b).latest_touch > recent);
        assert!(s.node(&c).latest_touch > recent);
    }

    #[test]
    fn t4_mail_bytes_are_exact() {
        let fx = fixture();
        let root = fx.path();
        write_file(&root.join(r"mail\a.pst"), 3000);
        write_file(&root.join(r"mail\old\b.OST"), 2000);
        write_file(&root.join(r"mail\c.txt"), 500);
        let s = scan(root, &root.join("home"), 0, vec![]);
        assert_eq!(s.node(&root.join("mail")).mail_bytes, 5000);
        assert_eq!(s.root.mail_bytes, 5000);
    }

    /// D3: rule nodes and their ancestors stay in the tree under the size threshold; other
    /// small folders do not.
    #[test]
    fn t4_rule_nodes_and_ancestors_stay_under_the_threshold() {
        let fx = fixture();
        let root = fx.path();
        write_file(&root.join(r"work\g\p1\package.json"), 10);
        write_file(&root.join(r"work\g\p1\node_modules\i.js"), 10);
        write_file(&root.join(r"work\g\p1\src\main.js"), 10);
        write_file(&root.join(r"work\other\x.txt"), 10);
        let s = scan(root, &root.join("home"), 1 << 30, vec![]);
        for p in [r"work", r"work\g", r"work\g\p1", r"work\g\p1\node_modules"] {
            assert!(s.has_node(&root.join(p)), "{p}");
        }
        assert!(!s.has_node(&root.join(r"work\g\p1\src")));
        assert!(!s.has_node(&root.join(r"work\other")));
    }

    /// With rules on but nothing matching, the tree is the M2 tree.
    #[test]
    fn t4_rules_that_match_nothing_leave_the_m2_tree() {
        let fx = fixture();
        let root = fx.path();
        write_file(&root.join(r"big\a.bin"), 3000);
        write_file(&root.join(r"big\sub\b.bin"), 2000);
        write_file(&root.join(r"small\c.bin"), 10);
        write_file(&root.join("top.log"), 10);
        let (m2, _) = walk_only(&cfg(root));
        let s = scan(root, &root.join("home"), KIB, vec![]);
        fn flat(n: &TreeNode, out: &mut Vec<(String, Option<u64>, usize)>) {
            out.push((
                n.path.to_string_lossy().into_owned(),
                n.logical,
                n.children.len(),
            ));
            for c in &n.children {
                flat(c, out);
            }
        }
        let mut got = Vec::new();
        flat(&s.root, &mut got);
        let want: Vec<_> = m2
            .nodes
            .iter()
            .map(|n| {
                let kids = m2
                    .nodes
                    .iter()
                    .filter(|c| c.parent_id == Some(n.id))
                    .count();
                (n.path.clone(), n.logical_bytes, kids)
            })
            .collect();
        got.sort();
        let mut want = want;
        want.sort();
        // The M2 flattening names the root by its display string; compare the rest.
        assert_eq!(got[1..], want[1..]);
    }
}
