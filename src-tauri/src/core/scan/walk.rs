//! Phase 1: `read_dir` + rayon parallel recursion. Sizes come from the directory listing
//! (`DirEntry::metadata` on Windows reads the find data), so no file is ever opened here.
//!
//! M3 (D3): each listing is read to the end before its folders are matched against the rules,
//! so `when` sees every file next to them. A "안전"/"아마 안전" rule stops the tree there (D9):
//! below it sizes and protection facts are still gathered, but there are no nodes, no rule
//! matching and no `.git`. Protection reasons are collected per folder and lifted to the
//! parent; only a built-in stopping rule folder bounds credential findings (D12).

use rayon::prelude::*;
use serde::Serialize;
use std::collections::HashMap;
use std::ffi::OsString;
use std::fs;
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use super::attrs::{self, EntryKind};
use super::policy::{DirDecision, DirPolicy, PolicyContext, TAG_SYSTEM};
use super::progress::Progress;
use crate::core::paths;
use crate::core::protect::{
    file_protection, CanonPath, ProtectContext, Protection, Protections, Reason, Stop,
};
use crate::core::rules::pattern::{is_install_root, RuleMatcher};

pub const MAX_EXTS: usize = 32;
pub const PARALLEL_DEPTH: usize = 24;
pub const REASON_TOO_DEEP: &str = "너무 깊음";

/// Mail stores counted exactly for the "큰 개인 파일" pin; `exts` keeps only the top 32.
pub const MAIL_EXTS: &[&str] = &[".pst", ".ost"];

#[derive(Debug, Clone, Serialize)]
pub struct Skipped {
    pub path: String,
    pub reason: String,
}

#[derive(Debug, Default)]
pub struct TreeNode {
    pub path: PathBuf,
    pub name: String,
    pub logical: Option<u64>,
    pub files: Option<u64>,
    /// FILETIME (100 ns since 1601) of the newest file below.
    pub latest_mtime: u64,
    pub exts: HashMap<String, u64>,
    pub children: Vec<TreeNode>,
    pub tag: Option<&'static str>,
    pub pinned: bool,
    pub is_file: bool,
    pub is_link: bool,
    pub skipped_descendants: u32,
    /// Index of the most specific rule matching this folder (`RuleMatcher::rule`).
    pub rule: Option<usize>,
    /// Set when this folder's rule stops the walk (D9): nothing below is a node.
    pub stop: Option<Stop>,
    /// Every protection reason, the folder's own and those lifted from below (S2).
    pub protections: Protections,
    /// Holds `.git`. Not looked for at or below a stopping rule folder.
    pub repo_root: bool,
    /// A repository root lies somewhere below.
    pub contains_repo: bool,
    /// A folder above holds `.git`.
    pub in_repo: bool,
    /// FILETIME of the latest creation or write of this folder or anything below (D10).
    pub latest_touch: u64,
    /// Exact bytes of `MAIL_EXTS` files below.
    pub mail_bytes: u64,
    /// A rule node lies at or below, so this node stays in the tree whatever its size (D3).
    pub keeps_rule_node: bool,
}

pub struct WalkConfig {
    pub threshold: u64,
    pub max_depth: usize,
    pub policy: PolicyContext,
    /// `None`: no rule matching (M2 behaviour).
    pub rules: Option<Arc<RuleMatcher>>,
    /// `None`: no path-based protection.
    pub protect: Option<Arc<ProtectContext>>,
}

pub struct WalkOutput {
    pub root: TreeNode,
    pub skipped: Vec<Skipped>,
    pub skipped_count: u64,
    pub cloud_only_files: u64,
}

pub const SKIPPED_KEEP: usize = 1000;

struct Shared<'a> {
    cfg: &'a WalkConfig,
    progress: &'a Progress,
    skipped: Mutex<Vec<Skipped>>,
    skipped_count: AtomicU64,
    cloud_only: AtomicU64,
}

impl Shared<'_> {
    fn skip(&self, path: &Path, reason: impl Into<String>) {
        self.skipped_count.fetch_add(1, Ordering::Relaxed);
        let mut s = self.skipped.lock().unwrap();
        if s.len() < SKIPPED_KEEP {
            s.push(Skipped {
                path: path.to_string_lossy().into_owned(),
                reason: reason.into(),
            });
        }
    }
}

/// What a folder inherits from above.
#[derive(Debug, Clone, Copy, Default)]
struct Above {
    /// This folder is a stopping rule folder or lies below one.
    stopped: bool,
    /// No rule is matched for this folder's children (stopped, or below an install root).
    no_rules: bool,
    in_repo: bool,
    /// max(creation, write) of the folder's own entry in its parent's listing.
    self_touch: u64,
}

/// Returns `None` if cancelled.
pub fn walk(
    root: &Path,
    root_name: &str,
    cfg: &WalkConfig,
    progress: &Progress,
) -> Option<WalkOutput> {
    let shared = Shared {
        cfg,
        progress,
        skipped: Mutex::new(Vec::new()),
        skipped_count: AtomicU64::new(0),
        cloud_only: AtomicU64::new(0),
    };
    let decision = DirDecision {
        policy: DirPolicy::Descend,
        tag: None,
        pinned: true,
    };
    let root = walk_dir(
        &shared,
        root.to_path_buf(),
        root_name.to_string(),
        0,
        &decision,
        None,
        Above::default(),
    );
    if progress.is_cancelled() {
        return None;
    }
    Some(WalkOutput {
        root,
        skipped: shared.skipped.into_inner().unwrap(),
        skipped_count: shared.skipped_count.into_inner(),
        cloud_only_files: shared.cloud_only.into_inner(),
    })
}

fn ext_of(name: &str) -> String {
    match name.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() && !ext.is_empty() && ext.len() <= 16 => {
            format!(".{}", ext.to_lowercase())
        }
        _ => "(없음)".to_string(),
    }
}

fn touch(meta: &fs::Metadata) -> u64 {
    meta.creation_time().max(meta.last_write_time())
}

/// The folder's own protection reasons from its path.
fn own_protections(sh: &Shared, path: &Path) -> Protections {
    sh.cfg
        .protect
        .as_ref()
        .map(|ctx| ctx.path_protections(path))
        .unwrap_or_default()
}

fn unreadable(
    sh: &Shared,
    path: PathBuf,
    name: String,
    decision: &DirDecision,
    tag: Option<&'static str>,
    above: Above,
) -> TreeNode {
    // Its contents are unknown, so something protected could hide there (S2).
    let mut protections = own_protections(sh, &path);
    protections.add(Protection::Contains(Reason::Unreadable));
    TreeNode {
        path,
        name,
        logical: Some(0),
        files: Some(0),
        tag,
        pinned: decision.pinned,
        skipped_descendants: 1,
        protections,
        in_repo: above.in_repo,
        latest_touch: above.self_touch,
        ..Default::default()
    }
}

/// A folder to descend into, with the facts its parent's listing gave about it.
struct Sub {
    path: PathBuf,
    name: String,
    decision: DirDecision,
    touch: u64,
}

fn walk_dir(
    sh: &Shared,
    path: PathBuf,
    name: String,
    depth: usize,
    decision: &DirDecision,
    inherited_tag: Option<&'static str>,
    above: Above,
) -> TreeNode {
    let tag = decision.tag.or(inherited_tag);
    if sh.progress.is_cancelled() {
        return TreeNode {
            path,
            name,
            ..Default::default()
        };
    }
    sh.progress.set_current(&path);

    let read = match fs::read_dir(paths::verbatim(&path)) {
        Ok(r) => r,
        Err(e) => {
            sh.skip(&path, e.to_string());
            return unreadable(sh, path, name, decision, tag, above);
        }
    };

    let measure_only = match &decision.policy {
        DirPolicy::MeasureChildrenOnly { allow } => Some(allow.as_slice()),
        _ => None,
    };

    let mut node = TreeNode {
        path: path.clone(),
        name,
        tag,
        pinned: decision.pinned,
        protections: own_protections(sh, &path),
        in_repo: above.in_repo,
        latest_touch: above.self_touch,
        ..Default::default()
    };
    let in_sync_root = node.protections.self_.contains(&Reason::SyncRoot);
    let (mut logical, mut files) = (0u64, 0u64);
    let mut subdirs: Vec<Sub> = Vec::new();
    let mut file_names: Vec<String> = Vec::new();
    let mut unmeasured_other = false;
    let mut repo_here = false;

    for entry in read {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                sh.skip(&path, e.to_string());
                node.skipped_descendants += 1;
                node.protections
                    .add(Protection::Contains(Reason::Unreadable));
                continue;
            }
        };
        let os_name: OsString = entry.file_name();
        let Ok(meta) = entry.metadata() else {
            sh.skip(&path.join(&os_name), "속성 읽기 실패");
            node.skipped_descendants += 1;
            node.protections
                .add(Protection::Contains(Reason::Unreadable));
            continue;
        };
        let ename = os_name.to_string_lossy().into_owned();
        if !above.stopped && paths::eq_ci(&ename, ".git") {
            // A worktree or submodule has a `.git` file, a normal clone a folder.
            repo_here = true;
        }
        let kind = attrs::classify(meta.file_attributes(), meta.file_type().is_symlink());
        match kind {
            EntryKind::Link => {}
            EntryKind::CloudOnly => {
                sh.cloud_only.fetch_add(1, Ordering::Relaxed);
                if measure_only.is_none() {
                    files += 1;
                }
                file_names.push(ename);
                // Outside every detected sync root a cloud placeholder means an undetected one.
                if !in_sync_root {
                    node.protections.add(Protection::Self_(Reason::CloudFile));
                }
            }
            EntryKind::File => {
                let is_sys_file = sh.cfg.policy.is_system_file(&path, &ename);
                if measure_only.is_some() && !is_sys_file {
                    unmeasured_other = true; // loose files in e.g. C:\Windows fold into "기타"
                    continue;
                }
                let size = meta.len();
                let mtime = meta.last_write_time();
                logical += size;
                files += 1;
                node.latest_mtime = node.latest_mtime.max(mtime);
                node.latest_touch = node.latest_touch.max(touch(&meta));
                let ext = ext_of(&ename);
                if MAIL_EXTS.contains(&ext.as_str()) {
                    node.mail_bytes += size;
                }
                *node.exts.entry(ext).or_default() += size;
                if let Some(r) = file_protection(&ename) {
                    node.protections.add(Protection::Self_(r));
                }
                if is_sys_file {
                    node.children.push(TreeNode {
                        path: path.join(&os_name),
                        name: ename.clone(),
                        logical: Some(size),
                        files: Some(1),
                        latest_mtime: mtime,
                        tag: Some(TAG_SYSTEM),
                        pinned: true,
                        is_file: true,
                        ..Default::default()
                    });
                }
                file_names.push(ename);
            }
            EntryKind::Dir => {
                // Joined to the plain path with the name as listed: `\\?\` is only for the read
                // itself (2nd audit D1), and the name is never re-encoded (A1).
                let child_path = path.join(&os_name);
                if attrs::is_cloud_only(meta.file_attributes()) && !in_sync_root {
                    node.protections.add(Protection::Self_(Reason::CloudFile));
                }
                let d = sh.cfg.policy.decide(&child_path, &ename, measure_only);
                match d.policy {
                    DirPolicy::Skip => {}
                    DirPolicy::Unmeasured { .. } if measure_only.is_some() => {
                        unmeasured_other = true
                    }
                    DirPolicy::Unmeasured { tag: utag } => node.children.push(TreeNode {
                        path: child_path,
                        name: ename,
                        tag: Some(utag),
                        pinned: d.pinned,
                        ..Default::default()
                    }),
                    _ if depth + 1 > sh.cfg.max_depth => {
                        sh.skip(&child_path, REASON_TOO_DEEP);
                        node.skipped_descendants += 1;
                        node.protections
                            .add(Protection::Contains(Reason::Unreadable));
                    }
                    _ => subdirs.push(Sub {
                        path: child_path,
                        name: ename,
                        decision: d,
                        touch: touch(&meta),
                    }),
                }
            }
        }
    }
    sh.progress.add(files, logical);
    node.repo_root = repo_here;

    // Rules are matched now that the whole listing is known (D3): `when` needs the files.
    let rules = sh.cfg.rules.as_deref();
    let no_rules_below = above.no_rules || is_install_root(&file_names);
    let child_above = |rule: Option<usize>| {
        let stop = rule.and_then(|i| rules.and_then(|m| m.rule(i).stop()));
        let stopped = above.stopped || stop.is_some();
        (
            stop,
            Above {
                stopped,
                no_rules: no_rules_below || stopped,
                in_repo: above.in_repo || repo_here,
                self_touch: 0,
            },
        )
    };
    let planned: Vec<(Sub, Option<usize>, Option<Stop>, Above)> = subdirs
        .into_iter()
        .map(|s| {
            let rule = match rules {
                Some(m) if !no_rules_below => {
                    CanonPath::new(&s.path).and_then(|c| m.best_index(&c, &file_names))
                }
                _ => None,
            };
            let (stop, mut a) = child_above(rule);
            a.self_touch = s.touch;
            (s, rule, stop, a)
        })
        .collect();

    // Deep levels recurse sequentially: rayon's join frames per level would exhaust the stack
    // long before MAX_DEPTH, and the shallow levels already give enough parallelism.
    let recurse = |(s, rule, stop, a): (Sub, Option<usize>, Option<Stop>, Above)| {
        let mut child = walk_dir(sh, s.path, s.name, depth + 1, &s.decision, tag, a);
        child.rule = rule;
        child.stop = stop;
        child
    };
    let children: Vec<TreeNode> = if depth < PARALLEL_DEPTH {
        planned.into_par_iter().map(recurse).collect()
    } else {
        planned.into_iter().map(recurse).collect()
    };

    for c in &children {
        logical += c.logical.unwrap_or(0);
        files += c.files.unwrap_or(0);
        node.latest_mtime = node.latest_mtime.max(c.latest_mtime);
        node.latest_touch = node.latest_touch.max(c.latest_touch);
        node.mail_bytes += c.mail_bytes;
        node.skipped_descendants += c.skipped_descendants;
        node.contains_repo |= c.repo_root || c.contains_repo;
        node.keeps_rule_node |= c.rule.is_some() || c.keeps_rule_node;
        node.protections
            .extend(&c.protections.lifted(c.stop == Some(Stop::Bounded)));
        for (k, v) in &c.exts {
            *node.exts.entry(k.clone()).or_default() += v;
        }
    }
    let threshold = sh.cfg.threshold;
    if above.stopped || node.stop.is_some() {
        // Inside a stopping rule folder: sizes and facts only, no nodes (D9).
        node.keeps_rule_node = false;
    } else {
        node.children.extend(children.into_iter().filter(|c| {
            c.pinned || c.logical.unwrap_or(0) >= threshold || c.rule.is_some() || c.keeps_rule_node
        }));
    }
    if unmeasured_other {
        let other_name = if sh
            .cfg
            .policy
            .system_root
            .as_deref()
            .is_some_and(|sr| paths::same_path(sr, &path))
        {
            "기타 Windows"
        } else {
            "기타 (측정 안 함)"
        };
        node.children.push(TreeNode {
            path: path.clone(),
            name: other_name.to_string(),
            tag: Some(TAG_SYSTEM),
            pinned: true,
            ..Default::default()
        });
    }
    node.logical = Some(logical);
    node.files = Some(files);
    trim_exts(&mut node.exts, MAX_EXTS);
    node
}

fn trim_exts(exts: &mut HashMap<String, u64>, keep: usize) {
    if exts.len() <= keep {
        return;
    }
    let mut v: Vec<_> = exts.drain().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    v.truncate(keep);
    exts.extend(v);
}
