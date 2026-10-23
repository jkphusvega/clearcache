//! Phase 1: `read_dir` + rayon parallel recursion. Sizes come from the directory listing
//! (`DirEntry::metadata` on Windows reads the find data), so no file is ever opened here.

use rayon::prelude::*;
use serde::Serialize;
use std::collections::HashMap;
use std::fs;
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use super::attrs::{self, EntryKind};
use super::policy::{DirDecision, DirPolicy, PolicyContext, TAG_SYSTEM};
use super::progress::Progress;

pub const MAX_EXTS: usize = 32;
pub const PARALLEL_DEPTH: usize = 24;
pub const REASON_TOO_DEEP: &str = "너무 깊음";

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
}

pub struct WalkConfig {
    pub threshold: u64,
    pub max_depth: usize,
    pub policy: PolicyContext,
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

fn unreadable(
    path: PathBuf,
    name: String,
    decision: &DirDecision,
    tag: Option<&'static str>,
) -> TreeNode {
    TreeNode {
        path,
        name,
        logical: Some(0),
        files: Some(0),
        tag,
        pinned: decision.pinned,
        skipped_descendants: 1,
        ..Default::default()
    }
}

fn walk_dir(
    sh: &Shared,
    path: PathBuf,
    name: String,
    depth: usize,
    decision: &DirDecision,
    inherited_tag: Option<&'static str>,
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

    let read = match fs::read_dir(&path) {
        Ok(r) => r,
        Err(e) => {
            sh.skip(&path, e.to_string());
            return unreadable(path, name, decision, tag);
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
        ..Default::default()
    };
    let (mut logical, mut files) = (0u64, 0u64);
    let mut subdirs: Vec<(PathBuf, String, DirDecision)> = Vec::new();
    let mut unmeasured_other = false;

    for entry in read {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                sh.skip(&path, e.to_string());
                node.skipped_descendants += 1;
                continue;
            }
        };
        let Ok(meta) = entry.metadata() else {
            sh.skip(&entry.path(), "속성 읽기 실패");
            continue;
        };
        let ename = entry.file_name().to_string_lossy().into_owned();
        let kind = attrs::classify(meta.file_attributes(), meta.file_type().is_symlink());
        match kind {
            EntryKind::Link => {}
            EntryKind::CloudOnly => {
                sh.cloud_only.fetch_add(1, Ordering::Relaxed);
                if measure_only.is_none() {
                    files += 1;
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
                *node.exts.entry(ext_of(&ename)).or_default() += size;
                if is_sys_file {
                    node.children.push(TreeNode {
                        path: entry.path(),
                        name: ename,
                        logical: Some(size),
                        files: Some(1),
                        latest_mtime: mtime,
                        tag: Some(TAG_SYSTEM),
                        pinned: true,
                        is_file: true,
                        ..Default::default()
                    });
                }
            }
            EntryKind::Dir => {
                let child_path = entry.path();
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
                    }
                    _ => subdirs.push((child_path, ename, d)),
                }
            }
        }
    }
    sh.progress.add(files, logical);

    // Deep levels recurse sequentially: rayon's join frames per level would exhaust the stack
    // long before MAX_DEPTH, and the shallow levels already give enough parallelism.
    let recurse =
        |(p, n, d): (PathBuf, String, DirDecision)| walk_dir(sh, p, n, depth + 1, &d, tag);
    let children: Vec<TreeNode> = if depth < PARALLEL_DEPTH {
        subdirs.into_par_iter().map(recurse).collect()
    } else {
        subdirs.into_iter().map(recurse).collect()
    };

    for c in &children {
        logical += c.logical.unwrap_or(0);
        files += c.files.unwrap_or(0);
        node.latest_mtime = node.latest_mtime.max(c.latest_mtime);
        node.skipped_descendants += c.skipped_descendants;
        for (k, v) in &c.exts {
            *node.exts.entry(k.clone()).or_default() += v;
        }
    }
    let threshold = sh.cfg.threshold;
    node.children.extend(
        children
            .into_iter()
            .filter(|c| c.pinned || c.logical.unwrap_or(0) >= threshold),
    );
    if unmeasured_other {
        let other_name = if sh
            .cfg
            .policy
            .system_root
            .as_deref()
            .is_some_and(|sr| crate::core::paths::same_path(sr, &path))
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
