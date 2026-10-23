//! Scan entry point: phase 1 walk → `ScanResult` (shown at once), phase 2 accounting →
//! `AccountingUpdate`s per node (D13).

pub mod attrs;
pub mod policy;
pub mod progress;
pub mod syncroots;
pub mod walk;

use serde::Serialize;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Instant;

use crate::core::accounting::{self, AccountingUpdate, FileOpener, Scope};
use crate::core::paths;
use crate::core::targets::{ScanTarget, TargetKind};
use policy::PolicyContext;
use progress::{Phase, Progress};
use syncroots::SyncRootDetection;
use walk::{Skipped, TreeNode, WalkConfig};

pub const GIB: u64 = 1 << 30;
pub const DEFAULT_THRESHOLD: u64 = GIB;
pub const MAX_DEPTH: usize = 512;
const STACK_BYTES: usize = 8 << 20;
const TOP_EXTS_SHOWN: usize = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountingState {
    /// Not on the allow list: only `logical_bytes` (shown as "최대치(미검증)").
    None,
    /// Allow-listed, result not in yet ("계산 중").
    Pending,
    Done,
    Cancelled,
    /// Skipped for safety: inside a sync root, or sync-root detection failed entirely.
    Unverified,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExtBytes {
    pub ext: String,
    pub bytes: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct FlatNode {
    pub id: u32,
    pub parent_id: Option<u32>,
    pub path: String,
    pub name: String,
    pub logical_bytes: Option<u64>,
    pub files: Option<u64>,
    pub exclusive_bytes: Option<u64>,
    pub shared_bytes: Option<u64>,
    pub unverified_files: u32,
    pub accounting: AccountingState,
    pub partial: bool,
    pub skipped_descendants: u32,
    pub top_exts: Vec<ExtBytes>,
    /// Unix seconds of the newest file below.
    pub last_modified: Option<i64>,
    pub tag: Option<&'static str>,
    pub is_file: bool,
    pub is_link: bool,
    pub in_sync_root: bool,
    pub read_only_volume: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PhaseStatus {
    Running,
    Complete,
    Cancelled,
    /// Accounting had nothing to do.
    NotNeeded,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanSummary {
    pub target_id: String,
    pub target_kind: TargetKind,
    pub root_display: String,
    pub total_logical_bytes: u64,
    pub files: u64,
    pub elapsed_ms: u64,
    pub accounting_ms: Option<u64>,
    pub accounting_status: PhaseStatus,
    pub skipped_count: u64,
    pub cloud_only_files: u64,
    pub drive_used_bytes: Option<u64>,
    pub unaccounted_bytes: Option<u64>,
    pub sync_root_detection: SyncRootDetection,
    pub threshold_bytes: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanResult {
    pub summary: ScanSummary,
    pub nodes: Vec<FlatNode>,
    /// First `walk::SKIPPED_KEEP` entries; the full count is `summary.skipped_count`.
    pub skipped: Vec<Skipped>,
}

/// Everything a scan needs, derived from the target and the environment.
#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub target_id: String,
    pub kind: TargetKind,
    pub root: PathBuf,
    pub root_display: String,
    pub threshold: u64,
    pub max_depth: usize,
    pub policy: PolicyContext,
    pub accounting_roots: Vec<PathBuf>,
    pub user_home: Option<PathBuf>,
    pub read_only_volume: bool,
    pub drive_used_bytes: Option<u64>,
}

impl ScanConfig {
    pub fn for_target(t: &ScanTarget, threshold: u64) -> Self {
        let system_root = paths::env_path("SystemRoot");
        let system_drive = system_root
            .as_deref()
            .and_then(paths::drive_letter)
            .unwrap_or('C');
        let drive = t.drive_letter();
        Self {
            target_id: t.id.clone(),
            kind: t.kind,
            root: t.root.clone(),
            root_display: t.root_display.clone(),
            threshold,
            max_depth: MAX_DEPTH,
            policy: PolicyContext {
                drive_root: (t.kind == TargetKind::Drive).then(|| t.root.clone()),
                system_root: system_root.clone(),
            },
            accounting_roots: default_accounting_roots(system_root.as_deref(), drive),
            user_home: paths::env_path("USERPROFILE"),
            // Only the system drive can be quarantined (same-volume rename); others are view-only.
            read_only_volume: drive != Some(system_drive),
            drive_used_bytes: match (t.kind, t.total_bytes, t.free_bytes) {
                (TargetKind::Drive, Some(total), Some(free)) => Some(total.saturating_sub(free)),
                _ => None,
            },
        }
    }
}

/// M2 allow list for `exclusive_bytes`: WinSxS, uv cache, pnpm store locations.
pub fn default_accounting_roots(
    system_root: Option<&Path>,
    scan_drive: Option<char>,
) -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Some(sr) = system_root {
        roots.push(sr.join("WinSxS"));
    }
    if let Some(lad) = paths::env_path("LOCALAPPDATA") {
        roots.push(lad.join("uv").join("cache"));
        roots.push(lad.join("pnpm").join("store"));
        roots.push(lad.join("pnpm-store"));
    }
    if let Some(home) = paths::env_path("USERPROFILE") {
        roots.push(home.join(".pnpm-store"));
    }
    if let Some(d) = scan_drive {
        roots.push(PathBuf::from(format!(r"{d}:\.pnpm-store")));
    }
    roots
}

/// `max(0, used − scanned)`: hard links inflate the scanned total, so it is an approximation (D15).
pub fn unaccounted_bytes(drive_used: u64, total_logical: u64) -> u64 {
    drive_used.saturating_sub(total_logical)
}

fn pool() -> &'static rayon::ThreadPool {
    static POOL: OnceLock<rayon::ThreadPool> = OnceLock::new();
    POOL.get_or_init(|| {
        rayon::ThreadPoolBuilder::new()
            .stack_size(STACK_BYTES)
            .thread_name(|i| format!("scan-{i}"))
            .build()
            .expect("scan thread pool")
    })
}

/// What phase 2 needs from phase 1.
#[derive(Debug, Clone)]
pub struct AccountingPlan {
    pub scopes: Vec<Scope>,
    pub max_depth: usize,
}

/// Phase 1. `None` if cancelled.
pub fn walk_phase(
    cfg: &ScanConfig,
    sync: &SyncRootDetection,
    progress: &Progress,
) -> Option<(ScanResult, AccountingPlan)> {
    progress.begin_phase(Phase::Walk);
    let started = Instant::now();
    let wcfg = WalkConfig {
        threshold: cfg.threshold,
        max_depth: cfg.max_depth,
        policy: cfg.policy.clone(),
    };
    let out = pool().install(|| walk::walk(&cfg.root, &cfg.root_display, &wcfg, progress))?;
    let elapsed_ms = started.elapsed().as_millis() as u64;

    let mut nodes = Vec::new();
    flatten(out.root, None, cfg, sync, &mut nodes);
    let plan = plan_accounting(&mut nodes, cfg, sync);
    let root = &nodes[0];
    let total = root.logical_bytes.unwrap_or(0);
    let summary = ScanSummary {
        target_id: cfg.target_id.clone(),
        target_kind: cfg.kind,
        root_display: cfg.root_display.clone(),
        total_logical_bytes: total,
        files: root.files.unwrap_or(0),
        elapsed_ms,
        accounting_ms: None,
        accounting_status: if plan.scopes.is_empty() {
            PhaseStatus::NotNeeded
        } else {
            PhaseStatus::Running
        },
        skipped_count: out.skipped_count,
        cloud_only_files: out.cloud_only_files,
        drive_used_bytes: cfg.drive_used_bytes,
        unaccounted_bytes: cfg.drive_used_bytes.map(|u| unaccounted_bytes(u, total)),
        sync_root_detection: sync.clone(),
        threshold_bytes: cfg.threshold,
    };
    Some((
        ScanResult {
            summary,
            nodes,
            skipped: out.skipped,
        },
        plan,
    ))
}

/// Phase 2. Returns whether it completed (false = cancelled).
pub fn accounting_phase(
    plan: &AccountingPlan,
    opener: &dyn FileOpener,
    sync: &SyncRootDetection,
    progress: &Progress,
    on_update: &mut (dyn FnMut(AccountingUpdate) + Send),
) -> bool {
    progress.begin_phase(Phase::Accounting);
    pool().install(|| {
        accounting::run(
            &plan.scopes,
            opener,
            sync,
            plan.max_depth,
            progress,
            on_update,
        )
    })
}

impl ScanResult {
    pub fn apply(&mut self, u: &AccountingUpdate) {
        if let Some(n) = self.nodes.get_mut(u.node_id as usize) {
            n.exclusive_bytes = Some(u.exclusive_bytes);
            n.shared_bytes = Some(u.shared_bytes);
            n.unverified_files = u.unverified_files;
            n.logical_bytes = Some(u.logical_bytes);
            n.accounting = AccountingState::Done;
        }
    }

    pub fn finish_accounting(&mut self, completed: bool, ms: u64) {
        if self.summary.accounting_status == PhaseStatus::NotNeeded {
            return;
        }
        self.summary.accounting_ms = Some(ms);
        self.summary.accounting_status = if completed {
            PhaseStatus::Complete
        } else {
            PhaseStatus::Cancelled
        };
        if !completed {
            for n in &mut self.nodes {
                if n.accounting == AccountingState::Pending {
                    n.accounting = AccountingState::Cancelled;
                }
            }
        }
    }
}

/// Both phases, synchronously (CLI and tests). Same structs as the Tauri path.
pub fn scan_blocking(
    cfg: &ScanConfig,
    sync: &SyncRootDetection,
    opener: &dyn FileOpener,
    progress: &Progress,
) -> Option<ScanResult> {
    let (mut result, plan) = walk_phase(cfg, sync, progress)?;
    let started = Instant::now();
    let mut updates = Vec::new();
    let completed = accounting_phase(&plan, opener, sync, progress, &mut |u| updates.push(u));
    for u in &updates {
        result.apply(u);
    }
    result.finish_accounting(completed, started.elapsed().as_millis() as u64);
    Some(result)
}

fn filetime_to_unix(ft: u64) -> Option<i64> {
    (ft > 0).then(|| (ft as i64 - 116_444_736_000_000_000) / 10_000_000)
}

/// Pre-order flattening; siblings sorted by size, largest first (unmeasured last, then by name).
fn flatten(
    mut n: TreeNode,
    parent: Option<u32>,
    cfg: &ScanConfig,
    sync: &SyncRootDetection,
    out: &mut Vec<FlatNode>,
) {
    let id = out.len() as u32;
    let mut exts: Vec<_> = n.exts.drain().collect();
    exts.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    exts.truncate(TOP_EXTS_SHOWN);
    out.push(FlatNode {
        id,
        parent_id: parent,
        path: n.path.to_string_lossy().into_owned(),
        name: n.name,
        logical_bytes: n.logical,
        files: n.files,
        exclusive_bytes: None,
        shared_bytes: None,
        unverified_files: 0,
        accounting: AccountingState::None,
        partial: n.skipped_descendants > 0,
        skipped_descendants: n.skipped_descendants,
        top_exts: exts
            .into_iter()
            .map(|(ext, bytes)| ExtBytes { ext, bytes })
            .collect(),
        last_modified: filetime_to_unix(n.latest_mtime),
        tag: n.tag,
        is_file: n.is_file,
        is_link: n.is_link,
        in_sync_root: sync.contains(&n.path),
        read_only_volume: cfg.read_only_volume,
    });
    n.children.sort_by(|a, b| {
        b.logical
            .unwrap_or(0)
            .cmp(&a.logical.unwrap_or(0))
            .then_with(|| a.logical.is_none().cmp(&b.logical.is_none()))
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });
    for c in n.children {
        flatten(c, Some(id), cfg, sync, out);
    }
}

/// Marks allow-listed nodes `Pending` (or `Unverified` when unsafe to open) and groups them
/// into scopes rooted at the topmost allow-listed node.
fn plan_accounting(
    nodes: &mut [FlatNode],
    cfg: &ScanConfig,
    sync: &SyncRootDetection,
) -> AccountingPlan {
    let mut scopes: Vec<Scope> = Vec::new();
    for n in nodes.iter_mut() {
        if n.is_file || n.logical_bytes.is_none() {
            continue;
        }
        let path = PathBuf::from(&n.path);
        if !cfg
            .accounting_roots
            .iter()
            .any(|r| paths::is_within(&path, r))
        {
            continue;
        }
        let blocked = n.in_sync_root
            || (sync.all_failed
                && cfg
                    .user_home
                    .as_deref()
                    .is_some_and(|h| paths::is_within(&path, h)));
        if blocked {
            n.accounting = AccountingState::Unverified;
            continue;
        }
        n.accounting = AccountingState::Pending;
        let id = n.id;
        match scopes.iter_mut().find(|s| paths::is_within(&path, &s.path)) {
            Some(s) => s.nodes.push((id, path)),
            None => scopes.push(Scope {
                node_id: id,
                path: path.clone(),
                nodes: vec![(id, path)],
            }),
        }
    }
    AccountingPlan {
        scopes,
        max_depth: cfg.max_depth,
    }
}

/// One line per scan in `%LOCALAPPDATA%\ClearCache\logs\scan.log`.
pub fn append_scan_log(s: &ScanSummary) {
    use std::io::Write;
    let Some(dir) = paths::env_path("LOCALAPPDATA").map(|p| p.join("ClearCache").join("logs"))
    else {
        return;
    };
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let sync: Vec<String> = s
        .sync_root_detection
        .sources
        .iter()
        .map(|r| match &r.error {
            Some(e) => format!("{}=ERR({})", r.source, e.replace(['\r', '\n'], " ")),
            None => format!("{}={}", r.source, r.found),
        })
        .collect();
    let line = format!(
        "ts={ts} target={} root=\"{}\" bytes={} files={} walk_ms={} accounting={:?} accounting_ms={} skipped={} cloud_only={} sync=[{}]\n",
        s.target_id,
        s.root_display,
        s.total_logical_bytes,
        s.files,
        s.elapsed_ms,
        s.accounting_status,
        s.accounting_ms.map(|m| m.to_string()).unwrap_or_else(|| "-".into()),
        s.skipped_count,
        s.cloud_only_files,
        sync.join(" "),
    );
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join("scan.log"))
    {
        let _ = f.write_all(line.as_bytes());
    }
}

#[cfg(test)]
mod tests;
