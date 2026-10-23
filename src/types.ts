// Mirrors the serde output of src-tauri/src/core (scan/mod.rs, targets.rs, commands.rs).
// Change both sides together.

export type TargetKind = "user_home" | "drive";

export interface ScanTarget {
  id: string;
  kind: TargetKind;
  label: string;
  root_display: string;
  fs: string | null;
  total_bytes: number | null;
  free_bytes: number | null;
  removable: boolean;
}

export type AccountingState = "none" | "pending" | "done" | "cancelled" | "unverified";
export type PhaseStatus = "running" | "complete" | "cancelled" | "not_needed";

export interface ExtBytes {
  ext: string;
  bytes: number;
}

export interface FlatNode {
  id: number;
  parent_id: number | null;
  path: string;
  name: string;
  /** null = not measured (e.g. "기타 Windows", ProgramData). */
  logical_bytes: number | null;
  files: number | null;
  exclusive_bytes: number | null;
  shared_bytes: number | null;
  unverified_files: number;
  accounting: AccountingState;
  partial: boolean;
  skipped_descendants: number;
  top_exts: ExtBytes[];
  /** Unix seconds. */
  last_modified: number | null;
  tag: "system" | "system_apps" | null;
  is_file: boolean;
  is_link: boolean;
  in_sync_root: boolean;
  read_only_volume: boolean;
}

export interface SourceResult {
  source: string;
  found: number;
  error: string | null;
}

export interface SyncRootDetection {
  sources: SourceResult[];
  roots: string[];
  partial_failure: boolean;
  all_failed: boolean;
}

export interface ScanSummary {
  target_id: string;
  target_kind: TargetKind;
  root_display: string;
  total_logical_bytes: number;
  files: number;
  elapsed_ms: number;
  accounting_ms: number | null;
  accounting_status: PhaseStatus;
  skipped_count: number;
  cloud_only_files: number;
  drive_used_bytes: number | null;
  unaccounted_bytes: number | null;
  sync_root_detection: SyncRootDetection;
  threshold_bytes: number;
}

export interface Skipped {
  path: string;
  reason: string;
}

export interface ScanResult {
  summary: ScanSummary;
  nodes: FlatNode[];
  skipped: Skipped[];
}

export interface ScanProgress {
  files: number;
  bytes: number;
  current: string;
  elapsed_ms: number;
  phase: "walk" | "accounting";
  done: boolean;
}

export interface AccountingUpdate {
  node_id: number;
  exclusive_bytes: number;
  shared_bytes: number;
  unverified_files: number;
  logical_bytes: number;
}

export type ScanEvent =
  | ({ kind: "progress" } & ScanProgress)
  | ({ kind: "accounting" } & AccountingUpdate)
  | { kind: "accounting_done"; completed: boolean; accounting_ms: number };
