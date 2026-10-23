// Applies accounting events to a scan result. Events can arrive before `get_scan_result`
// returns, so the UI buffers them and replays them here; applying one twice is harmless.

import type { AccountingState, ScanEvent, ScanResult } from "../types";

export type ResultEvent = Exclude<ScanEvent, { kind: "progress" }>;

export function applyEvent(result: ScanResult, e: ResultEvent): ScanResult {
  if (e.kind === "accounting") {
    const nodes = result.nodes.slice();
    const n = nodes[e.node_id];
    if (!n) return result;
    nodes[e.node_id] = {
      ...n,
      exclusive_bytes: e.exclusive_bytes,
      shared_bytes: e.shared_bytes,
      unverified_files: e.unverified_files,
      logical_bytes: e.logical_bytes,
      accounting: "done",
    };
    return { ...result, nodes };
  }
  const leftover: AccountingState = e.completed ? "done" : "cancelled";
  return {
    ...result,
    summary: {
      ...result.summary,
      accounting_ms: e.accounting_ms,
      accounting_status: e.completed ? "complete" : "cancelled",
    },
    nodes: result.nodes.map((n) => (n.accounting === "pending" ? { ...n, accounting: leftover } : n)),
  };
}
