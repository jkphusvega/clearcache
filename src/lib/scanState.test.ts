import { describe, expect, it } from "vitest";
import type { FlatNode, ScanResult } from "../types";
import { applyEvent } from "./scanState";

function result(): ScanResult {
  const n = (id: number, accounting: FlatNode["accounting"]): FlatNode => ({
    id,
    parent_id: id === 0 ? null : 0,
    path: `p${id}`,
    name: `n${id}`,
    logical_bytes: 100,
    files: 1,
    exclusive_bytes: null,
    shared_bytes: null,
    unverified_files: 0,
    accounting,
    partial: false,
    skipped_descendants: 0,
    top_exts: [],
    last_modified: null,
    tag: null,
    is_file: false,
    is_link: false,
    in_sync_root: false,
    read_only_volume: false,
  });
  return {
    summary: { accounting_status: "running", accounting_ms: null } as ScanResult["summary"],
    nodes: [n(0, "none"), n(1, "pending"), n(2, "pending")],
    skipped: [],
  };
}

describe("applyEvent", () => {
  it("fills a node by id and marks it done", () => {
    const r = applyEvent(result(), {
      kind: "accounting",
      node_id: 1,
      exclusive_bytes: 7,
      shared_bytes: 3,
      unverified_files: 1,
      logical_bytes: 120,
    });
    expect(r.nodes[1]).toMatchObject({ exclusive_bytes: 7, shared_bytes: 3, unverified_files: 1, logical_bytes: 120, accounting: "done" });
    expect(r.nodes[2].accounting).toBe("pending");
  });

  it("cancel turns remaining pending nodes into cancelled, keeps finished ones", () => {
    let r = applyEvent(result(), { kind: "accounting", node_id: 1, exclusive_bytes: 7, shared_bytes: 0, unverified_files: 0, logical_bytes: 100 });
    r = applyEvent(r, { kind: "accounting_done", completed: false, accounting_ms: 9 });
    expect(r.nodes.map((n) => n.accounting)).toEqual(["none", "done", "cancelled"]);
    expect(r.summary.accounting_status).toBe("cancelled");
    expect(r.summary.accounting_ms).toBe(9);
  });

  it("ignores unknown node ids", () => {
    const before = result();
    expect(applyEvent(before, { kind: "accounting", node_id: 99, exclusive_bytes: 1, shared_bytes: 0, unverified_files: 0, logical_bytes: 1 })).toBe(before);
  });
});
