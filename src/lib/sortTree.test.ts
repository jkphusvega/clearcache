import { describe, expect, it } from "vitest";
import type { FlatNode } from "../types";
import { compareSiblings, visibleRows } from "./sortTree";

function node(id: number, parent_id: number | null, name: string, logical_bytes: number | null): FlatNode {
  return {
    id,
    parent_id,
    path: name,
    name,
    logical_bytes,
    files: null,
    exclusive_bytes: null,
    shared_bytes: null,
    unverified_files: 0,
    accounting: "none",
    partial: false,
    skipped_descendants: 0,
    top_exts: [],
    last_modified: null,
    tag: null,
    is_file: false,
    is_link: false,
    in_sync_root: false,
    read_only_volume: false,
  };
}

describe("sortTree", () => {
  it("orders siblings by size, largest first", () => {
    const nodes = [node(0, null, "root", 100), node(1, 0, "small", 10), node(2, 0, "big", 80)];
    const rows = visibleRows(nodes, new Set([0]));
    expect(rows.map((r) => r.node.name)).toEqual(["root", "big", "small"]);
    expect(rows.map((r) => r.depth)).toEqual([0, 1, 1]);
  });

  it("puts unmeasured system rows after measured ones", () => {
    const nodes = [
      node(0, null, "C:\\", 100),
      node(1, 0, "ProgramData", null),
      node(2, 0, "Users", 5),
      node(3, 0, "$Recycle.Bin", null),
    ];
    const names = visibleRows(nodes, new Set([0])).map((r) => r.node.name);
    expect(names).toEqual(["C:\\", "Users", "$Recycle.Bin", "ProgramData"]);
  });

  it("breaks size ties by name", () => {
    expect(compareSiblings({ name: "b", logical_bytes: 5 }, { name: "a", logical_bytes: 5 })).toBeGreaterThan(0);
    expect(compareSiblings({ name: "a", logical_bytes: 5 }, { name: "b", logical_bytes: 5 })).toBeLessThan(0);
  });

  it("shows children only for expanded nodes and flags hasChildren", () => {
    const nodes = [node(0, null, "root", 100), node(1, 0, "a", 60), node(2, 1, "a1", 50), node(3, 0, "b", 40)];
    const collapsed = visibleRows(nodes, new Set([0]));
    expect(collapsed.map((r) => r.node.name)).toEqual(["root", "a", "b"]);
    expect(collapsed.find((r) => r.node.name === "a")!.hasChildren).toBe(true);
    expect(collapsed.find((r) => r.node.name === "b")!.hasChildren).toBe(false);
    const open = visibleRows(nodes, new Set([0, 1]));
    expect(open.map((r) => [r.node.name, r.depth])).toEqual([
      ["root", 0],
      ["a", 1],
      ["a1", 2],
      ["b", 1],
    ]);
  });
});
