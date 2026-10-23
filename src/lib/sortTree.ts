// Turns the flat node list into display rows: tree order, siblings by size (largest first),
// unmeasured rows after measured ones, ties by name.

import type { FlatNode } from "../types";

export interface Row {
  node: FlatNode;
  depth: number;
  hasChildren: boolean;
}

type SortInput = Pick<FlatNode, "logical_bytes" | "name">;

export function compareSiblings(a: SortInput, b: SortInput): number {
  const am = a.logical_bytes != null;
  const bm = b.logical_bytes != null;
  if (am !== bm) return am ? -1 : 1;
  if (am && bm && a.logical_bytes !== b.logical_bytes) return b.logical_bytes! - a.logical_bytes!;
  return a.name.localeCompare(b.name, "ko");
}

export function childrenIndex(nodes: FlatNode[]): Map<number | null, FlatNode[]> {
  const byParent = new Map<number | null, FlatNode[]>();
  for (const n of nodes) {
    const list = byParent.get(n.parent_id);
    if (list) list.push(n);
    else byParent.set(n.parent_id, [n]);
  }
  for (const list of byParent.values()) list.sort(compareSiblings);
  return byParent;
}

/** Rows to render. Children of a node appear only if its id is in `expanded`. */
export function visibleRows(nodes: FlatNode[], expanded: ReadonlySet<number>): Row[] {
  const byParent = childrenIndex(nodes);
  const rows: Row[] = [];
  const visit = (n: FlatNode, depth: number) => {
    const kids = byParent.get(n.id) ?? [];
    rows.push({ node: n, depth, hasChildren: kids.length > 0 });
    if (expanded.has(n.id)) for (const k of kids) visit(k, depth + 1);
  };
  for (const root of byParent.get(null) ?? []) visit(root, 0);
  return rows;
}
