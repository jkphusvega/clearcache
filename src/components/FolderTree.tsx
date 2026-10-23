import { useMemo } from "react";
import type { FlatNode } from "../types";
import { formatBytes, formatDate } from "../lib/format";
import { sizeLabel } from "../lib/sizeLabel";
import { visibleRows } from "../lib/sortTree";
import { Chevron, CloudIcon, LinkIcon, LockIcon } from "./icons";

interface Props {
  nodes: FlatNode[];
  expanded: ReadonlySet<number>;
  onToggle: (id: number) => void;
}

const SIZE_TONE: Record<string, string> = {
  reclaimable: "text-emerald-700",
  max_unverified: "text-slate-800",
  occupies: "text-slate-600",
  calculating: "text-slate-800",
  cancelled: "text-slate-800",
  unmeasured: "text-slate-400",
};

function SizeCell({ node }: { node: FlatNode }) {
  const l = sizeLabel(node);
  return (
    <div title={l.tooltip}>
      <div className={`font-medium tabular-nums ${SIZE_TONE[l.kind]}`}>{l.text}</div>
      {l.detail && (
        <div className={`text-xs ${l.kind === "calculating" ? "animate-pulse text-sky-700" : "text-slate-500"}`}>{l.detail}</div>
      )}
      {l.partial && <div className="text-xs text-amber-700">{l.partial}</div>}
    </div>
  );
}

function TopExts({ node }: { node: FlatNode }) {
  if (node.top_exts.length === 0) return <span className="text-slate-400">—</span>;
  return (
    <div className="flex flex-wrap gap-1">
      {node.top_exts.map((e) => (
        <span key={e.ext} className="rounded bg-slate-100 px-1 py-px text-[11px] text-slate-600" title={formatBytes(e.bytes)}>
          {e.ext}
        </span>
      ))}
    </div>
  );
}

export function FolderTree({ nodes, expanded, onToggle }: Props) {
  const rows = useMemo(() => visibleRows(nodes, expanded), [nodes, expanded]);

  return (
    <table className="w-full table-fixed text-left text-sm">
      <thead className="sticky top-0 z-10 bg-slate-100 text-xs font-medium text-slate-600">
        <tr>
          <th className="w-9 px-3 py-2">
            <input type="checkbox" disabled aria-label="전체 선택 (M3부터)" />
          </th>
          <th className="w-[26%] px-3 py-2">이름</th>
          <th className="px-3 py-2">경로</th>
          <th className="w-[19%] px-3 py-2">크기</th>
          <th className="w-[12%] px-3 py-2">확장자 상위 5</th>
          <th className="w-24 px-3 py-2">수정일</th>
          <th className="w-14 px-3 py-2">등급</th>
          <th className="w-14 px-3 py-2">근거</th>
          <th className="w-14 px-3 py-2">출처</th>
        </tr>
      </thead>
      <tbody>
        {rows.map(({ node, depth, hasChildren }) => {
          const open = expanded.has(node.id);
          const system = node.tag != null;
          return (
            <tr key={node.id} className="border-t border-slate-100 align-top hover:bg-slate-50">
              <td className="px-3 py-2">
                <input type="checkbox" disabled aria-label={`${node.name} 선택 (M3부터)`} />
              </td>
              <td className="px-3 py-2">
                <div className="flex min-w-0 items-center gap-1.5" style={{ paddingLeft: depth * 14 }}>
                  {hasChildren ? (
                    <button
                      type="button"
                      className="rounded p-0.5 text-slate-500 hover:bg-slate-200"
                      onClick={() => onToggle(node.id)}
                      aria-label={open ? "접기" : "펼치기"}
                      aria-expanded={open}
                    >
                      <Chevron open={open} />
                    </button>
                  ) : (
                    <span className="w-4 shrink-0" />
                  )}
                  <span className="truncate" title={node.name}>
                    {node.name}
                  </span>
                  {system && <LockIcon className="text-slate-400" title="시스템 항목 (보호됨)" />}
                  {node.is_link && <LinkIcon className="text-slate-400" title="링크 (따라가지 않음)" />}
                  {node.in_sync_root && <CloudIcon className="text-sky-500" title="클라우드 동기화 폴더 안" />}
                  {depth === 0 && node.read_only_volume && (
                    <span className="shrink-0 rounded bg-slate-200 px-1.5 text-[11px] text-slate-600">보기 전용</span>
                  )}
                </div>
              </td>
              <td className="truncate px-3 py-2 text-xs text-slate-500" title={node.path}>
                {node.path}
              </td>
              <td className="px-3 py-2">
                <SizeCell node={node} />
              </td>
              <td className="px-3 py-2">
                <TopExts node={node} />
              </td>
              <td className="px-3 py-2 text-xs tabular-nums text-slate-500">{formatDate(node.last_modified)}</td>
              <td className="px-3 py-2 text-slate-400">—</td>
              <td className="px-3 py-2 text-slate-400">—</td>
              <td className="px-3 py-2 text-slate-400">—</td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}
