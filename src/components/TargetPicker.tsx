import type { ScanTarget } from "../types";
import { formatBytes } from "../lib/format";

interface Props {
  targets: ScanTarget[];
  selected: string;
  disabled: boolean;
  onSelect: (id: string) => void;
}

function capacity(t: ScanTarget): string {
  if (t.total_bytes == null || t.free_bytes == null) return t.root_display;
  const used = t.total_bytes - t.free_bytes;
  return `${t.fs ?? ""} · ${formatBytes(used)} / ${formatBytes(t.total_bytes)} 사용${t.removable ? " · 이동식" : ""}`;
}

export function TargetPicker({ targets, selected, disabled, onSelect }: Props) {
  const current = targets.find((t) => t.id === selected);
  const usedRatio =
    current?.total_bytes && current.free_bytes != null ? (current.total_bytes - current.free_bytes) / current.total_bytes : null;

  return (
    <div className="flex min-w-0 items-center gap-3">
      <label className="sr-only" htmlFor="target">
        스캔 대상
      </label>
      <select
        id="target"
        className="rounded-md border border-slate-300 bg-white px-2.5 py-1.5 text-sm shadow-sm disabled:bg-slate-100 disabled:text-slate-400"
        value={selected}
        disabled={disabled || targets.length === 0}
        onChange={(e) => onSelect(e.target.value)}
      >
        {targets.map((t) => (
          <option key={t.id} value={t.id}>
            {t.label}
          </option>
        ))}
      </select>
      {current && (
        <div className="min-w-0 text-xs text-slate-500">
          <div className="truncate">{capacity(current)}</div>
          {usedRatio != null && (
            <div className="mt-1 h-1.5 w-40 overflow-hidden rounded-full bg-slate-200">
              <div className="h-full rounded-full bg-slate-500" style={{ width: `${Math.round(usedRatio * 100)}%` }} />
            </div>
          )}
        </div>
      )}
    </div>
  );
}
