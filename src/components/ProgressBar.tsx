import type { ScanProgress } from "../types";
import { formatBytes, formatDuration } from "../lib/format";

interface Props {
  progress: ScanProgress | null;
  /** Bytes in use on the drive, when scanning a whole drive: gives the walk a real fraction. */
  expectedBytes: number | null;
}

export function ProgressBar({ progress, expectedBytes }: Props) {
  if (!progress) return null;
  const walking = progress.phase === "walk";
  const fraction = walking && expectedBytes ? Math.min(1, progress.bytes / expectedBytes) : null;

  return (
    <div className="border-b border-slate-200 bg-white px-6 py-2.5 text-xs text-slate-600" aria-live="polite">
      <div className="flex items-baseline justify-between gap-4">
        <span className="font-medium text-slate-800">
          {walking ? "폴더 크기 훑는 중" : "확보량 계산 중"}
        </span>
        <span className="tabular-nums">
          파일 {progress.files.toLocaleString()}개
          {walking && ` · ${formatBytes(progress.bytes)}`} · {formatDuration(progress.elapsed_ms)}
        </span>
      </div>
      <div className="mt-1.5 h-1 overflow-hidden rounded-full bg-slate-200">
        {fraction != null ? (
          <div className="h-full bg-sky-600 transition-[width]" style={{ width: `${Math.round(fraction * 100)}%` }} />
        ) : (
          <div className="h-full w-1/3 animate-pulse rounded-full bg-sky-600" />
        )}
      </div>
      <div className="mt-1 truncate text-slate-400" title={progress.current}>
        {progress.current || " "}
      </div>
    </div>
  );
}
