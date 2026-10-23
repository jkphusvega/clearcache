import type { ScanSummary } from "../types";
import { formatBytes, formatDuration } from "../lib/format";

const UNACCOUNTED_TOOLTIP =
  "드라이브 사용량에서 스캔 합계를 뺀 근사치입니다. 측정하지 않은 시스템 폴더(기타 Windows, ProgramData 등), " +
  "읽지 못한 폴더, 루트 시스템 파일 일부가 여기에 들어갑니다. 하드링크 파일은 스캔 합계에 여러 번 들어가므로 실제보다 작게 보일 수 있습니다.";

function Item({ label, children, title }: { label: string; children: React.ReactNode; title?: string }) {
  return (
    <div title={title}>
      <span className="text-slate-400">{label} </span>
      <span className="tabular-nums text-slate-700">{children}</span>
    </div>
  );
}

export function Summary({ summary }: { summary: ScanSummary }) {
  const accounting =
    summary.accounting_status === "running"
      ? "계산 중"
      : summary.accounting_status === "cancelled"
        ? "취소됨"
        : summary.accounting_ms != null
          ? formatDuration(summary.accounting_ms)
          : null;
  const failedSources = summary.sync_root_detection.sources.filter((s) => s.error);

  return (
    <footer className="border-t border-slate-200 bg-white px-6 py-2.5 text-xs">
      {summary.sync_root_detection.partial_failure && (
        <div
          className="mb-2 rounded border border-amber-300 bg-amber-50 px-2.5 py-1.5 text-amber-800"
          title={failedSources.map((s) => `${s.source}: ${s.error}`).join("\n")}
        >
          동기화 폴더 감지 일부 실패
          {summary.sync_root_detection.all_failed &&
            " — 사용자 폴더 안의 확보량은 계산하지 않고 '미검증'으로 둡니다."}
        </div>
      )}
      <div className="flex flex-wrap gap-x-6 gap-y-1">
        <Item label="대상">{summary.root_display}</Item>
        <Item label="합계">{formatBytes(summary.total_logical_bytes)}</Item>
        <Item label="파일">{summary.files.toLocaleString()}개</Item>
        <Item label="걸린 시간">
          {formatDuration(summary.elapsed_ms)}
          {accounting && ` (확보량 ${accounting})`}
        </Item>
        <Item label="건너뜀">{summary.skipped_count.toLocaleString()}개</Item>
        <Item label="제외한 클라우드 파일">{summary.cloud_only_files.toLocaleString()}개</Item>
        {summary.unaccounted_bytes != null && (
          <Item label="스캔되지 않은 용량" title={UNACCOUNTED_TOOLTIP}>
            약 {formatBytes(summary.unaccounted_bytes)} (근사치)
          </Item>
        )}
      </div>
    </footer>
  );
}
