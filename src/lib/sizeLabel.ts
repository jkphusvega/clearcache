// What the size column says. The honest-number rules live here, not in components:
// only an `exclusive_bytes` result may be called "실제 확보"; everything else is a maximum,
// an occupancy, or a pending/cancelled state (D13, D16, SPEC "4. 메인 화면").

import type { FlatNode } from "../types";
import { formatBytes, formatExactBytes } from "./format";

export type SizeKind =
  | "reclaimable" // exclusive_bytes known
  | "max_unverified" // logical only
  | "occupies" // system item
  | "calculating" // accounting pending
  | "cancelled" // accounting cancelled
  | "unmeasured"; // not measured at all

export interface SizeLabel {
  kind: SizeKind;
  text: string;
  /** Extra line under the main text. */
  detail?: string;
  /** "일부만 측정 (N개 폴더 읽기 불가)" when some sub-folders could not be read. */
  partial?: string;
  tooltip?: string;
}

type SizeInput = Pick<
  FlatNode,
  | "logical_bytes"
  | "exclusive_bytes"
  | "shared_bytes"
  | "unverified_files"
  | "accounting"
  | "partial"
  | "skipped_descendants"
  | "tag"
>;

export const UNMEASURED_TOOLTIP = "측정하지 않음. '스캔되지 않은 용량'에 포함";

export function sizeLabel(n: SizeInput): SizeLabel {
  const partial = n.partial ? `일부만 측정 (${n.skipped_descendants}개 폴더 읽기 불가)` : undefined;

  if (n.logical_bytes == null) {
    return { kind: "unmeasured", text: "—", tooltip: UNMEASURED_TOOLTIP };
  }
  const logical = formatBytes(n.logical_bytes);
  const unverified = n.unverified_files > 0 ? `일부 미검증 ${n.unverified_files}개` : undefined;
  // Hover shows exact bytes: the label is rounded (1024-based "GB"), the tooltip is not.
  const exact = (lines: [string, number | null][]) =>
    lines
      .filter((l): l is [string, number] => l[1] != null)
      .map(([k, v]) => `${k}: ${formatExactBytes(v)}`)
      .join("\n");
  const tooltip = exact([["크기", n.logical_bytes]]);

  if (n.accounting === "pending") {
    return { kind: "calculating", text: logical, detail: "확보량 계산 중", partial, tooltip };
  }
  if (n.accounting === "cancelled") {
    return { kind: "cancelled", text: logical, detail: "확보량 계산 취소됨", partial, tooltip };
  }

  const isSystem = n.tag != null;
  if (n.accounting === "done" && n.exclusive_bytes != null) {
    const shared = formatBytes(n.shared_bytes ?? 0);
    const exclusiveName = isSystem ? "Windows와 공유되지 않음" : "실제 확보";
    const doneTooltip = exact([
      ["크기", n.logical_bytes],
      [exclusiveName, n.exclusive_bytes],
      [isSystem ? "Windows와 공유됨" : "공유", n.shared_bytes ?? 0],
    ]);
    if (isSystem) {
      // WinSxS: neutral wording — "not shared with Windows" is not the same as "removable".
      return {
        kind: "occupies",
        text: `차지하는 크기 ${logical}`,
        detail: [`Windows와 공유되지 않는 파일 ${formatBytes(n.exclusive_bytes)} (전부 확보 가능한 것은 아님)`, unverified]
          .filter(Boolean)
          .join(" · "),
        partial,
        tooltip: doneTooltip,
      };
    }
    return {
      kind: "reclaimable",
      text: `실제 확보 ${formatBytes(n.exclusive_bytes)}`,
      detail: [`공유 ${shared}`, unverified].filter(Boolean).join(" · "),
      partial,
      tooltip: doneTooltip,
    };
  }
  if (isSystem) {
    return { kind: "occupies", text: `차지하는 크기 ${logical}`, partial, tooltip };
  }
  return {
    kind: "max_unverified",
    text: logical,
    detail: n.accounting === "unverified" ? "최대치(미검증) · 동기화 폴더 확인 불가" : "최대치(미검증)",
    partial,
    tooltip,
  };
}
