import { describe, expect, it } from "vitest";
import { sizeLabel, UNMEASURED_TOOLTIP } from "./sizeLabel";

const GiB = 1024 ** 3;

const base = {
  logical_bytes: 5 * GiB,
  exclusive_bytes: null,
  shared_bytes: null,
  unverified_files: 0,
  accounting: "none" as const,
  partial: false,
  skipped_descendants: 0,
  tag: null,
};

describe("sizeLabel", () => {
  it("실제 확보: exclusive result with shared part", () => {
    const l = sizeLabel({ ...base, accounting: "done", exclusive_bytes: 3 * GiB, shared_bytes: 2 * GiB });
    expect(l.kind).toBe("reclaimable");
    expect(l.text).toBe("실제 확보 3.0 GB");
    expect(l.detail).toBe("공유 2.0 GB");
  });

  it("실제 확보 with unverified files says so", () => {
    const l = sizeLabel({ ...base, accounting: "done", exclusive_bytes: GiB, shared_bytes: 0, unverified_files: 4 });
    expect(l.detail).toBe("공유 0 B · 일부 미검증 4개");
  });

  it("최대치(미검증): logical only, never called 실제 확보", () => {
    const l = sizeLabel(base);
    expect(l.kind).toBe("max_unverified");
    expect(l.text).toBe("5.0 GB");
    expect(l.detail).toBe("최대치(미검증)");
    expect(l.text).not.toContain("실제 확보");
  });

  it("최대치(미검증) when accounting was skipped for safety", () => {
    const l = sizeLabel({ ...base, accounting: "unverified" });
    expect(l.kind).toBe("max_unverified");
    expect(l.detail).toContain("동기화 폴더");
  });

  it("차지하는 크기: system items", () => {
    const l = sizeLabel({ ...base, tag: "system_apps" });
    expect(l.kind).toBe("occupies");
    expect(l.text).toBe("차지하는 크기 5.0 GB");
  });

  it("차지하는 크기 for WinSxS keeps the neutral wording", () => {
    const l = sizeLabel({ ...base, tag: "system", accounting: "done", exclusive_bytes: 2 * GiB, shared_bytes: 3 * GiB });
    expect(l.kind).toBe("occupies");
    expect(l.detail).toBe("Windows와 공유되지 않는 파일 2.0 GB (전부 확보 가능한 것은 아님)");
    expect(l.text).not.toContain("실제 확보");
  });

  it("계산 중: pending accounting", () => {
    const l = sizeLabel({ ...base, accounting: "pending" });
    expect(l.kind).toBe("calculating");
    expect(l.detail).toBe("확보량 계산 중");
  });

  it("취소됨: cancelled accounting keeps the walk size", () => {
    const l = sizeLabel({ ...base, accounting: "cancelled" });
    expect(l.kind).toBe("cancelled");
    expect(l.text).toBe("5.0 GB");
    expect(l.detail).toBe("확보량 계산 취소됨");
  });

  it("일부만 측정: partial note on top of any kind", () => {
    const l = sizeLabel({ ...base, partial: true, skipped_descendants: 3 });
    expect(l.partial).toBe("일부만 측정 (3개 폴더 읽기 불가)");
    const done = sizeLabel({ ...base, partial: true, skipped_descendants: 1, accounting: "done", exclusive_bytes: 1 });
    expect(done.partial).toBe("일부만 측정 (1개 폴더 읽기 불가)");
    expect(sizeLabel(base).partial).toBeUndefined();
  });

  it("측정 안 함: dash with tooltip", () => {
    const l = sizeLabel({ ...base, logical_bytes: null, tag: "system" });
    expect(l).toEqual({ kind: "unmeasured", text: "—", tooltip: UNMEASURED_TOOLTIP });
  });

  it("hover shows exact bytes for every measured kind", () => {
    const exact = "크기: 5,368,709,120 바이트";
    for (const accounting of ["none", "pending", "cancelled", "unverified"] as const) {
      expect(sizeLabel({ ...base, accounting }).tooltip).toBe(exact);
    }
    expect(sizeLabel({ ...base, tag: "system" }).tooltip).toBe(exact);
  });

  it("hover lists exclusive and shared bytes once accounting is done", () => {
    const l = sizeLabel({ ...base, accounting: "done", exclusive_bytes: 3 * GiB, shared_bytes: 1000 });
    expect(l.tooltip).toBe("크기: 5,368,709,120 바이트\n실제 확보: 3,221,225,472 바이트\n공유: 1,000 바이트");
    const sys = sizeLabel({ ...base, tag: "system", accounting: "done", exclusive_bytes: 10, shared_bytes: 20 });
    expect(sys.tooltip).toBe("크기: 5,368,709,120 바이트\nWindows와 공유되지 않음: 10 바이트\nWindows와 공유됨: 20 바이트");
  });
});
