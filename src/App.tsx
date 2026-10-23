// M2: pick a target, scan, show the ≥1 GB tree. Accounting fills the size column afterwards (D13).
// The UI sends only target ids to Rust; it never holds a path it could send back.
import { useCallback, useEffect, useRef, useState } from "react";
import { Channel, invoke } from "@tauri-apps/api/core";
import type { ScanEvent, ScanProgress, ScanResult, ScanSummary, ScanTarget } from "./types";
import { applyEvent, type ResultEvent } from "./lib/scanState";
import { TargetPicker } from "./components/TargetPicker";
import { ProgressBar } from "./components/ProgressBar";
import { FolderTree } from "./components/FolderTree";
import { Summary } from "./components/Summary";

type Phase = "idle" | "walking" | "accounting" | "done" | "cancelled" | "error";

function App() {
  const [targets, setTargets] = useState<ScanTarget[]>([]);
  const [selected, setSelected] = useState("user_home");
  const [phase, setPhase] = useState<Phase>("idle");
  const [progress, setProgress] = useState<ScanProgress | null>(null);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [expanded, setExpanded] = useState<ReadonlySet<number>>(new Set([0]));
  const [error, setError] = useState<string | null>(null);
  // Result events that arrive before get_scan_result returns.
  const pending = useRef<ResultEvent[] | null>(null);

  useEffect(() => {
    invoke<ScanTarget[]>("list_scan_targets")
      .then(setTargets)
      .catch((e) => setError(String(e)));
  }, []);

  const onEvent = useCallback((e: ScanEvent) => {
    if (e.kind === "progress") {
      setProgress(e);
      return;
    }
    if (pending.current) {
      pending.current.push(e);
      return;
    }
    setResult((r) => (r ? applyEvent(r, e) : r));
    if (e.kind === "accounting_done") {
      setPhase("done");
      setProgress(null);
    }
  }, []);

  const start = async () => {
    setError(null);
    setResult(null);
    setProgress(null);
    setExpanded(new Set([0]));
    setPhase("walking");
    pending.current = [];
    const channel = new Channel<ScanEvent>();
    channel.onmessage = onEvent;
    try {
      const summary = await invoke<ScanSummary>("start_scan", { targetId: selected, onEvent: channel });
      const fetched = await invoke<ScanResult | null>("get_scan_result");
      if (!fetched) throw new Error("스캔 결과를 받지 못했습니다");
      const buffered = pending.current ?? [];
      pending.current = null;
      const merged = buffered.reduce(applyEvent, fetched);
      setResult(merged);
      const accountingOver = merged.summary.accounting_status !== "running";
      setPhase(summary.accounting_status === "running" && !accountingOver ? "accounting" : "done");
      if (accountingOver) setProgress(null);
    } catch (e) {
      pending.current = null;
      const msg = String(e);
      setProgress(null);
      if (msg.includes("cancelled")) {
        setPhase("cancelled");
      } else {
        setPhase("error");
        setError(msg);
      }
    }
  };

  const cancel = () => invoke("cancel_scan");

  const toggle = (id: number) =>
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  const busy = phase === "walking" || phase === "accounting";
  const target = targets.find((t) => t.id === selected);
  const expectedBytes =
    target?.total_bytes != null && target.free_bytes != null ? target.total_bytes - target.free_bytes : null;

  return (
    <div className="flex h-screen flex-col bg-slate-50 text-slate-900">
      <header className="flex items-center justify-between gap-6 border-b border-slate-200 bg-white px-6 py-3">
        <div className="shrink-0">
          <h1 className="text-lg font-semibold tracking-tight">ClearCache</h1>
          <p className="text-xs text-slate-500">큰 폴더를 찾아 지워도 되는지 판정하고, 고른 것만 격리합니다.</p>
        </div>
        <div className="flex min-w-0 items-center gap-3">
          <TargetPicker targets={targets} selected={selected} disabled={busy} onSelect={setSelected} />
          {busy ? (
            <button
              type="button"
              onClick={cancel}
              className="shrink-0 rounded-md border border-slate-300 bg-white px-3.5 py-1.5 text-sm font-medium text-slate-700 hover:bg-slate-100"
            >
              취소
            </button>
          ) : (
            <button
              type="button"
              onClick={start}
              disabled={targets.length === 0}
              className="shrink-0 rounded-md bg-slate-900 px-3.5 py-1.5 text-sm font-medium text-white hover:bg-slate-700 disabled:bg-slate-300"
            >
              스캔
            </button>
          )}
        </div>
      </header>

      {busy && <ProgressBar progress={progress} expectedBytes={phase === "walking" ? expectedBytes : null} />}

      <main className="min-h-0 flex-1 overflow-auto p-6">
        {error && (
          <div className="mb-4 rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-800">{error}</div>
        )}
        <div className="overflow-hidden rounded-lg border border-slate-200 bg-white">
          {result ? (
            <FolderTree nodes={result.nodes} expanded={expanded} onToggle={toggle} />
          ) : (
            <div className="px-3 py-16 text-center text-sm text-slate-400">
              {phase === "walking"
                ? "스캔 중입니다…"
                : phase === "cancelled"
                  ? "스캔을 취소했습니다."
                  : "아직 스캔한 폴더가 없습니다. 대상을 고르고 스캔을 누르세요."}
            </div>
          )}
        </div>
      </main>

      {result && <Summary summary={result.summary} />}
    </div>
  );
}

export default App;
