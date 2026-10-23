// Byte and date formatting. Units are 1024-based with Explorer's labels (KB, MB, GB) —
// decided 2026-10-23; DISM's 10⁹ "GB" differs, so tooltips carry the exact byte count.

const UNITS = ["B", "KB", "MB", "GB", "TB"] as const;

export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 1024) {
    return `${Math.max(0, Math.round(bytes || 0))} B`;
  }
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < UNITS.length - 1) {
    value /= 1024;
    unit++;
  }
  // 1 GiB − 1 byte must not print as "1024.0 MB".
  if (Number(value.toFixed(1)) >= 1024 && unit < UNITS.length - 1) {
    value /= 1024;
    unit++;
  }
  return `${value.toFixed(1)} ${UNITS[unit]}`;
}

/** Exact byte count for tooltips, e.g. "20,265,753,644 바이트". Locale-independent grouping. */
export function formatExactBytes(bytes: number): string {
  return `${String(Math.round(bytes)).replace(/\B(?=(\d{3})+(?!\d))/g, ",")} 바이트`;
}

export function formatDate(unixSeconds: number | null): string {
  if (unixSeconds == null) return "—";
  const d = new Date(unixSeconds * 1000);
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
}

export function formatDuration(ms: number): string {
  return ms < 1000 ? `${ms} ms` : `${(ms / 1000).toFixed(1)}초`;
}
