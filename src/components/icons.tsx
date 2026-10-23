// Small inline icons (no icon font: CSP allows only 'self').

type IconProps = { className?: string; title: string };

const base = "inline-block h-3.5 w-3.5 shrink-0";

export function LockIcon({ className = "", title }: IconProps) {
  return (
    <svg viewBox="0 0 16 16" className={`${base} ${className}`} fill="currentColor" role="img" aria-label={title}>
      <title>{title}</title>
      <path d="M5 7V5a3 3 0 1 1 6 0v2h.5A1.5 1.5 0 0 1 13 8.5v5A1.5 1.5 0 0 1 11.5 15h-7A1.5 1.5 0 0 1 3 13.5v-5A1.5 1.5 0 0 1 4.5 7H5Zm1.5 0h3V5a1.5 1.5 0 0 0-3 0v2Z" />
    </svg>
  );
}

export function CloudIcon({ className = "", title }: IconProps) {
  return (
    <svg viewBox="0 0 16 16" className={`${base} ${className}`} fill="currentColor" role="img" aria-label={title}>
      <title>{title}</title>
      <path d="M4.5 13A3.5 3.5 0 0 1 4 6.03 4.5 4.5 0 0 1 12.72 7 3 3 0 0 1 12 13H4.5Z" />
    </svg>
  );
}

export function LinkIcon({ className = "", title }: IconProps) {
  return (
    <svg viewBox="0 0 16 16" className={`${base} ${className}`} fill="none" stroke="currentColor" strokeWidth="1.6" role="img" aria-label={title}>
      <title>{title}</title>
      <path d="M6.5 9.5l3-3M7 4.5l1-1a2.8 2.8 0 0 1 4 4l-1 1M9 11.5l-1 1a2.8 2.8 0 0 1-4-4l1-1" strokeLinecap="round" />
    </svg>
  );
}

export function Chevron({ open }: { open: boolean }) {
  return (
    <svg viewBox="0 0 16 16" className={`h-3 w-3 transition-transform ${open ? "rotate-90" : ""}`} fill="currentColor" aria-hidden>
      <path d="M6 3.5 10.5 8 6 12.5V3.5Z" />
    </svg>
  );
}
