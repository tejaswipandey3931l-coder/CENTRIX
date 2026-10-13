export type ScanStatusType =
  | "running"
  | "pending"
  | "queued"
  | "paused"
  | "completed"
  | "stopped"
  | "error"
  | "failed"
  | "idle"
  | "enabled"
  | string

interface StatusPillProps {
  status: ScanStatusType
  size?: "xs" | "sm" | "md"
  className?: string
}

export function StatusPill({ status, size = "xs", className = "" }: StatusPillProps) {
  const norm = (status || "idle").toLowerCase()

  const { color, pulse, label } = (() => {
    switch (norm) {
      case "running":
        return {
          color: "text-cyan bg-cyan/10 border-cyan/40 shadow-[0_0_8px_rgba(0,240,255,0.2)]",
          pulse: true,
          label: "LIVE SCAN",
        }
      case "completed":
        return {
          color: "text-emerald bg-emerald/10 border-emerald/40",
          pulse: false,
          label: "COMPLETED",
        }
      case "paused":
        return {
          color: "text-medium bg-medium/10 border-medium/40",
          pulse: false,
          label: "PAUSED",
        }
      case "pending":
      case "queued":
        return {
          color: "text-violet bg-violet/10 border-violet/40",
          pulse: true,
          label: "QUEUED",
        }
      case "stopped":
        return {
          color: "text-ink-3 bg-elevated border-border-hi",
          pulse: false,
          label: "STOPPED",
        }
      case "error":
      case "failed":
        return {
          color: "text-critical bg-critical/10 border-critical/40",
          pulse: false,
          label: "FAILED",
        }
      case "enabled":
        return {
          color: "text-emerald bg-emerald/10 border-emerald/40",
          pulse: false,
          label: "ACTIVE",
        }
      case "fixed":
        return {
          color: "text-emerald bg-emerald/10 border-emerald/40",
          pulse: false,
          label: "FIXED",
        }
      case "in review":
      case "in_review":
        return {
          color: "text-cyan bg-cyan/10 border-cyan/40",
          pulse: true,
          label: "IN REVIEW",
        }
      case "still open":
      case "still_open":
        return {
          color: "text-amber-400 bg-amber-500/10 border-amber-500/40 shadow-[0_0_8px_rgba(245,158,11,0.2)]",
          pulse: true,
          label: "STILL OPEN",
        }
      case "needs review":
      case "needs_review":
        return {
          color: "text-violet bg-violet/10 border-violet/40",
          pulse: true,
          label: "NEEDS REVIEW",
        }
      case "accepted":
        return {
          color: "text-ink-2 bg-elevated border-border-hi",
          pulse: false,
          label: "ACCEPTED",
        }
      case "open":
        return {
          color: "text-critical bg-critical/10 border-critical/40",
          pulse: false,
          label: "OPEN",
        }
      default:
        return {
          color: "text-ink-2 bg-panel border-border",
          pulse: false,
          label: status.toUpperCase(),
        }
    }
  })()

  const sizeStyles = {
    xs: "text-[10px] px-2 py-0.5 tracking-wider",
    sm: "text-xs px-2.5 py-1 tracking-wider",
    md: "text-xs px-3 py-1.5 tracking-wider",
  }[size]

  return (
    <span
      className={`inline-flex items-center gap-1.5 font-mono uppercase font-semibold border rounded-sm ${color} ${sizeStyles} ${className}`}
    >
      <span
        className={`w-1.5 h-1.5 rounded-full ${
          norm === "running"
            ? "bg-cyan animate-ping"
            : norm === "completed" || norm === "fixed"
              ? "bg-emerald"
              : norm === "paused"
                ? "bg-medium"
                : norm.includes("still")
                  ? "bg-amber-400"
                  : norm.includes("review")
                    ? "bg-violet"
                    : norm === "error" || norm === "failed" || norm === "open"
                      ? "bg-critical"
                      : "bg-ink-3"
        } ${pulse ? "animate-pulse" : ""}`}
      />
      <span>{label}</span>
    </span>
  )
}

export default StatusPill
