export type SeverityType = "Critical" | "High" | "Medium" | "Low" | "Info" | string

interface SeverityBadgeProps {
  severity: SeverityType
  cvss?: number | null
  showDot?: boolean
  size?: "sm" | "md"
  className?: string
}

export function SeverityBadge({
  severity,
  cvss,
  showDot = true,
  size = "sm",
  className = "",
}: SeverityBadgeProps) {
  const norm = (severity || "Info").toLowerCase()

  const config = (() => {
    switch (norm) {
      case "critical":
        return {
          bg: "bg-critical/15 text-critical border-critical/30",
          dot: "bg-critical animate-pulse",
          label: "CRITICAL",
        }
      case "high":
        return {
          bg: "bg-high/15 text-high border-high/30",
          dot: "bg-high",
          label: "HIGH",
        }
      case "medium":
        return {
          bg: "bg-medium/15 text-medium border-medium/30",
          dot: "bg-medium",
          label: "MEDIUM",
        }
      case "low":
        return {
          bg: "bg-low/15 text-low border-low/30",
          dot: "bg-low",
          label: "LOW",
        }
      default:
        return {
          bg: "bg-info/15 text-info border-info/30",
          dot: "bg-info",
          label: "INFO",
        }
    }
  })()

  const sizeClass = size === "sm" ? "text-[10px] px-1.5 py-0.5" : "text-xs px-2 py-0.5"

  return (
    <span
      className={`inline-flex items-center gap-1.5 font-mono font-semibold border rounded-sm tracking-wider uppercase ${config.bg} ${sizeClass} ${className}`}
    >
      {showDot && <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${config.dot}`} />}
      <span>{config.label}</span>
      {cvss != null && cvss > 0 && (
        <span className="opacity-75 font-normal pl-0.5 border-l border-current/30 text-[9px]">
          {cvss.toFixed(1)}
        </span>
      )}
    </span>
  )
}

export default SeverityBadge
