import React from "react"

export interface StatWidgetProps {
  label: string
  value: string | number
  sublabel?: string
  icon?: React.ReactNode
  accent?: "cyan" | "critical" | "high" | "medium" | "emerald" | "violet" | "default"
  trend?: {
    text: string
    direction?: "up" | "down" | "neutral"
    status?: "good" | "bad" | "neutral"
  }
  progress?: number // 0 - 100
  className?: string
  onClick?: () => void
}

export function StatWidget({
  label,
  value,
  sublabel,
  icon,
  accent = "default",
  trend,
  progress,
  className = "",
  onClick,
}: StatWidgetProps) {
  const accentColors = {
    cyan: "text-cyan border-l-cyan",
    critical: "text-critical border-l-critical",
    high: "text-high border-l-high",
    medium: "text-medium border-l-medium",
    emerald: "text-emerald border-l-emerald",
    violet: "text-violet border-l-violet",
    default: "text-ink border-l-blue",
  }[accent]

  const barColor = {
    cyan: "bg-cyan",
    critical: "bg-critical",
    high: "bg-high",
    medium: "bg-medium",
    emerald: "bg-emerald",
    violet: "bg-violet",
    default: "bg-blue",
  }[accent]

  return (
    <div
      onClick={onClick}
      className={`bg-surface border border-border rounded-md p-4 transition-all duration-150 relative overflow-hidden border-l-2 ${accentColors} ${
        onClick ? "cursor-pointer hover:border-border-hi hover:bg-elevated/40" : ""
      } ${className}`}
    >
      <div className="flex items-start justify-between gap-2">
        <span className="text-[11px] uppercase tracking-wider font-mono text-ink-3">
          {label}
        </span>
        {icon && <span className="opacity-70 text-ink-2 shrink-0">{icon}</span>}
      </div>

      <div className="mt-2 flex items-baseline gap-2">
        <span className="text-2xl lg:text-3xl font-bold tracking-tight font-display text-ink">
          {value}
        </span>
        {trend && (
          <span
            className={`text-[10px] font-mono font-medium px-1.5 py-0.5 rounded-sm ${
              trend.status === "good"
                ? "text-emerald bg-emerald/10 border border-emerald/20"
                : trend.status === "bad"
                  ? "text-critical bg-critical/10 border border-critical/20"
                  : "text-ink-3 bg-canvas border border-border"
            }`}
          >
            {trend.text}
          </span>
        )}
      </div>

      {sublabel && <p className="text-[11px] text-ink-3 mt-1 truncate">{sublabel}</p>}

      {progress != null && (
        <div className="mt-3 w-full h-1 bg-surface rounded-full overflow-hidden">
          <div
            className={`h-full transition-all duration-500 rounded-full ${barColor}`}
            style={{ width: `${Math.min(100, Math.max(0, progress))}%` }}
          />
        </div>
      )}
    </div>
  )
}

export default StatWidget
