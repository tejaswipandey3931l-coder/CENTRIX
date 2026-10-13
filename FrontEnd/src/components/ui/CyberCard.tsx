import type { ReactNode, HTMLAttributes } from "react"

export interface CyberCardProps extends Omit<HTMLAttributes<HTMLDivElement>, "title"> {
  title?: ReactNode
  subtitle?: ReactNode
  icon?: ReactNode
  action?: ReactNode
  hudCorners?: boolean
  scanline?: boolean
  noPadding?: boolean
  glow?: "cyan" | "critical" | "none"
}

export function CyberCard({
  children,
  title,
  subtitle,
  icon,
  action,
  hudCorners = false,
  scanline = false,
  noPadding = false,
  glow = "none",
  className = "",
  ...props
}: CyberCardProps) {
  const glowClass = {
    cyan: "glow-cyan-sm border-cyan/40",
    critical: "glow-critical-sm border-critical/40",
    none: "border-border hover:border-border-hi",
  }[glow]

  return (
    <div
      className={`bg-surface border rounded-md transition-colors duration-200 ${glowClass} ${
        hudCorners ? "corner-hud" : ""
      } ${scanline ? "scanline-overlay" : ""} ${className}`}
      {...props}
    >
      {(title || action) && (
        <header className="px-4 py-3 border-b border-border flex items-center justify-between gap-3 min-h-[44px]">
          <div className="flex items-center gap-2.5 min-w-0">
            {icon && <span className="text-blue shrink-0">{icon}</span>}
            <div className="min-w-0">
              {typeof title === "string" ? (
                <h3 className="text-xs font-semibold uppercase tracking-wider text-ink font-mono truncate">
                  {title}
                </h3>
              ) : (
                title
              )}
              {subtitle && (
                <p className="text-[11px] text-ink-3 truncate mt-0.5">{subtitle}</p>
              )}
            </div>
          </div>
          {action && <div className="shrink-0 flex items-center gap-2">{action}</div>}
        </header>
      )}
      <div className={noPadding ? "" : "p-4"}>{children}</div>
    </div>
  )
}

export default CyberCard
