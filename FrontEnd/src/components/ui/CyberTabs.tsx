import React from "react"

export interface TabItem {
  id: string
  label: string
  icon?: React.ReactNode
  badge?: string | number
  badgeColor?: "cyan" | "critical" | "emerald" | "default"
}

interface CyberTabsProps {
  tabs: TabItem[]
  activeId: string
  onChange: (id: string) => void
  size?: "sm" | "md"
  className?: string
}

export function CyberTabs({
  tabs,
  activeId,
  onChange,
  size = "sm",
  className = "",
}: CyberTabsProps) {
  const sizeClass = size === "sm" ? "px-3 py-1.5 text-xs" : "px-4 py-2 text-sm"

  return (
    <div
      className={`inline-flex items-center p-0.5 bg-surface border border-border rounded-md gap-1 ${className}`}
      role="tablist"
    >
      {tabs.map((tab) => {
        const isActive = tab.id === activeId
        return (
          <button
            key={tab.id}
            role="tab"
            aria-selected={isActive}
            onClick={() => onChange(tab.id)}
            className={`inline-flex items-center gap-2 rounded font-medium transition-all duration-150 select-none cursor-pointer ${sizeClass} ${
              isActive
                ? "bg-elevated text-ink border border-blue/40 font-semibold"
                : "text-ink-3 hover:text-ink-2 hover:bg-panel border border-transparent"
            }`}
          >
            {tab.icon && <span className="shrink-0">{tab.icon}</span>}
            <span>{tab.label}</span>
            {tab.badge != null && (
              <span
                className={`font-mono text-[10px] px-1.5 py-0.2 rounded-sm ${
                  isActive
                    ? "bg-blue/20 text-blue border border-blue/40"
                    : "bg-canvas text-ink-3 border border-border"
                }`}
              >
                {tab.badge}
              </span>
            )}
          </button>
        )
      })}
    </div>
  )
}

export default CyberTabs
