import React, { useEffect } from "react"
import { X } from "lucide-react"

export interface CyberDrawerProps {
  isOpen: boolean
  onClose: () => void
  title: React.ReactNode
  subtitle?: React.ReactNode
  badge?: React.ReactNode
  children: React.ReactNode
  width?: "md" | "lg" | "xl" | "2xl"
  footer?: React.ReactNode
}

export function CyberDrawer({
  isOpen,
  onClose,
  title,
  subtitle,
  badge,
  children,
  width = "xl",
  footer,
}: CyberDrawerProps) {
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape" && isOpen) {
        onClose()
      }
    }
    window.addEventListener("keydown", handleKeyDown)
    return () => window.removeEventListener("keydown", handleKeyDown)
  }, [isOpen, onClose])

  if (!isOpen) return null

  const widthClass = {
    md: "max-w-md",
    lg: "max-w-lg",
    xl: "max-w-2xl",
    "2xl": "max-w-4xl",
  }[width]

  return (
    <div className="fixed inset-0 z-50 flex justify-end">
      {/* Backdrop */}
      <div
        className="fixed inset-0 bg-black/70 backdrop-blur-xs transition-opacity animate-in fade-in duration-200"
        onClick={onClose}
        aria-hidden="true"
      />

      {/* Drawer Body */}
      <aside
        className={`relative w-full ${widthClass} h-full bg-surface border-l border-border shadow-2xl flex flex-col z-10 animate-in slide-in-from-right duration-250 ease-out`}
        role="dialog"
        aria-modal="true"
      >
        {/* Header */}
        <header className="px-6 py-4 border-b border-border bg-[#0a0f19] flex items-start justify-between gap-4">
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2.5 flex-wrap">
              {typeof title === "string" ? (
                <h2 className="text-sm font-semibold uppercase tracking-wider text-ink font-mono">
                  {title}
                </h2>
              ) : (
                title
              )}
              {badge}
            </div>
            {subtitle && (
              <p className="text-xs text-ink-3 mt-1 font-mono truncate">{subtitle}</p>
            )}
          </div>

          <button
            onClick={onClose}
            aria-label="Close Drawer"
            className="p-1 rounded text-ink-3 hover:text-ink hover:bg-elevated transition-colors cursor-pointer shrink-0"
          >
            <X size={16} />
          </button>
        </header>

        {/* Scrollable Content */}
        <div className="flex-1 overflow-y-auto p-6">{children}</div>

        {/* Optional Footer */}
        {footer && (
          <footer className="px-6 py-3 border-t border-border bg-[#0a0f19] flex items-center justify-end gap-3">
            {footer}
          </footer>
        )}
      </aside>
    </div>
  )
}

export default CyberDrawer
