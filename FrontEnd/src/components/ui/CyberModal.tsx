import React, { useEffect } from "react"
import { X } from "lucide-react"

export interface CyberModalProps {
  isOpen: boolean
  onClose: () => void
  title: React.ReactNode
  subtitle?: React.ReactNode
  children: React.ReactNode
  maxWidth?: "sm" | "md" | "lg" | "xl" | "2xl"
  footer?: React.ReactNode
}

export function CyberModal({
  isOpen,
  onClose,
  title,
  subtitle,
  children,
  maxWidth = "lg",
  footer,
}: CyberModalProps) {
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

  const maxWClass = {
    sm: "max-w-sm",
    md: "max-w-md",
    lg: "max-w-lg",
    xl: "max-w-2xl",
    "2xl": "max-w-4xl",
  }[maxWidth]

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      {/* Backdrop */}
      <div
        className="fixed inset-0 bg-black/75 backdrop-blur-xs transition-opacity animate-in fade-in duration-200"
        onClick={onClose}
        aria-hidden="true"
      />

      {/* Modal Dialog */}
      <div
        className={`relative w-full ${maxWClass} bg-surface border border-border-hi shadow-2xl rounded-lg overflow-hidden z-10 animate-in zoom-in-95 duration-200`}
        role="dialog"
        aria-modal="true"
      >
        {/* Header */}
        <header className="px-5 py-4 border-b border-border bg-[#0a0f19] flex items-center justify-between gap-4">
          <div className="min-w-0">
            {typeof title === "string" ? (
              <h2 className="text-sm font-semibold uppercase tracking-wider text-ink font-mono">
                {title}
              </h2>
            ) : (
              title
            )}
            {subtitle && (
              <p className="text-xs text-ink-3 mt-0.5 font-mono truncate">{subtitle}</p>
            )}
          </div>

          <button
            onClick={onClose}
            aria-label="Close Modal"
            className="p-1 rounded text-ink-3 hover:text-ink hover:bg-elevated transition-colors cursor-pointer shrink-0"
          >
            <X size={16} />
          </button>
        </header>

        {/* Body */}
        <div className="p-5 overflow-y-auto max-h-[75vh]">{children}</div>

        {/* Footer */}
        {footer && (
          <footer className="px-5 py-3 border-t border-border bg-[#0a0f19] flex items-center justify-end gap-2.5">
            {footer}
          </footer>
        )}
      </div>
    </div>
  )
}

export default CyberModal
