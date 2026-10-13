import React from "react"
import { Shield } from "lucide-react"
import { CyberButton } from "./CyberButton"

export interface EmptyStateProps {
  icon?: React.ReactNode
  title: string
  description: string
  actionLabel?: string
  onAction?: () => void
  actionIcon?: React.ReactNode
  secondaryAction?: React.ReactNode
  compact?: boolean
  className?: string
}

export function EmptyState({
  icon,
  title,
  description,
  actionLabel,
  onAction,
  actionIcon,
  secondaryAction,
  compact = false,
  className = "",
}: EmptyStateProps) {
  return (
    <div
      className={`w-full rounded-md border border-border/80 bg-surface/60 flex flex-col items-center justify-center text-center font-mono ${
        compact ? "py-8 px-4" : "py-16 px-6"
      } ${className}`}
    >
      <div className="w-12 h-12 rounded-full bg-elevated border border-border flex items-center justify-center text-blue mb-4">
        {icon || <Shield size={22} className="opacity-80" />}
      </div>

      <h3 className="text-sm font-bold text-ink uppercase tracking-wider mb-1.5 font-display text-base">
        {title}
      </h3>

      <p className="text-xs text-ink-3 max-w-md leading-relaxed mb-6 font-sans">
        {description}
      </p>

      <div className="flex flex-wrap items-center justify-center gap-3">
        {actionLabel && onAction && (
          <CyberButton
            variant="primary"
            size={compact ? "xs" : "sm"}
            hudCorners
            icon={actionIcon}
            onClick={onAction}
          >
            {actionLabel}
          </CyberButton>
        )}
        {secondaryAction}
      </div>
    </div>
  )
}

export default EmptyState
