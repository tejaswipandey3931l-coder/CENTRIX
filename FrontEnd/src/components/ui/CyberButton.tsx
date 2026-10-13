import React from "react"
import { Loader2 } from "lucide-react"

export interface CyberButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: "primary" | "secondary" | "danger" | "outline" | "ghost"
  size?: "xs" | "sm" | "md" | "lg"
  loading?: boolean
  icon?: React.ReactNode
  iconRight?: React.ReactNode
  hudCorners?: boolean
}

export const CyberButton = React.forwardRef<HTMLButtonElement, CyberButtonProps>(
  (
    {
      children,
      variant = "secondary",
      size = "sm",
      loading = false,
      icon,
      iconRight,
      hudCorners = false,
      className = "",
      disabled,
      ...props
    },
    ref,
  ) => {
    const baseStyles =
      "inline-flex items-center justify-center font-medium transition-all duration-150 select-none cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan focus-visible:ring-offset-1 focus-visible:ring-offset-canvas disabled:opacity-40 disabled:cursor-not-allowed disabled:pointer-events-none"

    const sizeStyles = {
      xs: "text-[11px] px-2.5 py-1 gap-1.5 rounded-sm font-mono tracking-wider",
      sm: "text-xs px-3 py-1.5 gap-2 rounded",
      md: "text-sm px-4 py-2 gap-2.5 rounded",
      lg: "text-sm px-5 py-2.5 gap-3 rounded-md font-semibold",
    }[size]

    const variantStyles = {
      primary:
        "bg-primary-blue text-white font-semibold hover:bg-blue hover:shadow-[0_0_12px_rgba(37,99,235,0.35)] border border-blue active:translate-y-px",
      secondary:
        "bg-elevated hover:bg-[#1f2c44] text-ink border border-border hover:border-border-hi active:translate-y-px",
      danger:
        "bg-critical/15 text-critical border border-critical/40 hover:bg-critical/25 hover:border-critical/60 hover:shadow-[0_0_10px_rgba(244,63,94,0.25)] active:translate-y-px",
      outline:
        "bg-transparent text-blue border border-border-hi hover:border-blue hover:bg-blue/10 active:translate-y-px",
      ghost:
        "bg-transparent text-ink-2 hover:text-ink hover:bg-elevated/70 border border-transparent active:translate-y-px",
    }[variant]

    return (
      <button
        ref={ref}
        disabled={disabled || loading}
        className={`${baseStyles} ${sizeStyles} ${variantStyles} ${hudCorners ? "corner-hud" : ""} ${className}`}
        {...props}
      >
        {loading ? (
          <Loader2 size={size === "xs" ? 12 : 14} className="animate-spin text-current" />
        ) : (
          icon && <span className="shrink-0">{icon}</span>
        )}
        {children}
        {!loading && iconRight && <span className="shrink-0">{iconRight}</span>}
      </button>
    )
  },
)

CyberButton.displayName = "CyberButton"
export default CyberButton
