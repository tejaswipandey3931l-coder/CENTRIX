
export interface LoadingStateProps {
  label?: string
  sublabel?: string
  compact?: boolean
  className?: string
}

export function LoadingState({
  label = "LOADING TELEMETRY DATA...",
  sublabel = "Querying CENTRIX backend engine",
  compact = false,
  className = "",
}: LoadingStateProps) {
  return (
    <div
      role="status"
      aria-live="polite"
      className={`w-full rounded-md flex flex-col items-center justify-center text-center font-mono ${
        compact ? "py-6 px-4" : "py-16 px-6"
      } ${className}`}
    >
      <div className="relative w-10 h-10 mb-4 flex items-center justify-center">
        {/* Outer pulsing ring */}
        <div className="absolute inset-0 rounded-full border border-blue/30 animate-ping opacity-25" />
        {/* Spinning indicator */}
        <div className="w-10 h-10 rounded-full border-2 border-border border-t-blue animate-spin" />
        {/* Inner dot */}
        <div className="w-2 h-2 rounded-full bg-blue" />
      </div>

      <div className="text-xs font-bold text-ink uppercase tracking-wider">
        {label}
      </div>

      {sublabel && (
        <div className="text-[11px] text-ink-3 mt-1 font-sans">
          {sublabel}
        </div>
      )}
    </div>
  )
}

export default LoadingState
