import { useState } from "react"
import { AlertTriangle, RefreshCw, ChevronDown, ChevronUp, WifiOff } from "lucide-react"
import { CyberButton } from "./CyberButton"

export interface ErrorStateProps {
  title?: string
  message: string
  details?: string
  onRetry?: () => void
  isOffline?: boolean
  compact?: boolean
  className?: string
}

export function ErrorState({
  title = "Telemetry Error Detected",
  message,
  details,
  onRetry,
  isOffline = false,
  compact = false,
  className = "",
}: ErrorStateProps) {
  const [showDetails, setShowDetails] = useState(false)

  return (
    <div
      role="alert"
      className={`w-full rounded-md border border-critical/40 bg-critical/10 flex flex-col font-mono ${
        compact ? "p-4" : "p-6"
      } ${className}`}
    >
      <div className="flex items-start gap-3">
        <div className="w-9 h-9 rounded bg-critical/20 border border-critical/50 flex items-center justify-center text-critical shrink-0">
          {isOffline ? <WifiOff size={18} /> : <AlertTriangle size={18} />}
        </div>

        <div className="flex-1 min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <h4 className="text-xs font-bold uppercase tracking-wider text-critical">
              {title}
            </h4>
            {isOffline && (
              <span className="text-[10px] px-1.5 py-0.5 rounded bg-critical/30 border border-critical text-critical font-bold">
                OFFLINE
              </span>
            )}
          </div>

          <p className="text-xs text-ink-2 mt-1 leading-relaxed font-sans">
            {message}
          </p>

          {details && (
            <div className="mt-2.5">
              <button
                type="button"
                onClick={() => setShowDetails((v) => !v)}
                className="text-[11px] text-ink-3 hover:text-ink flex items-center gap-1 cursor-pointer transition-colors"
              >
                <span>{showDetails ? "Hide Technical Details" : "Show Technical Details"}</span>
                {showDetails ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
              </button>

              {showDetails && (
                <pre className="mt-2 p-2.5 rounded bg-surface border border-border text-[10px] text-ink-3 overflow-x-auto whitespace-pre-wrap font-mono">
                  {details}
                </pre>
              )}
            </div>
          )}

          {onRetry && (
            <div className="mt-4">
              <CyberButton
                size="xs"
                variant="secondary"
                icon={<RefreshCw size={12} />}
                onClick={onRetry}
              >
                RETRY REQUEST
              </CyberButton>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

export default ErrorState
