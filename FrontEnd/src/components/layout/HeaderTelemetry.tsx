import { useEffect, useState } from "react"
import { useNavigate } from "react-router-dom"
import { Search, Plus, Clock, Menu } from "lucide-react"
import { CyberButton } from "../ui/CyberButton"
import { useScanContext } from "../../context/ScanContext"

interface HeaderTelemetryProps {
  onOpenCommandPalette: () => void
  onToggleSidebar?: () => void
}

export function HeaderTelemetry({
  onOpenCommandPalette,
  onToggleSidebar,
}: HeaderTelemetryProps) {
  const navigate = useNavigate()
  const { backendOnline, backendLatency, scanActive, activeScanId } = useScanContext()

  const [timeUtc, setTimeUtc] = useState("")
  const [timeLocal, setTimeLocal] = useState("")

  // Clock ticker
  useEffect(() => {
    const updateTime = () => {
      const now = new Date()
      setTimeUtc(now.toUTCString().slice(17, 25) + " UTC")
      setTimeLocal(
        now.toLocaleTimeString("en-GB", {
          hour12: false,
          hour: "2-digit",
          minute: "2-digit",
          second: "2-digit",
        }),
      )
    }
    updateTime()
    const timer = setInterval(updateTime, 1000)
    return () => clearInterval(timer)
  }, [])

  return (
    <header className="h-13 shrink-0 border-b border-border bg-surface/95 backdrop-blur-md flex items-center px-4 sm:px-6 gap-3 sm:gap-4 z-20">
      {/* Mobile Menu Toggle */}
      {onToggleSidebar && (
        <button
          onClick={onToggleSidebar}
          aria-label="Toggle Navigation Menu"
          className="lg:hidden p-1.5 rounded text-ink-3 hover:text-ink hover:bg-elevated transition-colors cursor-pointer"
        >
          <Menu size={18} />
        </button>
      )}

      {/* Global Command Palette Search Trigger */}
      <button
        onClick={onOpenCommandPalette}
        aria-label="Open Command Palette (Ctrl+K)"
        className="flex items-center gap-2.5 px-3 py-1.5 rounded bg-panel border border-border hover:border-blue/50 text-ink-3 hover:text-ink transition-all text-xs font-mono max-w-xs w-full sm:w-72 cursor-pointer shadow-xs"
      >
        <Search size={14} className="text-ink-3 shrink-0" />
        <span className="truncate">Search commands, CVEs, findings...</span>
        <kbd className="hidden sm:inline-block ml-auto text-[10px] px-1.5 py-0.5 rounded bg-canvas border border-border text-ink-3 font-mono">
          Ctrl+K
        </kbd>
      </button>

      {/* Active Scan Telemetry Banner */}
      {scanActive && (
        <div
          onClick={() =>
            navigate(activeScanId ? `/scans/${encodeURIComponent(activeScanId)}` : "/scans/new")
          }
          className="hidden md:flex items-center gap-2 px-3 py-1 rounded bg-cyan/10 border border-cyan/40 text-cyan text-xs font-mono cursor-pointer hover:bg-cyan/20 transition-all animate-pulse"
        >
          <span className="w-2 h-2 rounded-full bg-cyan shadow-[0_0_8px_#38BDF8]" />
          <span className="font-semibold tracking-wider">ACTIVE DAST AUDIT</span>
          {activeScanId && (
            <span className="text-[10px] opacity-75 font-normal">
              [{activeScanId.slice(0, 12)}]
            </span>
          )}
        </div>
      )}

      <div className="flex-1" />

      {/* Live Clocks (UTC & Local) */}
      <div className="hidden xl:flex items-center gap-3 text-[11px] font-mono text-ink-3 border-r border-border pr-4">
        <div className="flex items-center gap-1.5">
          <Clock size={12} className="text-ink-3" />
          <span className="text-ink font-semibold">{timeLocal}</span>
          <span className="text-[10px] text-ink-3">LOC</span>
        </div>
        <span className="text-border-hi">|</span>
        <div className="text-ink-2">
          <span>{timeUtc}</span>
        </div>
      </div>

      {/* Backend Engine Status */}
      <div className="flex items-center gap-2 px-2.5 py-1 rounded bg-panel border border-border text-xs font-mono">
        <span
          className={`w-2 h-2 rounded-full ${
            backendOnline === true
              ? "bg-emerald shadow-[0_0_6px_#10b981]"
              : backendOnline === false
                ? "bg-critical shadow-[0_0_6px_#ef4444]"
                : "bg-medium animate-pulse"
          }`}
        />
        <span className="text-[11px] text-ink-2 hidden sm:inline">
          {backendOnline === true
            ? `ENGINE ONLINE (${backendLatency}ms)`
            : backendOnline === false
              ? "OFFLINE"
              : "CONNECTING..."}
        </span>
      </div>

      {/* Quick Launch New Scan Button */}
      <CyberButton
        variant="primary"
        size="xs"
        icon={<Plus size={13} />}
        hudCorners
        onClick={() => navigate("/scans/new")}
        className="hidden sm:inline-flex"
      >
        NEW SCAN
      </CyberButton>
    </header>
  )
}

export default HeaderTelemetry
