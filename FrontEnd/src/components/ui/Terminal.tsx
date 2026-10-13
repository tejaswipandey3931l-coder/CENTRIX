import { useEffect, useRef, useState } from "react"
import { Copy, Check, Terminal as TermIcon, ArrowDownCircle, Search, Trash2 } from "lucide-react"

export interface TerminalProps {
  logs: string[]
  title?: string
  subtitle?: string
  maxHeight?: string
  onClear?: () => void
  emptyMessage?: string
  className?: string
}

export function Terminal({
  logs,
  title = "SCANNER TELEMETRY LOGS",
  subtitle = "LIVE WEBSOCKET STREAM",
  maxHeight = "450px",
  onClear,
  emptyMessage = "Awaiting scanner telemetry feed...",
  className = "",
}: TerminalProps) {
  const [copied, setCopied] = useState(false)
  const [autoScroll, setAutoScroll] = useState(true)
  const [search, setSearch] = useState("")
  const bottomRef = useRef<HTMLDivElement>(null)
  const containerRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (autoScroll && bottomRef.current) {
      bottomRef.current.scrollIntoView({ behavior: "smooth" })
    }
  }, [logs, autoScroll])

  const copyLogs = async () => {
    try {
      await navigator.clipboard.writeText(logs.join("\n"))
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    } catch {
      // ignore
    }
  }

  const filteredLogs = search.trim()
    ? logs.filter((line) => line.toLowerCase().includes(search.toLowerCase()))
    : logs

  const colorizeLine = (line: string) => {
    if (line.startsWith("[ERROR]") || line.includes("ERR") || line.includes("FATAL")) {
      return "text-critical"
    }
    if (line.startsWith("[WARN]") || line.includes("WARNING")) {
      return "text-high"
    }
    if (line.startsWith("[+]") || line.includes("FOUND") || line.includes("SUCCESS")) {
      return "text-emerald font-semibold"
    }
    if (line.startsWith("[*]") || line.startsWith("[INFO]")) {
      return "text-cyan"
    }
    if (line.startsWith("[DEBUG]")) {
      return "text-ink-3"
    }
    return "text-ink-2"
  }

  return (
    <div
      className={`border border-border rounded-md bg-[#04070e] font-mono overflow-hidden flex flex-col corner-hud scanline-overlay ${className}`}
    >
      {/* Terminal Title Bar */}
      <div className="px-4 py-2.5 bg-surface/90 border-b border-border/80 flex flex-wrap items-center justify-between gap-3 text-xs">
        <div className="flex items-center gap-2">
          <TermIcon size={14} className="text-cyan animate-pulse" />
          <div>
            <span className="font-semibold text-ink uppercase tracking-wider">{title}</span>
            {subtitle && (
              <span className="text-[10px] text-ink-3 ml-2 font-normal">{subtitle}</span>
            )}
          </div>
          <span className="text-[10px] px-1.5 py-0.5 rounded bg-panel border border-border text-ink-3">
            {filteredLogs.length} {filteredLogs.length === 1 ? "line" : "lines"}
          </span>
        </div>

        {/* Toolbar */}
        <div className="flex items-center gap-1.5 ml-auto">
          {/* Search */}
          <div className="relative flex items-center">
            <Search size={11} className="absolute left-2 text-ink-3 pointer-events-none" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Filter stream..."
              className="bg-canvas border border-border/70 rounded px-2 pl-6 py-1 text-[11px] text-ink placeholder:text-ink-3 w-32 sm:w-40 focus:w-48 transition-all focus:border-cyan/40"
            />
          </div>

          {/* Autoscroll Toggle */}
          <button
            onClick={() => setAutoScroll((v) => !v)}
            title={autoScroll ? "Disable auto-scroll" : "Enable auto-scroll"}
            className={`px-2 py-1 rounded text-[11px] border cursor-pointer transition-colors flex items-center gap-1 ${
              autoScroll
                ? "bg-cyan/15 text-cyan border-cyan/40"
                : "bg-panel text-ink-3 border-border hover:text-ink"
            }`}
          >
            <ArrowDownCircle size={12} />
            <span className="hidden sm:inline">Follow</span>
          </button>

          {/* Copy */}
          <button
            onClick={copyLogs}
            title="Copy logs"
            className="p-1.5 rounded bg-panel border border-border text-ink-3 hover:text-ink hover:border-border-hi transition-colors cursor-pointer"
          >
            {copied ? <Check size={12} className="text-emerald" /> : <Copy size={12} />}
          </button>

          {/* Clear */}
          {onClear && (
            <button
              onClick={onClear}
              title="Clear terminal"
              className="p-1.5 rounded bg-panel border border-border text-ink-3 hover:text-critical hover:border-critical/40 transition-colors cursor-pointer"
            >
              <Trash2 size={12} />
            </button>
          )}
        </div>
      </div>

      {/* Terminal Body */}
      <div
        ref={containerRef}
        style={{ maxHeight }}
        className="p-4 overflow-y-auto space-y-1 text-xs text-ink-2 leading-relaxed selection:bg-cyan/30"
      >
        {filteredLogs.length === 0 ? (
          <div className="text-ink-3 text-xs italic py-8 text-center">{emptyMessage}</div>
        ) : (
          filteredLogs.map((line, idx) => (
            <div key={idx} className="flex items-start gap-2.5 hover:bg-surface/50 px-1 py-0.5 rounded">
              <span className="text-[10px] text-ink-3 shrink-0 select-none w-8 text-right font-mono opacity-50">
                {idx + 1}
              </span>
              <span className={`break-all whitespace-pre-wrap ${colorizeLine(line)}`}>
                {line}
              </span>
            </div>
          ))
        )}
        <div ref={bottomRef} />
      </div>
    </div>
  )
}

export default Terminal
