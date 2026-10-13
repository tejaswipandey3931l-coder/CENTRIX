import React, { useEffect, useState, useMemo } from "react"
import { useNavigate } from "react-router-dom"
import {
  Search,
  LayoutDashboard,
  Target,
  Cpu,
  ShieldAlert,
  Zap,
  FileText,
  Terminal,
  Radio,
  Crosshair,
  Code2,
  GitCompare,
  FolderOpen,
  ShieldCheck,
  KeyRound,
  Satellite,
  BarChart3,
  CalendarClock,
  Settings,
  ArrowRight,
} from "lucide-react"
import { useScanContext } from "../../context/ScanContext"

interface CommandItem {
  id: string
  label: string
  category: "Navigation" | "Action"
  icon: React.ComponentType<{ size?: number; className?: string }>
  path: string
  keywords?: string
}

interface CommandPaletteProps {
  isOpen: boolean
  onClose: () => void
}

export function CommandPalette({ isOpen, onClose }: CommandPaletteProps) {
  const navigate = useNavigate()
  const { scanActive, activeScanId } = useScanContext()
  const [query, setQuery] = useState("")
  const [selectedIndex, setSelectedIndex] = useState(0)

  const items: CommandItem[] = useMemo(
    () => [
      // Navigation
      {
        id: "nav-overview",
        label: "Overview Dashboard",
        category: "Navigation",
        icon: LayoutDashboard,
        path: "/overview",
        keywords: "dashboard metrics posture 3d globe home",
      },
      {
        id: "nav-scan-setup",
        label: "New Scan Setup",
        category: "Navigation",
        icon: Target,
        path: "/scans/new",
        keywords: "target launch profile openapi postman har configure",
      },
      {
        id: "nav-automated-scan",
        label: scanActive ? "Active Live Scan Workspace" : "Automated Scan Workspace",
        category: "Navigation",
        icon: Cpu,
        path: activeScanId ? `/scans/${encodeURIComponent(activeScanId)}` : "/scans/new",
        keywords: "live log stream terminal status progress pause stop",
      },
      {
        id: "nav-findings",
        label: "Findings Explorer",
        category: "Navigation",
        icon: ShieldAlert,
        path: "/findings",
        keywords: "vulnerabilities cwe cvss bugs security critical high",
      },
      {
        id: "nav-nuclei-cve",
        label: "Threat Intelligence & CVE Lookup",
        category: "Navigation",
        icon: Zap,
        path: "/nuclei-cve",
        keywords: "nuclei templates exploit cve advisory threat feed",
      },
      {
        id: "nav-reports",
        label: "Reports Center",
        category: "Navigation",
        icon: FileText,
        path: "/reports",
        keywords: "export pdf html sarif junit download compliance",
      },
      {
        id: "nav-risk-posture",
        label: "Risk Posture Analytics",
        category: "Navigation",
        icon: BarChart3,
        path: "/risk-posture",
        keywords: "exposure score trends categories executive",
      },
      {
        id: "nav-manual-testing",
        label: "Repeater (Manual Testing)",
        category: "Navigation",
        icon: Terminal,
        path: "/manual",
        keywords: "replay request response headers http burp",
      },
      {
        id: "nav-proxy-history",
        label: "Proxy History & CA Controller",
        category: "Navigation",
        icon: Radio,
        path: "/manual/proxy-history",
        keywords: "traffic corpus captured browser ca leaf ssl",
      },
      {
        id: "nav-intruder",
        label: "Intruder (Fuzzing)",
        category: "Navigation",
        icon: Crosshair,
        path: "/manual/intruder",
        keywords: "payload marker brute force attack extract regex",
      },
      {
        id: "nav-decoder",
        label: "Decoder / Transformer",
        category: "Navigation",
        icon: Code2,
        path: "/manual/decoder",
        keywords: "base64 url encode decode sha256 pretty json hash",
      },
      {
        id: "nav-comparer",
        label: "Comparer (Diff Analyzer)",
        category: "Navigation",
        icon: GitCompare,
        path: "/manual/comparer",
        keywords: "diff response compare hash length headers",
      },
      {
        id: "nav-evidence",
        label: "Evidence Vault",
        category: "Navigation",
        icon: FolderOpen,
        path: "/evidence",
        keywords: "sanitized proof artifacts responses forensics",
      },
      {
        id: "nav-proof-mode",
        label: "Proof Mode Tasks",
        category: "Navigation",
        icon: ShieldCheck,
        path: "/proof",
        keywords: "validation retest poc verification tasks",
      },
      {
        id: "nav-auth-matrix",
        label: "Authorization Matrix",
        category: "Navigation",
        icon: KeyRound,
        path: "/authorization-matrix",
        keywords: "idor bac roles privilege escalation permission",
      },
      {
        id: "nav-oob-monitor",
        label: "OOB Monitor (Callbacks)",
        category: "Navigation",
        icon: Satellite,
        path: "/oob-monitor",
        keywords: "out of band token ssrf interactsh callbacks",
      },
      {
        id: "nav-scheduled-scans",
        label: "Scheduled Scans",
        category: "Navigation",
        icon: CalendarClock,
        path: "/scans/scheduled",
        keywords: "cron repeat hourly daily weekly recurring",
      },
      {
        id: "nav-settings",
        label: "System Settings",
        category: "Navigation",
        icon: Settings,
        path: "/settings",
        keywords: "api integrations github slack nuclei config",
      },
    ],
    [scanActive, activeScanId],
  )

  const filtered = useMemo(() => {
    if (!query.trim()) return items
    const q = query.toLowerCase()
    return items.filter(
      (item) =>
        item.label.toLowerCase().includes(q) ||
        item.keywords?.toLowerCase().includes(q) ||
        item.category.toLowerCase().includes(q),
    )
  }, [items, query])

  useEffect(() => {
    setSelectedIndex(0)
  }, [query])

  const handleSelect = (item: CommandItem) => {
    navigate(item.path)
    onClose()
  }

  useEffect(() => {
    if (!isOpen) return

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        onClose()
      } else if (e.key === "ArrowDown") {
        e.preventDefault()
        setSelectedIndex((i) => (i + 1) % Math.max(1, filtered.length))
      } else if (e.key === "ArrowUp") {
        e.preventDefault()
        setSelectedIndex((i) => (i - 1 + filtered.length) % Math.max(1, filtered.length))
      } else if (e.key === "Enter" && filtered[selectedIndex]) {
        e.preventDefault()
        handleSelect(filtered[selectedIndex])
      }
    }

    window.addEventListener("keydown", handleKeyDown)
    return () => window.removeEventListener("keydown", handleKeyDown)
  }, [isOpen, onClose, filtered, selectedIndex])

  if (!isOpen) return null

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center pt-20 p-4">
      {/* Backdrop */}
      <div
        className="fixed inset-0 bg-black/80 backdrop-blur-xs transition-opacity animate-in fade-in duration-150"
        onClick={onClose}
        aria-hidden="true"
      />

      {/* Modal Box */}
      <div
        className="relative w-full max-w-xl bg-surface border border-border-hi shadow-2xl rounded-lg overflow-hidden z-10 animate-in zoom-in-95 duration-150 font-mono"
        role="dialog"
        aria-modal="true"
        aria-label="Command Palette"
      >
        {/* Search Input Bar */}
        <div className="flex items-center px-4 py-3 border-b border-border bg-[#0a0f19] gap-3">
          <Search size={16} className="text-blue shrink-0" />
          <input
            autoFocus
            type="text"
            placeholder="Type a command, tool name, or CVE..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="flex-1 bg-transparent text-ink text-sm outline-none placeholder:text-ink-3"
          />
          {query && (
            <button
              onClick={() => setQuery("")}
              className="text-[10px] text-ink-3 hover:text-ink px-1.5 py-0.5 rounded border border-border"
            >
              CLEAR
            </button>
          )}
          <kbd className="text-[10px] text-ink-3 px-1.5 py-0.5 rounded bg-elevated border border-border">
            ESC
          </kbd>
        </div>

        {/* Results List */}
        <div className="max-h-80 overflow-y-auto p-2 divide-y divide-border/30">
          {filtered.length === 0 ? (
            <div className="py-12 text-center text-xs text-ink-3">
              No command or module matching &quot;{query}&quot;
            </div>
          ) : (
            filtered.map((item, idx) => {
              const Icon = item.icon
              const isSelected = idx === selectedIndex

              return (
                <div
                  key={item.id}
                  onClick={() => handleSelect(item)}
                  onMouseEnter={() => setSelectedIndex(idx)}
                  className={`flex items-center justify-between px-3 py-2 rounded-sm cursor-pointer transition-colors text-xs ${
                    isSelected
                      ? "bg-blue/15 text-ink border border-blue/40"
                      : "text-ink-2 hover:bg-elevated/70 border border-transparent"
                  }`}
                >
                  <div className="flex items-center gap-2.5 truncate">
                    <Icon size={14} className={isSelected ? "text-blue" : "text-ink-3"} />
                    <span className="font-sans font-medium truncate">{item.label}</span>
                  </div>

                  <div className="flex items-center gap-2 shrink-0">
                    <span className="text-[10px] text-ink-3 uppercase font-mono">
                      {item.category}
                    </span>
                    {isSelected && <ArrowRight size={12} className="text-blue" />}
                  </div>
                </div>
              )
            })
          )}
        </div>

        {/* Footer Hints */}
        <div className="px-4 py-2 border-t border-border bg-surface/60 flex items-center justify-between text-[10px] text-ink-3">
          <div className="flex items-center gap-3">
            <span>
              <kbd className="bg-elevated px-1 rounded border border-border">↑</kbd>
              <kbd className="bg-elevated px-1 rounded border border-border ml-1">↓</kbd> Navigate
            </span>
            <span>
              <kbd className="bg-elevated px-1 rounded border border-border">ENTER</kbd> Select
            </span>
          </div>
          <span className="text-cyan/80">CENTRIX COMMAND PALETTE</span>
        </div>
      </div>
    </div>
  )
}

export default CommandPalette
