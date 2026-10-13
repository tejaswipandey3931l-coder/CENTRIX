import React from "react"
import { NavLink, useLocation, useNavigate } from "react-router-dom"
import {
  LayoutDashboard,
  Target,
  Cpu,
  Terminal,
  Radio,
  Crosshair,
  Code2,
  GitCompare,
  ShieldAlert,
  ShieldCheck,
  KeyRound,
  Satellite,
  FolderOpen,
  FileText,
  Zap,
  Settings,
  BarChart3,
  CalendarClock,
  Shield,
  Activity,
} from "lucide-react"
import { useScanContext } from "../../context/ScanContext"

interface NavItem {
  path: string
  label: string
  Icon: React.ComponentType<{ size?: number; strokeWidth?: number; className?: string }>
  badge?: string | number
  pulseBadge?: boolean
}

interface NavCategory {
  category: string
  items: NavItem[]
}

interface NavigationSidebarProps {
  onCloseMobile?: () => void
}

export function NavigationSidebar({ onCloseMobile }: NavigationSidebarProps) {
  const location = useLocation()
  const navigate = useNavigate()
  const { scanActive, activeScanId, findingsCount } = useScanContext()

  const NAV_CATEGORIES: NavCategory[] = [
    {
      category: "OPERATIONS",
      items: [
        { path: "/overview", label: "Overview", Icon: LayoutDashboard },
        { path: "/scans/new", label: "Scan Setup", Icon: Target },
        {
          path: activeScanId ? `/scans/${encodeURIComponent(activeScanId)}` : "/scans/new",
          label: "Automated Scan",
          Icon: Cpu,
          badge: scanActive ? "ACTIVE" : undefined,
          pulseBadge: scanActive,
        },
        { path: "/scans/scheduled", label: "Scheduled Scans", Icon: CalendarClock },
      ],
    },
    {
      category: "OFFENSIVE WORKBENCH",
      items: [
        { path: "/manual", label: "Repeater", Icon: Terminal },
        { path: "/manual/proxy-history", label: "Proxy History", Icon: Radio },
        { path: "/manual/intruder", label: "Intruder", Icon: Crosshair },
        { path: "/manual/decoder", label: "Decoder", Icon: Code2 },
        { path: "/manual/comparer", label: "Comparer", Icon: GitCompare },
      ],
    },
    {
      category: "VULNERABILITY MANAGEMENT",
      items: [
        {
          path: "/findings",
          label: "Findings",
          Icon: ShieldAlert,
          badge: findingsCount > 0 ? findingsCount : undefined,
        },
        { path: "/evidence", label: "Evidence", Icon: FolderOpen },
        { path: "/proof", label: "Proof Mode", Icon: ShieldCheck },
        { path: "/authorization-matrix", label: "Auth Matrix", Icon: KeyRound },
        { path: "/oob-monitor", label: "OOB Monitor", Icon: Satellite },
      ],
    },
    {
      category: "INTELLIGENCE & SYSTEM",
      items: [
        { path: "/nuclei-cve", label: "Nuclei & CVE", Icon: Zap },
        { path: "/risk-posture", label: "Risk Posture", Icon: BarChart3 },
        { path: "/reports", label: "Reports", Icon: FileText },
        { path: "/settings", label: "Settings", Icon: Settings },
      ],
    },
  ]

  const isItemActive = (path: string) => {
    if (path === "/overview") return location.pathname === "/" || location.pathname === "/overview"
    if (path.startsWith("/scans/")) {
      return location.pathname.startsWith("/scans/") && (path === location.pathname || (path === "/scans/new" && location.pathname === "/scans/new"))
    }
    if (path === "/manual") {
      return location.pathname === "/manual"
    }
    return location.pathname.startsWith(path)
  }

  return (
    <aside className="w-64 shrink-0 flex flex-col bg-canvas border-r border-border h-full select-none">
      {/* Brand Header */}
      <div
        className="h-13 px-5 flex items-center border-b border-border gap-3 bg-surface/50 cursor-pointer hover:bg-surface/80 transition-colors"
        onClick={() => {
          navigate("/overview")
          onCloseMobile?.()
        }}
      >
        <div className="relative flex items-center justify-center">
          <div className="w-8 h-8 rounded bg-blue/10 border border-blue/30 flex items-center justify-center">
            <Shield size={16} className="text-blue" />
          </div>
          <span className="absolute -bottom-0.5 -right-0.5 w-2 h-2 rounded-full bg-emerald" />
        </div>
        <div className="min-w-0">
          <div className="flex items-center gap-1.5">
            <span className="text-ink font-bold text-sm tracking-[0.14em] font-display">
              CENTRIX
            </span>
            <span className="text-[9px] font-mono px-1 py-0.2 rounded bg-elevated text-ink-2 border border-border">
              v2.4
            </span>
          </div>
          <p className="text-ink-3 text-[10px] font-mono uppercase tracking-widest truncate">
            DAST COMMAND CENTER
          </p>
        </div>
      </div>

      {/* Navigation Links by Category */}
      <nav className="flex-1 overflow-y-auto px-3 py-4 space-y-5">
        {NAV_CATEGORIES.map((cat) => (
          <div key={cat.category} className="space-y-1">
            <div className="px-2.5 mb-1.5 text-[10px] font-mono font-semibold uppercase tracking-widest text-ink-3/80">
              {cat.category}
            </div>

            {cat.items.map(({ path, label, Icon, badge, pulseBadge }) => {
              const on = isItemActive(path)
              return (
                <NavLink
                  key={label}
                  to={path}
                  onClick={() => onCloseMobile?.()}
                  className={`w-full flex items-center gap-2.5 px-3 py-1.5 rounded text-xs transition-all duration-150 cursor-pointer ${
                    on
                      ? "bg-blue/15 text-ink border border-blue/40 font-semibold"
                      : "text-ink-2 hover:text-ink hover:bg-elevated/70 border border-transparent"
                  }`}
                >
                  <Icon
                    size={14}
                    strokeWidth={on ? 2.2 : 1.6}
                    className={`shrink-0 ${on ? "text-blue" : "text-ink-3"}`}
                  />
                  <span className="flex-1 text-left truncate font-sans">{label}</span>
                  {badge !== undefined && (
                    <span
                      className={`font-mono text-[10px] px-1.5 py-0.2 rounded-sm shrink-0 ${
                        pulseBadge
                          ? "bg-cyan/15 text-cyan border border-cyan/30 animate-pulse font-bold"
                          : on
                            ? "bg-blue/20 text-white font-bold border border-blue/30"
                            : "bg-elevated text-ink-2 border border-border"
                      }`}
                    >
                      {badge}
                    </span>
                  )}
                </NavLink>
              )
            })}
          </div>
        ))}
      </nav>

      {/* Operator Status Footer */}
      <div className="border-t border-border p-3.5 bg-surface/40">
        <div className="flex items-center gap-2.5">
          <div className="w-7 h-7 rounded bg-elevated border border-border flex items-center justify-center shrink-0">
            <Activity size={14} className="text-cyan" />
          </div>
          <div className="flex-1 min-w-0">
            <p className="text-ink text-xs font-medium truncate">SecOps Operator</p>
            <div className="flex items-center gap-1.5 mt-0.5">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald" />
              <span className="text-ink-3 text-[10px] font-mono truncate">
                AUTHORIZED TESTER
              </span>
            </div>
          </div>
        </div>
      </div>
    </aside>
  )
}

export default NavigationSidebar
