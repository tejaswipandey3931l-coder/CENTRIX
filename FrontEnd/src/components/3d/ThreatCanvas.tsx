import React, { useState, useEffect, Suspense, useMemo } from "react"
import { ShieldAlert, Layers, RotateCcw, Info, Shield } from "lucide-react"
import { Topology2DFallback, type TopologyNode, type TopologyLink } from "./Topology2DFallback"
import { EmptyState } from "../ui/EmptyState"

// Dynamic lazy import to split Three.js and Fiber into an isolated asynchronous chunk
const ThreatCanvas3D = React.lazy(() => import("./ThreatCanvas3D"))

interface ThreatCanvasProps {
  nodes: TopologyNode[]
  links: TopologyLink[]
  selectedNodeId?: string | null
  onSelectNode?: (node: TopologyNode) => void
  onLaunchScan?: () => void
  className?: string
  height?: string
}

// Error Boundary for WebGL/Canvas failures
class CanvasErrorBoundary extends React.Component<
  { fallback: React.ReactNode; children: React.ReactNode },
  { hasError: boolean }
> {
  constructor(props: { fallback: React.ReactNode; children: React.ReactNode }) {
    super(props)
    this.state = { hasError: false }
  }

  static getDerivedStateFromError() {
    return { hasError: true }
  }

  componentDidCatch(error: any) {
    console.warn("ThreatCanvas WebGL Error — Falling back to 2D HUD:", error)
  }

  render() {
    if (this.state.hasError) {
      return this.props.fallback
    }
    return this.props.children
  }
}

export function ThreatCanvas({
  nodes,
  links,
  selectedNodeId,
  onSelectNode,
  onLaunchScan,
  className = "",
  height = "440px",
}: ThreatCanvasProps) {
  const [mode, setModeState] = useState<"3d" | "2d">(() => {
    try {
      const saved = localStorage.getItem("centrix_canvas_mode")
      return saved === "3d" ? "3d" : "2d"
    } catch {
      return "2d"
    }
  })

  const setMode = (nextMode: "3d" | "2d") => {
    setModeState(nextMode)
    try {
      localStorage.setItem("centrix_canvas_mode", nextMode)
    } catch {}
  }
  const [reducedMotion, setReducedMotion] = useState(false)
  const [severityFilter, setSeverityFilter] = useState<string>("ALL")
  const [typeFilter, setTypeFilter] = useState<"ALL" | "ENDPOINTS" | "THREATS">("ALL")
  const [resetTrigger, setResetTrigger] = useState(0)
  const [showLegend, setShowLegend] = useState(false)

  // Check prefers-reduced-motion
  useEffect(() => {
    const mediaQuery = window.matchMedia("(prefers-reduced-motion: reduce)")
    setReducedMotion(mediaQuery.matches)

    const handler = (e: MediaQueryListEvent) => setReducedMotion(e.matches)
    mediaQuery.addEventListener("change", handler)
    return () => mediaQuery.removeEventListener("change", handler)
  }, [])

  // Filter nodes according to type and severity
  const filteredNodes = useMemo(() => {
    return nodes.filter((node) => {
      // Type filter
      if (typeFilter === "ENDPOINTS" && node.type !== "endpoint" && node.type !== "target") {
        return false
      }
      if (typeFilter === "THREATS" && node.type !== "vulnerability" && node.type !== "target") {
        return false
      }

      // Severity filter for vulnerability nodes
      if (severityFilter !== "ALL" && node.type === "vulnerability") {
        return node.severity?.toUpperCase() === severityFilter
      }

      return true
    })
  }, [nodes, typeFilter, severityFilter])

  const filteredLinks = useMemo(() => {
    return links.filter((link) => {
      const s = filteredNodes.some((n) => n.id === link.source)
      const t = filteredNodes.some((n) => n.id === link.target)
      return s && t
    })
  }, [links, filteredNodes])

  const criticalCount = useMemo(
    () =>
      nodes.filter(
        (n) => n.type === "vulnerability" && n.severity?.toLowerCase() === "critical",
      ).length,
    [nodes],
  )

  const hasData = nodes.length > 0

  return (
    <div
      role="region"
      aria-label="Central Attack Surface and Threat Topology"
      style={{ height }}
      className={`relative w-full rounded-md border border-border bg-[#03060c] overflow-hidden corner-hud select-none flex flex-col ${className}`}
    >
      {/* Screen reader summary table */}
      <div className="sr-only">
        <h3>Attack Surface Topology Overview</h3>
        <table>
          <caption>Active discovered nodes and associated vulnerabilities</caption>
          <thead>
            <tr>
              <th scope="col">Node Label</th>
              <th scope="col">Type</th>
              <th scope="col">Severity</th>
              <th scope="col">Details</th>
            </tr>
          </thead>
          <tbody>
            {filteredNodes.map((node) => (
              <tr key={node.id}>
                <td>{node.label}</td>
                <td>{node.type}</td>
                <td>{node.severity || "None"}</td>
                <td>{node.details || "None"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Top HUD Controls Bar */}
      <div className="absolute top-0 left-0 right-0 z-20 px-4 py-3 bg-gradient-to-b from-[#03060c]/95 via-[#03060c]/60 to-transparent flex flex-wrap items-center justify-between gap-3 pointer-events-auto">
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 text-xs font-mono font-bold text-ink tracking-wider">
            <span className="w-2 h-2 rounded-full bg-cyan animate-pulse" />
            <span>CENTRAL ATTACK SURFACE & THREAT TOPOLOGY</span>
          </div>

          {criticalCount > 0 && (
            <span className="hidden sm:inline-flex items-center gap-1.5 text-[10px] font-mono font-semibold px-2 py-0.5 rounded bg-critical/15 text-critical border border-critical/30 animate-pulse">
              <ShieldAlert size={11} /> {criticalCount} CRITICAL THREATS
            </span>
          )}
        </div>

        {/* Action Controls */}
        <div className="flex items-center gap-2 text-xs font-mono">
          {hasData && (
            <>
              {/* Type Filter */}
              <div className="hidden lg:flex items-center bg-surface/90 border border-border rounded p-0.5 text-[10px]">
                {(["ALL", "ENDPOINTS", "THREATS"] as const).map((t) => (
                  <button
                    key={t}
                    onClick={() => setTypeFilter(t)}
                    className={`px-2 py-0.5 rounded-xs transition-colors cursor-pointer ${
                      typeFilter === t
                        ? "bg-blue/20 text-ink font-bold border border-blue/40"
                        : "text-ink-3 hover:text-ink"
                    }`}
                  >
                    {t}
                  </button>
                ))}
              </div>

              {/* Severity Filter Pills */}
              <div className="hidden md:flex items-center bg-surface/90 border border-border rounded p-0.5 text-[10px]">
                {["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"].map((sev) => (
                  <button
                    key={sev}
                    onClick={() => setSeverityFilter(sev)}
                    className={`px-2 py-0.5 rounded-xs transition-colors cursor-pointer ${
                      severityFilter === sev
                        ? "bg-blue/20 text-ink font-bold border border-blue/40"
                        : "text-ink-3 hover:text-ink"
                    }`}
                  >
                    {sev}
                  </button>
                ))}
              </div>

              {/* Reset Camera View */}
              {mode === "3d" && (
                <button
                  type="button"
                  title="Reset Camera View"
                  aria-label="Reset Camera View"
                  onClick={() => setResetTrigger((n) => n + 1)}
                  className="p-1.5 rounded bg-elevated/80 border border-border text-ink-2 hover:text-cyan hover:border-cyan/50 transition-colors cursor-pointer"
                >
                  <RotateCcw size={13} />
                </button>
              )}

              {/* Legend Toggle */}
              <button
                type="button"
                title="Toggle Topology Legend"
                aria-label="Toggle Topology Legend"
                onClick={() => setShowLegend((v) => !v)}
                className={`p-1.5 rounded border transition-colors cursor-pointer ${
                  showLegend
                    ? "bg-blue/20 border-blue text-ink"
                    : "bg-elevated/80 border-border text-ink-2 hover:text-ink"
                }`}
              >
                <Info size={13} />
              </button>
            </>
          )}

          {/* 3D / 2D Toggle Switch */}
          <button
            onClick={() => setMode((m) => (m === "3d" ? "2d" : "3d"))}
            aria-label={`Switch to ${mode === "3d" ? "2D HUD" : "3D Scene"}`}
            className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-elevated/80 border border-border text-ink hover:border-blue/50 hover:text-ink transition-colors cursor-pointer"
          >
            <Layers size={13} className="text-cyan" />
            <span className="tracking-wider">{mode === "3d" ? "3D SCENE" : "2D HUD"}</span>
          </button>
        </div>
      </div>

      {/* Floating Legend Overlay */}
      {showLegend && hasData && (
        <div className="absolute top-14 right-4 z-30 p-3 rounded bg-surface/95 border border-border-hi shadow-2xl backdrop-blur-md font-mono text-[10px] space-y-1.5 animate-in fade-in zoom-in-95 duration-150">
          <div className="text-[11px] font-bold text-ink border-b border-border pb-1">
            TOPOLOGY LEGEND
          </div>
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-[#38bdf8]" />
            <span className="text-ink">Target Origin Root</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-blue" />
            <span className="text-ink">Scanner Probe</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-violet" />
            <span className="text-ink">Discovered Endpoint</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-critical" />
            <span className="text-ink">Critical Threat</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-high" />
            <span className="text-ink">High Threat</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-medium" />
            <span className="text-ink">Medium Threat</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-low" />
            <span className="text-ink">Low / Info Threat</span>
          </div>
        </div>
      )}

      {/* Render Canvas, 2D Fallback, or Empty State */}
      <div className="flex-1 w-full h-full">
        {!hasData ? (
          <div className="w-full h-full flex items-center justify-center p-6">
            <EmptyState
              icon={<Shield size={24} className="text-cyan/70" />}
              title="NO TARGET TOPOLOGY AVAILABLE"
              description="No attack surface has been mapped yet. Launch an authorised DAST scan to discover endpoints, crawl assets, and map vulnerability vectors in 3D."
              actionLabel={onLaunchScan ? "LAUNCH FIRST DAST SCAN" : undefined}
              onAction={onLaunchScan}
              compact
            />
          </div>
        ) : mode === "2d" ? (
          <Topology2DFallback
            nodes={filteredNodes}
            links={filteredLinks}
            selectedNodeId={selectedNodeId}
            onSelectNode={onSelectNode}
          />
        ) : (
          <CanvasErrorBoundary
            fallback={
              <Topology2DFallback
                nodes={filteredNodes}
                links={filteredLinks}
                selectedNodeId={selectedNodeId}
                onSelectNode={onSelectNode}
              />
            }
          >
            <Suspense
              fallback={
                <div className="w-full h-full flex flex-col items-center justify-center font-mono text-xs text-ink-3 gap-3">
                  <div className="w-10 h-10 rounded-full border-2 border-blue/20 border-t-blue animate-spin" />
                  <span>INITIALIZING THREAT TOPOLOGY ENGINE...</span>
                </div>
              }
            >
              <ThreatCanvas3D
                nodes={filteredNodes}
                links={filteredLinks}
                selectedNodeId={selectedNodeId}
                onSelectNode={onSelectNode}
                reducedMotion={reducedMotion}
                resetTrigger={resetTrigger}
              />
            </Suspense>
          </CanvasErrorBoundary>
        )}
      </div>

      {/* Bottom Telemetry Bar */}
      {hasData && (
        <div className="absolute bottom-0 left-0 right-0 z-20 px-4 py-2 bg-gradient-to-t from-[#03060c]/90 via-[#03060c]/50 to-transparent flex items-center justify-between text-[11px] font-mono text-ink-3 pointer-events-none">
          <div className="flex items-center gap-4">
            <span>NODES: {filteredNodes.length}</span>
            <span>VECTORS: {filteredLinks.length}</span>
            <span className="hidden sm:inline">CONTROLS: DRAG TO ROTATE · SCROLL TO ZOOM</span>
          </div>
          <div className="text-cyan/70 font-semibold tracking-widest text-[10px]">
            CENTRIX 3D TELEMETRY
          </div>
        </div>
      )}
    </div>
  )
}

export default ThreatCanvas
