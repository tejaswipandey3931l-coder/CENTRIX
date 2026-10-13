import { useState } from "react"
import { ShieldAlert, Server, Globe } from "lucide-react"

export interface TopologyNode {
  id: string
  label: string
  type: "target" | "endpoint" | "vulnerability" | "scanner"
  severity?: "Critical" | "High" | "Medium" | "Low" | "Info"
  cvss?: number | null
  x?: number
  y?: number
  details?: string
}

export interface TopologyLink {
  source: string
  target: string
  status?: "active" | "scanned" | "exploited"
}

interface Topology2DFallbackProps {
  nodes: TopologyNode[]
  links: TopologyLink[]
  selectedNodeId?: string | null
  onSelectNode?: (node: TopologyNode) => void
  className?: string
}

export function Topology2DFallback({
  nodes,
  links,
  selectedNodeId,
  onSelectNode,
  className = "",
}: Topology2DFallbackProps) {
  const [hoveredNode, setHoveredNode] = useState<TopologyNode | null>(null)

  // Fallback layout coordinates if not supplied
  const width = 800
  const height = 480
  const centerX = width / 2
  const centerY = height / 2

  // Layout calculations
  const positionedNodes: (TopologyNode & { cx: number; cy: number })[] = nodes.map(
    (node) => {
      if (node.x != null && node.y != null) {
        return { ...node, cx: node.x, cy: node.y }
      }
      if (node.type === "scanner") {
        return { ...node, cx: 80, cy: centerY }
      }
      if (node.type === "target") {
        return { ...node, cx: centerX, cy: centerY }
      }
      if (node.type === "endpoint") {
        const endpoints = nodes.filter((n) => n.type === "endpoint")
        const epIdx = endpoints.findIndex((n) => n.id === node.id)
        const angle = (epIdx / Math.max(1, endpoints.length)) * 2 * Math.PI - Math.PI / 2
        const radius = 130
        return {
          ...node,
          cx: centerX + Math.cos(angle) * radius,
          cy: centerY + Math.sin(angle) * radius,
        }
      }
      // Vulnerability nodes positioned outside their respective endpoints
      const vulns = nodes.filter((n) => n.type === "vulnerability")
      const vIdx = vulns.findIndex((n) => n.id === node.id)
      const angle = (vIdx / Math.max(1, vulns.length)) * 2 * Math.PI
      const radius = 190
      return {
        ...node,
        cx: centerX + Math.cos(angle) * radius,
        cy: centerY + Math.sin(angle) * radius,
      }
    },
  )

  const nodeMap = new Map(positionedNodes.map((n) => [n.id, n]))

  const getNodeColor = (node: TopologyNode) => {
    if (node.type === "scanner") return "#2563eb"
    if (node.type === "target") return "#38bdf8"
    if (node.type === "endpoint") return "#8b5cf6"
    switch (node.severity?.toLowerCase()) {
      case "critical":
        return "#f43f5e"
      case "high":
        return "#f97316"
      case "medium":
        return "#eab308"
      case "low":
        return "#06b6d4"
      default:
        return "#64748b"
    }
  }

  return (
    <div className={`relative w-full h-full min-h-[380px] bg-[#03060c] select-none ${className}`}>
      {/* SVG Canvas */}
      <svg
        viewBox={`0 0 ${width} ${height}`}
        className="w-full h-full"
        preserveAspectRatio="xMidYMid meet"
      >
        <defs>
          {/* Glowing Filters */}
          <filter id="glow-cyan" x="-30%" y="-30%" width="160%" height="160%">
            <feGaussianBlur stdDeviation="4" result="blur" />
            <feComposite in="SourceGraphic" in2="blur" operator="over" />
          </filter>
          <filter id="glow-red" x="-30%" y="-30%" width="160%" height="160%">
            <feGaussianBlur stdDeviation="5" result="blur" />
            <feComposite in="SourceGraphic" in2="blur" operator="over" />
          </filter>

          {/* Gradients */}
          <radialGradient id="radar-sweep" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="rgba(56, 189, 248, 0.05)" />
            <stop offset="60%" stopColor="rgba(56, 189, 248, 0.01)" />
            <stop offset="100%" stopColor="transparent" />
          </radialGradient>
        </defs>

        {/* Radar Rings & Grid */}
        <circle
          cx={centerX}
          cy={centerY}
          r={210}
          fill="url(#radar-sweep)"
          stroke="rgba(37, 45, 61, 0.6)"
          strokeWidth="1"
          strokeDasharray="4 6"
        />
        <circle
          cx={centerX}
          cy={centerY}
          r={130}
          fill="none"
          stroke="rgba(37, 45, 61, 0.7)"
          strokeWidth="1"
        />
        <circle
          cx={centerX}
          cy={centerY}
          r={50}
          fill="none"
          stroke="rgba(56, 189, 248, 0.2)"
          strokeWidth="1"
        />

        {/* Coordinate Crosshairs */}
        <line
          x1={centerX - 230}
          y1={centerY}
          x2={centerX + 230}
          y2={centerY}
          stroke="rgba(37, 45, 61, 0.5)"
          strokeWidth="1"
        />
        <line
          x1={centerX}
          y1={centerY - 230}
          x2={centerX}
          y2={centerY + 230}
          stroke="rgba(37, 45, 61, 0.5)"
          strokeWidth="1"
        />

        {/* Links / Attack Arcs */}
        {links.map((link, idx) => {
          const s = nodeMap.get(link.source)
          const t = nodeMap.get(link.target)
          if (!s || !t) return null
          const isSelected = s.id === selectedNodeId || t.id === selectedNodeId
          return (
            <g key={`link-${idx}`}>
              <line
                x1={s.cx}
                y1={s.cy}
                x2={t.cx}
                y2={t.cy}
                stroke={
                  isSelected
                    ? "rgba(56, 189, 248, 0.8)"
                    : link.status === "exploited"
                      ? "rgba(244, 63, 94, 0.6)"
                      : "rgba(37, 45, 61, 0.8)"
                }
                strokeWidth={isSelected ? "2" : "1.2"}
                strokeDasharray={link.status === "active" ? "4 4" : undefined}
                className={link.status === "active" ? "animate-pulse" : ""}
              />
            </g>
          )
        })}

        {/* Nodes */}
        {positionedNodes.map((node) => {
          const isSelected = node.id === selectedNodeId
          const isHovered = hoveredNode?.id === node.id
          const color = getNodeColor(node)
          const radius =
            node.type === "target" ? 18 : node.type === "scanner" ? 12 : node.type === "endpoint" ? 8 : 6

          return (
            <g
              key={node.id}
              className="cursor-pointer"
              onClick={() => onSelectNode?.(node)}
              onMouseEnter={() => setHoveredNode(node)}
              onMouseLeave={() => setHoveredNode(null)}
            >
              {/* Outer Selection/Pulse Ring */}
              {(isSelected || isHovered) && (
                <circle
                  cx={node.cx}
                  cy={node.cy}
                  r={radius + 7}
                  fill="none"
                  stroke={color}
                  strokeWidth="1.5"
                  strokeDasharray="3 3"
                  className="animate-spin origin-center"
                />
              )}

              {/* Node Core */}
              <circle
                cx={node.cx}
                cy={node.cy}
                r={radius}
                fill="#0a101f"
                stroke={color}
                strokeWidth={isSelected ? 2.5 : 1.5}
                filter={node.severity === "Critical" ? "url(#glow-red)" : "url(#glow-cyan)"}
              />

              {/* Inner Node Accent */}
              <circle
                cx={node.cx}
                cy={node.cy}
                r={radius * 0.45}
                fill={color}
                className={node.severity === "Critical" ? "animate-pulse" : ""}
              />

              {/* Label */}
              <text
                x={node.cx}
                y={node.cy + radius + 12}
                textAnchor="middle"
                fill={isSelected ? "#00f0ff" : "#8fa0bc"}
                fontSize={node.type === "target" ? "10px" : "8.5px"}
                fontFamily="JetBrains Mono, monospace"
                fontWeight={isSelected ? "bold" : "normal"}
              >
                {node.label.length > 18 ? `${node.label.slice(0, 16)}...` : node.label}
              </text>
            </g>
          )
        })}
      </svg>

      {/* Floating HUD Tooltip */}
      {hoveredNode && (
        <div
          className="absolute z-20 pointer-events-none bg-surface/95 border border-cyan/40 p-2.5 rounded shadow-xl font-mono text-[11px] backdrop-blur-sm animate-in fade-in zoom-in-95 duration-100"
          style={{
            left: Math.min(width - 180, Math.max(10, ((hoveredNode.x ?? centerX) / width) * 100)) + "%",
            top: Math.min(height - 90, Math.max(10, ((hoveredNode.y ?? centerY) / height) * 100)) + "%",
          }}
        >
          <div className="flex items-center gap-1.5 text-ink font-semibold">
            {hoveredNode.type === "vulnerability" ? (
              <ShieldAlert size={12} className="text-critical" />
            ) : hoveredNode.type === "target" ? (
              <Globe size={12} className="text-cyan" />
            ) : (
              <Server size={12} className="text-violet" />
            )}
            <span className="truncate max-w-[180px]">{hoveredNode.label}</span>
          </div>
          <div className="text-ink-3 text-[10px] mt-1">
            TYPE: <span className="text-ink uppercase">{hoveredNode.type}</span>
          </div>
          {hoveredNode.severity && (
            <div className="text-ink-3 text-[10px]">
              SEVERITY: <span className="font-semibold text-critical">{hoveredNode.severity}</span>
              {hoveredNode.cvss && <span className="ml-1 text-ink">({hoveredNode.cvss})</span>}
            </div>
          )}
          {hoveredNode.details && (
            <p className="text-ink-2 text-[10px] mt-1 max-w-[200px] truncate">
              {hoveredNode.details}
            </p>
          )}
        </div>
      )}

      {/* 2D HUD Overlays */}
      <div className="absolute bottom-2.5 left-3 text-[10px] font-mono text-ink-3 flex items-center gap-4">
        <span>TOPOLOGY RADAR // 2D HUD ACTIVE</span>
        <span className="text-cyan">NODES: {nodes.length}</span>
        <span className="text-violet">LINKS: {links.length}</span>
      </div>
    </div>
  )
}

export default Topology2DFallback
