import { useRef, useState, useMemo, useEffect } from "react"
import { useFrame, useThree } from "@react-three/fiber"
import { OrbitControls, Html } from "@react-three/drei"
import * as THREE from "three"
import type { TopologyNode, TopologyLink } from "./Topology2DFallback"

interface ThreatTopology3DProps {
  nodes: TopologyNode[]
  links: TopologyLink[]
  selectedNodeId?: string | null
  onSelectNode?: (node: TopologyNode) => void
  reducedMotion?: boolean
  resetTrigger?: number
}

interface Node3D extends TopologyNode {
  position: [number, number, number]
  color: string
  size: number
}

function CameraControls({ resetTrigger = 0 }: { resetTrigger?: number }) {
  const { camera } = useThree()
  const controlsRef = useRef<any>(null)

  useEffect(() => {
    if (resetTrigger > 0) {
      camera.position.set(0, 6, 14)
      camera.lookAt(0, 0, 0)
      if (controlsRef.current) {
        controlsRef.current.target.set(0, 0, 0)
        controlsRef.current.update()
      }
    }
  }, [resetTrigger, camera])

  return (
    <OrbitControls
      ref={controlsRef}
      enableDamping
      dampingFactor={0.05}
      rotateSpeed={0.6}
      zoomSpeed={0.7}
      minDistance={3}
      maxDistance={25}
    />
  )
}

export function ThreatTopology3D({
  nodes,
  links,
  selectedNodeId,
  onSelectNode,
  reducedMotion = false,
  resetTrigger = 0,
}: ThreatTopology3DProps) {
  const [hoveredNode, setHoveredNode] = useState<Node3D | null>(null)
  const groupRef = useRef<THREE.Group>(null)

  // Compute 3D Positions for Nodes
  const nodes3D: Node3D[] = useMemo(() => {
    const endpoints = nodes.filter((n) => n.type === "endpoint")
    const vulns = nodes.filter((n) => n.type === "vulnerability")

    return nodes.map((node) => {
      let position: [number, number, number] = [0, 0, 0]
      let color = "#00f0ff"
      let size = 0.5

      if (node.type === "target") {
        position = [0, 0, 0]
        color = "#38bdf8"
        size = 0.9
      } else if (node.type === "scanner") {
        position = [-7, 2, 2]
        color = "#2563eb"
        size = 0.6
      } else if (node.type === "endpoint") {
        const epIdx = endpoints.findIndex((n) => n.id === node.id)
        const count = Math.max(1, endpoints.length)
        const angle = (epIdx / count) * 2 * Math.PI
        const radius = 4.2
        const yOffset = Math.sin(angle * 3) * 0.8
        position = [
          Math.cos(angle) * radius,
          yOffset,
          Math.sin(angle) * radius,
        ]
        color = "#8b5cf6"
        size = 0.45
      } else if (node.type === "vulnerability") {
        const vIdx = vulns.findIndex((n) => n.id === node.id)
        const count = Math.max(1, vulns.length)
        const angle = (vIdx / count) * 2 * Math.PI + 0.3
        const radius = 6.8
        const yOffset = Math.sin(angle * 2) * 1.5
        position = [
          Math.cos(angle) * radius,
          yOffset,
          Math.sin(angle) * radius,
        ]

        switch (node.severity?.toLowerCase()) {
          case "critical":
            color = "#f43f5e"
            size = 0.55
            break
          case "high":
            color = "#f97316"
            size = 0.48
            break
          case "medium":
            color = "#eab308"
            size = 0.42
            break
          case "low":
            color = "#06b6d4"
            size = 0.36
            break
          default:
            color = "#64748b"
            size = 0.32
        }
      }

      return {
        ...node,
        position,
        color,
        size,
      }
    })
  }, [nodes])

  const nodeMap = useMemo(() => new Map(nodes3D.map((n) => [n.id, n])), [nodes3D])

  // Compute 3D Line Geometries
  const linkLines = useMemo(() => {
    return links
      .map((link) => {
        const s = nodeMap.get(link.source)
        const t = nodeMap.get(link.target)
        if (!s || !t) return null
        const points = [
          new THREE.Vector3(...s.position),
          new THREE.Vector3(...t.position),
        ]
        const geometry = new THREE.BufferGeometry().setFromPoints(points)
        const isExploited = link.status === "exploited"
        const isSelected = s.id === selectedNodeId || t.id === selectedNodeId
        return {
          geometry,
          color: isSelected
            ? "#38bdf8"
            : isExploited
              ? "#f43f5e"
              : "#252d3d",
        }
      })
      .filter(Boolean)
  }, [links, nodeMap, selectedNodeId])

  // Ambient slow rotation (disabled in reduced-motion mode)
  useFrame((_, delta) => {
    if (!reducedMotion && groupRef.current) {
      groupRef.current.rotation.y += delta * 0.08
    }
  })

  return (
    <>
      {/* Lighting */}
      <ambientLight intensity={0.4} />
      <pointLight position={[10, 15, 10]} intensity={1.0} color="#38bdf8" />
      <pointLight position={[-10, -10, -10]} intensity={0.6} color="#8b5cf6" />
      <pointLight position={[0, 0, 0]} intensity={1.2} color="#2563eb" distance={8} />

      {/* Camera & Controls */}
      <CameraControls resetTrigger={resetTrigger} />

      {/* Rotating Scene Graph */}
      <group ref={groupRef}>
        {/* Central Orbital Rings */}
        <mesh rotation={[Math.PI / 2, 0, 0]}>
          <ringGeometry args={[4.15, 4.25, 64]} />
          <meshBasicMaterial color="#38bdf8" transparent opacity={0.12} side={THREE.DoubleSide} />
        </mesh>
        <mesh rotation={[Math.PI / 2.5, 0.4, 0]}>
          <ringGeometry args={[6.75, 6.85, 64]} />
          <meshBasicMaterial color="#8b5cf6" transparent opacity={0.08} side={THREE.DoubleSide} />
        </mesh>

        {/* Links */}
        {linkLines.map((line, idx) => (
          <primitive
            key={`line-${idx}`}
            object={
              new THREE.Line(
                line!.geometry,
                new THREE.LineBasicMaterial({
                  color: line!.color,
                  transparent: true,
                  opacity: 0.6,
                }),
              )
            }
          />
        ))}

        {/* Nodes */}
        {nodes3D.map((node) => {
          const isSelected = node.id === selectedNodeId
          const isHovered = hoveredNode?.id === node.id

          return (
            <group
              key={node.id}
              position={node.position}
              onClick={(e) => {
                e.stopPropagation()
                onSelectNode?.(node)
              }}
              onPointerOver={(e) => {
                e.stopPropagation()
                setHoveredNode(node)
                document.body.style.cursor = "pointer"
              }}
              onPointerOut={() => {
                setHoveredNode(null)
                document.body.style.cursor = "auto"
              }}
            >
              {/* Outer Selection/Pulse Glow Shell */}
              {(isSelected || isHovered) && (
                <mesh>
                  <sphereGeometry args={[node.size * 1.5, 16, 16]} />
                  <meshBasicMaterial
                    color={node.color}
                    wireframe
                    transparent
                    opacity={0.4}
                  />
                </mesh>
              )}

              {/* Node Core */}
              <mesh>
                <sphereGeometry args={[node.size, 32, 32]} />
                <meshStandardMaterial
                  color={node.color}
                  emissive={node.color}
                  emissiveIntensity={isSelected ? 1.5 : isHovered ? 1.0 : 0.4}
                  roughness={0.2}
                  metalness={0.8}
                />
              </mesh>

              {/* Hover HTML Tooltip */}
              {isHovered && (
                <Html distanceFactor={14} position={[0, node.size + 0.5, 0]} center>
                  <div className="pointer-events-none bg-surface/95 border border-cyan/50 p-2.5 rounded shadow-2xl font-mono text-[11px] text-ink whitespace-nowrap backdrop-blur-md">
                    <div className="font-bold flex items-center gap-1.5 text-cyan">
                      <span
                        className="w-2 h-2 rounded-full shrink-0"
                        style={{ backgroundColor: node.color }}
                      />
                      <span>{node.label}</span>
                    </div>
                    <div className="text-[10px] text-ink-3 mt-0.5">
                      TYPE: <span className="text-ink uppercase">{node.type}</span>
                    </div>
                    {node.severity && (
                      <div className="text-[10px] text-ink-3">
                        SEVERITY:{" "}
                        <span className="font-semibold text-critical">
                          {node.severity}
                        </span>
                        {node.cvss && <span> (CVSS {node.cvss})</span>}
                      </div>
                    )}
                    {node.details && (
                      <div className="text-[9px] text-ink-2 max-w-xs truncate mt-0.5">
                        {node.details}
                      </div>
                    )}
                  </div>
                </Html>
              )}
            </group>
          )
        })}
      </group>
    </>
  )
}

export default ThreatTopology3D
