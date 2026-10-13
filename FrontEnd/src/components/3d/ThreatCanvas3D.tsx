import { Canvas } from "@react-three/fiber"
import { ThreatTopology3D } from "./ThreatTopology3D"
import type { TopologyNode, TopologyLink } from "./Topology2DFallback"

export interface ThreatCanvas3DProps {
  nodes: TopologyNode[]
  links: TopologyLink[]
  selectedNodeId?: string | null
  onSelectNode?: (node: TopologyNode) => void
  reducedMotion?: boolean
  resetTrigger?: number
}

export default function ThreatCanvas3D({
  nodes,
  links,
  selectedNodeId,
  onSelectNode,
  reducedMotion = false,
  resetTrigger = 0,
}: ThreatCanvas3DProps) {
  return (
    <Canvas
      dpr={[1, 2]}
      camera={{ position: [0, 6, 14], fov: 45 }}
      gl={{
        antialias: true,
        alpha: true,
        powerPreference: "high-performance",
      }}
    >
      <ThreatTopology3D
        nodes={nodes}
        links={links}
        selectedNodeId={selectedNodeId}
        onSelectNode={onSelectNode}
        reducedMotion={reducedMotion}
        resetTrigger={resetTrigger}
      />
    </Canvas>
  )
}
