import { useEffect, useMemo, useState, useCallback } from "react"
import { useNavigate } from "react-router-dom"
import {
  ShieldAlert,
  Target,
  Cpu,
  RefreshCw,
  Plus,
  Zap,
  Radio,
  FileText,
} from "lucide-react"
import { findingsApi, scanApi, integrationsApi, type ApiFinding, type ScanItem } from "../api/client"
import { ThreatCanvas } from "../components/3d/ThreatCanvas"
import type { TopologyNode, TopologyLink } from "../components/3d/Topology2DFallback"
import { StatWidget } from "../components/ui/StatWidget"
import { CyberCard } from "../components/ui/CyberCard"
import { CyberButton } from "../components/ui/CyberButton"
import { CyberTable } from "../components/ui/CyberTable"
import { SeverityBadge } from "../components/ui/SeverityBadge"
import { StatusPill } from "../components/ui/StatusPill"
import { CyberDrawer } from "../components/ui/CyberDrawer"
import { ErrorState } from "../components/ui/ErrorState"
import { EmptyState } from "../components/ui/EmptyState"
import { useScanContext } from "../context/ScanContext"
import { calculatePosture } from "../utils/posture"

export default function Overview() {
  const navigate = useNavigate()
  const {
    backendOnline,
    backendLatency,
    scanActive,
    setActiveScanId,
    activeScanId,
  } = useScanContext()

  const [scans, setScans] = useState<ScanItem[]>([])
  const [findings, setFindings] = useState<ApiFinding[]>([])
  const [integrations, setIntegrations] = useState<any>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [selectedFinding, setSelectedFinding] = useState<ApiFinding | null>(null)
  const [drawerOpen, setDrawerOpen] = useState(false)

  const loadData = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const [scansList, findingsList, intelStatus] = await Promise.all([
        scanApi.list(),
        findingsApi.list(),
        integrationsApi.status().catch(() => null),
      ])
      setScans(scansList)
      setFindings(findingsList)
      setIntegrations(intelStatus)
    } catch (err: any) {
      setError(err.message || "Failed to query backend engine telemetry.")
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void loadData()
  }, [loadData])

  // Real-Data Truthful Posture Calculation
  const postureData = useMemo(() => {
    return calculatePosture(backendOnline, scans.length, findings)
  }, [backendOnline, scans.length, findings])

  const criticalFindings = useMemo(
    () => findings.filter((f) => f.severity?.toLowerCase() === "critical"),
    [findings],
  )
  const highFindings = useMemo(
    () => findings.filter((f) => f.severity?.toLowerCase() === "high"),
    [findings],
  )

  const totalUrlsDiscovered = useMemo(() => {
    return scans.reduce((acc, s) => acc + (s.urls_discovered || 0), 0)
  }, [scans])

  // Construct Real 3D Topology Nodes and Links (Strictly No Fake Nodes)
  const { topologyNodes, topologyLinks } = useMemo(() => {
    const nodes: TopologyNode[] = []
    const links: TopologyLink[] = []

    if (scans.length === 0) {
      return { topologyNodes: [], topologyLinks: [] }
    }

    // 1. Scanner Node
    nodes.push({
      id: "scanner-core",
      label: "CENTRIX PROBE",
      type: "scanner",
      details: "DAST Engine Probe",
    })

    // 2. Primary Target Node from actual scan data
    const primaryScan = scans[0]
    const primaryTarget = primaryScan?.target || ""
    const targetLabel = primaryTarget ? primaryTarget.replace(/^https?:\/\//, "") : "TARGET"

    nodes.push({
      id: "target-root",
      label: targetLabel,
      type: "target",
      details: `Target: ${primaryTarget}`,
    })

    // Link Scanner to Target
    links.push({
      source: "scanner-core",
      target: "target-root",
      status: scanActive ? "active" : "scanned",
    })

    // 3. Real Endpoints & Findings from Real Data
    const endpointMap = new Map<string, string>()

    findings.slice(0, 16).forEach((finding, idx) => {
      let path = "/api"
      try {
        const u = new URL(finding.target)
        path = u.pathname || "/endpoint"
      } catch {
        path = finding.target.slice(0, 24) || `/ep-${idx + 1}`
      }

      const epId = `ep-${path}`
      if (!endpointMap.has(epId)) {
        endpointMap.set(epId, path)
        nodes.push({
          id: epId,
          label: path,
          type: "endpoint",
          details: `Endpoint: ${finding.target}`,
        })
        links.push({
          source: "target-root",
          target: epId,
          status: "scanned",
        })
      }

      // Vulnerability Node connected to this endpoint
      const vulnId = `vuln-${finding.id}`
      nodes.push({
        id: vulnId,
        label: finding.title,
        type: "vulnerability",
        severity: finding.severity as any,
        cvss: finding.cvss,
        details: `${finding.category} - Parameter: ${finding.parameter || "none"}`,
      })

      links.push({
        source: epId,
        target: vulnId,
        status: finding.severity?.toLowerCase() === "critical" ? "exploited" : "scanned",
      })
    })

    return { topologyNodes: nodes, topologyLinks: links }
  }, [scans, findings, scanActive])

  const handleNodeSelect = (node: TopologyNode) => {
    if (node.type === "vulnerability") {
      const realId = node.id.replace(/^vuln-/, "")
      const match = findings.find((f) => f.id === realId)
      if (match) {
        setSelectedFinding(match)
        setDrawerOpen(true)
      }
    }
  }

  const openScan = (scanId: string) => {
    setActiveScanId(scanId)
    navigate(`/scans/${encodeURIComponent(scanId)}`)
  }

  const openFindingDetail = (f: ApiFinding) => {
    setSelectedFinding(f)
    setDrawerOpen(true)
  }

  const scanColumns = [
    {
      key: "id",
      title: "SCAN ID",
      width: "140px",
      render: (s: ScanItem) => (
        <span
          className="font-mono text-cyan font-semibold text-xs hover:underline cursor-pointer"
          onClick={() => openScan(s.id)}
        >
          {s.id}
        </span>
      ),
    },
    {
      key: "target",
      title: "TARGET URL",
      render: (s: ScanItem) => (
        <span className="text-ink font-mono text-xs truncate max-w-xs block">
          {s.target}
        </span>
      ),
    },
    {
      key: "status",
      title: "STATUS",
      width: "140px",
      render: (s: ScanItem) => <StatusPill status={s.status} />,
    },
    {
      key: "findings_count",
      title: "FINDINGS",
      width: "110px",
      render: (s: ScanItem) => (
        <span className="font-mono text-xs text-ink-2 font-bold">
          {s.findings_count}
        </span>
      ),
    },
    {
      key: "action",
      title: "",
      width: "100px",
      align: "right" as const,
      render: (s: ScanItem) => (
        <CyberButton
          size="xs"
          variant="outline"
          onClick={(e) => {
            e.stopPropagation()
            openScan(s.id)
          }}
        >
          INSPECT
        </CyberButton>
      ),
    },
  ]

  const findingColumns = [
    {
      key: "severity",
      title: "SEV",
      width: "120px",
      render: (f: ApiFinding) => (
        <SeverityBadge severity={f.severity} cvss={f.cvss} />
      ),
    },
    {
      key: "title",
      title: "VULNERABILITY",
      render: (f: ApiFinding) => (
        <div>
          <span
            className="text-ink font-medium text-xs hover:text-cyan cursor-pointer transition-colors block"
            onClick={() => openFindingDetail(f)}
          >
            {f.title}
          </span>
          <span className="text-[10px] text-ink-3 font-mono">
            {f.category} · Parameter: {f.parameter || "none"}
          </span>
        </div>
      ),
    },
    {
      key: "target",
      title: "TARGET PATH",
      render: (f: ApiFinding) => (
        <span className="text-ink-2 font-mono text-[11px] truncate max-w-xs block">
          {f.target}
        </span>
      ),
    },
    {
      key: "action",
      title: "",
      width: "90px",
      align: "right" as const,
      render: (f: ApiFinding) => (
        <CyberButton
          size="xs"
          variant="ghost"
          onClick={() => openFindingDetail(f)}
        >
          DETAILS
        </CyberButton>
      ),
    },
  ]

  return (
    <div className="p-4 sm:p-6 lg:p-8 max-w-[1700px] mx-auto space-y-6">
      {/* Executive Command Header */}
      <div className="flex flex-wrap items-start justify-between gap-4 border-b border-border pb-5">
        <div>
          <div className="flex items-center gap-2.5">
            <span className="w-2.5 h-2.5 rounded-full bg-cyan shadow-[0_0_10px_#00f0ff] animate-pulse" />
            <h1 className="text-xl font-bold tracking-wider text-ink uppercase font-display">
              CENTRIX Command Center & Threat Surface
            </h1>
          </div>
          <p className="text-xs text-ink-3 font-mono mt-1">
            Dynamic application security telemetry, live vector mapping, and verified vulnerability exposure.
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <CyberButton
            variant="secondary"
            size="sm"
            icon={<RefreshCw size={13} className={loading ? "animate-spin" : ""} />}
            onClick={() => void loadData()}
          >
            REFRESH
          </CyberButton>

          <CyberButton
            variant="primary"
            size="sm"
            hudCorners
            icon={<Plus size={14} />}
            onClick={() => navigate("/scans/new")}
          >
            LAUNCH NEW DAST SCAN
          </CyberButton>
        </div>
      </div>

      {error && (
        <ErrorState
          title="Telemetry API Query Failed"
          message={error}
          isOffline={backendOnline === false}
          onRetry={() => void loadData()}
        />
      )}

      {/* Top Telemetry KPI Row */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatWidget
          label="SECURITY POSTURE"
          value={postureData.score}
          sublabel={postureData.sublabel}
          accent={postureData.accent}
          progress={postureData.progress}
          trend={postureData.trend}
        />

        <StatWidget
          label="ACTIVE AUDITS"
          value={scanActive ? "1 ACTIVE" : `${scans.length} ARCHIVED`}
          sublabel={scanActive ? "Engine probes active" : "Scanner idle"}
          icon={<Cpu size={18} />}
          accent={scanActive ? "cyan" : "default"}
          onClick={() => navigate(activeScanId ? `/scans/${encodeURIComponent(activeScanId)}` : "/scans/new")}
        />

        <StatWidget
          label="CRITICAL FINDINGS"
          value={String(criticalFindings.length)}
          sublabel={`${highFindings.length} High severity issues`}
          icon={<ShieldAlert size={18} />}
          accent={criticalFindings.length > 0 ? "critical" : highFindings.length > 0 ? "high" : "emerald"}
          onClick={() => navigate("/findings")}
        />

        <StatWidget
          label="ATTACK SURFACE"
          value={`${totalUrlsDiscovered} URLS`}
          sublabel={`${scans.length} Tested Scopes`}
          icon={<Target size={18} />}
          accent="violet"
          onClick={() => navigate("/risk-posture")}
        />
      </div>

      {/* Central 3D Threat Topology Viewport */}
      <CyberCard
        title="Dynamic Attack Vector & Attack Surface Topology"
        subtitle={
          scans.length > 0
            ? `Target: ${scans[0]?.target || "Audit Scope"} · ${findings.length} findings mapped`
            : "No active target topology mapped"
        }
        icon={<Zap size={16} />}
        noPadding
      >
        <ThreatCanvas
          nodes={topologyNodes}
          links={topologyLinks}
          onSelectNode={handleNodeSelect}
          onLaunchScan={() => navigate("/scans/new")}
          height="450px"
        />
      </CyberCard>

      {/* Grid: Recent Scans + High Impact Findings */}
      <div className="grid lg:grid-cols-12 gap-6">
        {/* Recent Scans (5 cols) */}
        <div className="lg:col-span-5 space-y-4">
          <CyberCard
            title="Recent Scan Executions"
            subtitle={`${scans.length} target assessments registered`}
            icon={<Target size={16} />}
            action={
              <CyberButton
                size="xs"
                variant="ghost"
                onClick={() => navigate("/scans/new")}
              >
                + NEW SCAN
              </CyberButton>
            }
            noPadding
          >
            {scans.length === 0 && !loading ? (
              <EmptyState
                compact
                title="NO SCANS EXECUTED"
                description="No DAST scans have been launched yet. Run an audit against an authorized target to populate security telemetry."
                actionLabel="CONFIGURE SCAN"
                onAction={() => navigate("/scans/new")}
              />
            ) : (
              <CyberTable
                columns={scanColumns}
                data={scans.slice(0, 5)}
                keyExtractor={(s) => s.id}
                loading={loading}
              />
            )}
          </CyberCard>
        </div>

        {/* High Severity Findings Feed (7 cols) */}
        <div className="lg:col-span-7 space-y-4">
          <CyberCard
            title="High-Impact Threat Feed"
            subtitle="Immediate vulnerability exposures requiring remediation"
            icon={<ShieldAlert size={16} />}
            action={
              <CyberButton
                size="xs"
                variant="ghost"
                onClick={() => navigate("/findings")}
              >
                VIEW ALL FINDINGS ({findings.length})
              </CyberButton>
            }
            noPadding
          >
            {findings.length === 0 && !loading ? (
              <EmptyState
                compact
                title="NO THREATS DETECTED"
                description="Zero security vulnerabilities currently recorded in audit scope. Launch a scan to perform automated testing."
                actionLabel="START AUDIT"
                onAction={() => navigate("/scans/new")}
              />
            ) : (
              <CyberTable
                columns={findingColumns}
                data={findings.slice(0, 5)}
                keyExtractor={(f) => f.id}
                loading={loading}
              />
            )}
          </CyberCard>
        </div>
      </div>

      {/* Threat Intel & Subsystem Telemetry Status Bar */}
      <CyberCard
        title="Security Engine & Intelligence Feeds"
        subtitle="Live status of connected analysis engines"
        icon={<Radio size={16} />}
      >
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 font-mono text-xs">
          <div className="p-3 rounded bg-surface border border-border">
            <span className="text-ink-3 block text-[10px] uppercase font-semibold">
              BACKEND ENGINE
            </span>
            <div className="flex items-center gap-2 mt-1 font-bold">
              <span
                className={`w-2 h-2 rounded-full ${
                  backendOnline ? "bg-emerald shadow-[0_0_8px_#10b981]" : "bg-critical"
                }`}
              />
              <span className={backendOnline ? "text-emerald" : "text-critical"}>
                {backendOnline ? `ONLINE (${backendLatency}ms)` : "OFFLINE"}
              </span>
            </div>
          </div>

          <div className="p-3 rounded bg-surface border border-border">
            <span className="text-ink-3 block text-[10px] uppercase font-semibold">
              NUCLEI ENGINE
            </span>
            <div className="flex items-center gap-2 mt-1 font-bold">
              <span
                className={`w-2 h-2 rounded-full ${
                  integrations?.nuclei?.available
                    ? "bg-emerald shadow-[0_0_8px_#10b981]"
                    : "bg-ink-3"
                }`}
              />
              <span className="text-ink">
                {integrations?.nuclei?.available ? "READY" : "BUILT-IN"}
              </span>
            </div>
          </div>

          <div className="p-3 rounded bg-surface border border-border">
            <span className="text-ink-3 block text-[10px] uppercase font-semibold">
              CVE INTELLIGENCE
            </span>
            <div className="flex items-center gap-2 mt-1 font-bold">
              <span
                className={`w-2 h-2 rounded-full ${
                  integrations?.cve_lookup?.available
                    ? "bg-emerald shadow-[0_0_8px_#10b981]"
                    : "bg-ink-3"
                }`}
              />
              <span className="text-ink">
                {integrations?.cve_lookup?.available ? "CONNECTED" : "STANDALONE"}
              </span>
            </div>
          </div>

          <div className="p-3 rounded bg-surface border border-border">
            <span className="text-ink-3 block text-[10px] uppercase font-semibold">
              REPORTS GENERATED
            </span>
            <div className="flex items-center gap-2 mt-1 font-bold text-cyan">
              <FileText size={13} />
              <span>DELIVERABLES READY</span>
            </div>
          </div>
        </div>
      </CyberCard>

      {/* Forensic Inspection Drawer */}
      <CyberDrawer
        isOpen={drawerOpen}
        onClose={() => setDrawerOpen(false)}
        title={selectedFinding?.title || "Vulnerability Forensic Analysis"}
        subtitle={selectedFinding ? `ID: ${selectedFinding.id} · Found: ${selectedFinding.found_at}` : undefined}
        badge={
          selectedFinding && (
            <SeverityBadge
              severity={selectedFinding.severity}
              cvss={selectedFinding.cvss}
            />
          )
        }
        footer={
          <div className="flex items-center justify-between w-full">
            <span className="text-xs text-ink-3 font-mono">
              Status: <span className="text-ink font-bold">{selectedFinding?.status}</span>
            </span>
            <CyberButton
              size="xs"
              variant="primary"
              onClick={() => {
                setDrawerOpen(false)
                if (selectedFinding) {
                  navigate(`/findings/${encodeURIComponent(selectedFinding.id)}`)
                }
              }}
            >
              OPEN IN FINDINGS EXPLORER
            </CyberButton>
          </div>
        }
      >
        {selectedFinding && (
          <div className="space-y-6 font-mono text-xs">
            <div>
              <label className="text-[10px] uppercase text-ink-3 block mb-1">
                TARGET ENDPOINT
              </label>
              <div className="p-2.5 rounded bg-surface border border-border text-ink break-all select-all">
                {selectedFinding.target}
              </div>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="text-[10px] uppercase text-ink-3 block mb-1">
                  CATEGORY
                </label>
                <div className="p-2 rounded bg-surface border border-border text-cyan">
                  {selectedFinding.category}
                </div>
              </div>

              <div>
                <label className="text-[10px] uppercase text-ink-3 block mb-1">
                  CWE CLASSIFICATION
                </label>
                <div className="p-2 rounded bg-surface border border-border text-ink-2">
                  {selectedFinding.cwe || "N/A"}
                </div>
              </div>
            </div>

            {selectedFinding.description && (
              <div>
                <label className="text-[10px] uppercase text-ink-3 block mb-1 font-semibold">
                  ANALYSIS & TECHNICAL IMPACT
                </label>
                <div className="p-3 rounded bg-surface border border-border text-ink-2 font-sans text-xs leading-relaxed">
                  {selectedFinding.description}
                </div>
              </div>
            )}

            {selectedFinding.evidence && (
              <div>
                <label className="text-[10px] uppercase text-ink-3 block mb-1 font-semibold">
                  SANITIZED PROOF-OF-CONCEPT EVIDENCE
                </label>
                <pre className="p-3 rounded bg-[#03060c] border border-border text-ink-2 text-[11px] overflow-x-auto whitespace-pre-wrap font-mono">
                  {selectedFinding.evidence}
                </pre>
              </div>
            )}

            {selectedFinding.recommendation && (
              <div>
                <label className="text-[10px] uppercase text-ink-3 block mb-1 font-semibold text-emerald">
                  REMEDIATION GUIDANCE
                </label>
                <div className="p-3 rounded bg-emerald/5 border border-emerald/30 text-ink font-sans text-xs leading-relaxed">
                  {selectedFinding.recommendation}
                </div>
              </div>
            )}
          </div>
        )}
      </CyberDrawer>
    </div>
  )
}
