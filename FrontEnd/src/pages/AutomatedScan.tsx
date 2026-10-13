import { useEffect, useMemo, useState } from "react"
import { useParams, useNavigate } from "react-router-dom"
import {
  Pause,
  Play,
  Square,
  Target,
  Clock,
  ShieldAlert,
  ArrowRight,
  ExternalLink,
  Plus,
} from "lucide-react"
import { findingsApi, scanApi, type ApiFinding } from "../api/client"
import { CyberCard } from "../components/ui/CyberCard"
import { CyberButton } from "../components/ui/CyberButton"
import { StatWidget } from "../components/ui/StatWidget"
import { StatusPill } from "../components/ui/StatusPill"
import { SeverityBadge } from "../components/ui/SeverityBadge"
import { Terminal } from "../components/ui/Terminal"
import { CyberDrawer } from "../components/ui/CyberDrawer"
import { EmptyState } from "../components/ui/EmptyState"
import { useScanContext } from "../context/ScanContext"

const STAGES = ["validate", "discover", "crawl", "probe", "analyze", "report", "done"]

export default function AutomatedScan() {
  const { scanId: paramScanId } = useParams<{ scanId?: string }>()
  const navigate = useNavigate()

  const {
    activeScanId,
    setActiveScanId,
    scanStatus: contextStatus,
    scanActive,
    scanProgress,
    scanStage,
    logs: contextLogs,
    clearLogs,
    pauseScan,
    stopScan,
  } = useScanContext()

  // Use URL param or active context scan
  const currentScanId = paramScanId || activeScanId

  const [findings, setFindings] = useState<ApiFinding[]>([])
  const [selectedFinding, setSelectedFinding] = useState<ApiFinding | null>(null)
  const [drawerOpen, setDrawerOpen] = useState(false)
  const [busyAction, setBusyAction] = useState(false)
  const [targetUrl, setTargetUrl] = useState("")

  // If URL has a scanId different from context, sync it
  useEffect(() => {
    if (paramScanId && paramScanId !== activeScanId) {
      setActiveScanId(paramScanId)
    }
  }, [paramScanId, activeScanId, setActiveScanId])

  // Load findings and target info for current scan
  useEffect(() => {
    if (!currentScanId) return

    let cancelled = false
    const fetchFindings = async () => {
      try {
        const [nextFindings, scanDetails] = await Promise.all([
          findingsApi.list(currentScanId),
          scanApi.status(currentScanId).catch(() => null),
        ])
        if (cancelled) return
        setFindings(nextFindings)
        if (scanDetails) {
          // check target if available from first finding
          if (nextFindings[0]?.target) {
            setTargetUrl(nextFindings[0].target)
          }
        }
      } catch {
        // ignore
      }
    }

    void fetchFindings()
    const timer = setInterval(fetchFindings, 3000)
    return () => {
      cancelled = true
      clearInterval(timer)
    }
  }, [currentScanId])

  const stageIndex = useMemo(
    () => STAGES.indexOf((scanStage || "").toLowerCase()),
    [scanStage],
  )

  const isPaused = contextStatus?.status === "paused"

  const handleTogglePause = async () => {
    if (!currentScanId) return
    setBusyAction(true)
    try {
      if (isPaused) {
        // Resume by starting or unpausing
        await pauseScan(currentScanId)
      } else {
        await pauseScan(currentScanId)
      }
    } finally {
      setBusyAction(false)
    }
  }

  const handleStop = async () => {
    if (!currentScanId) return
    if (window.confirm("Are you sure you want to stop this running DAST scan?")) {
      setBusyAction(true)
      try {
        await stopScan(currentScanId)
      } finally {
        setBusyAction(false)
      }
    }
  }

  if (!currentScanId) {
    return (
      <div className="p-6 max-w-4xl mx-auto min-h-[70vh] flex items-center justify-center">
        <EmptyState
          title="NO SCAN SESSION SELECTED"
          description="There is no active or selected DAST scan workspace. Select an existing scan from the overview or launch a new scan against an authorised target."
          actionLabel="LAUNCH NEW SCAN"
          actionIcon={<Plus size={14} />}
          onAction={() => navigate("/scans/new")}
        />
      </div>
    )
  }

  return (
    <div className="p-4 sm:p-6 lg:p-8 max-w-[1700px] mx-auto space-y-6">
      {/* Top Header */}
      <div className="flex flex-wrap items-start justify-between gap-4 border-b border-border pb-5">
        <div>
          <div className="flex items-center gap-2.5">
            <span
              className={`w-2.5 h-2.5 rounded-full ${
                scanActive ? "bg-cyan shadow-[0_0_10px_#00f0ff] animate-pulse" : "bg-emerald"
              }`}
            />
            <h1 className="text-xl font-bold tracking-wider text-ink uppercase font-display">
              Live Automated DAST Workspace
            </h1>
            <StatusPill status={contextStatus?.status || (scanActive ? "running" : "ready")} />
          </div>
          <p className="text-xs text-ink-3 font-mono mt-1">
            Scan ID: <span className="text-cyan font-bold">{currentScanId}</span>
            {targetUrl && (
              <>
                {" "}
                · Target: <span className="text-ink-2">{targetUrl}</span>
              </>
            )}
          </p>
        </div>

        {/* Scan Actions */}
        <div className="flex items-center gap-2.5">
          {scanActive && (
            <>
              <CyberButton
                variant="secondary"
                size="sm"
                loading={busyAction}
                icon={isPaused ? <Play size={13} fill="currentColor" /> : <Pause size={13} />}
                onClick={() => void handleTogglePause()}
              >
                {isPaused ? "RESUME" : "PAUSE"}
              </CyberButton>

              <CyberButton
                variant="danger"
                size="sm"
                loading={busyAction}
                icon={<Square size={13} fill="currentColor" />}
                onClick={() => void handleStop()}
              >
                ABORT SCAN
              </CyberButton>
            </>
          )}

          <CyberButton
            variant="outline"
            size="sm"
            icon={<ExternalLink size={13} />}
            onClick={() => navigate(`/findings?scan_id=${encodeURIComponent(currentScanId)}`)}
          >
            VIEW FINDINGS ({findings.length})
          </CyberButton>
        </div>
      </div>

      {/* Progress & Stage Pipeline */}
      <CyberCard title="Dynamic Pipeline Execution Stage" icon={<Target size={16} />}>
        <div className="space-y-4 pt-1">
          {/* Progress Bar with Glow */}
          <div className="space-y-1.5 font-mono">
            <div className="flex justify-between items-center text-xs">
              <span className="text-ink font-semibold">
                EXECUTION PROGRESS: <span className="text-cyan">{scanProgress}%</span>
              </span>
              <span className="text-ink-3 text-[11px]">
                STAGE: <span className="text-ink font-bold uppercase">{scanStage}</span>
              </span>
            </div>
            <div className="h-2.5 w-full bg-surface rounded-full overflow-hidden border border-border">
              <div
                className="h-full bg-gradient-to-r from-cyan/80 to-cyan shadow-[0_0_12px_#00f0ff] transition-all duration-300 rounded-full"
                style={{ width: `${Math.max(2, scanProgress)}%` }}
              />
            </div>
          </div>

          {/* Stepper Stages */}
          <div className="grid grid-cols-7 gap-1 pt-2">
            {STAGES.map((stg, idx) => {
              const isPast = stageIndex > idx
              const isCurrent = stageIndex === idx
              return (
                <div
                  key={stg}
                  className={`p-2 rounded border text-center transition-all font-mono text-[11px] ${
                    isCurrent
                      ? "bg-cyan/15 border-cyan text-cyan font-bold shadow-[0_0_10px_rgba(0,240,255,0.2)]"
                      : isPast
                        ? "bg-surface border-border text-ink-3"
                        : "bg-surface/40 border-border/50 text-ink-3/50"
                  }`}
                >
                  <div className="text-[9px] uppercase tracking-wider">{stg}</div>
                  <div className="text-[10px] mt-0.5 font-bold">
                    {isCurrent ? "ACTIVE" : isPast ? "DONE" : "PENDING"}
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      </CyberCard>

      {/* Telemetry Metrics Row */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatWidget
          label="REQUESTS TRANSMITTED"
          value={String(contextStatus?.requests_sent || 0)}
          sublabel="Active HTTP probes"
          accent="cyan"
        />

        <StatWidget
          label="URLS DISCOVERED"
          value={String(contextStatus?.urls_discovered || 0)}
          sublabel="Crawled origin endpoints"
          accent="violet"
        />

        <StatWidget
          label="DETECTED FINDINGS"
          value={String(findings.length)}
          sublabel="Confirmed vulnerabilities"
          accent={findings.length > 0 ? "critical" : "emerald"}
          onClick={() => navigate(`/findings?scan_id=${encodeURIComponent(currentScanId)}`)}
        />

        <StatWidget
          label="DURATION"
          value={
            contextStatus?.duration_s
              ? `${Math.round(contextStatus.duration_s)}s`
              : scanActive
                ? "RUNNING..."
                : "COMPLETED"
          }
          sublabel="Wall clock test duration"
          icon={<Clock size={16} />}
        />
      </div>

      {/* Grid: Terminal Left (7 cols) + Live Findings Right (5 cols) */}
      <div className="grid lg:grid-cols-12 gap-6">
        {/* Terminal Live Stream (7 cols) */}
        <div className="lg:col-span-7">
          <Terminal
            title={`Real-Time Engine Telemetry [${currentScanId.slice(0, 8)}]`}
            logs={contextLogs}
            onClear={clearLogs}
            maxHeight="460px"
          />
        </div>

        {/* Live Detected Vulnerabilities (5 cols) */}
        <div className="lg:col-span-5">
          <CyberCard
            title="Confirmed Security Findings"
            subtitle={`${findings.length} issues identified during execution`}
            icon={<ShieldAlert size={16} />}
            noPadding
          >
            {findings.length === 0 ? (
              <div className="py-16 text-center text-xs text-ink-3 font-mono">
                {scanActive ? (
                  <div className="flex flex-col items-center gap-2">
                    <div className="w-6 h-6 rounded-full border border-cyan border-t-transparent animate-spin" />
                    <span>Awaiting initial vulnerability probes...</span>
                  </div>
                ) : (
                  <span>No vulnerabilities detected in this target run.</span>
                )}
              </div>
            ) : (
              <div className="max-h-[440px] overflow-y-auto divide-y divide-border font-mono text-xs">
                {findings.map((finding) => (
                  <div
                    key={finding.id}
                    onClick={() => {
                      setSelectedFinding(finding)
                      setDrawerOpen(true)
                    }}
                    className="p-3.5 hover:bg-surface transition-colors cursor-pointer flex items-start justify-between gap-3"
                  >
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2">
                        <SeverityBadge severity={finding.severity} cvss={finding.cvss} />
                        <span className="text-ink font-semibold truncate font-sans text-xs">
                          {finding.title}
                        </span>
                      </div>
                      <p className="text-[11px] text-ink-3 truncate mt-1">
                        {finding.target}
                      </p>
                    </div>

                    <ArrowRight size={14} className="text-ink-3 shrink-0 mt-1" />
                  </div>
                ))}
              </div>
            )}
          </CyberCard>
        </div>
      </div>

      {/* Forensic Drawer */}
      <CyberDrawer
        isOpen={drawerOpen}
        onClose={() => setDrawerOpen(false)}
        title={selectedFinding?.title || "Vulnerability Details"}
        subtitle={selectedFinding ? `ID: ${selectedFinding.id}` : undefined}
        badge={
          selectedFinding && (
            <SeverityBadge severity={selectedFinding.severity} cvss={selectedFinding.cvss} />
          )
        }
      >
        {selectedFinding && (
          <div className="space-y-6 font-mono text-xs">
            <div>
              <label className="text-[10px] uppercase text-ink-3 block mb-1">TARGET URL</label>
              <div className="p-2 rounded bg-surface border border-border text-ink break-all select-all">
                {selectedFinding.target}
              </div>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="text-[10px] uppercase text-ink-3 block mb-1">CATEGORY</label>
                <div className="p-2 rounded bg-surface border border-border text-cyan">
                  {selectedFinding.category}
                </div>
              </div>
              <div>
                <label className="text-[10px] uppercase text-ink-3 block mb-1">PARAMETER</label>
                <div className="p-2 rounded bg-surface border border-border text-ink-2">
                  {selectedFinding.parameter || "none"}
                </div>
              </div>
            </div>

            {selectedFinding.description && (
              <div>
                <label className="text-[10px] uppercase text-ink-3 block mb-1 font-semibold">
                  ANALYSIS & IMPACT
                </label>
                <div className="p-3 rounded bg-surface border border-border text-ink-2 font-sans leading-relaxed">
                  {selectedFinding.description}
                </div>
              </div>
            )}

            {selectedFinding.evidence && (
              <div>
                <label className="text-[10px] uppercase text-ink-3 block mb-1 font-semibold">
                  EVIDENCE LOGS
                </label>
                <pre className="p-3 rounded bg-[#03060c] border border-border text-ink-2 text-[11px] overflow-x-auto whitespace-pre-wrap">
                  {selectedFinding.evidence}
                </pre>
              </div>
            )}

            {selectedFinding.recommendation && (
              <div>
                <label className="text-[10px] uppercase text-ink-3 block mb-1 font-semibold text-emerald">
                  REMEDIATION
                </label>
                <div className="p-3 rounded bg-emerald/5 border border-emerald/30 text-ink font-sans leading-relaxed">
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
