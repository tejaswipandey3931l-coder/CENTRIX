import { useEffect, useMemo, useState, useCallback } from "react"
import { useParams, useSearchParams, useNavigate } from "react-router-dom"
import {
  RefreshCw,
  RotateCcw,
  Search,
  Send,
  CheckCircle2,
  FolderOpen,
  Terminal,
  ShieldCheck,
} from "lucide-react"
import {
  findingsApi,
  integrationsApi,
  type ApiFinding,
} from "../api/client"
import { CyberCard } from "../components/ui/CyberCard"
import { CyberButton } from "../components/ui/CyberButton"
import { SeverityBadge } from "../components/ui/SeverityBadge"
import { CyberTable, type CyberTableColumn } from "../components/ui/CyberTable"
import { CyberDrawer } from "../components/ui/CyberDrawer"
import { CyberModal } from "../components/ui/CyberModal"
import { CyberTabs, type TabItem } from "../components/ui/CyberTabs"
import { EmptyState } from "../components/ui/EmptyState"
import { ErrorState } from "../components/ui/ErrorState"
import { useScanContext } from "../context/ScanContext"

type FindingStatus = "Open" | "In Review" | "Fixed" | "Accepted" | "Still Open" | "Needs Review"
const STATUSES: FindingStatus[] = ["Open", "In Review", "Fixed", "Accepted", "Still Open", "Needs Review"]

const isHeaderNoise = (finding: ApiFinding) =>
  finding.category === "Security Headers" ||
  finding.title.toLowerCase().startsWith("missing security header")

export default function Findings() {
  const { findingId: routeFindingId } = useParams<{ findingId?: string }>()
  const [searchParams, setSearchParams] = useSearchParams()
  const navigate = useNavigate()
  const { setRepeaterRequest, refreshStats } = useScanContext()

  const [findings, setFindings] = useState<ApiFinding[]>([])
  const [selectedFinding, setSelectedFinding] = useState<ApiFinding | null>(null)
  const [singleFindingLoading, setSingleFindingLoading] = useState(false)
  const [singleFindingError, setSingleFindingError] = useState<string | null>(null)
  const [drawerOpen, setDrawerOpen] = useState(false)
  const [drawerTab, setDrawerTab] = useState("overview")
  const [busyId, setBusyId] = useState("")
  const [message, setMessage] = useState("")
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)

  // Modal confirmation for status change
  const [pendingStatusChange, setPendingStatusChange] = useState<{
    finding: ApiFinding
    newStatus: FindingStatus
  } | null>(null)

  // Read search params
  const severityParam = searchParams.get("severity") || "All"
  const statusParam = searchParams.get("status") || "All"
  const scanFilterParam = searchParams.get("scan_id") || ""
  const searchQueryParam = searchParams.get("search") || ""

  const [query, setQuery] = useState(searchQueryParam)
  const [severityFilter, setSeverityFilter] = useState(severityParam)
  const [statusFilter, setStatusFilter] = useState(statusParam)
  const [showHeaderNoise, setShowHeaderNoise] = useState(false)

  // Sync state with URL params
  const updateUrlParams = useCallback(
    (newParams: Record<string, string>) => {
      setSearchParams((prev) => {
        const next = new URLSearchParams(prev)
        Object.entries(newParams).forEach(([k, v]) => {
          if (!v || v === "All") {
            next.delete(k)
          } else {
            next.set(k, v)
          }
        })
        return next
      })
    },
    [setSearchParams],
  )

  const load = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const result = await findingsApi.list(scanFilterParam || undefined)
      setFindings(result)
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to load findings from CENTRIX backend.")
    } finally {
      setLoading(false)
    }
  }, [scanFilterParam])

  useEffect(() => {
    void load()
  }, [load])

  // Deep-link handler: open drawer if routeFindingId is present, with direct API fetch fallback
  useEffect(() => {
    if (!routeFindingId) {
      setSingleFindingError(null)
      setSingleFindingLoading(false)
      return
    }

    // Check if already in current findings list
    const match = findings.find((f) => f.id === routeFindingId)
    if (match) {
      setSelectedFinding(match)
      setDrawerOpen(true)
      setSingleFindingError(null)
      return
    }

    // Direct backend fetch if not in the cached list
    let active = true
    setSingleFindingLoading(true)
    setSingleFindingError(null)

    findingsApi
      .get(routeFindingId)
      .then((item) => {
        if (!active) return
        setSelectedFinding(item)
        setDrawerOpen(true)
        setSingleFindingLoading(false)
      })
      .catch((err: unknown) => {
        if (!active) return
        setSingleFindingLoading(false)
        const msg = err instanceof Error ? err.message : String(err)
        setSingleFindingError(
          msg.includes("404")
            ? `Finding #${routeFindingId} not found in database or has been purged.`
            : `Failed to retrieve finding #${routeFindingId}: ${msg}`,
        )
      })

    return () => {
      active = false
    }
  }, [routeFindingId, findings])

  const hiddenHeaderNoiseCount = useMemo(
    () => findings.filter(isHeaderNoise).length,
    [findings],
  )

  // Live Counts by Severity
  const counts = useMemo(() => {
    const list = showHeaderNoise ? findings : findings.filter((f) => !isHeaderNoise(f))
    return {
      All: list.length,
      Critical: list.filter((f) => f.severity === "Critical").length,
      High: list.filter((f) => f.severity === "High").length,
      Medium: list.filter((f) => f.severity === "Medium").length,
      Low: list.filter((f) => f.severity === "Low").length,
      Info: list.filter((f) => f.severity === "Info").length,
    }
  }, [findings, showHeaderNoise])

  const filtered = useMemo(() => {
    return findings.filter((finding) => {
      if (!showHeaderNoise && isHeaderNoise(finding)) return false
      if (severityFilter !== "All" && finding.severity !== severityFilter) return false
      if (statusFilter !== "All" && finding.status !== statusFilter) return false

      if (query.trim()) {
        const needle = query.toLowerCase()
        const text = `${finding.title} ${finding.target} ${finding.parameter} ${finding.category} ${finding.cwe || ""}`.toLowerCase()
        if (!text.includes(needle)) return false
      }

      return true
    })
  }, [findings, showHeaderNoise, severityFilter, statusFilter, query])

  const handleSeverityFilterChange = (sev: string) => {
    setSeverityFilter(sev)
    updateUrlParams({ severity: sev })
  }

  const handleStatusFilterChange = (stat: string) => {
    setStatusFilter(stat)
    updateUrlParams({ status: stat })
  }

  const handleSearchChange = (val: string) => {
    setQuery(val)
    updateUrlParams({ search: val })
  }

  const confirmStatusChange = async () => {
    if (!pendingStatusChange) return
    const { finding, newStatus } = pendingStatusChange
    setBusyId(finding.id)
    try {
      const updated = await findingsApi.updateStatus(finding.id, newStatus)
      setFindings((current) =>
        current.map((item) => (item.id === updated.id ? { ...item, status: updated.status } : item)),
      )
      if (selectedFinding?.id === updated.id) {
        setSelectedFinding((prev) => (prev ? { ...prev, status: updated.status } : null))
      }
      setMessage(`Finding #${finding.id} status updated to ${newStatus}.`)
      setTimeout(() => setMessage(""), 4000)
    } catch (err: any) {
      setError(err.message || "Status update failed.")
    } finally {
      setBusyId("")
      setPendingStatusChange(null)
    }
  }

  const retest = async (findingId: string) => {
    setBusyId(findingId)
    try {
      const result = await findingsApi.retest(findingId)
      setMessage(`Retest scheduled in scan ${result.scan_id}.`)
      setTimeout(() => setMessage(""), 5000)
      void refreshStats()
    } catch (err: any) {
      setError(err.message || "Retest request failed.")
    } finally {
      setBusyId("")
    }
  }

  const pushFinding = async (findingId: string, destination: "local" | "slack" | "github" | "jira") => {
    setBusyId(findingId)
    try {
      await integrationsApi.pushFinding(findingId, destination)
      setMessage(`Dispatched finding to ${destination.toUpperCase()}.`)
      setTimeout(() => setMessage(""), 4000)
    } catch (err: any) {
      setError(err.message || "Dispatch failed.")
    } finally {
      setBusyId("")
    }
  }

  const sendToRepeaterAction = (finding: ApiFinding) => {
    setRepeaterRequest({
      scan_id: finding.scan_id,
      method: "GET",
      url: finding.target,
      headers: {
        "User-Agent": "CENTRIX-DAST/2.4",
        Accept: "*/*",
      },
      note: `Investigation for ${finding.title} (#${finding.id})`,
    })
    navigate("/manual")
  }

  const openFinding = (finding: ApiFinding) => {
    setSelectedFinding(finding)
    setDrawerOpen(true)
    navigate(`/findings/${encodeURIComponent(finding.id)}`)
  }

  const closeDrawer = () => {
    setDrawerOpen(false)
    setSelectedFinding(null)
    setSingleFindingError(null)
    if (routeFindingId) {
      navigate("/findings", { replace: true })
    }
  }

  const columns: CyberTableColumn<ApiFinding>[] = [
    {
      key: "severity",
      title: "SEVERITY",
      width: "140px",
      render: (f) => <SeverityBadge severity={f.severity} cvss={f.cvss} />,
    },
    {
      key: "title",
      title: "VULNERABILITY TITLE & CATEGORY",
      render: (f) => (
        <div className="space-y-0.5">
          <span
            onClick={() => openFinding(f)}
            className="text-ink font-semibold hover:text-cyan cursor-pointer transition-colors block text-xs"
          >
            {f.title}
          </span>
          <div className="flex items-center gap-2 text-[10px] text-ink-3 font-mono">
            <span className="text-cyan font-bold">{f.category}</span>
            {f.cwe && <span>· {f.cwe}</span>}
            {f.parameter && <span>· Param: {f.parameter}</span>}
          </div>
        </div>
      ),
    },
    {
      key: "target",
      title: "TARGET URL",
      render: (f) => (
        <span className="text-ink-2 font-mono text-xs truncate max-w-sm block">
          {f.target}
        </span>
      ),
    },
    {
      key: "status",
      title: "STATUS",
      width: "140px",
      render: (f) => (
        <select
          value={f.status}
          disabled={busyId === f.id}
          onChange={(e) =>
            setPendingStatusChange({
              finding: f,
              newStatus: e.target.value as FindingStatus,
            })
          }
          className="bg-surface border border-border focus:border-cyan/50 rounded px-2 py-1 text-xs text-ink font-mono cursor-pointer"
        >
          {STATUSES.map((status) => (
            <option key={status} value={status}>
              {status}
            </option>
          ))}
        </select>
      ),
    },
    {
      key: "actions",
      title: "ACTIONS",
      width: "180px",
      align: "right",
      render: (f) => (
        <div className="flex items-center justify-end gap-1.5">
          <CyberButton
            size="xs"
            variant="secondary"
            loading={busyId === f.id}
            icon={<RotateCcw size={11} />}
            onClick={() => void retest(f.id)}
            title="Retest this vulnerability"
          >
            RETEST
          </CyberButton>

          <CyberButton
            size="xs"
            variant="ghost"
            onClick={() => openFinding(f)}
          >
            INSPECT
          </CyberButton>
        </div>
      ),
    },
  ]

  const drawerTabs: TabItem[] = [
    { id: "overview", label: "Overview" },
    { id: "evidence", label: "Evidence" },
    { id: "remediation", label: "Remediation" },
  ]

  return (
    <div className="p-4 sm:p-6 lg:p-8 max-w-[1700px] mx-auto space-y-6">
      {/* Top Header */}
      <div className="flex flex-wrap items-start justify-between gap-4 border-b border-border pb-5">
        <div>
          <h1 className="text-xl font-bold tracking-wider text-ink uppercase font-display flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-cyan shadow-[0_0_8px_#00f0ff]" />
            Vulnerability Findings Explorer
          </h1>
          <p className="text-xs text-ink-3 font-mono mt-1">
            Triaged security vulnerabilities, validated exploit vectors, and remediation tracking.
            {scanFilterParam && (
              <span className="text-cyan ml-2">
                (Filtered by scan: <span className="font-bold">{scanFilterParam}</span>)
              </span>
            )}
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          {scanFilterParam && (
            <CyberButton
              variant="outline"
              size="sm"
              onClick={() => updateUrlParams({ scan_id: "" })}
            >
              CLEAR SCAN FILTER
            </CyberButton>
          )}

          <CyberButton
            variant="secondary"
            size="sm"
            icon={<RefreshCw size={13} className={loading ? "animate-spin" : ""} />}
            onClick={() => void load()}
          >
            REFRESH
          </CyberButton>
        </div>
      </div>

      {message && (
        <div className="p-3.5 rounded border border-emerald/40 bg-emerald/10 text-emerald text-xs font-mono flex items-center gap-2">
          <CheckCircle2 size={16} className="shrink-0" />
          <span>{message}</span>
        </div>
      )}

      {error && (
        <ErrorState
          title="Findings Query Failed"
          message={error}
          onRetry={() => void load()}
        />
      )}

      {singleFindingError && (
        <div className="p-3.5 rounded border border-critical/40 bg-critical/10 text-critical text-xs font-mono flex items-center justify-between gap-3 animate-in fade-in">
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-critical shrink-0" />
            <span>{singleFindingError}</span>
          </div>
          <CyberButton
            size="xs"
            variant="ghost"
            onClick={() => {
              setSingleFindingError(null)
              navigate("/findings", { replace: true })
            }}
          >
            DISMISS
          </CyberButton>
        </div>
      )}

      {/* Severity Filter Counters Bar */}
      <div className="flex flex-wrap items-center gap-2 pb-1 font-mono text-xs">
        {(["All", "Critical", "High", "Medium", "Low", "Info"] as const).map((sev) => {
          const isSelected = severityFilter === sev
          const count = counts[sev]
          return (
            <button
              key={sev}
              onClick={() => handleSeverityFilterChange(sev)}
              className={`px-3 py-1.5 rounded border text-xs cursor-pointer transition-all flex items-center gap-2 ${
                isSelected
                  ? "bg-blue/15 border-blue text-ink font-bold"
                  : "bg-surface border-border text-ink-2 hover:border-border-hi"
              }`}
            >
              <span>{sev.toUpperCase()}</span>
              <span
                className={`px-1.5 py-0.2 rounded text-[10px] ${
                  isSelected ? "bg-blue/30 text-ink font-bold" : "bg-elevated text-ink-3"
                }`}
              >
                {count}
              </span>
            </button>
          )
        })}
      </div>

      {/* Search, Status Filter & Table Container */}
      <CyberCard noPadding>
        {/* Controls Bar */}
        <div className="p-4 border-b border-border bg-surface/40 flex flex-wrap items-center justify-between gap-4 font-mono text-xs">
          <div className="flex-1 min-w-[260px] relative">
            <Search size={14} className="absolute left-3 top-2.5 text-ink-3 pointer-events-none" />
            <input
              type="text"
              placeholder="Filter by title, URL, parameter, category, or CWE..."
              value={query}
              onChange={(e) => handleSearchChange(e.target.value)}
              className="w-full bg-surface border border-border focus:border-cyan/50 rounded pl-9 pr-3 py-1.5 text-ink text-xs placeholder:text-ink-3"
            />
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <div className="flex items-center gap-2">
              <span className="text-ink-3 text-[11px] uppercase">STATUS:</span>
              <select
                value={statusFilter}
                onChange={(e) => handleStatusFilterChange(e.target.value)}
                className="bg-surface border border-border rounded px-2.5 py-1 text-ink text-xs cursor-pointer"
              >
                <option value="All">All Statuses</option>
                {STATUSES.map((s) => (
                  <option key={s} value={s}>
                    {s}
                  </option>
                ))}
              </select>
            </div>

            <label className="flex items-center gap-2 cursor-pointer text-[11px] text-ink-3">
              <input
                type="checkbox"
                checked={showHeaderNoise}
                onChange={(e) => setShowHeaderNoise(e.target.checked)}
                className="accent-cyan w-3.5 h-3.5 rounded"
              />
              <span>Include Header Warnings ({hiddenHeaderNoiseCount})</span>
            </label>
          </div>
        </div>

        {/* Findings Table or Empty State */}
        {filtered.length === 0 && !loading ? (
          <div className="p-8">
            <EmptyState
              title={query || severityFilter !== "All" ? "NO MATCHING FINDINGS" : "NO VULNERABILITIES DETECTED"}
              description={
                query || severityFilter !== "All"
                  ? "No security findings match your active filter criteria. Try resetting the filters."
                  : "Zero findings recorded in audit database. Launch an active DAST scan to test the target."
              }
              actionLabel={query || severityFilter !== "All" ? "RESET FILTERS" : "LAUNCH SCAN"}
              onAction={
                query || severityFilter !== "All"
                  ? () => {
                      setQuery("")
                      setSeverityFilter("All")
                      setStatusFilter("All")
                      updateUrlParams({ severity: "All", status: "All", search: "" })
                    }
                  : () => navigate("/scans/new")
              }
            />
          </div>
        ) : (
          <CyberTable
            columns={columns}
            data={filtered}
            keyExtractor={(f) => f.id}
            loading={loading}
          />
        )}
      </CyberCard>

      {/* Status Transition Confirmation Modal */}
      {pendingStatusChange && (
        <CyberModal
          isOpen={Boolean(pendingStatusChange)}
          onClose={() => setPendingStatusChange(null)}
          title="Confirm Finding Status Update"
          maxWidth="md"
          footer={
            <div className="flex items-center justify-end gap-2">
              <CyberButton
                size="xs"
                variant="ghost"
                onClick={() => setPendingStatusChange(null)}
              >
                CANCEL
              </CyberButton>
              <CyberButton
                size="xs"
                variant="primary"
                onClick={() => void confirmStatusChange()}
              >
                CONFIRM CHANGE
              </CyberButton>
            </div>
          }
        >
          <div className="space-y-3 font-mono text-xs">
            <p className="text-ink font-sans">
              Are you sure you want to change the status of finding:
            </p>
            <div className="p-3 rounded bg-surface border border-border">
              <span className="text-cyan font-bold block">{pendingStatusChange.finding.title}</span>
              <span className="text-ink-3 text-[11px] block mt-1">
                From <span className="text-ink font-semibold">{pendingStatusChange.finding.status}</span> to{" "}
                <span className="text-cyan font-semibold">{pendingStatusChange.newStatus}</span>
              </span>
            </div>
          </div>
        </CyberModal>
      )}

      {/* Forensic Deep Inspection Drawer */}
      <CyberDrawer
        isOpen={drawerOpen || singleFindingLoading}
        onClose={closeDrawer}
        width="2xl"
        title={
          singleFindingLoading
            ? "Retrieving Forensic Finding..."
            : selectedFinding?.title || "Vulnerability Forensic Report"
        }
        subtitle={
          singleFindingLoading
            ? "Fetching record from database..."
            : selectedFinding
              ? `ID: ${selectedFinding.id} · Discovered: ${selectedFinding.found_at}`
              : undefined
        }
        badge={
          selectedFinding && (
            <SeverityBadge
              severity={selectedFinding.severity}
              cvss={selectedFinding.cvss}
            />
          )
        }
        footer={
          selectedFinding && (
            <div className="flex flex-wrap items-center justify-between gap-3 w-full font-mono text-xs">
              <div className="flex items-center gap-2">
                <CyberButton
                  size="xs"
                  variant="outline"
                  icon={<Terminal size={12} />}
                  onClick={() => sendToRepeaterAction(selectedFinding)}
                >
                  SEND TO REPEATER
                </CyberButton>

                <CyberButton
                  size="xs"
                  variant="outline"
                  icon={<ShieldCheck size={12} />}
                  onClick={() => navigate("/proof")}
                >
                  PROOF MODE
                </CyberButton>
              </div>

              <CyberButton
                size="xs"
                variant="secondary"
                icon={<RotateCcw size={12} />}
                loading={busyId === selectedFinding.id}
                onClick={() => void retest(selectedFinding.id)}
              >
                SCHEDULE RETEST
              </CyberButton>
            </div>
          )
        }
      >
        {singleFindingLoading ? (
          <div className="flex flex-col items-center justify-center py-20 gap-3 font-mono text-xs text-ink-3">
            <div className="w-8 h-8 rounded-full border-2 border-blue/20 border-t-blue animate-spin" />
            <span>FETCHING FORENSIC FINDING RECORD...</span>
          </div>
        ) : selectedFinding ? (
          <div className="space-y-5 font-mono text-xs">
            {/* Drawer Tabs */}
            <CyberTabs
              tabs={drawerTabs}
              activeId={drawerTab}
              onChange={setDrawerTab}
            />

            {drawerTab === "overview" && (
              <div className="space-y-4">
                <div>
                  <label className="text-[10px] uppercase text-ink-3 block mb-1">
                    TARGET URL & ENDPOINT
                  </label>
                  <div className="p-2.5 rounded bg-surface border border-border text-ink break-all select-all font-mono text-xs">
                    {selectedFinding.target}
                  </div>
                </div>

                <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
                  <div>
                    <label className="text-[10px] uppercase text-ink-3 block mb-1">
                      CATEGORY
                    </label>
                    <div className="p-2 rounded bg-surface border border-border text-cyan font-bold truncate">
                      {selectedFinding.category}
                    </div>
                  </div>

                  <div>
                    <label className="text-[10px] uppercase text-ink-3 block mb-1">
                      CWE WEAKNESS
                    </label>
                    <div className="p-2 rounded bg-surface border border-border text-ink-2 truncate">
                      {selectedFinding.cwe || "N/A"}
                    </div>
                  </div>

                  <div>
                    <label className="text-[10px] uppercase text-ink-3 block mb-1">
                      CLASSIFICATION & CONFIDENCE
                    </label>
                    <div className="p-2 rounded bg-surface border border-border flex items-center justify-between text-xs">
                      <span className="font-bold text-ink-1">
                        {selectedFinding.classification || selectedFinding.confidence || "Tentative"}
                      </span>
                      <span className="text-emerald font-mono text-[11px]">
                        {selectedFinding.confidence_score !== undefined ? `${selectedFinding.confidence_score}/10` : "Score N/A"}
                      </span>
                    </div>
                  </div>
                </div>

                {selectedFinding.why_false_positive_risk && (
                  <div className="p-3 rounded bg-amber-500/10 border border-amber-500/30 text-amber-300 text-xs leading-relaxed">
                    <span className="font-bold uppercase tracking-wider text-[10px] block mb-1 text-amber-400">
                      Why this may be a false positive
                    </span>
                    {selectedFinding.why_false_positive_risk}
                  </div>
                )}

                {selectedFinding.affected_urls_count && selectedFinding.affected_urls_count > 1 && (
                  <div>
                    <label className="text-[10px] uppercase text-ink-3 block mb-1">
                      SYSTEMIC IMPACT
                    </label>
                    <div className="p-2.5 rounded bg-surface border border-border text-ink-2 text-xs">
                      Observed across <span className="font-bold text-white">{selectedFinding.affected_urls_count}</span> endpoints.
                    </div>
                  </div>
                )}

                {selectedFinding.parameter && (
                  <div>
                    <label className="text-[10px] uppercase text-ink-3 block mb-1">
                      VULNERABLE PARAMETER / INJECTION VECTOR
                    </label>
                    <div className="p-2.5 rounded bg-surface border border-border text-ink-2 font-mono">
                      {selectedFinding.parameter}
                    </div>
                  </div>
                )}

                {selectedFinding.description && (
                  <div>
                    <label className="text-[10px] uppercase text-ink-3 block mb-1 font-semibold">
                      TECHNICAL IMPACT & SUMMARY
                    </label>
                    <div className="p-3.5 rounded bg-surface border border-border text-ink-2 font-sans text-xs leading-relaxed">
                      {selectedFinding.description}
                    </div>
                  </div>
                )}


                {/* External Notification Dispatch */}
                <div className="pt-2 border-t border-border">
                  <label className="text-[10px] uppercase text-ink-3 block mb-2 font-semibold">
                    DISPATCH TO INCIDENT WORKFLOWS
                  </label>
                  <div className="flex flex-wrap gap-2">
                    <CyberButton
                      size="xs"
                      variant="outline"
                      icon={<Send size={11} />}
                      onClick={() => void pushFinding(selectedFinding.id, "slack")}
                    >
                      SLACK CHANNEL
                    </CyberButton>
                    <CyberButton
                      size="xs"
                      variant="outline"
                      icon={<Send size={11} />}
                      onClick={() => void pushFinding(selectedFinding.id, "github")}
                    >
                      GITHUB ISSUE
                    </CyberButton>
                    <CyberButton
                      size="xs"
                      variant="outline"
                      icon={<Send size={11} />}
                      onClick={() => void pushFinding(selectedFinding.id, "jira")}
                    >
                      JIRA TICKET
                    </CyberButton>
                  </div>
                </div>
              </div>
            )}

            {drawerTab === "evidence" && (
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <label className="text-[10px] uppercase text-ink-3 font-semibold">
                    SANITIZED RAW PROOF-OF-CONCEPT EVIDENCE
                  </label>
                  <CyberButton
                    size="xs"
                    variant="ghost"
                    icon={<FolderOpen size={11} />}
                    onClick={() => navigate("/evidence")}
                  >
                    OPEN EVIDENCE VAULT
                  </CyberButton>
                </div>

                {selectedFinding.evidence ? (
                  <pre className="p-4 rounded bg-[#03060c] border border-border text-ink-2 text-xs overflow-x-auto whitespace-pre-wrap font-mono max-h-[420px]">
                    {selectedFinding.evidence}
                  </pre>
                ) : (
                  <p className="text-ink-3 py-8 text-center italic">
                    No raw evidence recorded for this finding.
                  </p>
                )}
              </div>
            )}

            {drawerTab === "remediation" && (
              <div className="space-y-4">
                <label className="text-[10px] uppercase text-ink-3 block font-semibold text-emerald">
                  STEP-BY-STEP REMEDIATION GUIDANCE
                </label>
                <div className="p-4 rounded bg-emerald/5 border border-emerald/30 text-ink font-sans text-xs leading-relaxed">
                  {selectedFinding.recommendation || (
                    <p className="text-ink-3 italic">
                      Remediate by validating input and applying secure coding controls according to OWASP guidelines.
                    </p>
                  )}
                </div>
              </div>
            )}
          </div>
        ) : null}
      </CyberDrawer>
    </div>
  )
}
