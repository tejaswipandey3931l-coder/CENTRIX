import { useEffect, useMemo, useState } from "react"
import { Activity, RefreshCw, BarChart3 } from "lucide-react"
import { findingsApi, scanApi, type ApiFinding, type ScanItem } from "../api/client"
import { CyberCard } from "../components/ui/CyberCard"
import { CyberButton } from "../components/ui/CyberButton"
import { StatWidget } from "../components/ui/StatWidget"
import { CyberTable, type CyberTableColumn } from "../components/ui/CyberTable"
import { StatusPill } from "../components/ui/StatusPill"

const ORDER = ["Critical", "High", "Medium", "Low", "Info"]

export default function RiskPosture() {
  const [findings, setFindings] = useState<ApiFinding[]>([])
  const [scans, setScans] = useState<ScanItem[]>([])
  const [loading, setLoading] = useState(true)

  const load = async () => {
    setLoading(true)
    try {
      const [nextFindings, nextScans] = await Promise.all([
        findingsApi.list(),
        scanApi.list(),
      ])
      setFindings(nextFindings)
      setScans(nextScans)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    void load().catch(() => undefined)
  }, [])

  const severityCounts = useMemo(() => {
    const counts: Record<string, number> = Object.fromEntries(ORDER.map((item) => [item, 0]))
    findings.forEach((f) => {
      counts[f.severity] = (counts[f.severity] || 0) + 1
    })
    return counts
  }, [findings])

  const topCategories = useMemo(() => {
    const counts: Record<string, number> = {}
    findings.forEach((f) => {
      counts[f.category] = (counts[f.category] || 0) + 1
    })
    return Object.entries(counts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 7)
  }, [findings])

  const openCount = findings.filter((f) => f.status === "Open").length
  const highSignalCount = findings.filter((f) =>
    ["Critical", "High"].includes(f.severity),
  ).length

  const scanColumns: CyberTableColumn<ScanItem>[] = [
    {
      key: "id",
      title: "SCAN ID",
      width: "150px",
      render: (s) => (
        <span className="font-mono text-cyan font-bold text-xs">{s.id}</span>
      ),
    },
    {
      key: "target",
      title: "TARGET AUDIT SCOPE",
      render: (s) => (
        <span className="text-ink font-mono text-xs truncate max-w-sm block">
          {s.target}
        </span>
      ),
    },
    {
      key: "status",
      title: "STATUS",
      width: "130px",
      render: (s) => <StatusPill status={s.status} />,
    },
    {
      key: "findings_count",
      title: "EXPOSURES",
      width: "110px",
      render: (s) => (
        <span className="font-mono text-xs font-bold text-ink">
          {s.findings_count} findings
        </span>
      ),
    },
  ]

  return (
    <div className="p-4 sm:p-6 lg:p-8 max-w-[1700px] mx-auto space-y-6">
      {/* Header */}
      <div className="flex flex-wrap items-start justify-between gap-4 border-b border-border pb-5">
        <div>
          <h1 className="text-xl font-bold tracking-wider text-ink uppercase font-display flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-blue" />
            Enterprise Risk Posture & Exposure Analytics
          </h1>
          <p className="text-xs text-ink-3 font-mono mt-1">
            Executive exposure breakdown, vulnerability severity distribution, and target coverage.
          </p>
        </div>

        <CyberButton
          variant="secondary"
          size="sm"
          icon={<RefreshCw size={13} className={loading ? "animate-spin" : ""} />}
          onClick={() => void load()}
        >
          REFRESH ANALYTICS
        </CyberButton>
      </div>

      {/* Metric Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatWidget
          label="TOTAL DETECTED FINDINGS"
          value={String(findings.length)}
          sublabel="Across all tested endpoints"
          accent="violet"
        />

        <StatWidget
          label="ACTIVE UNRESOLVED ISSUES"
          value={String(openCount)}
          sublabel="Open status requiring mitigation"
          accent={openCount > 0 ? "high" : "emerald"}
        />

        <StatWidget
          label="CRITICAL & HIGH IMPACT"
          value={String(highSignalCount)}
          sublabel="Immediate attack vectors"
          accent={highSignalCount > 0 ? "critical" : "emerald"}
        />

        <StatWidget
          label="TESTED AUDIT SCOPES"
          value={String(scans.length)}
          sublabel="Authorised target applications"
          accent="cyan"
        />
      </div>

      {/* Distribution Charts */}
      <div className="grid lg:grid-cols-2 gap-6">
        {/* Severity Distribution */}
        <CyberCard
          title="Severity Distribution Matrix"
          subtitle="Proportion of findings grouped by threat severity"
          icon={<Activity size={16} />}
        >
          <div className="space-y-4 pt-2 font-mono text-xs">
            {ORDER.map((item) => {
              const val = severityCounts[item] || 0
              const pct = findings.length ? Math.round((val / findings.length) * 100) : 0
              const color =
                item === "Critical"
                  ? "bg-critical"
                  : item === "High"
                    ? "bg-high"
                    : item === "Medium"
                      ? "bg-medium"
                      : item === "Low"
                        ? "bg-low"
                        : "bg-info"

              return (
                <div key={item} className="space-y-1.5">
                  <div className="flex justify-between items-center text-xs">
                    <span className="text-ink font-semibold flex items-center gap-2">
                      <span className={`w-2 h-2 rounded-full ${color}`} />
                      {item.toUpperCase()}
                    </span>
                    <span className="text-ink-2">
                      {val} <span className="text-ink-3">({pct}%)</span>
                    </span>
                  </div>
                  <div className="h-2 w-full bg-surface rounded-full overflow-hidden border border-border/40">
                    <div
                      className={`h-full ${color} transition-all duration-500 rounded-full`}
                      style={{ width: `${pct}%` }}
                    />
                  </div>
                </div>
              )
            })}
          </div>
        </CyberCard>

        {/* Top Vulnerability Categories */}
        <CyberCard
          title="Top Attack Categories"
          subtitle="Most prevalent vulnerability classes across scope"
          icon={<BarChart3 size={16} />}
        >
          <div className="space-y-4 pt-2 font-mono text-xs">
            {topCategories.length === 0 ? (
              <p className="text-ink-3 py-8 text-center italic">No categorized findings available.</p>
            ) : (
              topCategories.map(([cat, val]) => {
                const pct = findings.length ? Math.round((val / findings.length) * 100) : 0
                return (
                  <div key={cat} className="space-y-1.5">
                    <div className="flex justify-between items-center text-xs">
                      <span className="text-ink truncate max-w-xs">{cat}</span>
                      <span className="text-ink-2 shrink-0">
                        {val} <span className="text-ink-3">({pct}%)</span>
                      </span>
                    </div>
                    <div className="h-2 w-full bg-surface rounded-full overflow-hidden border border-border/40">
                      <div
                        className="h-full bg-blue transition-all duration-500 rounded-full"
                        style={{ width: `${pct}%` }}
                      />
                    </div>
                  </div>
                )
              })
            )}
          </div>
        </CyberCard>
      </div>

      {/* Target Scans Table */}
      <CyberCard
        title="Audit Coverage & Scan Archives"
        subtitle="Historical scan targets and vulnerability yield"
        noPadding
      >
        <CyberTable
          columns={scanColumns}
          data={scans}
          keyExtractor={(s) => s.id}
          emptyMessage="No audit scans recorded in backend storage."
          loading={loading}
        />
      </CyberCard>
    </div>
  )
}
