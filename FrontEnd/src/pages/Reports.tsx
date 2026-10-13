import { useEffect, useState } from "react"
import {
  Download,
  FileText,
  RefreshCw,
  CheckCircle2,
  FileCheck2,
} from "lucide-react"
import { reportsApi, scanApi, type ApiReport, type ScanItem } from "../api/client"
import { CyberCard } from "../components/ui/CyberCard"
import { CyberButton } from "../components/ui/CyberButton"
import { CyberTable, type CyberTableColumn } from "../components/ui/CyberTable"
import { StatusPill } from "../components/ui/StatusPill"

interface ReportsProps {
  onNavigate?: (page: string) => void
  findingsCount?: number
}

type ReportFormat = "json" | "html" | "pdf" | "sarif" | "junit" | "evidence" | "github_issues" | "jira"
type ReportType = "technical" | "executive" | "compliance"

const FORMAT_LABELS: Record<ReportFormat, string> = {
  json: "JSON Format",
  html: "Interactive HTML Report",
  pdf: "Executive PDF Document",
  sarif: "OASIS SARIF Spec",
  junit: "CI/CD JUnit XML",
  evidence: "Forensic Evidence Bundle",
  github_issues: "GitHub Issues (Markdown)",
  jira: "JIRA Issue Import (JSON)",
}

export default function Reports(_props?: ReportsProps) {
  const [reports, setReports] = useState<ApiReport[]>([])
  const [scans, setScans] = useState<ScanItem[]>([])
  const [selectedScanId, setSelectedScanId] = useState("")
  const [selectedFormat, setSelectedFormat] = useState<ReportFormat>("html")
  const [selectedType, setSelectedType] = useState<ReportType>("technical")
  const [targetScope, setTargetScope] = useState("")
  const [busyScan, setBusyScan] = useState(false)
  const [message, setMessage] = useState("")
  const [error, setError] = useState("")
  const [loading, setLoading] = useState(true)

  const load = async () => {
    setLoading(true)
    try {
      const [nextReports, nextScans] = await Promise.all([
        reportsApi.list(),
        scanApi.list(),
      ])
      setReports(nextReports)
      setScans(nextScans)
      if (!selectedScanId && nextScans[0]) {
        setSelectedScanId(nextScans[0].id)
      }
      setError("")
    } catch {
      setError("Could not load reports archive.")
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    void load()
  }, [])

  const generate = async () => {
    if (!selectedScanId) return
    setBusyScan(true)
    setError("")
    setMessage("")
    try {
      const result = await reportsApi.generate({
        scan_id: selectedScanId,
        format: selectedFormat,
        report_type: selectedType,
        target_scope: targetScope || undefined,
      })
      setMessage(`Report "${result.name}" successfully generated in ${selectedFormat.toUpperCase()} format!`)
      await load()
    } catch {
      setError("Report generation failed. Verify scan findings and backend generator.")
    } finally {
      setBusyScan(false)
    }
  }

  const reportColumns: CyberTableColumn<ApiReport>[] = [
    {
      key: "name",
      title: "REPORT ARTIFACT",
      render: (r) => (
        <div>
          <span className="text-ink font-semibold text-xs block">{r.name}</span>
          <span className="text-[10px] text-ink-3 font-mono">
            Scan: {r.scan_id} · Target: {r.target}
          </span>
        </div>
      ),
    },
    {
      key: "format",
      title: "FORMAT",
      width: "110px",
      render: (r) => (
        <span className="font-mono text-[10px] uppercase font-bold px-2 py-0.5 rounded bg-surface border border-border text-cyan">
          {r.format}
        </span>
      ),
    },
    {
      key: "findings_count",
      title: "FINDINGS",
      width: "100px",
      render: (r) => (
        <span className="font-mono text-xs font-bold text-ink">
          {r.findings_count}
        </span>
      ),
    },
    {
      key: "size",
      title: "SIZE",
      width: "100px",
      render: (r) => (
        <span className="font-mono text-xs text-ink-3">
          {r.size || "12.4 KB"}
        </span>
      ),
    },
    {
      key: "status",
      title: "STATUS",
      width: "120px",
      render: (r) => <StatusPill status={r.status || "ready"} />,
    },
    {
      key: "actions",
      title: "",
      width: "140px",
      align: "right",
      render: (r) => (
        <div className="flex items-center justify-end gap-2">
          <a
            href={reportsApi.downloadUrl(r.id)}
            download
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded bg-elevated hover:bg-elevated/80 border border-border hover:border-cyan/40 text-ink text-xs font-mono font-medium transition-colors"
          >
            <Download size={13} className="text-cyan" />
            <span>DOWNLOAD</span>
          </a>
        </div>
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
            Security Reports & Compliance Studio
          </h1>
          <p className="text-xs text-ink-3 font-mono mt-1">
            Export technical penetration testing deliverables, executive briefs, and CI/CD security telemetry.
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <CyberButton
            variant="secondary"
            size="sm"
            icon={<RefreshCw size={13} className={loading ? "animate-spin" : ""} />}
            onClick={() => void load()}
          >
            REFRESH ARCHIVE
          </CyberButton>
        </div>
      </div>

      {message && (
        <div className="p-3.5 rounded border border-emerald/40 bg-emerald/10 text-emerald text-xs font-mono flex items-center gap-2">
          <CheckCircle2 size={15} className="shrink-0" />
          <span>{message}</span>
        </div>
      )}

      {error && (
        <div className="p-3.5 rounded border border-critical/40 bg-critical/10 text-critical text-xs font-mono">
          {error}
        </div>
      )}

      {/* Report Generator Studio */}
      <CyberCard
        title="Generate Technical or Executive Deliverable"
        subtitle="Produce customized vulnerability audit documents"
        icon={<FileText size={16} />}
      >
        <div className="grid md:grid-cols-3 gap-6 text-xs font-sans">
          {/* Target Scan Selection */}
          <div className="space-y-1.5">
            <label className="block text-ink-3 font-mono text-[11px] uppercase font-semibold">
              SELECT SCAN TARGET DATA:
            </label>
            <select
              value={selectedScanId}
              onChange={(e) => setSelectedScanId(e.target.value)}
              className="w-full bg-surface border border-border focus:border-cyan/50 rounded px-3 py-2 text-ink font-mono text-xs cursor-pointer"
            >
              {scans.length === 0 ? (
                <option value="">No scans available</option>
              ) : (
                scans.map((scan) => (
                  <option key={scan.id} value={scan.id}>
                    {scan.id} - {scan.target}
                  </option>
                ))
              )}
            </select>
          </div>

          {/* Export Format */}
          <div className="space-y-1.5">
            <label className="block text-ink-3 font-mono text-[11px] uppercase font-semibold">
              DELIVERABLE FORMAT:
            </label>
            <select
              value={selectedFormat}
              onChange={(e) => setSelectedFormat(e.target.value as ReportFormat)}
              className="w-full bg-surface border border-border focus:border-cyan/50 rounded px-3 py-2 text-ink font-mono text-xs cursor-pointer"
            >
              {(Object.keys(FORMAT_LABELS) as ReportFormat[]).map((fmt) => (
                <option key={fmt} value={fmt}>
                  {FORMAT_LABELS[fmt]} ({fmt.toUpperCase()})
                </option>
              ))}
            </select>
          </div>

          {/* Report Type */}
          <div className="space-y-1.5">
            <label className="block text-ink-3 font-mono text-[11px] uppercase font-semibold">
              REPORT AUDIENCE & TYPE:
            </label>
            <select
              value={selectedType}
              onChange={(e) => setSelectedType(e.target.value as ReportType)}
              className="w-full bg-surface border border-border focus:border-cyan/50 rounded px-3 py-2 text-ink font-mono text-xs cursor-pointer"
            >
              <option value="technical">Technical Vulnerability Audit</option>
              <option value="executive">C-Suite Executive Risk Summary</option>
              <option value="compliance">Regulatory Compliance Matrix (OWASP/PCI)</option>
            </select>
          </div>

          {/* Scope Filter Override */}
          <div className="space-y-1.5 md:col-span-3">
            <label className="block text-ink-3 font-mono text-[11px] uppercase font-semibold">
              SCOPE FILTER OVERRIDE (OPTIONAL):
            </label>
            <input
              type="text"
              value={targetScope}
              onChange={(e) => setTargetScope(e.target.value)}
              placeholder="e.g. /api/v1/auth or subdomains"
              className="w-full bg-surface border border-border focus:border-cyan/50 rounded px-3 py-2 text-ink font-mono text-xs placeholder:text-ink-3"
            />
          </div>
        </div>

        <div className="mt-5 flex items-center justify-between gap-4 pt-4 border-t border-border">
          <p className="text-xs text-ink-3 font-mono">
            Outputs include sanitized evidence, CVSS metrics, CWE tags, and step-by-step remediation advice.
          </p>

          <CyberButton
            variant="primary"
            size="md"
            hudCorners
            loading={busyScan}
            disabled={!selectedScanId}
            icon={<FileCheck2 size={14} />}
            onClick={() => void generate()}
          >
            GENERATE DELIVERABLE
          </CyberButton>
        </div>
      </CyberCard>

      {/* Generated Reports Archive */}
      <CyberCard
        title="Saved Deliverables & Generated Reports Archive"
        subtitle={`${reports.length} generated documents available for export`}
        noPadding
      >
        <CyberTable
          columns={reportColumns}
          data={reports}
          keyExtractor={(r) => r.id}
          emptyMessage="No reports have been generated yet. Use the studio above to export scan results."
          loading={loading}
        />
      </CyberCard>
    </div>
  )
}
