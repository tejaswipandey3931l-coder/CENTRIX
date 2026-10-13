import { useEffect, useState } from "react"
import {
  RefreshCw,
  Search,
  Zap,
  ExternalLink,
  AlertTriangle,
  Globe,
} from "lucide-react"
import { integrationsApi, scanApi, type ScanItem, type CveResultItem } from "../api/client"
import { CyberCard } from "../components/ui/CyberCard"
import { CyberButton } from "../components/ui/CyberButton"

export default function NucleiCve() {
  const [status, setStatus] = useState<Record<string, any> | null>(null)
  const [scans, setScans] = useState<ScanItem[]>([])
  const [scanId, setScanId] = useState("")
  const [query, setQuery] = useState("OpenSSL")
  const [cves, setCves] = useState<CveResultItem[]>([])
  const [nucleiResults, setNucleiResults] = useState<unknown[]>([])
  const [nucleiEngine, setNucleiEngine] = useState("")
  const [busy, setBusy] = useState("")
  const [error, setError] = useState("")

  const load = async () => {
    try {
      const [nextStatus, nextScans] = await Promise.all([
        integrationsApi.status(),
        scanApi.list(),
      ])
      setStatus(nextStatus)
      setScans(nextScans)
      if (!scanId && nextScans[0]) setScanId(nextScans[0].id)
    } catch {
      // ignore
    }
  }

  useEffect(() => {
    void load()
    // Perform initial sample CVE search
    void search("CVE-2024")
  }, [])

  const search = async (overrideQuery?: string) => {
    const q = overrideQuery || query
    if (!q.trim()) return
    setBusy("cve")
    setError("")
    try {
      const result = await integrationsApi.searchCves(q)
      setCves(result.results || [])
    } catch (reason: unknown) {
      setError(reason instanceof Error ? reason.message : "CVE threat lookup failed.")
    } finally {
      setBusy("")
    }
  }

  const runNuclei = async () => {
    setBusy("nuclei")
    setError("")
    try {
      const result = await integrationsApi.runNuclei(scanId, ["critical", "high", "medium"])
      setNucleiResults(result.results || [])
      setNucleiEngine(result.engine || "Centrix Core")
    } catch (reason: unknown) {
      setError(reason instanceof Error ? reason.message : "Nuclei template runner encountered an error.")
    } finally {
      setBusy("")
    }
  }

  return (
    <div className="p-4 sm:p-6 lg:p-8 max-w-[1700px] mx-auto space-y-6">
      {/* Title */}
      <div className="flex flex-wrap items-start justify-between gap-4 border-b border-border pb-5">
        <div>
          <h1 className="text-xl font-bold tracking-wider text-ink uppercase font-display flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-blue" />
            Threat Intelligence & Nuclei Engine
          </h1>
          <p className="text-xs text-ink-3 font-mono mt-1">
            Global vulnerability database feeds, CVE correlation, and community-driven safe template probing.
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <CyberButton
            variant="secondary"
            size="sm"
            icon={<RefreshCw size={13} className={busy ? "animate-spin" : ""} />}
            onClick={() => void load()}
          >
            REFRESH FEEDS
          </CyberButton>
        </div>
      </div>

      {error && (
        <div className="p-3.5 rounded border border-critical/40 bg-critical/10 text-critical text-xs font-mono flex items-center gap-2">
          <AlertTriangle size={15} className="shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Main Grid: Nuclei Engine (6 cols) & CVE Threat Feed (6 cols) */}
      <div className="grid lg:grid-cols-2 gap-6">
        {/* Left: Nuclei Engine Console */}
        <CyberCard
          title="Nuclei Security Template Engine"
          subtitle="Automated targeted checks based on ProjectDiscovery templates"
          icon={<Zap size={16} />}
        >
          <div className="space-y-4 font-sans text-xs">
            {/* Status pill row */}
            <div className="p-3 rounded bg-surface border border-border flex items-center justify-between font-mono">
              <div>
                <span className="text-ink-3 text-[10px] uppercase block">ENGINE STATUS</span>
                <span className="text-ink font-semibold flex items-center gap-1.5 mt-0.5">
                  <span
                    className={`w-2 h-2 rounded-full ${
                      status?.nuclei?.available ? "bg-emerald shadow-[0_0_6px_#10b981]" : "bg-cyan"
                    }`}
                  />
                  {status?.nuclei?.available
                    ? "Nuclei Binary Available"
                    : "Centrix Built-in Template Engine"}
                </span>
              </div>
              <div className="text-right">
                <span className="text-ink-3 text-[10px] uppercase block">MODE</span>
                <span className="text-cyan font-bold">{status?.nuclei?.mode || "standard"}</span>
              </div>
            </div>

            {/* Target selector */}
            <div>
              <label className="block text-ink-3 font-mono text-[11px] uppercase mb-1 font-semibold">
                SELECT TARGET SCAN TO EXECUTE TEMPLATES AGAINST:
              </label>
              <select
                value={scanId}
                onChange={(e) => setScanId(e.target.value)}
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

            <CyberButton
              variant="primary"
              size="md"
              disabled={!scanId || busy === "nuclei"}
              loading={busy === "nuclei"}
              icon={<Zap size={14} className="fill-current" />}
              hudCorners
              onClick={() => void runNuclei()}
              className="w-full"
            >
              RUN SAFE VULNERABILITY TEMPLATES
            </CyberButton>

            {nucleiEngine && (
              <p className="text-[11px] font-mono text-ink-3">
                Execution engine: <strong className="text-ink">{nucleiEngine}</strong>
              </p>
            )}

            {/* Template Output Terminal */}
            <div>
              <div className="flex items-center justify-between font-mono text-[11px] text-ink-3 mb-1.5">
                <span>EXECUTION FINDINGS & AUDIT TRACE</span>
                <span>{nucleiResults.length} detections</span>
              </div>
              <div className="max-h-[380px] overflow-y-auto border border-border rounded bg-[#03060c] p-3 divide-y divide-border/40 font-mono text-xs">
                {nucleiResults.length === 0 ? (
                  <div className="text-center py-8 text-ink-3 italic">
                    {busy === "nuclei"
                      ? "Executing template checks against endpoints..."
                      : "No template execution results in memory. Click above to run safe templates."}
                  </div>
                ) : (
                  nucleiResults.map((item, idx) => (
                    <div key={idx} className="py-2.5 first:pt-0 last:pb-0">
                      <pre className="text-ink-2 whitespace-pre-wrap text-[11px]">
                        {typeof item === "string" ? item : JSON.stringify(item, null, 2)}
                      </pre>
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>
        </CyberCard>

        {/* Right: CVE Threat Feed & Lookup */}
        <CyberCard
          title="Global CVE Intelligence & Advisories"
          subtitle="Real-time threat feed & public exploitability database"
          icon={<Globe size={16} />}
        >
          <div className="space-y-4 font-sans text-xs">
            {/* Search Input */}
            <div className="flex gap-2">
              <div className="relative flex-1">
                <Search size={14} className="absolute left-3 top-3 text-ink-3 pointer-events-none" />
                <input
                  type="text"
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") void search()
                  }}
                  placeholder="Search CVE ID (e.g. CVE-2024-3094), software name, library..."
                  className="w-full bg-surface border border-border focus:border-cyan/50 rounded pl-9 pr-3 py-2 text-ink font-mono text-xs placeholder:text-ink-3"
                />
              </div>

              <CyberButton
                variant="secondary"
                size="sm"
                loading={busy === "cve"}
                onClick={() => void search()}
              >
                Lookup
              </CyberButton>
            </div>

            {/* Quick Keyword Pills */}
            <div className="flex flex-wrap gap-1.5 font-mono text-[10px]">
              <span className="text-ink-3 py-0.5">TRENDING:</span>
              {["OpenSSL", "Spring4Shell", "Log4j", "Apache", "WordPress", "CVE-2024"].map((tag) => (
                <button
                  key={tag}
                  onClick={() => {
                    setQuery(tag)
                    void search(tag)
                  }}
                  className="px-2 py-0.5 rounded bg-surface border border-border text-ink-2 hover:text-cyan hover:border-cyan/40 transition-colors cursor-pointer"
                >
                  {tag}
                </button>
              ))}
            </div>

            {/* CVE Items Feed */}
            <div className="max-h-[500px] overflow-y-auto border border-border rounded bg-surface/40 divide-y divide-border/60">
              {cves.length === 0 ? (
                <div className="p-8 text-center text-ink-3 font-mono">
                  {busy === "cve" ? "Searching CVE databases..." : "No CVE threat advisories found."}
                </div>
              ) : (
                cves.map((cve) => (
                  <a
                    key={cve.id}
                    href={cve.url || `https://nvd.nist.gov/vuln/detail/${cve.id}`}
                    target="_blank"
                    rel="noreferrer"
                    className="block p-3.5 hover:bg-elevated/70 transition-colors group"
                  >
                    <div className="flex items-center justify-between gap-3">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-xs font-bold text-cyan group-hover:underline">
                          {cve.id}
                        </span>
                        <ExternalLink size={11} className="text-ink-3 group-hover:text-cyan" />
                      </div>
                      {cve.score != null ? (
                        <span
                          className={`font-mono text-[10px] font-bold px-2 py-0.5 rounded ${
                            cve.score >= 9
                              ? "bg-critical/20 text-critical border border-critical/40"
                              : cve.score >= 7
                                ? "bg-high/20 text-high border border-high/40"
                                : "bg-medium/20 text-medium border border-medium/40"
                          }`}
                        >
                          CVSS {cve.score}
                        </span>
                      ) : (
                        <span className="font-mono text-[10px] text-ink-3">Score Unranked</span>
                      )}
                    </div>

                    <p className="mt-2 text-xs text-ink-2 leading-relaxed line-clamp-3">
                      {cve.summary || "Advisory documentation currently processing."}
                    </p>

                    <div className="mt-2 text-[10px] font-mono text-ink-3 flex items-center justify-between">
                      <span>SOURCE: NIST NVD / MITRE</span>
                      <span className="text-cyan/70">Verified Threat Record</span>
                    </div>
                  </a>
                ))
              )}
            </div>
          </div>
        </CyberCard>
      </div>
    </div>
  )
}
