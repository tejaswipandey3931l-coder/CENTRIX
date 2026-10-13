import { useEffect, useState } from "react"
import { Crosshair, Play } from "lucide-react"
import { manualApi, scanApi, type ScanItem, type IntruderResultItem } from "../api/client"
import { CyberCard } from "../components/ui/CyberCard"
import { CyberButton } from "../components/ui/CyberButton"

export default function Intruder() {
  const [scans, setScans] = useState<ScanItem[]>([])
  const [scanId, setScanId] = useState("")
  const [method, setMethod] = useState("GET")
  const [url, setUrl] = useState("https://example.com/search?q={{payload}}")
  const [headers, setHeaders] = useState("{\n}")
  const [body, setBody] = useState("")
  const [marker, setMarker] = useState("{{payload}}")
  const [payloads, setPayloads] = useState("centrix-test\n'\n<script>alert(1)</script>\nadmin' --\n%27%22")
  const [matchText, setMatchText] = useState("")
  const [extractRegex, setExtractRegex] = useState("")
  const [results, setResults] = useState<IntruderResultItem[]>([])
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState("")

  useEffect(() => {
    void scanApi
      .list()
      .then((items) => {
        setScans(items)
        if (items[0]) {
          setScanId(items[0].id)
          setUrl(`${items[0].target}${items[0].target.includes("?") ? "&" : "?"}q={{payload}}`)
        }
      })
      .catch(() => undefined)
  }, [])

  const run = async () => {
    setBusy(true)
    setError("")
    setResults([])
    try {
      const parsedHeaders = JSON.parse(headers || "{}")
      const result = await manualApi.intruder({
        scan_id: scanId,
        method,
        url,
        headers: parsedHeaders,
        body: body || undefined,
        marker,
        payloads: payloads.split(/\r?\n/).map((line) => line.trim()).filter(Boolean),
        max_requests: 50,
        delay_ms: 100,
        match_text: matchText,
        extract_regex: extractRegex,
      })
      setResults(result.results || [])
    } catch (reason: unknown) {
      setError(reason instanceof Error ? reason.message : "Intruder fuzzing execution failed.")
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="p-4 sm:p-6 lg:p-8 max-w-[1700px] mx-auto space-y-6">
      {/* Header */}
      <div className="flex flex-wrap items-start justify-between gap-4 border-b border-border pb-5">
        <div>
          <h1 className="text-xl font-bold tracking-wider text-ink uppercase font-display flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-blue" />
            Offensive Intruder & Fuzzing Workbench
          </h1>
          <p className="text-xs text-ink-3 font-mono mt-1">
            Scoped parameter fuzzing, custom payload lists, pattern matching, and automated response extraction.
          </p>
        </div>

        <CyberButton
          variant="primary"
          size="sm"
          hudCorners
          disabled={!scanId || !url || busy}
          loading={busy}
          icon={<Play size={13} className="fill-current" />}
          onClick={() => void run()}
        >
          EXECUTE FUZZING RUN
        </CyberButton>
      </div>

      {error && (
        <div className="p-3.5 rounded border border-critical/40 bg-critical/10 text-critical text-xs font-mono">
          {error}
        </div>
      )}

      {/* Grid: Config (Left) + Results (Right) */}
      <div className="grid xl:grid-cols-12 gap-6">
        {/* Left Config (5 cols) */}
        <div className="xl:col-span-5 space-y-4">
          <CyberCard title="Attack Target & Payload Configuration" icon={<Crosshair size={15} />}>
            <div className="space-y-3 font-mono text-xs">
              <div>
                <label className="block text-ink-3 text-[10px] uppercase font-semibold mb-1">
                  TARGET AUDIT SCOPE:
                </label>
                <select
                  value={scanId}
                  onChange={(e) => setScanId(e.target.value)}
                  className="w-full bg-surface border border-border focus:border-cyan/50 rounded px-2.5 py-1.5 text-ink cursor-pointer"
                >
                  {scans.map((s) => (
                    <option key={s.id} value={s.id}>
                      {s.id} - {s.target}
                    </option>
                  ))}
                </select>
              </div>

              <div className="grid grid-cols-[100px_1fr] gap-2">
                <div>
                  <label className="block text-ink-3 text-[10px] uppercase font-semibold mb-1">
                    METHOD
                  </label>
                  <select
                    value={method}
                    onChange={(e) => setMethod(e.target.value)}
                    className="w-full bg-surface border border-border rounded px-2 py-1.5 text-cyan font-bold"
                  >
                    {["GET", "POST", "PUT", "PATCH", "DELETE"].map((m) => (
                      <option key={m} value={m}>
                        {m}
                      </option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className="block text-ink-3 text-[10px] uppercase font-semibold mb-1">
                    URL (INCLUDE MARKER)
                  </label>
                  <input
                    value={url}
                    onChange={(e) => setUrl(e.target.value)}
                    className="w-full bg-surface border border-border rounded px-2.5 py-1.5 text-ink text-xs"
                  />
                </div>
              </div>

              <div>
                <label className="block text-ink-3 text-[10px] uppercase font-semibold mb-1">
                  INJECTION POSITION MARKER
                </label>
                <input
                  value={marker}
                  onChange={(e) => setMarker(e.target.value)}
                  className="w-full bg-surface border border-border rounded px-2.5 py-1.5 text-cyan font-bold"
                />
              </div>

              <div>
                <label className="block text-ink-3 text-[10px] uppercase font-semibold mb-1">
                  HEADERS (JSON)
                </label>
                <textarea
                  value={headers}
                  onChange={(e) => setHeaders(e.target.value)}
                  rows={2}
                  className="w-full bg-[#03060c] border border-border rounded p-2 text-xs text-ink-2"
                />
              </div>

              <div>
                <label className="block text-ink-3 text-[10px] uppercase font-semibold mb-1">
                  OPTIONAL BODY (WITH MARKER)
                </label>
                <textarea
                  value={body}
                  onChange={(e) => setBody(e.target.value)}
                  rows={2}
                  placeholder="e.g. { 'search': '{{payload}}' }"
                  className="w-full bg-[#03060c] border border-border rounded p-2 text-xs text-ink-2"
                />
              </div>

              <div>
                <label className="block text-ink-3 text-[10px] uppercase font-semibold mb-1">
                  PAYLOAD SET (ONE PER LINE)
                </label>
                <textarea
                  value={payloads}
                  onChange={(e) => setPayloads(e.target.value)}
                  rows={6}
                  className="w-full bg-[#03060c] border border-border rounded p-2.5 text-xs text-ink-2"
                />
              </div>

              <div className="grid sm:grid-cols-2 gap-2 pt-1">
                <div>
                  <label className="block text-ink-3 text-[10px] uppercase font-semibold mb-1">
                    GREP MATCH TEXT
                  </label>
                  <input
                    value={matchText}
                    onChange={(e) => setMatchText(e.target.value)}
                    placeholder="e.g. error, root, SQL syntax"
                    className="w-full bg-surface border border-border rounded px-2.5 py-1.5 text-ink"
                  />
                </div>
                <div>
                  <label className="block text-ink-3 text-[10px] uppercase font-semibold mb-1">
                    EXTRACT REGEX
                  </label>
                  <input
                    value={extractRegex}
                    onChange={(e) => setExtractRegex(e.target.value)}
                    placeholder="e.g. token=([a-f0-9]+)"
                    className="w-full bg-surface border border-border rounded px-2.5 py-1.5 text-ink"
                  />
                </div>
              </div>
            </div>
          </CyberCard>
        </div>

        {/* Right Results (7 cols) */}
        <div className="xl:col-span-7">
          <CyberCard
            title="Attack Execution Results"
            subtitle={`${results.length} response frames captured`}
            noPadding
          >
            <div className="overflow-x-auto">
              <table className="w-full text-left font-mono text-xs">
                <thead>
                  <tr className="border-b border-border bg-surface text-[10px] text-ink-3 uppercase">
                    <th className="p-3">#</th>
                    <th className="p-3">PAYLOAD</th>
                    <th className="p-3">STATUS</th>
                    <th className="p-3">LENGTH</th>
                    <th className="p-3">TIME</th>
                    <th className="p-3">MATCH</th>
                    <th className="p-3">EXTRACTED</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border/60">
                  {results.length === 0 ? (
                    <tr>
                      <td colSpan={7} className="p-12 text-center text-ink-3 italic">
                        {busy ? "Transmitting fuzzing payloads..." : "No active attack results. Configure parameters and run."}
                      </td>
                    </tr>
                  ) : (
                    results.map((res, i) => (
                      <tr key={i} className="hover:bg-surface/60 transition-colors">
                        <td className="p-3 text-ink-3">{i + 1}</td>
                        <td className="p-3 text-ink font-semibold break-all max-w-xs">
                          {res.payload}
                        </td>
                        <td className="p-3">
                          <span
                            className={`font-bold ${
                              res.status >= 200 && res.status < 300
                                ? "text-emerald"
                                : res.status >= 500
                                  ? "text-critical"
                                  : "text-ink-2"
                            }`}
                          >
                            {res.status || "ERR"}
                          </span>
                        </td>
                        <td className="p-3 text-ink-3">{res.length || "-"} B</td>
                        <td className="p-3 text-ink-3">{res.duration_ms ? `${res.duration_ms}ms` : "-"}</td>
                        <td className="p-3">
                          {res.matched ? (
                            <span className="text-critical font-bold">MATCH</span>
                          ) : (
                            <span className="text-ink-3">-</span>
                          )}
                        </td>
                        <td className="p-3 text-cyan truncate max-w-xs">
                          {res.extracted || "-"}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </CyberCard>
        </div>
      </div>
    </div>
  )
}
