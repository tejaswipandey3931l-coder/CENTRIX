import { useEffect, useState } from "react"
import { GitCompare } from "lucide-react"
import { manualApi, scanApi, type ScanItem, type CorpusItem, type CompareResult } from "../api/client"
import { CyberCard } from "../components/ui/CyberCard"
import { CyberButton } from "../components/ui/CyberButton"
import { StatWidget } from "../components/ui/StatWidget"

export default function Comparer() {
  const [scans, setScans] = useState<ScanItem[]>([])
  const [scanId, setScanId] = useState("")
  const [items, setItems] = useState<CorpusItem[]>([])
  const [leftId, setLeftId] = useState("")
  const [rightId, setRightId] = useState("")
  const [result, setResult] = useState<CompareResult | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState("")

  useEffect(() => {
    void scanApi
      .list()
      .then((next) => {
        setScans(next)
        if (next[0]) setScanId(next[0].id)
      })
      .catch(() => undefined)
  }, [])

  useEffect(() => {
    if (!scanId) return
    void manualApi
      .corpus(scanId)
      .then((next) => {
        setItems(next)
        setLeftId(next[0]?.id || "")
        setRightId(next[1]?.id || next[0]?.id || "")
      })
      .catch(() => setItems([]))
  }, [scanId])

  const compare = async () => {
    setError("")
    setBusy(true)
    try {
      setResult(await manualApi.compareCorpus(leftId, rightId))
    } catch (reason: any) {
      setError(reason.message || "Differential comparison failed.")
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
            <span className="w-2.5 h-2.5 rounded-full bg-cyan shadow-[0_0_8px_#00f0ff]" />
            Response Differential Comparer
          </h1>
          <p className="text-xs text-ink-3 font-mono mt-1">
            Analyze discrepancies between two captured server responses across status, byte length, execution timing, and headers.
          </p>
        </div>

        <CyberButton
          variant="primary"
          size="sm"
          hudCorners
          disabled={!leftId || !rightId}
          loading={busy}
          icon={<GitCompare size={13} />}
          onClick={() => void compare()}
        >
          EXECUTE COMPARISON
        </CyberButton>
      </div>

      {error && (
        <div className="p-3.5 rounded border border-critical/40 bg-critical/10 text-critical text-xs font-mono">
          {error}
        </div>
      )}

      {/* Frame Selection Bar */}
      <CyberCard
        title="Select Traffic Frames to Compare"
        subtitle="Compare baseline response against fuzzing payload"
      >
        <div className="grid md:grid-cols-3 gap-4 font-mono text-xs">
          <div>
            <label className="block text-ink-3 text-[10px] uppercase font-semibold mb-1">
              TARGET SCAN CORPUS:
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

          <div>
            <label className="block text-ink-3 text-[10px] uppercase font-semibold mb-1">
              FRAME A (BASELINE):
            </label>
            <select
              value={leftId}
              onChange={(e) => setLeftId(e.target.value)}
              className="w-full bg-surface border border-border focus:border-cyan/50 rounded px-2.5 py-1.5 text-ink cursor-pointer"
            >
              {items.map((it) => (
                <option key={it.id} value={it.id}>
                  {it.method} {it.status || "-"} {it.path || it.url}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="block text-ink-3 text-[10px] uppercase font-semibold mb-1">
              FRAME B (PROBE):
            </label>
            <select
              value={rightId}
              onChange={(e) => setRightId(e.target.value)}
              className="w-full bg-surface border border-border focus:border-cyan/50 rounded px-2.5 py-1.5 text-ink cursor-pointer"
            >
              {items.map((it) => (
                <option key={it.id} value={it.id}>
                  {it.method} {it.status || "-"} {it.path || it.url}
                </option>
              ))}
            </select>
          </div>
        </div>
      </CyberCard>

      {/* Comparison Results */}
      {result ? (
        <div className="space-y-6">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <StatWidget
              label="STATUS CODE DRIFT"
              value={result.status_changed ? "CHANGED" : "IDENTICAL"}
              sublabel={result.status_changed ? "Anomaly detected" : "No HTTP status delta"}
              accent={result.status_changed ? "critical" : "emerald"}
            />

            <StatWidget
              label="BYTE LENGTH DELTA"
              value={`${(result.length_delta ?? 0) > 0 ? "+" : ""}${result.length_delta ?? 0} B`}
              sublabel="Size variance between frames"
              accent={Math.abs(result.length_delta ?? 0) > 50 ? "high" : "default"}
            />

            <StatWidget
              label="TIMING VARIANCE"
              value={`${Math.round(result.time_delta_ms ?? 0)} ms`}
              sublabel="Latency delta"
              accent="cyan"
            />

            <StatWidget
              label="BODY HASH COMPARISON"
              value={result.body_hash_changed ? "MUTATED" : "IDENTICAL"}
              sublabel="Cryptographic hash diff"
              accent={result.body_hash_changed ? "violet" : "default"}
            />
          </div>

          {/* Header Changes */}
          <div className="grid md:grid-cols-2 gap-6 font-mono text-xs">
            <CyberCard title="Headers Added in Frame B" subtitle="New response headers detected">
              <div className="p-3 bg-surface border border-border rounded">
                {(result.header_keys_added || []).length > 0 ? (
                  <ul className="space-y-1 text-emerald">
                    {(result.header_keys_added || []).map((k: string) => (
                      <li key={k}>+ {k}</li>
                    ))}
                  </ul>
                ) : (
                  <span className="text-ink-3">None</span>
                )}
              </div>
            </CyberCard>

            <CyberCard title="Headers Removed in Frame B" subtitle="Omitted headers detected">
              <div className="p-3 bg-surface border border-border rounded">
                {(result.header_keys_removed || []).length > 0 ? (
                  <ul className="space-y-1 text-critical">
                    {(result.header_keys_removed || []).map((k: string) => (
                      <li key={k}>- {k}</li>
                    ))}
                  </ul>
                ) : (
                  <span className="text-ink-3">None</span>
                )}
              </div>
            </CyberCard>
          </div>
        </div>
      ) : (
        <div className="p-16 border border-border rounded bg-panel text-center text-xs font-mono text-ink-3">
          Select two captured response frames above and execute comparison to evaluate variances.
        </div>
      )}
    </div>
  )
}
