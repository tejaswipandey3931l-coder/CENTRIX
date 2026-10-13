import { useEffect, useState } from "react"
import { Save, GitCompare, Send, Terminal, CheckCircle2 } from "lucide-react"
import { manualApi, scanApi, type ScanItem, type ReplayResponse, type CompareResult, type RepeaterRequest } from "../api/client"
import { CyberCard } from "../components/ui/CyberCard"
import { CyberButton } from "../components/ui/CyberButton"

import { useScanContext } from "../context/ScanContext"

interface ManualTestingProps {
  onNavigate?: (page: string) => void
  repeaterRequest?: RepeaterRequest | null
  setRepeaterRequest?: (value: RepeaterRequest | null) => void
}

function originOf(value: string) {
  try {
    const parsed = new URL(value)
    return `${parsed.protocol}//${parsed.host}`.toLowerCase()
  } catch {
    return ""
  }
}

function scanMatchesUrl(scan: ScanItem | null | undefined, requestUrl: string) {
  const requestOrigin = originOf(requestUrl)
  const scanOrigin = originOf(scan?.target || "")
  return Boolean(requestOrigin && scanOrigin && requestOrigin === scanOrigin)
}

function bestScan(scans: ScanItem[], requestUrl = ""): ScanItem | null {
  if (!scans.length) return null
  if (requestUrl) {
    const matching = scans.find((scan) => scanMatchesUrl(scan, requestUrl))
    if (matching) return matching
  }
  return (
    scans.find((scan) => scan.status === "completed" && scan.findings_count > 0) ||
    scans.find((scan) => scan.status === "completed") ||
    scans[0] ||
    null
  )
}

export default function ManualTesting({
  repeaterRequest,
  setRepeaterRequest,
}: ManualTestingProps) {
  const context = useScanContext()
  const activeReq = repeaterRequest ?? context.repeaterRequest
  const setActiveReq = setRepeaterRequest ?? context.setRepeaterRequest

  const [scans, setScans] = useState<ScanItem[]>([])
  const [scanId, setScanId] = useState("")
  const [method, setMethod] = useState("GET")
  const [url, setUrl] = useState("")
  const [headers, setHeaders] = useState("{\n}")
  const [body, setBody] = useState("")
  const [activeSlot, setActiveSlot] = useState<"left" | "right">("left")
  const [leftResult, setLeftResult] = useState<ReplayResponse | null>(null)
  const [rightResult, setRightResult] = useState<ReplayResponse | null>(null)
  const [comparison, setComparison] = useState<CompareResult | null>(null)
  const [busy, setBusy] = useState(false)
  const [saveMessage, setSaveMessage] = useState("")
  const [error, setError] = useState("")

  useEffect(() => {
    void scanApi
      .list()
      .then((items) => {
        setScans(items)
        const selected = bestScan(items)
        if (selected) {
          setScanId(selected.id)
          if (!url && selected.target) {
            setUrl(`${selected.target}/api/v1/resource`)
          }
        }
      })
      .catch(() => setScans([]))
  }, [])

  useEffect(() => {
    if (!url || !scans.length) return
    const matching = bestScan(scans, url)
    if (matching && matching.id !== scanId && scanMatchesUrl(matching, url)) {
      setScanId(matching.id)
    }
  }, [url, scans, scanId])

  useEffect(() => {
    if (!activeReq) return
    if (activeReq.url) setUrl(activeReq.url)
    if (activeReq.method) setMethod(activeReq.method)
    if (activeReq.scan_id) setScanId(activeReq.scan_id)
    if (activeReq.request_headers || activeReq.headers) {
      setHeaders(JSON.stringify(activeReq.request_headers || activeReq.headers, null, 2))
    }
    if (activeReq.request_body || activeReq.body) {
      setBody(activeReq.request_body || activeReq.body || "")
    }
    setActiveReq(null)
  }, [activeReq, setActiveReq])

  const replay = async () => {
    setError("")
    setComparison(null)
    setBusy(true)
    try {
      const matching = bestScan(scans, url)
      const requestScanId = matching && scanMatchesUrl(matching, url) ? matching.id : scanId
      if (requestScanId !== scanId) setScanId(requestScanId)
      const parsedHeaders = JSON.parse(headers || "{}")
      const result = await manualApi.replay({
        scan_id: requestScanId,
        method,
        url,
        headers: parsedHeaders,
        body: body || undefined,
      })
      if (activeSlot === "left") setLeftResult(result)
      else setRightResult(result)
    } catch (reason: any) {
      setError(reason.message || "Manual request replay failed.")
    } finally {
      setBusy(false)
    }
  }

  const saveRequest = async () => {
    try {
      const activeResp = activeSlot === "left" ? leftResult : rightResult
      await manualApi.saveRequest({
        scan_id: scanId,
        method,
        url,
        headers: JSON.parse(headers || "{}"),
        body: body || undefined,
        response: activeResp || undefined,
      })
      setSaveMessage("Captured request & response committed to corpus vault.")
      setTimeout(() => setSaveMessage(""), 3000)
    } catch (reason: any) {
      setError(reason.message || "Failed to save request to corpus.")
    }
  }

  const compare = async () => {
    if (!leftResult || !rightResult) return
    try {
      const result = await manualApi.compare(leftResult, rightResult)
      setComparison(result)
    } catch (reason: any) {
      setError(reason.message || "Response comparison failed.")
    }
  }

  const currentResult = activeSlot === "left" ? leftResult : rightResult

  return (
    <div className="p-4 sm:p-6 lg:p-8 max-w-[1700px] mx-auto space-y-6">
      {/* Header */}
      <div className="flex flex-wrap items-start justify-between gap-4 border-b border-border pb-5">
        <div>
          <h1 className="text-xl font-bold tracking-wider text-ink uppercase font-display flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-cyan shadow-[0_0_8px_#00f0ff]" />
            Offensive Repeater Workbench
          </h1>
          <p className="text-xs text-ink-3 font-mono mt-1">
            Manual HTTP payload modification, response replay verification, and differential analysis.
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <CyberButton
            variant="secondary"
            size="sm"
            icon={<Save size={13} />}
            disabled={!url}
            onClick={() => void saveRequest()}
          >
            SAVE TO CORPUS
          </CyberButton>

          <CyberButton
            variant="primary"
            size="sm"
            hudCorners
            loading={busy}
            disabled={!url}
            icon={<Send size={13} />}
            onClick={() => void replay()}
          >
            TRANSMIT REQUEST
          </CyberButton>
        </div>
      </div>

      {saveMessage && (
        <div className="p-3 rounded border border-emerald/40 bg-emerald/10 text-emerald text-xs font-mono flex items-center gap-2">
          <CheckCircle2 size={14} className="shrink-0" />
          <span>{saveMessage}</span>
        </div>
      )}

      {error && (
        <div className="p-3.5 rounded border border-critical/40 bg-critical/10 text-critical text-xs font-mono">
          {error}
        </div>
      )}

      {/* Target & Method Bar */}
      <CyberCard noPadding className="p-3.5">
        <div className="grid md:grid-cols-12 gap-3 items-center font-mono text-xs">
          <div className="md:col-span-3">
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

          <div className="md:col-span-2">
            <select
              value={method}
              onChange={(e) => setMethod(e.target.value)}
              className="w-full bg-surface border border-border focus:border-cyan/50 rounded px-2.5 py-1.5 text-cyan font-bold cursor-pointer"
            >
              {["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"].map((m) => (
                <option key={m} value={m}>
                  {m}
                </option>
              ))}
            </select>
          </div>

          <div className="md:col-span-7">
            <input
              type="text"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://target.com/api/v1/auth"
              className="w-full bg-surface border border-border focus:border-cyan/50 rounded px-3 py-1.5 text-ink text-xs font-mono"
            />
          </div>
        </div>
      </CyberCard>

      {/* Split Workbench: Request (Left) + Response (Right) */}
      <div className="grid lg:grid-cols-2 gap-6">
        {/* Request Editor */}
        <CyberCard
          title="HTTP Request Frame"
          subtitle="Headers & payload buffer"
          icon={<Terminal size={15} />}
        >
          <div className="space-y-4 font-mono text-xs">
            <div>
              <span className="text-ink-3 text-[10px] uppercase font-semibold mb-1 block">
                HEADERS (JSON FORMAT)
              </span>
              <textarea
                value={headers}
                onChange={(e) => setHeaders(e.target.value)}
                rows={7}
                spellCheck={false}
                className="w-full bg-[#03060c] border border-border rounded p-3 text-xs font-mono text-ink-2 selection:bg-cyan/30 focus:border-cyan/40"
              />
            </div>

            <div>
              <span className="text-ink-3 text-[10px] uppercase font-semibold mb-1 block">
                PAYLOAD BODY
              </span>
              <textarea
                value={body}
                onChange={(e) => setBody(e.target.value)}
                rows={11}
                spellCheck={false}
                placeholder="Raw POST/PUT body..."
                className="w-full bg-[#03060c] border border-border rounded p-3 text-xs font-mono text-ink-2 selection:bg-cyan/30 focus:border-cyan/40"
              />
            </div>
          </div>
        </CyberCard>

        {/* Response Viewer */}
        <CyberCard
          title="Server Response Analysis"
          subtitle={
            currentResult
              ? `HTTP ${currentResult.status} · ${currentResult.duration_ms}ms · ${currentResult.length} bytes`
              : "Awaiting transmission"
          }
          action={
            <div className="flex items-center gap-2">
              <div className="flex items-center bg-surface border border-border rounded p-0.5 text-[10px] font-mono">
                <button
                  onClick={() => setActiveSlot("left")}
                  className={`px-2 py-0.5 rounded ${
                    activeSlot === "left"
                      ? "bg-cyan/20 text-cyan font-bold"
                      : "text-ink-3 hover:text-ink"
                  }`}
                >
                  SLOT A
                </button>
                <button
                  onClick={() => setActiveSlot("right")}
                  className={`px-2 py-0.5 rounded ${
                    activeSlot === "right"
                      ? "bg-cyan/20 text-cyan font-bold"
                      : "text-ink-3 hover:text-ink"
                  }`}
                >
                  SLOT B
                </button>
              </div>

              {leftResult && rightResult && (
                <CyberButton
                  size="xs"
                  variant="outline"
                  icon={<GitCompare size={11} />}
                  onClick={() => void compare()}
                >
                  DIFF
                </CyberButton>
              )}
            </div>
          }
        >
          {currentResult ? (
            <div className="space-y-4 font-mono text-xs">
              {/* Status Header */}
              <div className="flex items-center gap-3 p-2.5 rounded bg-surface border border-border">
                <span
                  className={`font-bold text-xs px-2 py-0.5 rounded ${
                    currentResult.status >= 200 && currentResult.status < 300
                      ? "bg-emerald/20 text-emerald"
                      : currentResult.status >= 400 && currentResult.status < 500
                        ? "bg-high/20 text-high"
                        : currentResult.status >= 500
                          ? "bg-critical/20 text-critical"
                          : "bg-cyan/20 text-cyan"
                  }`}
                >
                  HTTP {currentResult.status}
                </span>
                <span className="text-ink-3">LATENCY: <strong className="text-ink">{currentResult.duration_ms} ms</strong></span>
                <span className="text-ink-3">SIZE: <strong className="text-ink">{currentResult.length} B</strong></span>
              </div>

              {/* Response Headers */}
              <div>
                <span className="text-ink-3 text-[10px] uppercase font-semibold mb-1 block">
                  RESPONSE HEADERS
                </span>
                <pre className="p-2.5 rounded bg-[#03060c] border border-border text-[11px] text-ink-2 max-h-36 overflow-y-auto whitespace-pre-wrap">
                  {JSON.stringify(currentResult.headers, null, 2)}
                </pre>
              </div>

              {/* Response Body */}
              <div>
                <span className="text-ink-3 text-[10px] uppercase font-semibold mb-1 block">
                  RESPONSE BODY
                </span>
                <pre className="p-3.5 rounded bg-[#03060c] border border-border text-xs text-ink-2 max-h-80 overflow-y-auto whitespace-pre-wrap selection:bg-cyan/30">
                  {currentResult.body || "[Empty Response Body]"}
                </pre>
              </div>

              {/* Comparison Results */}
              {comparison && (
                <div className="p-3 rounded bg-surface border border-cyan/40 text-xs space-y-1">
                  <span className="font-bold text-cyan uppercase text-[11px]">DIFFERENTIAL REPORT:</span>
                  <div className="grid grid-cols-2 gap-2 text-[11px] text-ink-2">
                    <div>Status Changed: <strong className="text-ink">{comparison.status_changed ? "YES" : "NO"}</strong></div>
                    <div>Length Delta: <strong className="text-ink">{comparison.length_delta} B</strong></div>
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="py-20 text-center text-xs font-mono text-ink-3 space-y-2">
              <p>No response in {activeSlot.toUpperCase()}.</p>
              <p className="text-[11px]">Click "Transmit Request" to fire an HTTP probe.</p>
            </div>
          )}
        </CyberCard>
      </div>
    </div>
  )
}
