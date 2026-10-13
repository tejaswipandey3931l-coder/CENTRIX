import { useEffect, useMemo, useState } from "react"
import {
  Radio,
  ShieldCheck,
  Send,
  Search,
  CheckCircle2,
} from "lucide-react"
import {
  manualApi,
  scanApi,
  type ScanItem,
  type CorpusItem,
  type ProxyStatus,
  type CaStatus,
  type BrowserStatus,
  type RepeaterRequest,
} from "../api/client"
import { CyberCard } from "../components/ui/CyberCard"
import { CyberButton } from "../components/ui/CyberButton"

import { useNavigate } from "react-router-dom"
import { useScanContext } from "../context/ScanContext"

interface ProxyHistoryProps {
  onNavigate?: (page: string) => void
  onSendToRepeater?: (request: RepeaterRequest) => void
}

export default function ProxyHistory({ onNavigate, onSendToRepeater }: ProxyHistoryProps) {
  const navigate = useNavigate()
  const { setRepeaterRequest } = useScanContext()
  const [scans, setScans] = useState<ScanItem[]>([])
  const [scanId, setScanId] = useState("")
  const [items, setItems] = useState<CorpusItem[]>([])
  const [selected, setSelected] = useState<CorpusItem | null>(null)
  const [proxy, setProxy] = useState<ProxyStatus | null>(null)
  const [ca, setCa] = useState<CaStatus | null>(null)
  const [browser, setBrowser] = useState<BrowserStatus | null>(null)
  const [filter, setFilter] = useState("")
  const [message, setMessage] = useState("")

  const load = async () => {
    try {
      const [nextScans, nextProxy, nextCa, nextBrowser] = await Promise.all([
        scanApi.list(),
        manualApi.proxyStatus(),
        manualApi.caStatus(),
        manualApi.browserStatus(),
      ])
      setScans(nextScans)
      setProxy(nextProxy)
      setCa(nextCa)
      setBrowser(nextBrowser)
      const chosen = scanId || nextScans[0]?.id || ""
      if (chosen) {
        setScanId(chosen)
        const nextItems = await manualApi.corpus(chosen)
        setItems(nextItems)
        setSelected((current: any) => current || nextItems[0] || null)
      }
    } catch {
      // ignore
    }
  }

  useEffect(() => {
    void load().catch(() => undefined)
  }, [])

  useEffect(() => {
    if (!scanId) return
    void manualApi
      .corpus(scanId)
      .then((next) => {
        setItems(next)
        setSelected(next[0] || null)
      })
      .catch(() => setItems([]))
  }, [scanId])

  const filtered = useMemo(() => {
    const needle = filter.toLowerCase()
    return items.filter((item) =>
      `${item.method} ${item.url} ${item.status || ""}`.toLowerCase().includes(needle),
    )
  }, [items, filter])

  const toggleProxy = async () => {
    setProxy(proxy?.running ? await manualApi.proxyStop() : await manualApi.proxyStart(scanId))
  }

  const generateCa = async () => {
    setCa(await manualApi.caGenerate())
    setMessage("CENTRIX Local Testing Root CA generated. Trust it strictly inside an isolated testing browser profile.")
  }

  const generateLeaf = async () => {
    const scan = scans.find((item) => item.id === scanId)
    const target = scan?.target || selected?.url || ""
    if (!target) return
    const hostname = new URL(target).hostname
    await manualApi.leafGenerate(hostname)
    setMessage(`Leaf SSL certificate generated for ${hostname}.`)
  }

  const openBrowser = async () => {
    const scan = scans.find((item) => item.id === scanId)
    const target = scan?.target || selected?.url || ""
    const result = await manualApi.browserOpen(target, scanId, Boolean(proxy?.running))
    setBrowser(result)
    setMessage(result.ok ? "Controlled browser session initialized." : result.error || "Browser could not open.")
  }

  const runPassive = async () => {
    if (!scanId) return
    const result = await manualApi.runPassive(scanId)
    setMessage(`Passive analysis extracted and imported ${result.imported} findings from captured traffic.`)
  }

  const sendToRepeater = (item: any) => {
    const payload = {
      method: item.method,
      url: item.url,
      scan_id: scanId,
      request_headers: item.request_headers,
      request_body: item.request_body,
    }
    if (onSendToRepeater) {
      onSendToRepeater(payload)
    } else {
      setRepeaterRequest(payload)
    }
    if (onNavigate) {
      onNavigate("manual-testing")
    } else {
      navigate("/manual")
    }
  }

  return (
    <div className="p-4 sm:p-6 lg:p-8 max-w-[1700px] mx-auto space-y-6">
      {/* Header */}
      <div className="flex flex-wrap items-start justify-between gap-4 border-b border-border pb-5">
        <div>
          <h1 className="text-xl font-bold tracking-wider text-ink uppercase font-display flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-cyan shadow-[0_0_8px_#00f0ff]" />
            Capture Proxy & Traffic Corpus History
          </h1>
          <p className="text-xs text-ink-3 font-mono mt-1">
            Intercept, review, and extract passive vulnerabilities from browser and API traffic.
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <CyberButton
            variant="secondary"
            size="sm"
            disabled={!scanId}
            icon={<ShieldCheck size={14} className="text-emerald" />}
            onClick={() => void runPassive()}
          >
            PASSIVE SCAN
          </CyberButton>

          <CyberButton
            variant={proxy?.running ? "danger" : "primary"}
            size="sm"
            hudCorners
            icon={<Radio size={14} className={proxy?.running ? "animate-pulse" : ""} />}
            onClick={() => void toggleProxy()}
          >
            {proxy?.running ? "TERMINATE PROXY" : "ACTIVATE PROXY"}
          </CyberButton>
        </div>
      </div>

      {message && (
        <div className="p-3 rounded border border-emerald/40 bg-emerald/10 text-emerald text-xs font-mono flex items-center gap-2">
          <CheckCircle2 size={14} className="shrink-0" />
          <span>{message}</span>
        </div>
      )}

      {/* Controller HUD Bar */}
      <div className="grid md:grid-cols-3 gap-4 font-mono text-xs">
        <CyberCard title="Proxy Engine Telemetry" noPadding className="p-3.5">
          <div className="flex items-center justify-between">
            <span className="text-ink-3">PROXY LISTENER:</span>
            <span className={`font-bold ${proxy?.running ? "text-cyan" : "text-ink-3"}`}>
              {proxy?.running ? `PORT ${proxy?.port || 8080} ACTIVE` : "INACTIVE"}
            </span>
          </div>
          <p className="text-[11px] text-ink-3 mt-1 truncate">
            {proxy?.running ? "Routing client traffic through local analyzer" : "Proxy listener offline"}
          </p>
        </CyberCard>

        <CyberCard title="SSL / TLS CA Controller" noPadding className="p-3.5">
          <div className="flex items-center justify-between">
            <span className="text-ink-3">ROOT CA:</span>
            <div className="flex gap-2">
              <button
                onClick={() => void generateCa()}
                className="text-[11px] text-cyan hover:underline cursor-pointer"
              >
                Generate
              </button>
              {ca?.ready && (
                <a
                  href={manualApi.caDownloadUrl()}
                  download
                  className="text-[11px] text-emerald hover:underline"
                >
                  Download
                </a>
              )}
            </div>
          </div>
          <button
            onClick={() => void generateLeaf()}
            className="text-[11px] text-ink-3 hover:text-ink mt-1 block text-left"
          >
            Issue leaf cert for target host
          </button>
        </CyberCard>

        <CyberCard title="Controlled Test Browser" noPadding className="p-3.5">
          <div className="flex items-center justify-between">
            <span className="text-ink-3">PLAYWRIGHT BROWSER:</span>
            <button
              onClick={() => void openBrowser()}
              className="text-[11px] text-cyan hover:underline font-bold cursor-pointer"
            >
              Launch Browser
            </button>
          </div>
          <p className="text-[11px] text-ink-3 mt-1 truncate">
            {browser?.running ? "Dedicated test profile active" : "Standalone isolated browser"}
          </p>
        </CyberCard>
      </div>

      {/* Scope Selector & Search */}
      <div className="flex flex-wrap items-center gap-3">
        <select
          value={scanId}
          onChange={(e) => setScanId(e.target.value)}
          className="bg-panel border border-border rounded px-3 py-2 text-xs font-mono text-ink cursor-pointer"
        >
          {scans.map((s) => (
            <option key={s.id} value={s.id}>
              {s.id} - {s.target}
            </option>
          ))}
        </select>

        <div className="relative flex-1 min-w-[240px]">
          <Search size={14} className="absolute left-3 top-3 text-ink-3 pointer-events-none" />
          <input
            type="text"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            placeholder="Filter traffic corpus by method, URL, or status..."
            className="w-full bg-panel border border-border focus:border-cyan/60 rounded pl-9 pr-3 py-2 text-xs text-ink font-mono placeholder:text-ink-3"
          />
        </div>
      </div>

      {/* Split Traffic Corpus: Table (Left) + Request Inspector (Right) */}
      <div className="grid lg:grid-cols-12 gap-6">
        {/* Left: Corpus Table */}
        <div className="lg:col-span-7">
          <CyberCard
            title="Captured Traffic Records"
            subtitle={`${filtered.length} requests in active corpus`}
            noPadding
          >
            <div className="max-h-[560px] overflow-y-auto divide-y divide-border/60 font-mono text-xs">
              {filtered.length === 0 ? (
                <p className="p-8 text-center text-ink-3">No captured requests recorded yet.</p>
              ) : (
                filtered.map((item) => {
                  const isSelected = selected?.id === item.id
                  return (
                    <div
                      key={item.id}
                      onClick={() => setSelected(item)}
                      className={`p-3.5 transition-colors cursor-pointer flex items-center justify-between gap-3 ${
                        isSelected
                          ? "bg-elevated border-l-2 border-l-cyan"
                          : "hover:bg-surface"
                      }`}
                    >
                      <div className="flex items-center gap-3 min-w-0">
                        <span
                          className={`font-bold w-12 shrink-0 ${
                            item.method === "POST"
                              ? "text-emerald"
                              : item.method === "DELETE"
                                ? "text-critical"
                                : item.method === "PUT"
                                  ? "text-high"
                                  : "text-cyan"
                          }`}
                        >
                          {item.method}
                        </span>
                        <span className="text-ink truncate max-w-sm">{item.url}</span>
                      </div>

                      <div className="flex items-center gap-3 shrink-0">
                        <span className="text-ink-3 text-[11px]">{item.status || "-"}</span>
                        <CyberButton
                          size="xs"
                          variant="ghost"
                          onClick={(e) => {
                            e.stopPropagation()
                            sendToRepeater(item)
                          }}
                        >
                          Repeater
                        </CyberButton>
                      </div>
                    </div>
                  )
                })
              )}
            </div>
          </CyberCard>
        </div>

        {/* Right: Forensic Request/Response Inspector */}
        <div className="lg:col-span-5">
          <CyberCard
            title="Traffic Inspection & Frame Viewer"
            subtitle={selected ? `${selected.method} ${selected.url}` : "Select a request"}
            action={
              selected && (
                <CyberButton
                  size="xs"
                  variant="primary"
                  icon={<Send size={12} />}
                  onClick={() => sendToRepeater(selected)}
                >
                  SEND TO REPEATER
                </CyberButton>
              )
            }
          >
            {selected ? (
              <div className="space-y-4 font-mono text-xs">
                <div>
                  <span className="text-ink-3 text-[10px] uppercase font-bold block mb-1">
                    CAPTURED REQUEST HEADERS
                  </span>
                  <pre className="p-3 rounded bg-[#03060c] border border-border text-xs text-ink-2 max-h-40 overflow-y-auto whitespace-pre-wrap">
                    {JSON.stringify(selected.request_headers || {}, null, 2)}
                  </pre>
                </div>

                {selected.request_body && (
                  <div>
                    <span className="text-ink-3 text-[10px] uppercase font-bold block mb-1">
                      REQUEST BODY
                    </span>
                    <pre className="p-3 rounded bg-[#03060c] border border-border text-xs text-ink-2 max-h-36 overflow-y-auto whitespace-pre-wrap">
                      {selected.request_body}
                    </pre>
                  </div>
                )}

                <div>
                  <span className="text-ink-3 text-[10px] uppercase font-bold block mb-1">
                    SERVER RESPONSE EXCERPT
                  </span>
                  <pre className="p-3 rounded bg-[#03060c] border border-border text-xs text-ink-2 max-h-56 overflow-y-auto whitespace-pre-wrap">
                    {selected.response_body || selected.response_excerpt || "[No response body captured]"}
                  </pre>
                </div>
              </div>
            ) : (
              <div className="py-24 text-center text-ink-3 font-mono text-xs">
                Click any captured request row from the corpus list to inspect headers and payloads.
              </div>
            )}
          </CyberCard>
        </div>
      </div>
    </div>
  )
}
