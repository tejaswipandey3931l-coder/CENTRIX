import { useEffect, useState } from "react"
import { Copy, RefreshCw, Satellite, Check, Radio } from "lucide-react"
import { oobApi, scanApi } from "../api/client"
import { CyberCard } from "../components/ui/CyberCard"
import { CyberButton } from "../components/ui/CyberButton"

export default function OobMonitor() {
  const [scans, setScans] = useState<any[]>([])
  const [scanId, setScanId] = useState("")
  const [token, setToken] = useState("")
  const [events, setEvents] = useState<any[]>([])
  const [copied, setCopied] = useState(false)
  const [message, setMessage] = useState("")
  const [loading, setLoading] = useState(true)

  const load = async () => {
    setLoading(true)
    try {
      const [nextScans, nextEvents] = await Promise.all([
        scanApi.list(),
        oobApi.events(token || undefined),
      ])
      setScans(nextScans)
      if (!scanId && nextScans[0]) setScanId(nextScans[0].id)
      setEvents(nextEvents)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    void load().catch(() => undefined)
    const interval = setInterval(() => {
      if (token) void oobApi.events(token).then(setEvents).catch(() => undefined)
    }, 4000)
    return () => clearInterval(interval)
  }, [token])

  const create = async () => {
    const result = await oobApi.createToken(scanId)
    setToken(result.token)
    setMessage("New Out-of-Band callback token generated. Use a public tunnel if the target must call back from the internet.")
    setEvents([])
  }

  const callback = token ? oobApi.callbackUrl(token) : ""

  const copyUrl = async () => {
    if (!callback) return
    await navigator.clipboard.writeText(callback)
    setCopied(true)
    setTimeout(() => setCopied(false), 1500)
  }

  return (
    <div className="p-4 sm:p-6 lg:p-8 max-w-[1700px] mx-auto space-y-6">
      {/* Header */}
      <div className="flex flex-wrap items-start justify-between gap-4 border-b border-border pb-5">
        <div>
          <h1 className="text-xl font-bold tracking-wider text-ink uppercase font-display flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-cyan shadow-[0_0_8px_#00f0ff]" />
            Out-of-Band (OOB) Interaction Monitor
          </h1>
          <p className="text-xs text-ink-3 font-mono mt-1">
            Real-time listener for blind SSRF, asynchronous XXE, and DNS/HTTP external callback triggers.
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <CyberButton
            variant="secondary"
            size="sm"
            icon={<RefreshCw size={13} className={loading ? "animate-spin" : ""} />}
            onClick={() => void load()}
          >
            REFRESH
          </CyberButton>

          <CyberButton
            variant="primary"
            size="sm"
            hudCorners
            icon={<Satellite size={13} />}
            onClick={() => void create()}
          >
            GENERATE OOB TOKEN
          </CyberButton>
        </div>
      </div>

      {message && (
        <div className="p-3.5 rounded border border-cyan/40 bg-cyan/10 text-cyan text-xs font-mono">
          {message}
        </div>
      )}

      {/* Target & Token Card */}
      <CyberCard
        title="OOB Callback Configuration"
        subtitle="Route callback payloads into your active assessment session"
      >
        <div className="space-y-3 font-mono text-xs">
          <div>
            <label className="block text-ink-3 text-[10px] uppercase font-semibold mb-1">
              ASSOCIATED AUDIT SCOPE:
            </label>
            <select
              value={scanId}
              onChange={(e) => setScanId(e.target.value)}
              className="w-full bg-surface border border-border focus:border-cyan/50 rounded px-2.5 py-1.5 text-ink cursor-pointer max-w-md"
            >
              {scans.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.id} - {s.target}
                </option>
              ))}
            </select>
          </div>

          {callback && (
            <div className="pt-2">
              <label className="block text-ink-3 text-[10px] uppercase font-semibold mb-1 text-cyan">
                ACTIVE OOB HTTP CALLBACK ENDPOINT
              </label>
              <div className="flex gap-2 max-w-2xl">
                <input
                  readOnly
                  value={callback}
                  className="flex-1 bg-[#03060c] border border-border focus:border-cyan/50 rounded px-3 py-1.5 text-xs text-ink select-all"
                />
                <CyberButton
                  size="sm"
                  variant="secondary"
                  icon={copied ? <Check size={12} className="text-emerald" /> : <Copy size={12} />}
                  onClick={() => void copyUrl()}
                >
                  {copied ? "Copied" : "Copy"}
                </CyberButton>
              </div>
            </div>
          )}
        </div>
      </CyberCard>

      {/* Captured Interactions List */}
      <CyberCard
        title="Captured Out-of-Band Hits & Interactions"
        subtitle={`${events.length} interaction callbacks logged by server`}
        noPadding
      >
        <div className="divide-y divide-border/60 font-mono text-xs">
          {events.length === 0 ? (
            <div className="p-16 text-center text-ink-3 italic">
              <Radio size={24} className="mx-auto mb-2 text-ink-3 animate-pulse opacity-60" />
              Listener active — awaiting asynchronous callback interaction...
            </div>
          ) : (
            events.map((ev) => (
              <div key={ev.id} className="p-4 hover:bg-surface/50 transition-colors space-y-1.5">
                <div className="flex items-center justify-between gap-3">
                  <div className="flex items-center gap-2">
                    <span className="font-bold text-emerald text-xs px-2 py-0.5 rounded bg-emerald/10 border border-emerald/30">
                      HIT {ev.method}
                    </span>
                    <span className="font-semibold text-ink text-xs">{ev.token}</span>
                  </div>
                  <span className="text-ink-3 text-[11px]">{ev.captured_at || "Recent"}</span>
                </div>
                <p className="text-[11px] text-ink-2 break-all">{ev.url}</p>
                {ev.body_excerpt && (
                  <pre className="p-2.5 rounded bg-[#03060c] border border-border text-[11px] text-ink-3 whitespace-pre-wrap">
                    {ev.body_excerpt}
                  </pre>
                )}
              </div>
            ))
          )}
        </div>
      </CyberCard>
    </div>
  )
}
