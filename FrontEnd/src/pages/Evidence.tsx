import { useEffect, useState } from "react"
import { useNavigate } from "react-router-dom"
import { RefreshCw, Send, Search, Copy, Check, ChevronDown, ChevronUp, FolderOpen, ShieldCheck } from "lucide-react"
import { evidenceApi, type EvidenceItem } from "../api/client"
import { CyberCard } from "../components/ui/CyberCard"
import { CyberButton } from "../components/ui/CyberButton"
import { EmptyState } from "../components/ui/EmptyState"
import { ErrorState } from "../components/ui/ErrorState"
import { useScanContext } from "../context/ScanContext"

export default function Evidence() {
  const navigate = useNavigate()
  const { setRepeaterRequest } = useScanContext()

  const [items, setItems] = useState<EvidenceItem[]>([])
  const [query, setQuery] = useState("")
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [copiedId, setCopiedId] = useState<string | null>(null)
  const [expandedIds, setExpandedIds] = useState<Set<string>>(new Set())

  const load = async () => {
    setLoading(true)
    setError(null)
    try {
      const data = await evidenceApi.list()
      setItems(data)
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Could not load evidence vault records.")
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    void load()
  }, [])

  const copyToClipboard = async (text: string, id: string) => {
    try {
      await navigator.clipboard.writeText(text)
      setCopiedId(id)
      setTimeout(() => setCopiedId(null), 2500)
    } catch {
      // ignore
    }
  }

  const toggleExpand = (id: string) => {
    setExpandedIds((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  const sendToRepeater = (item: EvidenceItem) => {
    setRepeaterRequest({
      method: (item as any).method || "GET",
      url: item.url || item.target || "",
      headers: {
        "User-Agent": "CENTRIX-DAST/2.4",
        Accept: "*/*",
      },
      note: `Replaying evidence item #${item.id}`,
    })
    navigate("/manual")
  }

  const filtered = items.filter((item) =>
    `${item.method || ""} ${item.url || ""} ${item.status_code || ""}`
      .toLowerCase()
      .includes(query.toLowerCase()),
  )

  return (
    <div className="p-4 sm:p-6 lg:p-8 max-w-[1700px] mx-auto space-y-6">
      {/* Header */}
      <div className="flex flex-wrap items-start justify-between gap-4 border-b border-border pb-5">
        <div>
          <h1 className="text-xl font-bold tracking-wider text-ink uppercase font-display flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-cyan shadow-[0_0_8px_#00f0ff]" />
            Sanitized Evidence & Forensic Vault
          </h1>
          <p className="text-xs text-ink-3 font-mono mt-1">
            Redacted Proof-of-Concept HTTP interactions captured during automated audit executions.
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <CyberButton
            variant="secondary"
            size="sm"
            icon={<RefreshCw size={13} className={loading ? "animate-spin" : ""} />}
            onClick={() => void load()}
          >
            REFRESH VAULT
          </CyberButton>
        </div>
      </div>

      {error && (
        <ErrorState
          title="Evidence Query Failed"
          message={error}
          onRetry={() => void load()}
        />
      )}

      {/* Search Filter */}
      <div className="relative max-w-md">
        <Search size={14} className="absolute left-3 top-2.5 text-ink-3 pointer-events-none" />
        <input
          type="text"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Filter captured evidence artifacts..."
          className="w-full bg-panel border border-border focus:border-cyan/60 rounded pl-9 pr-3 py-1.5 text-xs font-mono text-ink placeholder:text-ink-3"
        />
      </div>

      {/* Evidence Cards Feed */}
      <div className="space-y-4">
        {filtered.length === 0 && !loading ? (
          <EmptyState
            icon={<FolderOpen size={24} className="text-cyan/70" />}
            title="NO EVIDENCE ARTIFACTS"
            description={
              query
                ? "No evidence artifacts match your query string."
                : "No sanitized evidence artifacts recorded yet. Evidence is automatically extracted when vulnerabilities are confirmed."
            }
            actionLabel={query ? "CLEAR QUERY" : "START SCAN"}
            onAction={query ? () => setQuery("") : () => navigate("/scans/new")}
          />
        ) : (
          filtered.map((item) => {
            const isExpanded = expandedIds.has(item.id)
            const isCopied = copiedId === item.id

            return (
              <CyberCard
                key={item.id}
                title={
                  <div className="flex items-center gap-2.5">
                    <span
                      className={`font-bold font-mono text-xs ${
                        item.method === "POST"
                          ? "text-emerald"
                          : item.method === "DELETE"
                            ? "text-critical"
                            : "text-cyan"
                      }`}
                    >
                      {item.method || "GET"}
                    </span>
                    <span className="text-ink font-mono text-xs truncate max-w-xl">
                      {item.url}
                    </span>
                  </div>
                }
                action={
                  <div className="flex items-center gap-2">
                    <CyberButton
                      size="xs"
                      variant="ghost"
                      icon={isCopied ? <Check size={11} className="text-emerald" /> : <Copy size={11} />}
                      onClick={() =>
                        void copyToClipboard(
                          item.response_excerpt || JSON.stringify(item, null, 2),
                          item.id,
                        )
                      }
                    >
                      {isCopied ? "COPIED" : "COPY"}
                    </CyberButton>

                    <CyberButton
                      size="xs"
                      variant="secondary"
                      icon={<Send size={11} />}
                      onClick={() => sendToRepeater(item)}
                    >
                      REPEATER
                    </CyberButton>
                  </div>
                }
              >
                <div className="space-y-3 font-mono text-xs">
                  <div className="flex flex-wrap items-center gap-4 text-[11px] text-ink-3">
                    <span>
                      STATUS: <strong className="text-ink font-bold">HTTP {item.status_code || 200}</strong>
                    </span>
                    <span>
                      LENGTH: <strong className="text-ink font-bold">{item.response_length || 0} B</strong>
                    </span>
                    <span>
                      CONTENT-TYPE: <strong className="text-ink">{item.content_type || "application/json"}</strong>
                    </span>
                    <span className="ml-auto text-[10px] text-emerald px-1.5 py-0.2 rounded bg-emerald/10 border border-emerald/30 flex items-center gap-1">
                      <ShieldCheck size={10} /> SANITIZED ARTIFACT
                    </span>
                  </div>

                  <div>
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-ink-3 text-[10px] uppercase font-bold">
                        RESPONSE EXCERPT
                      </span>
                      {item.response_excerpt && item.response_excerpt.length > 300 && (
                        <button
                          type="button"
                          onClick={() => toggleExpand(item.id)}
                          className="text-[10px] text-cyan hover:underline flex items-center gap-1 cursor-pointer"
                        >
                          <span>{isExpanded ? "Collapse" : "Show Full Payload"}</span>
                          {isExpanded ? <ChevronUp size={10} /> : <ChevronDown size={10} />}
                        </button>
                      )}
                    </div>

                    <pre
                      className={`p-3.5 rounded bg-[#03060c] border border-border text-xs text-ink-2 overflow-y-auto whitespace-pre-wrap font-mono selection:bg-cyan/30 ${
                        isExpanded ? "max-h-[500px]" : "max-h-48"
                      }`}
                    >
                      {item.response_excerpt || "No raw payload excerpt available."}
                    </pre>
                  </div>
                </div>
              </CyberCard>
            )
          })
        )}
      </div>
    </div>
  )
}
