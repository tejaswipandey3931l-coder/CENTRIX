import { useEffect, useState } from "react"
import { Play, Plus, RefreshCw, Trash2, KeyRound } from "lucide-react"
import { authzApi, manualApi, scanApi, type ScanItem, type AuthProfile, type CorpusItem, type MatrixRunItem } from "../api/client"
import { CyberCard } from "../components/ui/CyberCard"
import { CyberButton } from "../components/ui/CyberButton"

export default function AuthorizationMatrix() {
  const [scans, setScans] = useState<ScanItem[]>([])
  const [scanId, setScanId] = useState("")
  const [profiles, setProfiles] = useState<AuthProfile[]>([])
  const [corpus, setCorpus] = useState<CorpusItem[]>([])
  const [runs, setRuns] = useState<MatrixRunItem[]>([])
  const [selectedProfiles, setSelectedProfiles] = useState<string[]>([])
  const [selectedRequests, setSelectedRequests] = useState<string[]>([])
  const [name, setName] = useState("Restricted User")
  const [role, setRole] = useState("user")
  const [headers, setHeaders] = useState('{\n  "Authorization": "Bearer paste-token-here"\n}')
  const [cookies, setCookies] = useState("{\n}")
  const [busy, setBusy] = useState("")
  const [error, setError] = useState("")

  const load = async () => {
    const [nextScans, nextProfiles] = await Promise.all([
      scanApi.list(),
      authzApi.profiles(),
    ])
    setScans(nextScans)
    setProfiles(nextProfiles)
    const chosen = scanId || nextScans[0]?.id || ""
    if (chosen) setScanId(chosen)
  }

  useEffect(() => {
    void load().catch(() => undefined)
  }, [])

  useEffect(() => {
    if (!scanId) return
    void Promise.all([
      manualApi.corpus(scanId),
      authzApi.matrixRuns(scanId),
    ])
      .then(([nextCorpus, nextRuns]) => {
        setCorpus(nextCorpus)
        setRuns(nextRuns)
        setSelectedRequests(nextCorpus.slice(0, 10).map((item) => item.id))
      })
      .catch(() => undefined)
  }, [scanId])

  const createProfile = async () => {
    setBusy("create")
    setError("")
    try {
      await authzApi.createProfile({
        name,
        role,
        headers: JSON.parse(headers || "{}"),
        cookies: JSON.parse(cookies || "{}"),
      })
      await load()
    } catch (reason: any) {
      setError(reason.message || "Failed to create authorization role profile.")
    } finally {
      setBusy("")
    }
  }

  const deleteProfile = async (id: string) => {
    try {
      await authzApi.deleteProfile(id)
      await load()
    } catch {
      // ignore
    }
  }

  const runMatrix = async () => {
    setBusy("run")
    setError("")
    try {
      await authzApi.runMatrix({
        scan_id: scanId,
        request_ids: selectedRequests,
        profile_ids: selectedProfiles,
      })
      setRuns(await authzApi.matrixRuns(scanId))
    } catch (reason: any) {
      setError(reason.message || "Authorization matrix execution failed.")
    } finally {
      setBusy("")
    }
  }

  const toggle = (value: string, setter: (fn: (items: string[]) => string[]) => void) => {
    setter((items) =>
      items.includes(value) ? items.filter((item) => item !== value) : [...items, value],
    )
  }

  const latestRun = runs[0]

  return (
    <div className="p-4 sm:p-6 lg:p-8 max-w-[1700px] mx-auto space-y-6">
      {/* Header */}
      <div className="flex flex-wrap items-start justify-between gap-4 border-b border-border pb-5">
        <div>
          <h1 className="text-xl font-bold tracking-wider text-ink uppercase font-display flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-cyan shadow-[0_0_8px_#00f0ff]" />
            Authorization & Access Control Matrix (BAC / IDOR)
          </h1>
          <p className="text-xs text-ink-3 font-mono mt-1">
            Replay sensitive API requests across user roles to automatically detect privilege escalation and broken object access.
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <CyberButton
            variant="secondary"
            size="sm"
            icon={<RefreshCw size={13} />}
            onClick={() => void load()}
          >
            REFRESH
          </CyberButton>

          <CyberButton
            variant="primary"
            size="sm"
            hudCorners
            disabled={!scanId || busy === "run"}
            loading={busy === "run"}
            icon={<Play size={13} className="fill-current" />}
            onClick={() => void runMatrix()}
          >
            EXECUTE MATRIX AUDIT
          </CyberButton>
        </div>
      </div>

      {error && (
        <div className="p-3.5 rounded border border-critical/40 bg-critical/10 text-critical text-xs font-mono">
          {error}
        </div>
      )}

      {/* Grid: Profiles & Requests Configuration (Left) + Matrix Results (Right) */}
      <div className="grid xl:grid-cols-12 gap-6">
        {/* Left Column (5 cols) */}
        <div className="xl:col-span-5 space-y-6">
          {/* Target Scan Selector */}
          <CyberCard title="Scope & Roles Configuration" icon={<KeyRound size={15} />}>
            <div className="space-y-4 font-mono text-xs">
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

              {/* Profiles Manager */}
              <div className="pt-2 border-t border-border space-y-2">
                <span className="text-ink-3 text-[10px] uppercase font-bold block">
                  REGISTERED AUTH ROLES ({profiles.length})
                </span>
                <div className="space-y-1.5 max-h-40 overflow-y-auto pr-1">
                  {profiles.length === 0 ? (
                    <p className="text-ink-3 italic py-2">No auth profiles defined.</p>
                  ) : (
                    profiles.map((prof) => (
                      <div
                        key={prof.id}
                        className="p-2.5 rounded bg-surface border border-border flex items-center justify-between gap-2"
                      >
                        <label className="flex items-center gap-2 cursor-pointer truncate">
                          <input
                            type="checkbox"
                            checked={selectedProfiles.includes(prof.id)}
                            onChange={() => toggle(prof.id, setSelectedProfiles)}
                            className="accent-cyan w-3.5 h-3.5 rounded"
                          />
                          <span className="text-ink font-semibold">{prof.name}</span>
                          <span className="text-cyan text-[10px]">({prof.role})</span>
                        </label>
                        <button
                          onClick={() => void deleteProfile(prof.id)}
                          className="text-ink-3 hover:text-critical p-1 transition-colors"
                        >
                          <Trash2 size={12} />
                        </button>
                      </div>
                    ))
                  )}
                </div>
              </div>

              {/* New Profile Accordion */}
              <div className="pt-3 border-t border-border space-y-2">
                <span className="text-ink font-bold uppercase text-[10px] text-cyan block">
                  + REGISTER NEW TEST ROLE PROFILE
                </span>
                <div className="grid grid-cols-2 gap-2">
                  <input
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    placeholder="Profile Name (e.g. Guest)"
                    className="bg-surface border border-border rounded px-2 py-1 text-ink"
                  />
                  <input
                    value={role}
                    onChange={(e) => setRole(e.target.value)}
                    placeholder="Role (e.g. guest)"
                    className="bg-surface border border-border rounded px-2 py-1 text-ink"
                  />
                </div>
                <textarea
                  value={headers}
                  onChange={(e) => setHeaders(e.target.value)}
                  rows={2}
                  placeholder='Headers: {"Authorization": "Bearer ..."}'
                  className="w-full bg-[#03060c] border border-border rounded p-2 text-ink-2"
                />
                <textarea
                  value={cookies}
                  onChange={(e) => setCookies(e.target.value)}
                  rows={2}
                  placeholder='Cookies: {"session": "..."}'
                  className="w-full bg-[#03060c] border border-border rounded p-2 text-ink-2"
                />
                <CyberButton
                  size="xs"
                  variant="secondary"
                  loading={busy === "create"}
                  icon={<Plus size={11} />}
                  onClick={() => void createProfile()}
                >
                  Save Profile
                </CyberButton>
              </div>

              {/* Corpus selection */}
              <div className="pt-2 border-t border-border text-[11px] text-ink-3">
                <span>AUDIT CORPUS: <strong className="text-ink">{selectedRequests.length} of {corpus.length}</strong> captured requests selected for matrix testing.</span>
              </div>
            </div>
          </CyberCard>
        </div>

        {/* Right Column: Execution Results (7 cols) */}
        <div className="xl:col-span-7">
          <CyberCard
            title="Authorization Permutation Matrix"
            subtitle={latestRun ? `Run ID: ${latestRun.id} · Timestamp: ${latestRun.executed_at || "Recent"}` : "No run executed"}
            noPadding
          >
            {latestRun ? (
              <div className="overflow-x-auto">
                <table className="w-full text-left font-mono text-xs">
                  <thead>
                    <tr className="border-b border-border bg-surface text-[10px] text-ink-3 uppercase">
                      <th className="p-3">REQUEST URL</th>
                      <th className="p-3">ROLE</th>
                      <th className="p-3">STATUS</th>
                      <th className="p-3">EXPECTED</th>
                      <th className="p-3">VERDICT</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border/60">
                    {(latestRun.results || []).map((res: any, idx: number) => {
                      const isVulnerable = res.verdict === "vulnerable" || res.unauthorized_access
                      return (
                        <tr key={idx} className="hover:bg-surface/50">
                          <td className="p-3 text-ink font-semibold truncate max-w-xs">
                            {res.url || res.path}
                          </td>
                          <td className="p-3 text-cyan">{res.role || res.profile_name}</td>
                          <td className="p-3 text-ink-2">HTTP {res.status_code}</td>
                          <td className="p-3 text-ink-3">HTTP 401/403</td>
                          <td className="p-3">
                            <span
                              className={`font-bold px-1.5 py-0.5 rounded text-[10px] ${
                                isVulnerable
                                  ? "bg-critical/20 text-critical border border-critical/40 animate-pulse"
                                  : "bg-emerald/20 text-emerald"
                              }`}
                            >
                              {isVulnerable ? "IDOR DETECTED" : "ENFORCED"}
                            </span>
                          </td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="p-16 text-center text-ink-3 font-mono text-xs">
                No matrix execution records found. Select roles and click "Execute Matrix Audit".
              </div>
            )}
          </CyberCard>
        </div>
      </div>
    </div>
  )
}
