import { useEffect, useState } from "react"
import { Download, Play, Plus, RefreshCw } from "lucide-react"
import { evidenceBundleUrl, findingsApi, proofApi, type ApiFinding } from "../api/client"
import { CyberCard } from "../components/ui/CyberCard"
import { CyberButton } from "../components/ui/CyberButton"
import { StatusPill } from "../components/ui/StatusPill"

export default function ProofMode() {
  const [findings, setFindings] = useState<ApiFinding[]>([])
  const [tasks, setTasks] = useState<any[]>([])
  const [findingId, setFindingId] = useState("")
  const [busy, setBusy] = useState("")
  const [error, setError] = useState("")
  const [loading, setLoading] = useState(true)

  const load = async () => {
    setLoading(true)
    try {
      const [nextFindings, nextTasks] = await Promise.all([
        findingsApi.list(),
        proofApi.list(),
      ])
      setFindings(nextFindings)
      setTasks(nextTasks)
      if (!findingId && nextFindings[0]) setFindingId(nextFindings[0].id)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    void load().catch(() => undefined)
  }, [])

  const create = async () => {
    if (!findingId) return
    setBusy("create")
    setError("")
    try {
      await proofApi.create(findingId)
      await load()
    } catch (reason: any) {
      setError(reason.message || "Failed to create verification task.")
    } finally {
      setBusy("")
    }
  }

  const run = async (taskId: string) => {
    setBusy(taskId)
    setError("")
    try {
      await proofApi.run(taskId)
      await load()
    } catch (reason: any) {
      setError(reason.message || "Failed to execute validation task.")
    } finally {
      setBusy("")
    }
  }

  return (
    <div className="p-4 sm:p-6 lg:p-8 max-w-[1700px] mx-auto space-y-6">
      {/* Header */}
      <div className="flex flex-wrap items-start justify-between gap-4 border-b border-border pb-5">
        <div>
          <h1 className="text-xl font-bold tracking-wider text-ink uppercase font-display flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-cyan shadow-[0_0_8px_#00f0ff]" />
            Proof Mode & Validation Tasks
          </h1>
          <p className="text-xs text-ink-3 font-mono mt-1">
            Automated isolated PoC re-execution to verify zero false positives and produce forensic evidence bundles.
          </p>
        </div>

        <CyberButton
          variant="secondary"
          size="sm"
          icon={<RefreshCw size={13} className={loading ? "animate-spin" : ""} />}
          onClick={() => void load()}
        >
          REFRESH TASKS
        </CyberButton>
      </div>

      {error && (
        <div className="p-3.5 rounded border border-critical/40 bg-critical/10 text-critical text-xs font-mono">
          {error}
        </div>
      )}

      {/* Task Creation Launcher Bar */}
      <CyberCard
        title="Initialize New Validation Task"
        subtitle="Select an unresolved finding to generate an isolated re-verification pipeline"
      >
        <div className="flex flex-col sm:flex-row gap-3">
          <select
            value={findingId}
            onChange={(e) => setFindingId(e.target.value)}
            className="flex-1 bg-surface border border-border focus:border-cyan/50 rounded px-3 py-2 text-xs font-mono text-ink cursor-pointer"
          >
            {findings.length === 0 ? (
              <option value="">No findings available</option>
            ) : (
              findings.map((f) => (
                <option key={f.id} value={f.id}>
                  [{f.severity.toUpperCase()}] {f.title} - {f.target}
                </option>
              ))
            )}
          </select>

          <CyberButton
            variant="primary"
            size="sm"
            hudCorners
            disabled={!findingId || busy === "create"}
            loading={busy === "create"}
            icon={<Plus size={13} />}
            onClick={() => void create()}
          >
            CREATE PROOF TASK
          </CyberButton>
        </div>
      </CyberCard>

      {/* Tasks List */}
      <CyberCard
        title="Active & Completed Proof Verification Tasks"
        subtitle={`${tasks.length} verification jobs queued or recorded`}
        noPadding
      >
        <div className="divide-y divide-border/60 font-mono text-xs">
          {tasks.length === 0 ? (
            <div className="p-12 text-center text-ink-3 italic">
              No proof tasks created yet. Select a finding above to launch a validation task.
            </div>
          ) : (
            tasks.map((task) => (
              <div key={task.id} className="p-4 hover:bg-surface/50 transition-colors flex flex-col md:flex-row md:items-center justify-between gap-4">
                <div className="min-w-0 space-y-1">
                  <div className="flex items-center gap-2.5">
                    <StatusPill status={task.status} size="xs" />
                    <span className="font-semibold text-ink text-xs">{task.title}</span>
                  </div>
                  <p className="text-[11px] text-ink-3">
                    TASK ID: <span className="text-cyan">{task.id}</span> · TARGET: {task.target}
                  </p>
                  {task.result && (
                    <p className="text-[11px] text-ink-2 bg-[#03060c] p-2 rounded border border-border/80 mt-1.5">
                      {task.result}
                    </p>
                  )}
                </div>

                <div className="flex items-center gap-2 shrink-0">
                  <CyberButton
                    size="xs"
                    variant="secondary"
                    loading={busy === task.id}
                    icon={<Play size={11} className="fill-current" />}
                    onClick={() => void run(task.id)}
                  >
                    RUN VERIFICATION
                  </CyberButton>

                  <a
                    href={evidenceBundleUrl(task.finding_id)}
                    download
                    className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-elevated border border-border hover:border-cyan/40 text-ink text-xs transition-colors"
                  >
                    <Download size={11} className="text-cyan" />
                    <span>EVIDENCE BUNDLE</span>
                  </a>
                </div>
              </div>
            ))
          )}
        </div>
      </CyberCard>
    </div>
  )
}
