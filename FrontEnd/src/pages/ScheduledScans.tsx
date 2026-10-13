import { useEffect, useState } from "react"
import {
  CalendarClock,
  Pause,
  Play,
  RefreshCw,
  Trash2,
  Plus,
  AlertTriangle,
} from "lucide-react"
import { schedulesApi, type ScheduleItem } from "../api/client"
import { CyberCard } from "../components/ui/CyberCard"
import { CyberButton } from "../components/ui/CyberButton"
import { StatusPill } from "../components/ui/StatusPill"

type Frequency = "once" | "hourly" | "daily" | "weekly"

export default function ScheduledScans() {
  const [items, setItems] = useState<ScheduleItem[]>([])
  const [name, setName] = useState("Daily Automated Audit")
  const [target, setTarget] = useState("")
  const [frequency, setFrequency] = useState<Frequency>("daily")
  const [firstRun, setFirstRun] = useState("")
  const [safety, setSafety] = useState<"passive" | "standard" | "aggressive">("standard")
  const [authorized, setAuthorized] = useState(false)
  const [busy, setBusy] = useState("")
  const [error, setError] = useState("")
  const [loading, setLoading] = useState(true)

  const load = async () => {
    setLoading(true)
    try {
      setItems(await schedulesApi.list())
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    void load().catch(() => undefined)
  }, [])

  const create = async () => {
    if (!target) {
      setError("Please provide a target URL.")
      return
    }
    if (!authorized) {
      setError("Please confirm testing authorisation.")
      return
    }
    setBusy("create")
    setError("")
    try {
      await schedulesApi.create({
        name,
        frequency,
        first_run_at: firstRun ? new Date(firstRun).toISOString() : null,
        config: {
          target,
          scope: [],
          imported_urls: [],
          imported_requests: [],
          authorized,
          profile: "full",
          safety,
          depth: 3,
          timeout: 30,
          concurrency: 10,
          max_requests: 500,
          respect_robots: false,
          environment: "Production",
        },
      })
      setTarget("")
      await load()
    } catch (reason: unknown) {
      setError(reason instanceof Error ? reason.message : "Failed to register schedule.")
    } finally {
      setBusy("")
    }
  }

  const runNow = async (id: string) => {
    setBusy(id)
    setError("")
    try {
      await schedulesApi.run(id)
      await load()
    } catch (reason: unknown) {
      setError(reason instanceof Error ? reason.message : "Failed to trigger scheduled run.")
    } finally {
      setBusy("")
    }
  }

  const toggle = async (item: ScheduleItem) => {
    setBusy(item.id)
    setError("")
    try {
      await schedulesApi.setStatus(
        item.id,
        item.status === "enabled" ? "paused" : "enabled",
      )
      await load()
    } catch (reason: unknown) {
      setError(reason instanceof Error ? reason.message : "Failed to update schedule status.")
    } finally {
      setBusy("")
    }
  }

  const remove = async (id: string) => {
    setBusy(id)
    setError("")
    try {
      await schedulesApi.remove(id)
      await load()
    } catch (reason: unknown) {
      setError(reason instanceof Error ? reason.message : "Failed to remove schedule.")
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
            <span className="w-2.5 h-2.5 rounded-full bg-blue" />
            Autonomous Scheduled Audit Jobs
          </h1>
          <p className="text-xs text-ink-3 font-mono mt-1">
            Automate continuous penetration testing runs and periodic baseline scans without external cron services.
          </p>
        </div>

        <CyberButton
          variant="secondary"
          size="sm"
          icon={<RefreshCw size={13} className={loading ? "animate-spin" : ""} />}
          onClick={() => void load()}
        >
          REFRESH
        </CyberButton>
      </div>

      {error && (
        <div className="p-3.5 rounded border border-critical/40 bg-critical/10 text-critical text-xs font-mono flex items-center gap-2">
          <AlertTriangle size={15} className="shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Grid: Create Form (Left) + Schedules List (Right) */}
      <div className="grid xl:grid-cols-12 gap-6">
        {/* Left Form (5 cols) */}
        <div className="xl:col-span-5 space-y-4">
          <CyberCard title="Create Recurring DAST Schedule" icon={<CalendarClock size={16} />}>
            <div className="space-y-4 font-mono text-xs">
              <div>
                <label className="block text-ink-3 text-[10px] uppercase font-semibold mb-1">
                  JOB IDENTIFIER:
                </label>
                <input
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="e.g. Weekly Staging Audit"
                  className="w-full bg-surface border border-border focus:border-cyan/50 rounded px-2.5 py-1.5 text-ink"
                />
              </div>

              <div>
                <label className="block text-ink-3 text-[10px] uppercase font-semibold mb-1">
                  TARGET URL:
                </label>
                <input
                  type="url"
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  placeholder="https://staging.target-app.com"
                  className="w-full bg-surface border border-border focus:border-cyan/50 rounded px-2.5 py-1.5 text-ink"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-ink-3 text-[10px] uppercase font-semibold mb-1">
                    FREQUENCY:
                  </label>
                  <select
                    value={frequency}
                    onChange={(e) => setFrequency(e.target.value as Frequency)}
                    className="w-full bg-surface border border-border rounded px-2.5 py-1.5 text-ink cursor-pointer"
                  >
                    <option value="once">Once</option>
                    <option value="hourly">Hourly</option>
                    <option value="daily">Daily</option>
                    <option value="weekly">Weekly</option>
                  </select>
                </div>

                <div>
                  <label className="block text-ink-3 text-[10px] uppercase font-semibold mb-1">
                    SAFETY LEVEL:
                  </label>
                  <select
                    value={safety}
                    onChange={(e) => setSafety(e.target.value as any)}
                    className="w-full bg-surface border border-border rounded px-2.5 py-1.5 text-ink cursor-pointer"
                  >
                    <option value="passive">Passive</option>
                    <option value="standard">Standard</option>
                    <option value="aggressive">Aggressive</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-ink-3 text-[10px] uppercase font-semibold mb-1">
                  FIRST RUN AT (OPTIONAL):
                </label>
                <input
                  type="datetime-local"
                  value={firstRun}
                  onChange={(e) => setFirstRun(e.target.value)}
                  className="w-full bg-surface border border-border focus:border-cyan/50 rounded px-2.5 py-1.5 text-ink font-mono text-xs"
                />
              </div>

              <div className="p-3 rounded bg-surface border border-border">
                <label className="flex items-center gap-2.5 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={authorized}
                    onChange={(e) => setAuthorized(e.target.checked)}
                    className="accent-cyan w-4 h-4 rounded"
                  />
                  <span className="text-[11px] text-ink-2 font-bold">
                    CONFIRM CONTINUOUS AUDIT AUTHORIZATION
                  </span>
                </label>
              </div>

              <CyberButton
                variant="primary"
                size="md"
                hudCorners
                loading={busy === "create"}
                disabled={!target}
                icon={<Plus size={14} />}
                onClick={() => void create()}
                className="w-full"
              >
                SCHEDULE AUDIT JOB
              </CyberButton>
            </div>
          </CyberCard>
        </div>

        {/* Right List (7 cols) */}
        <div className="xl:col-span-7">
          <CyberCard
            title="Registered Autonomous Schedules"
            subtitle={`${items.length} active or paused schedules`}
            noPadding
          >
            <div className="divide-y divide-border/60 font-mono text-xs">
              {items.length === 0 ? (
                <div className="p-16 text-center text-ink-3 italic">
                  No automated schedules configured. Create a recurring audit job above.
                </div>
              ) : (
                items.map((it) => (
                  <div key={it.id} className="p-4 hover:bg-surface/50 transition-colors flex flex-col md:flex-row md:items-center justify-between gap-3">
                    <div className="min-w-0 space-y-1">
                      <div className="flex items-center gap-2.5">
                        <StatusPill status={it.status} size="xs" />
                        <span className="font-bold text-ink text-xs">{it.name}</span>
                        <span className="text-cyan text-[10px] uppercase font-bold">[{it.frequency}]</span>
                      </div>
                      <p className="text-[11px] text-ink-3 truncate">
                        TARGET: <strong className="text-ink">{it.config?.target}</strong>
                      </p>
                      {it.last_run_at && (
                        <p className="text-[10px] text-ink-3">
                          Last run: {it.last_run_at} · Yield: {it.last_findings_count || 0} findings
                        </p>
                      )}
                    </div>

                    <div className="flex items-center gap-2 shrink-0">
                      <CyberButton
                        size="xs"
                        variant="secondary"
                        loading={busy === it.id}
                        icon={<Play size={11} className="fill-current" />}
                        onClick={() => void runNow(it.id)}
                      >
                        RUN NOW
                      </CyberButton>

                      <CyberButton
                        size="xs"
                        variant="ghost"
                        loading={busy === it.id}
                        icon={it.status === "enabled" ? <Pause size={11} /> : <Play size={11} />}
                        onClick={() => void toggle(it)}
                      >
                        {it.status === "enabled" ? "Pause" : "Resume"}
                      </CyberButton>

                      <button
                        onClick={() => void remove(it.id)}
                        className="p-1.5 text-ink-3 hover:text-critical transition-colors cursor-pointer"
                        title="Delete schedule"
                      >
                        <Trash2 size={13} />
                      </button>
                    </div>
                  </div>
                ))
              )}
            </div>
          </CyberCard>
        </div>
      </div>
    </div>
  )
}
