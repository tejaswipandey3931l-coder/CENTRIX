import { useEffect, useState } from "react"
import {
  RefreshCw,
  CheckCircle2,
  Shield,
  Cpu,
  Bell,
} from "lucide-react"
import { integrationsApi } from "../api/client"
import { CyberCard } from "../components/ui/CyberCard"
import { CyberButton } from "../components/ui/CyberButton"

interface SettingsProps {
  onNavigate?: (page: string) => void
}

export default function SettingsPage(_props?: SettingsProps) {
  const [status, setStatus] = useState<any>(null)
  const [error, setError] = useState("")
  const [loading, setLoading] = useState(true)

  const loadStatus = async () => {
    setLoading(true)
    try {
      setStatus(await integrationsApi.status())
      setError("")
    } catch {
      setError("Could not load backend integration status.")
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    void loadStatus()
  }, [])

  return (
    <div className="p-4 sm:p-6 lg:p-8 max-w-[1500px] mx-auto space-y-6">
      {/* Header */}
      <div className="flex flex-wrap items-start justify-between gap-4 border-b border-border pb-5">
        <div>
          <h1 className="text-xl font-bold tracking-wider text-ink uppercase font-display flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-cyan shadow-[0_0_8px_#00f0ff]" />
            Security Engine Settings & Integrations
          </h1>
          <p className="text-xs text-ink-3 font-mono mt-1">
            DAST execution boundaries, external notification webhooks, engine modules, and authorization tokens.
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <CyberButton
            variant="secondary"
            size="sm"
            icon={<RefreshCw size={13} className={loading ? "animate-spin" : ""} />}
            onClick={() => void loadStatus()}
          >
            REFRESH STATUS
          </CyberButton>
        </div>
      </div>

      {error && (
        <div className="p-3.5 rounded border border-critical/40 bg-critical/10 text-critical text-xs font-mono">
          {error}
        </div>
      )}

      {/* Grid */}
      <div className="grid lg:grid-cols-2 gap-6">
        {/* Core Security Governance Controls */}
        <CyberCard
          title="Security Governance & Scope Rules"
          subtitle="Built-in safeguards preventing accidental out-of-scope testing"
          icon={<Shield size={16} />}
        >
          <div className="space-y-3 font-sans text-xs">
            <div className="p-3 rounded bg-surface border border-border flex items-start gap-3">
              <CheckCircle2 size={16} className="text-emerald shrink-0 mt-0.5" />
              <div>
                <span className="font-semibold text-ink font-mono">EXPLICIT AUTHORIZATION GATE</span>
                <p className="text-ink-3 text-[11px] mt-0.5">
                  Operators must check the legal acknowledgement box before any HTTP probes are fired.
                </p>
              </div>
            </div>

            <div className="p-3 rounded bg-surface border border-border flex items-start gap-3">
              <CheckCircle2 size={16} className="text-emerald shrink-0 mt-0.5" />
              <div>
                <span className="font-semibold text-ink font-mono">STRICT BOUNDARY SCOPE CONTROLS</span>
                <p className="text-ink-3 text-[11px] mt-0.5">
                  All crawler links outside declared target domains/subdomains are automatically discarded.
                </p>
              </div>
            </div>

            <div className="p-3 rounded bg-surface border border-border flex items-start gap-3">
              <CheckCircle2 size={16} className="text-emerald shrink-0 mt-0.5" />
              <div>
                <span className="font-semibold text-ink font-mono">SANITIZED EVIDENCE ENCRYPTION</span>
                <p className="text-ink-3 text-[11px] mt-0.5">
                  Captured session tokens and passwords in evidence logs are automatically redacted before disk persistence.
                </p>
              </div>
            </div>
          </div>
        </CyberCard>

        {/* Dynamic Engine Modules */}
        <CyberCard
          title="Active Dynamic Assessment Modules"
          subtitle="Integrated offensive probes and verification modules"
          icon={<Cpu size={16} />}
        >
          <div className="space-y-3 font-sans text-xs">
            <p className="text-ink-3 text-[11px] leading-relaxed">
              CENTRIX combines high-performance Go-inspired async DAST probing with modular vulnerability checkers:
            </p>

            <div className="grid sm:grid-cols-2 gap-2 text-xs font-mono">
              <div className="p-2.5 rounded bg-surface border border-border">
                <span className="text-cyan font-semibold block">SQLi / NoSQLi</span>
                <span className="text-[10px] text-ink-3">Error & boolean blind checks</span>
              </div>
              <div className="p-2.5 rounded bg-surface border border-border">
                <span className="text-cyan font-semibold block">Cross-Site Scripting</span>
                <span className="text-[10px] text-ink-3">Reflected, DOM & attribute XSS</span>
              </div>
              <div className="p-2.5 rounded bg-surface border border-border">
                <span className="text-cyan font-semibold block">Broken Object Auth (IDOR)</span>
                <span className="text-[10px] text-ink-3">Multi-role token permutation</span>
              </div>
              <div className="p-2.5 rounded bg-surface border border-border">
                <span className="text-cyan font-semibold block">SSRF & OOB Calls</span>
                <span className="text-[10px] text-ink-3">Automated callback listener</span>
              </div>
              <div className="p-2.5 rounded bg-surface border border-border">
                <span className="text-cyan font-semibold block">Security Headers & SSL</span>
                <span className="text-[10px] text-ink-3">HSTS, CSP, and cipher suites</span>
              </div>
              <div className="p-2.5 rounded bg-surface border border-border">
                <span className="text-cyan font-semibold block">JWT / Auth Tokens</span>
                <span className="text-[10px] text-ink-3">None-alg, key confusion, expired</span>
              </div>
            </div>
          </div>
        </CyberCard>

        {/* Integration Connectors */}
        <CyberCard
          title="External Alert & Notification Pipelines"
          subtitle="Live status of outbox dispatch webhooks"
          icon={<Bell size={16} />}
          className="lg:col-span-2"
        >
          <div className="grid sm:grid-cols-2 md:grid-cols-4 gap-4 font-mono text-xs">
            <IntegrationTile
              name="Nuclei Engine"
              desc="Vulnerability Template Runner"
              available={Boolean(status?.nuclei?.available)}
              statusText={status?.nuclei?.available ? "READY" : "BUILT-IN"}
            />
            <IntegrationTile
              name="CVE Threat Lookup"
              desc="NIST NVD & MITRE Feeds"
              available={Boolean(status?.cve_lookup?.available)}
              statusText={status?.cve_lookup?.available ? "CONNECTED" : "UNAVAILABLE"}
            />
            <IntegrationTile
              name="GitHub Security"
              desc="Issues & Security Advisories"
              available={Boolean(status?.github?.configured)}
              statusText={status?.github?.configured ? "CONFIGURED" : "TOKEN MISSING"}
            />
            <IntegrationTile
              name="Slack Notifications"
              desc="SOC Emergency Webhook"
              available={Boolean(status?.slack?.configured)}
              statusText={status?.slack?.configured ? "CONNECTED" : "WEBHOOK MISSING"}
            />
          </div>
        </CyberCard>
      </div>
    </div>
  )
}

function IntegrationTile({
  name,
  desc,
  available,
  statusText,
}: {
  name: string
  desc: string
  available: boolean
  statusText: string
}) {
  return (
    <div className="p-4 rounded bg-surface border border-border flex flex-col justify-between h-28">
      <div>
        <div className="flex items-center justify-between">
          <span className="text-ink font-semibold text-xs">{name}</span>
          <span
            className={`w-2 h-2 rounded-full ${
              available ? "bg-emerald shadow-[0_0_6px_#10b981]" : "bg-ink-3"
            }`}
          />
        </div>
        <p className="text-[11px] text-ink-3 mt-1">{desc}</p>
      </div>
      <div className="pt-2 border-t border-border flex items-center justify-between text-[10px]">
        <span className="text-ink-3">STATUS</span>
        <span
          className={`font-bold ${
            available ? "text-emerald" : "text-ink-3"
          }`}
        >
          {statusText}
        </span>
      </div>
    </div>
  )
}
