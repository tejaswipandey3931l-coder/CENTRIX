import { useMemo, useState, useEffect } from "react"
import { useNavigate } from "react-router-dom"
import {
  Play,
  Upload,
  Sliders,
  FileCode,
  CheckCircle2,
  AlertTriangle,
  ExternalLink,
} from "lucide-react"
import { importApi, type ScanConfig } from "../api/client"
import { CyberCard } from "../components/ui/CyberCard"
import { CyberButton } from "../components/ui/CyberButton"
import { useScanContext } from "../context/ScanContext"

type ImportFormat = "openapi" | "postman" | "har" | "graphql"
type ImportedEndpoint = { method: string; url: string; name?: string; source?: string }

const DRAFT_KEY = "centrix_scan_setup_draft"

const EXAMPLE_IMPORTS: Record<ImportFormat, string> = {
  openapi: '{\n  "openapi": "3.0.0",\n  "servers": [{ "url": "https://staging.example.com" }],\n  "paths": { "/api/users": { "get": {}, "post": {} } }\n}',
  postman: '{\n  "item": [{\n    "name": "Users",\n    "request": { "method": "GET", "url": { "raw": "https://staging.example.com/api/users" } }\n  }]\n}',
  har: '{\n  "log": { "entries": [{\n    "request": { "method": "GET", "url": "https://staging.example.com/api/users" }\n  }] }\n}',
  graphql: '{\n  "endpoint": "https://staging.example.com/graphql"\n}',
}

const EXAMPLE_SEQUENCE = '{\n  "name": "API login sequence",\n  "steps": [\n    {\n      "name": "login",\n      "method": "POST",\n      "url": "/login",\n      "json": { "username": "alice", "password": "password" },\n      "extract": { "token": { "jsonpath": "$.token" } },\n      "assertions": [{ "status_code": [200, 201] }]\n    },\n    {\n      "name": "profile",\n      "method": "GET",\n      "url": "/api/profile",\n      "headers": { "Authorization": "Bearer {{token}}" },\n      "assertions": [{ "status_code": 200 }]\n    }\n  ]\n}'

const EXAMPLE_BROWSER_WORKFLOW = '{\n  "name": "Browser login and discovery",\n  "steps": [\n    { "action": "goto", "url": "/login" },\n    { "action": "fill", "selector": "input[name=username]", "value": "admin" },\n    { "action": "fill", "selector": "input[name=password]", "value": "password" },\n    { "action": "click", "selector": "button[type=submit], input[type=submit]" },\n    { "action": "wait", "timeout": 1000 },\n    { "action": "goto", "url": "/vulnerabilities/sqli/" }\n  ]\n}'

export default function ScanSetup() {
  const navigate = useNavigate()
  const { startScan, scanActive, activeScanId, backendOnline } = useScanContext()

  // Load initial draft from sessionStorage
  const savedDraft = useMemo(() => {
    try {
      const item = sessionStorage.getItem(DRAFT_KEY)
      return item ? JSON.parse(item) : {}
    } catch {
      return {}
    }
  }, [])

  const [target, setTarget] = useState<string>(savedDraft.target || "")
  const [scope, setScope] = useState<string>(savedDraft.scope || "")
  const [safety, setSafety] = useState<"passive" | "standard" | "aggressive">(savedDraft.safety || "standard")
  const [profile, setProfile] = useState<"quick" | "full" | "api" | "custom">(savedDraft.profile || "full")
  const [depth, setDepth] = useState<number>(savedDraft.depth ?? 3)
  const [concurrency, setConcurrency] = useState<number>(savedDraft.concurrency ?? 10)
  const [timeout, setTimeoutVal] = useState<number>(savedDraft.timeout ?? 30)
  const [authorized, setAuthorized] = useState<boolean>(savedDraft.authorized || false)

  const [busy, setBusy] = useState(false)
  const [importBusy, setImportBusy] = useState(false)
  const [error, setError] = useState("")
  const [importError, setImportError] = useState("")
  const [importFormat, setImportFormat] = useState<ImportFormat>("openapi")
  const [importText, setImportText] = useState(EXAMPLE_IMPORTS.openapi)
  const [importedEndpoints, setImportedEndpoints] = useState<ImportedEndpoint[]>([])
  const [showAdvanced, setShowAdvanced] = useState(false)
  const [sequenceText, setSequenceText] = useState("")
  const [browserWorkflowText, setBrowserWorkflowText] = useState("")

  // Save draft changes to sessionStorage
  useEffect(() => {
    try {
      sessionStorage.setItem(
        DRAFT_KEY,
        JSON.stringify({ target, scope, safety, profile, depth, concurrency, timeout, authorized }),
      )
    } catch {
      // ignore
    }
  }, [target, scope, safety, profile, depth, concurrency, timeout, authorized])

  const importedUrls = useMemo(
    () => Array.from(new Set(importedEndpoints.map((endpoint) => endpoint.url).filter(Boolean))),
    [importedEndpoints],
  )

  const scopeLines = useMemo(
    () => scope.split("\n").map((value) => value.trim()).filter(Boolean),
    [scope],
  )

  // Target URL Validation Helper
  const targetValidation = useMemo(() => {
    if (!target.trim()) return null
    try {
      const u = new URL(target.trim())
      if (!["http:", "https:"].includes(u.protocol)) {
        return { valid: false, message: "Target protocol must be http:// or https://" }
      }
      if (u.hostname === "localhost" || u.hostname === "127.0.0.1") {
        return {
          valid: true,
          warning: "Note: Local targets are restricted by the CENTRIX safety model unless whitelisted.",
        }
      }
      return { valid: true }
    } catch {
      return { valid: false, message: "Invalid target URL structure (expected https://domain.com)" }
    }
  }, [target])

  const previewImport = async () => {
    setImportError("")
    setImportBusy(true)
    try {
      const parsed = JSON.parse(importText)
      const result = await importApi.preview(importFormat, parsed, target || undefined)
      setImportedEndpoints(result.endpoints)
    } catch (reason: unknown) {
      setImportedEndpoints([])
      setImportError(reason instanceof Error ? reason.message : "Could not parse this import specification.")
    } finally {
      setImportBusy(false)
    }
  }

  const clearImport = () => {
    setImportedEndpoints([])
    setImportError("")
  }

  const changeFormat = (nextFormat: ImportFormat) => {
    setImportFormat(nextFormat)
    setImportText(EXAMPLE_IMPORTS[nextFormat])
    setImportedEndpoints([])
    setImportError("")
  }

  const launch = async () => {
    setError("")
    if (!target.trim()) {
      setError("Please specify a target URL to scan.")
      return
    }

    if (targetValidation && !targetValidation.valid) {
      setError(targetValidation.message || "Please fix target URL format.")
      return
    }

    if (!authorized) {
      setError("Authorisation confirmation required. Confirm that you have explicit permission to test this target.")
      return
    }

    setBusy(true)
    try {
      let sequenceWorkflows: Record<string, unknown>[] = []
      if (sequenceText.trim()) {
        const parsedSequence = JSON.parse(sequenceText)
        sequenceWorkflows = Array.isArray(parsedSequence)
          ? parsedSequence
          : Array.isArray(parsedSequence.workflows)
            ? parsedSequence.workflows
            : [parsedSequence]
      }

      let browserWorkflows: Record<string, unknown>[] = []
      if (browserWorkflowText.trim()) {
        const parsedWorkflow = JSON.parse(browserWorkflowText)
        browserWorkflows = Array.isArray(parsedWorkflow)
          ? parsedWorkflow
          : Array.isArray(parsedWorkflow.workflows)
            ? parsedWorkflow.workflows
            : [parsedWorkflow]
      }

      const scanConfig: ScanConfig = {
        target: target.trim(),
        scope: scopeLines,
        imported_urls: importedUrls,
        imported_requests: importedEndpoints,
        sequence_workflows: sequenceWorkflows,
        browser_workflows: browserWorkflows,
        authorized,
        safety,
        profile: importedUrls.length ? "api" : profile,
        depth,
        timeout,
        concurrency,
        max_requests: 500,
        respect_robots: false,
      }

      const scanId = await startScan(scanConfig)

      // Clear draft on successful launch
      try {
        sessionStorage.removeItem(DRAFT_KEY)
      } catch {
        // ignore
      }

      navigate(`/scans/${encodeURIComponent(scanId)}`)
    } catch (reason: unknown) {
      setError(reason instanceof Error ? reason.message : "Failed to launch DAST scan.")
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="p-4 sm:p-6 lg:p-8 max-w-[1700px] mx-auto space-y-6">
      {/* Top Header */}
      <div className="flex flex-wrap items-start justify-between gap-4 border-b border-border pb-5">
        <div>
          <h1 className="text-xl font-bold tracking-wider text-ink uppercase font-display flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-blue" />
            DAST Scan Launch Cockpit
          </h1>
          <p className="text-xs text-ink-3 font-mono mt-1">
            Authorised active penetration testing, endpoint discovery, and automated vulnerability verification.
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          {scanActive && activeScanId && (
            <CyberButton
              variant="outline"
              size="sm"
              icon={<ExternalLink size={13} className="text-cyan" />}
              onClick={() => navigate(`/scans/${encodeURIComponent(activeScanId)}`)}
            >
              ACTIVE SCAN IN PROGRESS
            </CyberButton>
          )}

          <CyberButton
            variant="primary"
            size="sm"
            hudCorners
            loading={busy}
            disabled={!target || !authorized || Boolean(targetValidation && !targetValidation.valid)}
            icon={<Play size={13} fill="currentColor" />}
            onClick={() => void launch()}
          >
            EXECUTE DAST PROBE
          </CyberButton>
        </div>
      </div>

      {backendOnline === false && (
        <div className="p-3.5 rounded border border-critical/40 bg-critical/10 text-critical text-xs font-mono flex items-center gap-2">
          <AlertTriangle size={16} className="shrink-0" />
          <span>
            CENTRIX backend engine is currently offline. Verify backend service is running on http://localhost:8000.
          </span>
        </div>
      )}

      {error && (
        <div className="p-3.5 rounded border border-critical/40 bg-critical/10 text-critical text-xs font-mono flex items-center gap-2">
          <AlertTriangle size={16} className="shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Main Grid: Form Left (7 cols) + Schema Importer Right (5 cols) */}
      <div className="grid lg:grid-cols-12 gap-6">
        {/* Left Column: Target & Audit Settings */}
        <div className="lg:col-span-7 space-y-6">
          {/* Target Host Config */}
          <CyberCard title="Target Specification" icon={<Sliders size={15} />}>
            <div className="space-y-4 text-xs font-sans">
              <div>
                <label className="block text-ink-3 uppercase font-mono text-[11px] mb-1.5 font-semibold">
                  PRIMARY TARGET URL <span className="text-critical">*</span>
                </label>
                <div className="flex gap-2">
                  <input
                    type="url"
                    value={target}
                    onChange={(e) => setTarget(e.target.value)}
                    placeholder="https://staging.target-domain.com"
                    className={`flex-1 bg-surface border rounded px-3 py-2 text-ink font-mono text-sm placeholder:text-ink-3 transition-colors ${
                      targetValidation && !targetValidation.valid
                        ? "border-critical focus:border-critical"
                        : "border-border focus:border-cyan/60"
                    }`}
                  />
                  <CyberButton
                    size="xs"
                    variant="secondary"
                    onClick={() => setTarget("https://juice-shop.herokuapp.com")}
                  >
                    Demo URL
                  </CyberButton>
                </div>
                {targetValidation && !targetValidation.valid && (
                  <p className="text-critical text-[11px] font-mono mt-1">
                    {targetValidation.message}
                  </p>
                )}
                {targetValidation && targetValidation.warning && (
                  <p className="text-medium text-[11px] font-mono mt-1">
                    {targetValidation.warning}
                  </p>
                )}
              </div>

              <div>
                <label className="block text-ink-3 uppercase font-mono text-[11px] mb-1.5 font-semibold">
                  SCOPE RESTRICTIONS (ONE REGEX OR SUBPATH PER LINE)
                </label>
                <textarea
                  value={scope}
                  onChange={(e) => setScope(e.target.value)}
                  rows={3}
                  placeholder=".*\.example\.com&#10;/api/v[12]/.*&#10;!/admin/destructive"
                  className="w-full bg-surface border border-border focus:border-cyan/60 rounded p-2.5 text-ink font-mono text-xs placeholder:text-ink-3"
                />
              </div>

              {/* Audit Profile */}
              <div>
                <label className="block text-ink-3 uppercase font-mono text-[11px] mb-1.5 font-semibold">
                  AUDIT PROFILE
                </label>
                <div className="grid grid-cols-4 gap-2">
                  {[
                    { id: "full", label: "Full Audit" },
                    { id: "quick", label: "Quick Scan" },
                    { id: "api", label: "API Focused" },
                    { id: "custom", label: "Custom" },
                  ].map((p) => (
                    <button
                      key={p.id}
                      type="button"
                      onClick={() => setProfile(p.id as any)}
                      className={`px-3 py-2 rounded border text-center font-mono text-xs cursor-pointer transition-all ${
                        profile === p.id
                          ? "bg-cyan/15 border-cyan text-cyan font-bold shadow-[0_0_10px_rgba(0,240,255,0.15)]"
                          : "bg-surface border-border text-ink-2 hover:border-border-hi"
                      }`}
                    >
                      {p.label}
                    </button>
                  ))}
                </div>
              </div>

              {/* Safety Level */}
              <div>
                <label className="block text-ink-3 uppercase font-mono text-[11px] mb-1.5 font-semibold">
                  AUDIT SAFETY LEVEL
                </label>
                <div className="grid grid-cols-3 gap-3">
                  {[
                    {
                      id: "passive",
                      title: "Passive",
                      desc: "Non-intrusive header, SSL & crawling probes",
                    },
                    {
                      id: "standard",
                      title: "Standard",
                      desc: "Safe active payloads, SQLi/XSS/IDOR verification",
                    },
                    {
                      id: "aggressive",
                      title: "Aggressive",
                      desc: "Concurrency stress, blind time-based injections",
                    },
                  ].map((lvl) => {
                    const isSelected = safety === lvl.id
                    return (
                      <button
                        key={lvl.id}
                        type="button"
                        onClick={() => setSafety(lvl.id as any)}
                        className={`p-3 rounded border text-left cursor-pointer transition-all ${
                          isSelected
                            ? "bg-cyan/10 border-cyan text-cyan shadow-[0_0_12px_rgba(0,240,255,0.15)]"
                            : "bg-surface border-border text-ink-2 hover:border-border-hi"
                        }`}
                      >
                        <div className="font-mono uppercase font-bold text-xs">
                          {lvl.title}
                        </div>
                        <p className="text-[10px] text-ink-3 mt-1 leading-snug">
                          {lvl.desc}
                        </p>
                      </button>
                    )
                  })}
                </div>
              </div>

              {/* Concurrency & Depth Controls */}
              <div className="grid grid-cols-3 gap-3 pt-2">
                <div>
                  <label className="block text-ink-3 font-mono text-[10px] uppercase mb-1">
                    CRAWL DEPTH
                  </label>
                  <input
                    type="number"
                    min={1}
                    max={10}
                    value={depth}
                    onChange={(e) => setDepth(Number(e.target.value))}
                    className="w-full bg-surface border border-border rounded px-2.5 py-1.5 text-ink font-mono text-xs"
                  />
                </div>
                <div>
                  <label className="block text-ink-3 font-mono text-[10px] uppercase mb-1">
                    CONCURRENCY
                  </label>
                  <input
                    type="number"
                    min={1}
                    max={25}
                    value={concurrency}
                    onChange={(e) => setConcurrency(Number(e.target.value))}
                    className="w-full bg-surface border border-border rounded px-2.5 py-1.5 text-ink font-mono text-xs"
                  />
                </div>
                <div>
                  <label className="block text-ink-3 font-mono text-[10px] uppercase mb-1">
                    TIMEOUT (SEC)
                  </label>
                  <input
                    type="number"
                    min={5}
                    max={120}
                    value={timeout}
                    onChange={(e) => setTimeoutVal(Number(e.target.value))}
                    className="w-full bg-surface border border-border rounded px-2.5 py-1.5 text-ink font-mono text-xs"
                  />
                </div>
              </div>

              {/* Legal Confirmation */}
              <div className="p-3.5 rounded bg-surface border border-border mt-4">
                <label className="flex items-start gap-3 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={authorized}
                    onChange={(e) => setAuthorized(e.target.checked)}
                    className="mt-0.5 accent-cyan w-4 h-4 rounded cursor-pointer shrink-0"
                  />
                  <div className="text-xs">
                    <span className="font-semibold text-ink uppercase font-mono">
                      CONFIRM OPERATIONAL AUTHORIZATION
                    </span>
                    <p className="text-ink-3 text-[11px] mt-0.5 leading-relaxed">
                      I confirm that I own or have explicit written authorisation to perform active vulnerability assessment against the target specified above.
                    </p>
                  </div>
                </label>
              </div>
            </div>
          </CyberCard>

          {/* Advanced Macro Sequences Toggle */}
          <CyberCard
            title="Advanced Workflows & Sequences"
            subtitle="Custom API auth sequences & Playwright macro scripts"
            action={
              <CyberButton
                size="xs"
                variant="ghost"
                onClick={() => setShowAdvanced((v) => !v)}
              >
                {showAdvanced ? "Hide Workflows" : "Configure"}
              </CyberButton>
            }
          >
            {showAdvanced ? (
              <div className="space-y-4 pt-2">
                <div>
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-mono text-[11px] uppercase text-ink-3">
                      API SEQUENCE WORKFLOW (JSON)
                    </span>
                    <button
                      type="button"
                      onClick={() => setSequenceText(EXAMPLE_SEQUENCE)}
                      className="text-[10px] text-cyan hover:underline font-mono"
                    >
                      Load Template
                    </button>
                  </div>
                  <textarea
                    value={sequenceText}
                    onChange={(e) => setSequenceText(e.target.value)}
                    rows={6}
                    placeholder='{"name": "Login", "steps": [...]}'
                    className="w-full bg-surface border border-border rounded p-2 text-xs font-mono text-ink"
                  />
                </div>

                <div>
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-mono text-[11px] uppercase text-ink-3">
                      BROWSER MACRO (PLAYWRIGHT JSON)
                    </span>
                    <button
                      type="button"
                      onClick={() => setBrowserWorkflowText(EXAMPLE_BROWSER_WORKFLOW)}
                      className="text-[10px] text-cyan hover:underline font-mono"
                    >
                      Load Template
                    </button>
                  </div>
                  <textarea
                    value={browserWorkflowText}
                    onChange={(e) => setBrowserWorkflowText(e.target.value)}
                    rows={6}
                    placeholder='{"name": "Browser macro", "steps": [...]}'
                    className="w-full bg-surface border border-border rounded p-2 text-xs font-mono text-ink"
                  />
                </div>
              </div>
            ) : (
              <p className="text-xs text-ink-3">
                Optional: Pre-configure stateful multi-step API logins or authenticated browser navigation before automated probing begins.
              </p>
            )}
          </CyberCard>
        </div>

        {/* Right Column: Schema & Specification Importer (5 cols) */}
        <div className="lg:col-span-5 space-y-6">
          <CyberCard
            title="API Schema / HAR Importer"
            subtitle="Import endpoints from OpenAPI, Postman, HAR, or GraphQL"
            icon={<FileCode size={15} />}
          >
            <div className="space-y-4">
              {/* Format Switcher */}
              <div className="grid grid-cols-4 gap-1 p-1 bg-surface rounded border border-border font-mono text-[11px]">
                {(["openapi", "postman", "har", "graphql"] as ImportFormat[]).map((fmt) => (
                  <button
                    key={fmt}
                    type="button"
                    onClick={() => changeFormat(fmt)}
                    className={`py-1 rounded-xs uppercase font-medium cursor-pointer transition-colors ${
                      importFormat === fmt
                        ? "bg-cyan/20 text-cyan font-bold border border-cyan/30"
                        : "text-ink-3 hover:text-ink"
                    }`}
                  >
                    {fmt}
                  </button>
                ))}
              </div>

              <div>
                <textarea
                  value={importText}
                  onChange={(e) => setImportText(e.target.value)}
                  rows={9}
                  className="w-full bg-surface border border-border focus:border-cyan/50 rounded p-2.5 font-mono text-xs text-ink"
                />
              </div>

              {importError && (
                <div className="p-2.5 rounded bg-critical/10 border border-critical/40 text-critical text-xs font-mono">
                  {importError}
                </div>
              )}

              <div className="flex gap-2">
                <CyberButton
                  variant="secondary"
                  size="xs"
                  loading={importBusy}
                  icon={<Upload size={12} />}
                  onClick={() => void previewImport()}
                >
                  PREVIEW PARSED ENDPOINTS
                </CyberButton>
                {importedEndpoints.length > 0 && (
                  <CyberButton size="xs" variant="ghost" onClick={clearImport}>
                    CLEAR
                  </CyberButton>
                )}
              </div>

              {importedEndpoints.length > 0 && (
                <div className="border border-border rounded overflow-hidden">
                  <div className="px-3 py-2 bg-surface text-ink text-xs font-mono font-semibold flex justify-between">
                    <span>IMPORTED ENDPOINTS ({importedEndpoints.length})</span>
                    <span className="text-cyan font-normal">{importedUrls.length} distinct URLs</span>
                  </div>
                  <div className="max-h-48 overflow-y-auto divide-y divide-border text-[11px] font-mono">
                    {importedEndpoints.map((ep, idx) => (
                      <div key={idx} className="px-3 py-1.5 flex items-center gap-2 hover:bg-surface/50">
                        <span className="font-bold text-cyan uppercase w-12">{ep.method}</span>
                        <span className="truncate text-ink-2 flex-1">{ep.url}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </CyberCard>

          {/* Safety Checklist Card */}
          <CyberCard title="Pre-Flight Safety Directives" icon={<CheckCircle2 size={15} />}>
            <ul className="space-y-2 text-xs text-ink-3 font-mono">
              <li className="flex items-center gap-2">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald" />
                <span>Private & local subnet probing strictly prohibited</span>
              </li>
              <li className="flex items-center gap-2">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald" />
                <span>Scope boundaries enforced on all discovered links</span>
              </li>
              <li className="flex items-center gap-2">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald" />
                <span>Sanitized disk persistence for credentials & tokens</span>
              </li>
              <li className="flex items-center gap-2">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald" />
                <span>Bounded request rate budget prevent target degradation</span>
              </li>
            </ul>
          </CyberCard>
        </div>
      </div>
    </div>
  )
}
