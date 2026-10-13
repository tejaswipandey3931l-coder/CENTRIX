/**
 * CENTRIX Security Command Center - API Client
 * Strongly-typed HTTP + WebSocket facade for the CENTRIX DAST Engine at localhost:8000
 */

export const BASE = import.meta.env.VITE_API_BASE || "http://localhost:8000"
export const WS_BASE = BASE.replace(/^http/, "ws")

// ── Custom ApiError Class ───────────────────────────────────────────────────
export class ApiError extends Error {
  public status?: number
  public statusText?: string
  public isOffline: boolean
  public isTimeout: boolean
  public data?: any

  constructor(
    message: string,
    options?: {
      status?: number
      statusText?: string
      isOffline?: boolean
      isTimeout?: boolean
      data?: any
    },
  ) {
    super(message)
    this.name = "ApiError"
    this.status = options?.status
    this.statusText = options?.statusText
    this.isOffline = options?.isOffline ?? false
    this.isTimeout = options?.isTimeout ?? false
    this.data = options?.data
  }
}

interface RequestOptions extends RequestInit {
  timeoutMs?: number
  retry?: boolean
}

/**
 * Robust request wrapper with timeout, typed responses, error normalization,
 * and single retry for safe idempotent GET queries.
 */
export async function request<T>(endpoint: string, options: RequestOptions = {}): Promise<T> {
  const { timeoutMs = 15000, retry = true, ...fetchOptions } = options
  const url = endpoint.startsWith("http") ? endpoint : `${BASE}${endpoint}`
  const method = (fetchOptions.method || "GET").toUpperCase()

  const execute = async (attempt: number): Promise<T> => {
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), timeoutMs)

    // Combine caller signal with timeout controller
    let signal = controller.signal
    if (fetchOptions.signal) {
      const callerSignal = fetchOptions.signal
      callerSignal.addEventListener("abort", () => controller.abort())
    }

    try {
      const res = await fetch(url, {
        ...fetchOptions,
        signal,
        headers: {
          Accept: "application/json",
          ...fetchOptions.headers,
        },
      })

      clearTimeout(timer)

      if (!res.ok) {
        let errorData: any = null
        let errorMsg = `Server returned HTTP ${res.status} ${res.statusText}`
        try {
          const text = await res.text()
          try {
            errorData = JSON.parse(text)
            if (errorData?.detail) {
              errorMsg = typeof errorData.detail === "string" ? errorData.detail : JSON.stringify(errorData.detail)
            } else if (errorData?.message) {
              errorMsg = errorData.message
            }
          } catch {
            if (text) errorMsg = text
          }
        } catch {
          // ignore stream read error
        }

        throw new ApiError(errorMsg, {
          status: res.status,
          statusText: res.statusText,
          data: errorData,
        })
      }

      // 204 No Content
      if (res.status === 204) {
        return undefined as unknown as T
      }

      const contentType = res.headers.get("content-type") || ""
      if (contentType.includes("application/json")) {
        return (await res.json()) as T
      }
      return (await res.text()) as unknown as T
    } catch (err: any) {
      clearTimeout(timer)

      if (err instanceof ApiError) {
        throw err
      }

      const isAbort = err.name === "AbortError"
      const isOffline = !navigator.onLine || err.message?.includes("Failed to fetch") || err.message?.includes("NetworkError")

      const friendlyMsg = isAbort
        ? `Request timed out after ${timeoutMs}ms.`
        : isOffline
          ? "CENTRIX backend engine is unreachable. Verify backend is running on http://localhost:8000."
          : (err.message || "Network request failed.")

      // Safe GET retry once on network error or timeout
      if (method === "GET" && retry && attempt === 0 && !isAbort) {
        await new Promise((r) => setTimeout(r, 600))
        return execute(attempt + 1)
      }

      throw new ApiError(friendlyMsg, {
        isOffline,
        isTimeout: isAbort,
      })
    }
  }

  return execute(0)
}

// ── Models & Type Definitions ───────────────────────────────────────────────

export interface ScanConfig {
  target: string
  scope?: string[]
  imported_urls?: string[]
  imported_requests?: Record<string, any>[]
  sequence_workflows?: Record<string, any>[]
  browser_workflows?: Record<string, any>[]
  authorized: boolean
  profile?: "quick" | "full" | "api" | "custom"
  safety?: "passive" | "standard" | "aggressive"
  depth?: number
  timeout?: number
  concurrency?: number
  max_requests?: number
  respect_robots?: boolean
  auth_token?: string | null
  label?: string | null
  environment?: string
}

export interface ScanItem {
  id: string
  target: string
  status: "pending" | "running" | "completed" | "failed" | "paused" | "stopped" | string
  stage?: string
  progress: number
  findings_count: number
  requests_sent: number
  urls_discovered: number
  created_at?: string
  started_at: string | null
  finished_at: string | null
  duration_s: number | null
  profile?: string
  safety?: string
}

export interface ScanStatus {
  scan_id: string
  status: "pending" | "running" | "completed" | "failed" | "paused" | "stopped" | string
  stage: string
  progress: number
  findings_count: number
  requests_sent: number
  urls_discovered: number
  started_at: string | null
  finished_at: string | null
  duration_s: number | null
}

export interface ApiFinding {
  id: string
  scan_id: string
  title: string
  severity: "Critical" | "High" | "Medium" | "Low" | "Info" | string
  category: string
  target: string
  parameter: string
  confidence: string
  classification?: "Confirmed" | "Probable" | "Tentative" | "Informational" | "Rejected" | string
  status: "Open" | "In Review" | "Fixed" | "Accepted" | "Still Open" | "Needs Review" | string
  found_at: string
  cwe: string | null
  cvss: number | null
  description?: string
  recommendation?: string
  evidence?: string
  vuln_type?: string
  confidence_score?: number
  confidence_reasons?: string[]
  false_positive_indicators?: string[]
  why_false_positive_risk?: string
  validation_status?: string
  reproduction_status?: string
  affected_urls_count?: number
  example_urls?: string[]
  evidence_artifact_ids?: string[]
}


export interface ApiReport {
  id: string
  scan_id: string
  name: string
  report_type: string
  target: string
  generated_at: string
  status: string
  findings_count: number
  size: string
  format: string
}

export interface ProxyStatus {
  running: boolean
  port?: number
  intercepting?: boolean
  request_count?: number
}

export interface CaStatus {
  installed?: boolean
  ready?: boolean
  path?: string
  cert_pem?: string
  success?: boolean
}

export interface BrowserStatus {
  ok?: boolean
  running: boolean
  url?: string
  target_url?: string
  proxy_connected?: boolean
  proxy_server?: string
  scan_id?: string
  profile_dir?: string
  mode?: string
  error?: string
  warning?: string
}

export interface CorpusItem {
  id: string
  scan_id: string
  method: string
  url: string
  path?: string
  status?: number
  status_code?: number
  headers?: Record<string, string>
  body?: string
  request_headers?: string | Record<string, string>
  request_body?: string
  response_headers?: Record<string, string>
  response_body?: string
  response_excerpt?: string
  timestamp?: string
  length?: number
  duration_ms?: number
}

export interface ScheduleItem {
  id: string
  name: string
  target: string
  frequency: "once" | "hourly" | "daily" | "weekly"
  status: "enabled" | "paused" | "completed"
  next_run_at?: string
  last_run_at?: string
  first_run_at?: string | null
  config?: ScanConfig
  last_findings_count?: number
}

export interface AuthProfile {
  id: string
  name: string
  role: string
  headers?: Record<string, string>
  cookies?: Record<string, string>
  notes?: string
}

export interface OobEvent {
  id: string
  token: string
  protocol: string
  source_ip: string
  timestamp: string
  data?: any
}

export interface ProofTask {
  id: string
  finding_id: string
  status: "pending" | "running" | "verified" | "failed"
  proof_type?: string
  output?: string
  created_at?: string
}

export interface IntegrationsStatus {
  nuclei?: { available: boolean; version?: string }
  cve_lookup?: { available: boolean }
  github?: { configured: boolean }
  slack?: { configured: boolean }
  jira?: { configured: boolean }
}

export interface ReplayResponse {
  status: number
  headers: Record<string, string>
  body: string
  length: number
  duration_ms: number
  request_id?: string
}

export interface CompareResult {
  status_diff?: boolean
  status_changed?: boolean
  length_delta?: number
  time_delta_ms?: number
  body_hash_changed?: boolean
  header_keys_added?: string[]
  header_keys_removed?: string[]
  left_status?: number
  right_status?: number
  body_diff?: string[]
  headers_diff?: Record<string, { left?: string; right?: string }>
}

export interface IntruderResultItem {
  id?: string
  payload: string
  status: number
  length: number
  duration_ms?: number
  matched?: boolean
  extracted?: string
  error?: string
}

export interface EvidenceItem {
  id: string
  scan_id: string
  finding_id: string
  type: string
  title?: string
  description?: string
  target?: string
  url?: string
  method?: string
  status_code?: number
  parameter?: string
  request?: string
  response?: string
  response_excerpt?: string
  response_length?: number
  content_type?: string
  payload?: string
  timestamp?: string
  data?: Record<string, unknown>
}

export interface CveResultItem {
  id?: string
  cve_id?: string
  url?: string
  score?: number
  summary?: string
  description?: string
  cvss?: number
  severity?: string
  references?: string[]
  published_date?: string
}

export interface MatrixRunItem {
  id: string
  scan_id: string
  status: string
  created_at: string
  executed_at?: string
  results: {
    request_id: string
    url: string
    method: string
    profile_id: string
    role: string
    status: number
    violation?: boolean
    detail?: string
  }[]
}

export interface RepeaterRequest {
  method: string
  url: string
  headers?: Record<string, string>
  body?: string
  request_headers?: string | Record<string, string>
  request_body?: string
  scan_id?: string
  note?: string
}

// ── Scan API ────────────────────────────────────────────────────────────────
export const scanApi = {
  async start(config: ScanConfig): Promise<{ scan_id: string; status: string; message: string }> {
    return request<{ scan_id: string; status: string; message: string }>("/api/scan/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(config),
      retry: false,
    })
  },

  async status(scanId: string): Promise<ScanStatus> {
    return request<ScanStatus>(`/api/scan/${encodeURIComponent(scanId)}/status`)
  },

  async pause(scanId: string): Promise<{ status: string }> {
    return request<{ status: string }>(`/api/scan/${encodeURIComponent(scanId)}/pause`, {
      method: "POST",
      retry: false,
    })
  },

  async stop(scanId: string): Promise<{ status: string }> {
    return request<{ status: string }>(`/api/scan/${encodeURIComponent(scanId)}/stop`, {
      method: "POST",
      retry: false,
    })
  },

  async list(): Promise<ScanItem[]> {
    return request<ScanItem[]>("/api/scans")
  },

  async resume(scanId: string): Promise<{ scan_id: string; status: string; message: string }> {
    return request<{ scan_id: string; status: string; message: string }>(
      `/api/scan/${encodeURIComponent(scanId)}/resume`,
      { method: "POST", retry: false },
    )
  },

  async getCheckpoints(scanId: string): Promise<{ scan_id: string; checkpoints: any[] }> {
    return request<{ scan_id: string; checkpoints: any[] }>(
      `/api/scan/${encodeURIComponent(scanId)}/checkpoints`,
    )
  },

  async getDiff(scanId: string, previousScanId: string): Promise<any> {
    return request<any>(
      `/api/scan/${encodeURIComponent(scanId)}/diff/${encodeURIComponent(previousScanId)}`,
    )
  },
}

// ── Findings API ─────────────────────────────────────────────────────────────
export const findingsApi = {
  async list(scanId?: string): Promise<ApiFinding[]> {
    const query = scanId ? `?scan_id=${encodeURIComponent(scanId)}` : ""
    return request<ApiFinding[]>(`/api/findings${query}`)
  },

  async get(findingId: string): Promise<ApiFinding> {
    return request<ApiFinding>(`/api/findings/${encodeURIComponent(findingId)}`)
  },

  async updateStatus(
    findingId: string,
    status: "Open" | "In Review" | "Fixed" | "Accepted" | "Still Open" | "Needs Review",
  ): Promise<ApiFinding> {
    return request<ApiFinding>(`/api/findings/${encodeURIComponent(findingId)}/status`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status }),
      retry: false,
    })
  },

  async retest(findingId: string): Promise<{ scan_id: string; finding_id: string; status: string }> {
    return request<{ scan_id: string; finding_id: string; status: string }>(
      `/api/findings/${encodeURIComponent(findingId)}/retest`,
      { method: "POST", retry: false },
    )
  },
}

// ── Reports API ──────────────────────────────────────────────────────────────
export const reportsApi = {
  async generate(params: {
    scan_id: string
    format?: "json" | "html" | "pdf" | "sarif" | "junit" | "evidence" | "github_issues" | "jira"
    report_type?: "technical" | "executive" | "compliance"
    target_scope?: string
  }): Promise<ApiReport> {
    return request<ApiReport>("/api/reports/generate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(params),
      retry: false,
    })
  },

  async list(): Promise<ApiReport[]> {
    return request<ApiReport[]>("/api/reports")
  },

  downloadUrl(reportId: string): string {
    return `${BASE}/api/reports/${encodeURIComponent(reportId)}/download`
  },
}

// ── Manual Workbench API ────────────────────────────────────────────────────
export const manualApi = {
  async replay(requestData: {
    scan_id: string
    method: string
    url: string
    headers?: Record<string, string>
    body?: string
  }): Promise<{ status: number; headers: Record<string, string>; body: string; length: number; duration_ms: number }> {
    return request<{ status: number; headers: Record<string, string>; body: string; length: number; duration_ms: number }>(
      "/api/manual/replay",
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(requestData),
        retry: false,
      },
    )
  },

  async compare(left: object, right: object): Promise<{
    left_status: number
    right_status: number
    left_length: number
    right_length: number
    status_changed: boolean
    length_delta: number
  }> {
    return request("/api/manual/compare-responses", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ left, right }),
      retry: false,
    })
  },

  async saveRequest(requestData: {
    scan_id: string
    method: string
    url: string
    headers?: Record<string, string>
    body?: string
    response?: object
    note?: string
  }): Promise<any> {
    return request("/api/manual/save-request", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(requestData),
      retry: false,
    })
  },

  async corpus(scanId?: string): Promise<CorpusItem[]> {
    const query = scanId ? `?scan_id=${encodeURIComponent(scanId)}` : ""
    return request<CorpusItem[]>(`/api/manual/corpus${query}`)
  },

  async corpusItem(requestId: string): Promise<CorpusItem> {
    return request<CorpusItem>(`/api/manual/corpus/${encodeURIComponent(requestId)}`)
  },

  async compareCorpus(leftId: string, rightId: string): Promise<CompareResult> {
    return request<CompareResult>(`/api/manual/compare-corpus?left_id=${encodeURIComponent(leftId)}&right_id=${encodeURIComponent(rightId)}`, {
      method: "POST",
      retry: false,
    })
  },

  async intruder(payload: {
    scan_id: string
    method: string
    url: string
    headers?: Record<string, string>
    body?: string
    marker: string
    payloads: string[]
    delay_ms?: number
    max_requests?: number
    match_text?: string
    extract_regex?: string
  }): Promise<{ scan_id: string; results: IntruderResultItem[] }> {
    return request<{ scan_id: string; results: IntruderResultItem[] }>("/api/manual/intruder/run", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      retry: false,
    })
  },

  async runPassive(scanId: string): Promise<{ scan_id: string; imported: number }> {
    return request<{ scan_id: string; imported: number }>(`/api/manual/passive/${encodeURIComponent(scanId)}/run`, {
      method: "POST",
      retry: false,
    })
  },

  async decode(mode: string, value: string): Promise<{ mode: string; output: string }> {
    return request<{ mode: string; output: string }>("/api/manual/decode", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ mode, value }),
      retry: false,
    })
  },

  async proxyStatus(): Promise<ProxyStatus> {
    return request<ProxyStatus>("/api/manual/proxy/status")
  },

  async proxyStart(scanId = ""): Promise<{ running: boolean; port: number }> {
    const query = scanId ? `?scan_id=${encodeURIComponent(scanId)}` : ""
    return request<{ running: boolean; port: number }>(`/api/manual/proxy/start${query}`, {
      method: "POST",
      retry: false,
    })
  },

  async proxyStop(): Promise<{ running: boolean }> {
    return request<{ running: boolean }>("/api/manual/proxy/stop", {
      method: "POST",
      retry: false,
    })
  },

  async caStatus(): Promise<CaStatus> {
    return request<CaStatus>("/api/manual/proxy/ca/status")
  },

  async caGenerate(): Promise<{ success: boolean; cert_pem: string }> {
    return request<{ success: boolean; cert_pem: string }>("/api/manual/proxy/ca/generate", {
      method: "POST",
      retry: false,
    })
  },

  caDownloadUrl(): string {
    return `${BASE}/api/manual/proxy/ca/download`
  },

  async leafGenerate(hostname: string): Promise<any> {
    return request(`/api/manual/proxy/ca/leaf/generate?hostname=${encodeURIComponent(hostname)}`, {
      method: "POST",
      retry: false,
    })
  },

  async browserOpen(url: string, scanId = "", useProxy = false): Promise<BrowserStatus> {
    return request<BrowserStatus>(
      `/api/manual/browser/open?url=${encodeURIComponent(url)}&scan_id=${encodeURIComponent(scanId)}&use_proxy=${useProxy}`,
      { method: "POST", retry: false },
    )
  },

  async browserStatus(): Promise<BrowserStatus> {
    return request<BrowserStatus>("/api/manual/browser/status")
  },

  async browserClose(): Promise<{ running: boolean }> {
    return request<{ running: boolean }>("/api/manual/browser/close", {
      method: "POST",
      retry: false,
    })
  },
}

// ── Schema Import API ───────────────────────────────────────────────────────
export const importApi = {
  async preview(
    format: "openapi" | "postman" | "har" | "graphql",
    document: object,
    base_url?: string,
  ): Promise<{ endpoints: { method: string; url: string; name?: string }[] }> {
    return request<{ endpoints: { method: string; url: string; name?: string }[] }>("/api/import/preview", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ format, document, base_url }),
      retry: false,
    })
  },
}

// ── Evidence API ────────────────────────────────────────────────────────────
export const evidenceApi = {
  async list(scanId?: string): Promise<EvidenceItem[]> {
    const query = scanId ? `?scan_id=${encodeURIComponent(scanId)}` : ""
    return request<EvidenceItem[]>(`/api/evidence${query}`)
  },
}

export const evidenceBundleUrl = (findingId: string) => `${BASE}/api/evidence/bundle/${encodeURIComponent(findingId)}`

// ── Integrations & Intelligence API ─────────────────────────────────────────
export const integrationsApi = {
  async status(): Promise<IntegrationsStatus> {
    return request<IntegrationsStatus>("/api/integrations/status")
  },

  async searchCves(query: string): Promise<{ query: string; results: CveResultItem[] }> {
    return request<{ query: string; results: CveResultItem[] }>(`/api/integrations/cves/search?query=${encodeURIComponent(query)}`)
  },

  async runNuclei(scan_id: string, severity: string[] = []): Promise<{ scan_id: string; imported: number; results: any[]; engine?: string }> {
    return request<{ scan_id: string; imported: number; results: any[]; engine?: string }>("/api/integrations/nuclei/run", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scan_id, severity }),
      retry: false,
    })
  },

  async pushFinding(
    findingId: string,
    destination: "local" | "slack" | "github" | "jira" = "local",
    note = "",
  ): Promise<{ status: string; destination: string }> {
    return request<{ status: string; destination: string }>(`/api/integrations/findings/${encodeURIComponent(findingId)}/push`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ destination, note }),
      retry: false,
    })
  },

  async outbox(findingId?: string): Promise<any[]> {
    const query = findingId ? `?finding_id=${encodeURIComponent(findingId)}` : ""
    return request<any[]>(`/api/integrations/outbox${query}`)
  },
}

// ── Proof of Concept Mode API ───────────────────────────────────────────────
export const proofApi = {
  async list(findingId?: string): Promise<ProofTask[]> {
    const query = findingId ? `?finding_id=${encodeURIComponent(findingId)}` : ""
    return request<ProofTask[]>(`/api/proof/tasks${query}`)
  },

  async create(findingId: string): Promise<ProofTask> {
    return request<ProofTask>(`/api/proof/${encodeURIComponent(findingId)}/task`, {
      method: "POST",
      retry: false,
    })
  },

  async run(taskId: string): Promise<ProofTask> {
    return request<ProofTask>(`/api/proof/${encodeURIComponent(taskId)}/run`, {
      method: "POST",
      retry: false,
    })
  },
}

// ── Autonomous Schedules API ────────────────────────────────────────────────
export const schedulesApi = {
  async list(): Promise<ScheduleItem[]> {
    return request<ScheduleItem[]>("/api/schedules")
  },

  async create(payload: {
    name: string
    frequency: "once" | "hourly" | "daily" | "weekly"
    first_run_at?: string | null
    config: ScanConfig
  }): Promise<ScheduleItem> {
    return request<ScheduleItem>("/api/schedules", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      retry: false,
    })
  },

  async run(scheduleId: string): Promise<{ message: string; scan_id: string }> {
    return request<{ message: string; scan_id: string }>(`/api/schedules/${encodeURIComponent(scheduleId)}/run`, {
      method: "POST",
      retry: false,
    })
  },

  async setStatus(scheduleId: string, status: "enabled" | "paused" | "completed"): Promise<ScheduleItem> {
    return request<ScheduleItem>(`/api/schedules/${encodeURIComponent(scheduleId)}/status`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status }),
      retry: false,
    })
  },

  async remove(scheduleId: string): Promise<{ message: string }> {
    return request<{ message: string }>(`/api/schedules/${encodeURIComponent(scheduleId)}`, {
      method: "DELETE",
      retry: false,
    })
  },
}

// ── Authorization & Access Matrix API ───────────────────────────────────────
export const authzApi = {
  async profiles(): Promise<AuthProfile[]> {
    return request<AuthProfile[]>("/api/authz/profiles")
  },

  async createProfile(profile: {
    name: string
    role: string
    headers?: Record<string, string>
    cookies?: Record<string, string>
    notes?: string
  }): Promise<AuthProfile> {
    return request<AuthProfile>("/api/authz/profiles", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(profile),
      retry: false,
    })
  },

  async deleteProfile(profileId: string): Promise<{ message: string }> {
    return request<{ message: string }>(`/api/authz/profiles/${encodeURIComponent(profileId)}`, {
      method: "DELETE",
      retry: false,
    })
  },

  async matrixRuns(scanId?: string): Promise<MatrixRunItem[]> {
    const query = scanId ? `?scan_id=${encodeURIComponent(scanId)}` : ""
    return request<MatrixRunItem[]>(`/api/authz/matrix/runs${query}`)
  },

  async runMatrix(payload: { scan_id: string; request_ids?: string[]; profile_ids?: string[] }): Promise<any> {
    return request("/api/authz/matrix/run", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      retry: false,
    })
  },
}

// ── Out-Of-Band Callback API ────────────────────────────────────────────────
export const oobApi = {
  async createToken(scanId = "", findingId = ""): Promise<{ token: string; callback_url: string }> {
    return request<{ token: string; callback_url: string }>(
      `/api/oob/token?scan_id=${encodeURIComponent(scanId)}&finding_id=${encodeURIComponent(findingId)}`,
      { method: "POST", retry: false },
    )
  },

  async events(token?: string): Promise<OobEvent[]> {
    const query = token ? `?token=${encodeURIComponent(token)}` : ""
    return request<OobEvent[]>(`/api/oob/events${query}`)
  },

  callbackUrl(token: string): string {
    return `${BASE}/api/oob/hit/${encodeURIComponent(token)}`
  },
}

// ── WebSocket Log Stream ────────────────────────────────────────────────────
export function createScanLogStream(
  scanId: string,
  onMessage: (msg: string) => void,
  onDone: () => void,
  onError?: (err: Event) => void,
): WebSocket {
  const ws = new WebSocket(`${WS_BASE}/ws/scan/${encodeURIComponent(scanId)}`)

  ws.onmessage = (event) => {
    const msg: string = event.data
    if (msg === "__DONE__") {
      onDone()
      try {
        ws.close()
      } catch {
        // ignore
      }
      return
    }
    if (msg !== "[PING]") {
      onMessage(msg)
    }
  }

  ws.onerror = (e) => {
    onError?.(e)
    onMessage("[ERROR] WebSocket connection lost — checking backend polling fallback...")
  }

  return ws
}

// ── Health Check ─────────────────────────────────────────────────────────────
export async function checkBackendHealth(): Promise<{ online: boolean; latencyMs: number }> {
  const start = performance.now()
  try {
    const res = await fetch(`${BASE}/health`, { signal: AbortSignal.timeout(3500) })
    const latencyMs = Math.round(performance.now() - start)
    return { online: res.ok, latencyMs }
  } catch {
    return { online: false, latencyMs: 0 }
  }
}

// ── Autonomous Agent API ───────────────────────────────────────────────────
export interface AgentApprovalRequest {
  id: string
  tool_name: string
  arguments: Record<string, any>
  risk_level: string
  justification: string
  status: "pending" | "approved" | "rejected"
  created_at: string
}

export interface AssessmentPlanStep {
  id: string
  specialist: string
  objective: string
  tools: string[]
  status: "pending" | "running" | "completed" | "skipped"
}

export interface AssessmentPlan {
  target: string
  created_at: string
  steps: AssessmentPlanStep[]
  summary: string
}

export interface AgentSession {
  id: string
  target_url: string
  scope_domains: string[]
  safety_profile: string
  status: "created" | "planning" | "running" | "paused" | "completed" | "failed" | "stopped"
  organization_id: string
  user_id: string
  current_stage: string
  current_specialist: string
  current_model: string
  plan?: AssessmentPlan
  pending_approval?: AgentApprovalRequest
  discovered_urls: string[]
  discovered_forms: Record<string, any>[]
  captured_requests_count: number
  selected_scanner_modules: string[]
  findings_count: number
  evidence_count: number
  browser_status: string
  proxy_status: string
  step_count: number
  stop_reason?: string
  tool_history: Array<{
    session_id: string
    current_agent: string
    objective: string
    tool: string
    result_summary: string
    step: number
  }>
  created_at: string
  updated_at: string
}

export const agentApi = {
  async createSession(data: {
    target_url: string
    scope_domains?: string[]
    safety_profile?: string
  }): Promise<AgentSession> {
    return request<AgentSession>("/api/agent/sessions", {
      method: "POST",
      body: JSON.stringify(data),
      headers: { "Content-Type": "application/json" },
    })
  },

  async listSessions(): Promise<AgentSession[]> {
    return request<AgentSession[]>("/api/agent/sessions")
  },

  async getSession(sessionId: string): Promise<AgentSession> {
    return request<AgentSession>(`/api/agent/sessions/${encodeURIComponent(sessionId)}`)
  },

  async startSession(sessionId: string): Promise<AgentSession> {
    return request<AgentSession>(`/api/agent/sessions/${encodeURIComponent(sessionId)}/start`, {
      method: "POST",
    })
  },

  async pauseSession(sessionId: string, reason = "Operator manual pause"): Promise<AgentSession> {
    return request<AgentSession>(`/api/agent/sessions/${encodeURIComponent(sessionId)}/pause`, {
      method: "POST",
      body: JSON.stringify({ reason }),
      headers: { "Content-Type": "application/json" },
    })
  },

  async resumeSession(sessionId: string): Promise<AgentSession> {
    return request<AgentSession>(`/api/agent/sessions/${encodeURIComponent(sessionId)}/resume`, {
      method: "POST",
    })
  },

  async stopSession(sessionId: string, reason = "Operator emergency stop"): Promise<AgentSession> {
    return request<AgentSession>(`/api/agent/sessions/${encodeURIComponent(sessionId)}/stop`, {
      method: "POST",
      body: JSON.stringify({ reason }),
      headers: { "Content-Type": "application/json" },
    })
  },

  async approveAction(sessionId: string, approvalId: string, comment?: string): Promise<AgentSession> {
    return request<AgentSession>(`/api/agent/sessions/${encodeURIComponent(sessionId)}/approve`, {
      method: "POST",
      body: JSON.stringify({ approval_id: approvalId, comment }),
      headers: { "Content-Type": "application/json" },
    })
  },

  async rejectAction(sessionId: string, approvalId: string, comment?: string): Promise<AgentSession> {
    return request<AgentSession>(`/api/agent/sessions/${encodeURIComponent(sessionId)}/reject`, {
      method: "POST",
      body: JSON.stringify({ approval_id: approvalId, comment }),
      headers: { "Content-Type": "application/json" },
    })
  },

  async getEvents(sessionId: string, limit = 50): Promise<any[]> {
    return request<any[]>(`/api/agent/sessions/${encodeURIComponent(sessionId)}/events?limit=${limit}`)
  },

  async getAiHealth(): Promise<{
    status: string
    provider: string
    base_url: string
    free_models_enforced: boolean
    allowed_models: string[]
  }> {
    return request<{
      status: string
      provider: string
      base_url: string
      free_models_enforced: boolean
      allowed_models: string[]
    }>("/api/ai/health")
  },

  async getAiModels(): Promise<{
    models: Array<{ id: string; tier: string; provider: string }>
    routing_matrix: Record<string, { model: string; reason: string }>
  }> {
    return request<{
      models: Array<{ id: string; tier: string; provider: string }>
      routing_matrix: Record<string, { model: string; reason: string }>
    }>("/api/ai/models")
  },

  async getAiUsage(): Promise<any> {
    return request<any>("/api/ai/usage")
  },

  async getAuditEvents(limit = 100): Promise<any[]> {
    return request<any[]>(`/api/audit/events?limit=${limit}`)
  },

  createAgentStream(
    sessionId: string,
    onMessage: (msg: any) => void,
    onError?: (err: Event) => void,
  ): WebSocket {
    const ws = new WebSocket(`${WS_BASE}/api/agent/ws/${encodeURIComponent(sessionId)}`)
    ws.onmessage = (event) => {
      try {
        const parsed = JSON.parse(event.data)
        onMessage(parsed)
      } catch {
        onMessage(event.data)
      }
    }
    ws.onerror = (e) => onError?.(e)
    return ws
  },
}
