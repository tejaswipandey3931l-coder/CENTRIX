import React, { createContext, useContext, useState, useEffect, useCallback, useRef } from "react"
import {
  scanApi,
  findingsApi,
  checkBackendHealth,
  createScanLogStream,
  type ScanConfig,
  type ScanStatus,
  type ScanItem,
  type RepeaterRequest,
} from "../api/client"
import { calculateBackoffDelay, boundLogs } from "../utils/telemetry"

const ACTIVE_SCAN_STORAGE_KEY = "centrix_active_scan_id"
const MAX_LOG_LINES = 1000

export type TelemetryMode = "websocket" | "polling" | "idle"

export interface ScanContextValue {
  backendOnline: boolean | null
  backendLatency: number
  activeScanId: string | null
  scanStatus: ScanStatus | null
  scanActive: boolean
  scanProgress: number
  scanStage: string
  findingsCount: number
  logs: string[]
  wsConnected: boolean
  telemetryMode: TelemetryMode
  lastEventTime: Date | null
  repeaterRequest: RepeaterRequest | null
  setRepeaterRequest: (req: RepeaterRequest | null) => void
  setActiveScanId: (scanId: string | null) => void
  startScan: (config: ScanConfig) => Promise<string>
  pauseScan: (scanId?: string) => Promise<void>
  stopScan: (scanId?: string) => Promise<void>
  refreshHealth: () => Promise<boolean>
  refreshStats: () => Promise<void>
  resetActiveScan: () => void
  clearLogs: () => void
  addLogMessage: (msg: string) => void
}

const ScanContext = createContext<ScanContextValue | null>(null)

export function ScanProvider({ children }: { children: React.ReactNode }) {
  const [backendOnline, setBackendOnline] = useState<boolean | null>(null)
  const [backendLatency, setBackendLatency] = useState(0)

  // Initialize activeScanId from localStorage
  const [activeScanId, setActiveScanIdState] = useState<string | null>(() => {
    try {
      return localStorage.getItem(ACTIVE_SCAN_STORAGE_KEY)
    } catch {
      return null
    }
  })

  const [scanStatus, setScanStatus] = useState<ScanStatus | null>(null)
  const [findingsCount, setFindingsCount] = useState(0)
  const [logs, setLogs] = useState<string[]>([])
  const [wsConnected, setWsConnected] = useState(false)
  const [telemetryMode, setTelemetryMode] = useState<TelemetryMode>("idle")
  const [lastEventTime, setLastEventTime] = useState<Date | null>(null)
  const [repeaterRequest, setRepeaterRequest] = useState<RepeaterRequest | null>(null)

  const wsRef = useRef<WebSocket | null>(null)
  const pollTimerRef = useRef<ReturnType<typeof setInterval> | null>(null)
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const reconnectAttemptRef = useRef(0)
  const isPollingRef = useRef(false)
  const lastPollTimeRef = useRef(0)

  // Sync activeScanId to localStorage
  const setActiveScanId = useCallback((id: string | null) => {
    setActiveScanIdState(id)
    try {
      if (id) {
        localStorage.setItem(ACTIVE_SCAN_STORAGE_KEY, id)
      } else {
        localStorage.removeItem(ACTIVE_SCAN_STORAGE_KEY)
      }
    } catch {
      // ignore
    }
  }, [])

  const scanActive = Boolean(
    scanStatus && scanStatus.status?.toLowerCase() === "running",
  )
  const scanProgress = scanStatus?.progress ?? 0
  const scanStage = scanStatus?.stage ?? "IDLE"

  // Append log lines safely with bounding
  const addLogMessage = useCallback((msg: string) => {
    setLastEventTime(new Date())
    setLogs((prev) => boundLogs(prev, msg, MAX_LOG_LINES))
  }, [])

  const clearLogs = useCallback(() => setLogs([]), [])

  // 1. Health Monitor Loop
  const refreshHealth = useCallback(async (): Promise<boolean> => {
    const result = await checkBackendHealth()
    setBackendOnline(result.online)
    setBackendLatency(result.latencyMs)
    return result.online
  }, [])

  useEffect(() => {
    void refreshHealth()
    const timer = setInterval(() => {
      void refreshHealth()
    }, 20000)
    return () => clearInterval(timer)
  }, [refreshHealth])

  // 2. Fetch Findings Count & Check Running Scans on Mount
  const refreshStats = useCallback(async () => {
    try {
      const [scans, findings] = await Promise.all([
        scanApi.list(),
        findingsApi.list(),
      ])

      const securityFindings = findings.filter(
        (f) =>
          f.category !== "Security Headers" &&
          !f.title.toLowerCase().startsWith("missing security header"),
      )
      setFindingsCount(securityFindings.length)

      // Only pick up a scan as active if it's genuinely running (not stale pending)
      const running = scans.find((s: ScanItem) => s.status?.toLowerCase() === "running")
      if (running) {
        setActiveScanId(running.id)
      } else if (!activeScanId && scans[0]) {
        // Default to most recent completed scan
        setActiveScanId(scans[0].id)
      }
    } catch {
      // Backend might be offline
    }
  }, [activeScanId, setActiveScanId])

  useEffect(() => {
    void refreshStats()
  }, [refreshStats])

  // 3. Status Polling Logic with Overlapping Request Protection and Throttling
  const pollStatus = useCallback(async (id: string, force = false) => {
    const now = Date.now()
    if (!force && now - lastPollTimeRef.current < 1200) {
      return null
    }
    if (isPollingRef.current) {
      return null
    }

    isPollingRef.current = true
    lastPollTimeRef.current = now

    try {
      const status = await scanApi.status(id)
      setScanStatus(status)
      setLastEventTime(new Date())
      setFindingsCount((prev) => Math.max(prev, status.findings_count || 0))
      return status
    } catch {
      return null
    } finally {
      isPollingRef.current = false
    }
  }, [])

  // 4. Resilient WebSocket Stream with Exponential Backoff + Polling Fallback
  useEffect(() => {
    if (!activeScanId) {
      setScanStatus(null)
      setTelemetryMode("idle")
      return
    }

    let isSubscribed = true
    reconnectAttemptRef.current = 0

    // Fetch initial status immediately
    void pollStatus(activeScanId, true).then((status) => {
      if (!isSubscribed) return
      if (status && status.status?.toLowerCase() === "running") {
        connectWebSocket(activeScanId)
      } else {
        setTelemetryMode("idle")
      }
    })

    function connectWebSocket(id: string) {
      if (!isSubscribed) return

      if (wsRef.current) {
        try {
          wsRef.current.close()
        } catch {
          // ignore
        }
      }

      addLogMessage(`[CLIENT] Establishing telemetry socket for scan: ${id}...`)

      const ws = createScanLogStream(
        id,
        (msg) => {
          if (!isSubscribed) return
          addLogMessage(msg)
          // Throttled poll keeping stage and progress in sync
          void pollStatus(id, false)
        },
        () => {
          if (!isSubscribed) return
          setWsConnected(false)
          setTelemetryMode("idle")
          addLogMessage("[CLIENT] Scan log stream closed. Scan concluded.")
          void pollStatus(id, true)
          void refreshStats()
        },
        () => {
          if (!isSubscribed) return
          setWsConnected(false)
          // Fall back to polling mode
          setTelemetryMode("polling")

          // Exponential backoff reconnect: 1s, 1.5s, 2.25s, ... max 10s
          const attempt = reconnectAttemptRef.current
          const delay = calculateBackoffDelay(attempt)
          reconnectAttemptRef.current += 1

          addLogMessage(`[CLIENT] Socket disconnected. Retrying in ${Math.round(delay / 1000)}s (attempt ${attempt + 1})...`)

          reconnectTimerRef.current = setTimeout(() => {
            if (isSubscribed) {
              void pollStatus(id, true).then((st) => {
                if (st && st.status?.toLowerCase() === "running") {
                  connectWebSocket(id)
                }
              })
            }
          }, delay)
        },
      )

      ws.onopen = () => {
        if (!isSubscribed) return
        setWsConnected(true)
        setTelemetryMode("websocket")
        reconnectAttemptRef.current = 0
        addLogMessage("[CLIENT] WebSocket connected. Live stream active.")
      }

      wsRef.current = ws
    }

    // Polling Interval: Runs every 2s to ensure progress, stage, and metrics stay synced
    pollTimerRef.current = setInterval(() => {
      if (!isSubscribed) return

      void pollStatus(activeScanId, false).then((status) => {
        if (!status) return
        const isDone = ["completed", "failed", "stopped"].includes(status.status?.toLowerCase())
        if (isDone) {
          if (pollTimerRef.current) clearInterval(pollTimerRef.current)
          setTelemetryMode("idle")
        }
      })
    }, 2000)

    return () => {
      isSubscribed = false
      if (reconnectTimerRef.current) clearTimeout(reconnectTimerRef.current)
      if (pollTimerRef.current) clearInterval(pollTimerRef.current)
      if (wsRef.current) {
        try {
          wsRef.current.close()
        } catch {
          // ignore
        }
      }
    }
  }, [activeScanId, addLogMessage, pollStatus, refreshStats, wsConnected])

  // 5. Actions
  const startScan = useCallback(
    async (config: ScanConfig): Promise<string> => {
      clearLogs()
      addLogMessage(`[INIT] Launching authorised DAST scan against ${config.target}...`)
      const res = await scanApi.start(config)
      const scanId = res.scan_id
      setActiveScanId(scanId)
      setScanStatus({
        scan_id: scanId,
        status: "running",
        stage: "VALIDATE",
        progress: 0,
        findings_count: 0,
        requests_sent: 0,
        urls_discovered: 0,
        started_at: new Date().toISOString(),
        finished_at: null,
        duration_s: 0,
      })
      void pollStatus(scanId, true)
      return scanId
    },
    [clearLogs, addLogMessage, setActiveScanId, pollStatus],
  )

  const pauseScan = useCallback(
    async (scanId?: string) => {
      const id = scanId || activeScanId
      if (!id) return
      await scanApi.pause(id)
      addLogMessage(`[COMMAND] Scan ${id} paused by operator.`)
      void pollStatus(id)
    },
    [activeScanId, addLogMessage, pollStatus],
  )

  const stopScan = useCallback(
    async (scanId?: string) => {
      const id = scanId || activeScanId
      if (!id) return
      await scanApi.stop(id)
      addLogMessage(`[COMMAND] Scan ${id} stopped by operator.`)
      void pollStatus(id)
      void refreshStats()
    },
    [activeScanId, addLogMessage, pollStatus, refreshStats],
  )

  const resetActiveScan = useCallback(() => {
    setActiveScanId(null)
    setScanStatus(null)
    clearLogs()
  }, [setActiveScanId, clearLogs])

  return (
    <ScanContext.Provider
      value={{
        backendOnline,
        backendLatency,
        activeScanId,
        scanStatus,
        scanActive,
        scanProgress,
        scanStage,
        findingsCount,
        logs,
        wsConnected,
        telemetryMode,
        lastEventTime,
        repeaterRequest,
        setRepeaterRequest,
        setActiveScanId,
        startScan,
        pauseScan,
        stopScan,
        refreshHealth,
        refreshStats,
        resetActiveScan,
        clearLogs,
        addLogMessage,
      }}
    >
      {children}
    </ScanContext.Provider>
  )
}

export function useScanContext(): ScanContextValue {
  const ctx = useContext(ScanContext)
  if (!ctx) {
    throw new Error("useScanContext must be used within a ScanProvider")
  }
  return ctx
}
