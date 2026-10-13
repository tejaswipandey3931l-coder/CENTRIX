import { useState, useEffect, lazy, Suspense } from "react"
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom"
import { HeaderTelemetry } from "./components/layout/HeaderTelemetry"
import { NavigationSidebar } from "./components/layout/NavigationSidebar"
import { CommandPalette } from "./components/ui/CommandPalette"
import { LoadingState } from "./components/ui/LoadingState"
import { ScanProvider } from "./context/ScanContext"
import { CyberErrorBoundary } from "./components/ui/CyberErrorBoundary"

// Lazy load route views for optimal bundle splitting
const Overview = lazy(() => import("./pages/Overview"))
const ScanSetup = lazy(() => import("./pages/ScanSetup"))
const AutomatedScan = lazy(() => import("./pages/AutomatedScan"))
const ScheduledScans = lazy(() => import("./pages/ScheduledScans"))
const ManualTesting = lazy(() => import("./pages/ManualTesting"))
const ProxyHistory = lazy(() => import("./pages/ProxyHistory"))
const Intruder = lazy(() => import("./pages/Intruder"))
const Decoder = lazy(() => import("./pages/Decoder"))
const Comparer = lazy(() => import("./pages/Comparer"))
const Findings = lazy(() => import("./pages/Findings"))
const Evidence = lazy(() => import("./pages/Evidence"))
const Reports = lazy(() => import("./pages/Reports"))
const SettingsPage = lazy(() => import("./pages/Settings"))
const ProofMode = lazy(() => import("./pages/ProofMode"))
const NucleiCve = lazy(() => import("./pages/NucleiCve"))
const RiskPosture = lazy(() => import("./pages/RiskPosture"))
const AuthorizationMatrix = lazy(() => import("./pages/AuthorizationMatrix"))
const OobMonitor = lazy(() => import("./pages/OobMonitor"))
const NotFound = lazy(() => import("./pages/NotFound"))

function AppLayout() {
  const [commandPaletteOpen, setCommandPaletteOpen] = useState(false)
  const [mobileSidebarOpen, setMobileSidebarOpen] = useState(false)

  // Global Keyboard Shortcuts (Ctrl+K or Cmd+K)
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault()
        setCommandPaletteOpen((prev) => !prev)
      }
    }
    window.addEventListener("keydown", handleKeyDown)
    return () => window.removeEventListener("keydown", handleKeyDown)
  }, [])

  return (
    <div className="flex h-screen overflow-hidden bg-[#050811] text-ink font-sans bg-grid-cyber selection:bg-cyan/30">
      {/* ── Desktop Sidebar ─────────────────────────────────────── */}
      <div className="hidden lg:flex shrink-0">
        <NavigationSidebar />
      </div>

      {/* ── Mobile Sidebar Drawer ────────────────────────────────── */}
      {mobileSidebarOpen && (
        <div className="lg:hidden fixed inset-0 z-50 flex">
          <div
            className="fixed inset-0 bg-black/80 backdrop-blur-xs"
            onClick={() => setMobileSidebarOpen(false)}
            aria-hidden="true"
          />
          <div className="relative z-10 h-full">
            <NavigationSidebar onCloseMobile={() => setMobileSidebarOpen(false)} />
          </div>
        </div>
      )}

      {/* ── Main Command Viewport ─────────────────────────────────── */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {/* Topbar Telemetry Header */}
        <HeaderTelemetry
          onOpenCommandPalette={() => setCommandPaletteOpen(true)}
          onToggleSidebar={() => setMobileSidebarOpen((v) => !v)}
        />

        {/* Content Viewport with Route Suspense */}
        <main className="flex-1 overflow-y-auto bg-canvas/60">
          <Suspense
            fallback={
              <div className="min-h-[60vh] flex items-center justify-center">
                <LoadingState
                  label="INITIALIZING COMMAND INTERFACE..."
                  sublabel="Loading cryptographic & telemetry view modules"
                />
              </div>
            }
          >
            <Routes>
              {/* Default Redirect */}
              <Route path="/" element={<Navigate to="/overview" replace />} />
              <Route path="/overview" element={<Overview />} />

              {/* Scans & Execution */}
              <Route path="/scans/new" element={<ScanSetup />} />
              <Route path="/scans/active" element={<AutomatedScan />} />
              <Route path="/scans/:scanId" element={<AutomatedScan />} />
              <Route path="/scans/scheduled" element={<ScheduledScans />} />

              {/* Vulnerabilities & Investigation */}
              <Route path="/findings" element={<Findings />} />
              <Route path="/findings/:findingId" element={<Findings />} />
              <Route path="/evidence" element={<Evidence />} />
              <Route path="/proof" element={<ProofMode />} />
              <Route path="/authorization-matrix" element={<AuthorizationMatrix />} />
              <Route path="/oob-monitor" element={<OobMonitor />} />

              {/* Offensive Workbench */}
              <Route path="/manual" element={<ManualTesting />} />
              <Route path="/manual/proxy-history" element={<ProxyHistory />} />
              <Route path="/manual/intruder" element={<Intruder />} />
              <Route path="/manual/decoder" element={<Decoder />} />
              <Route path="/manual/comparer" element={<Comparer />} />

              {/* Intelligence & Reporting */}
              <Route path="/nuclei-cve" element={<NucleiCve />} />
              <Route path="/risk-posture" element={<RiskPosture />} />
              <Route path="/reports" element={<Reports />} />
              <Route path="/settings" element={<SettingsPage />} />

              {/* Legacy Hash/Path Redirects */}
              <Route path="/scan-setup" element={<Navigate to="/scans/new" replace />} />
              <Route path="/automated-scan" element={<Navigate to="/scans/active" replace />} />
              <Route path="/scheduled-scans" element={<Navigate to="/scans/scheduled" replace />} />
              <Route path="/manual-testing" element={<Navigate to="/manual" replace />} />
              <Route path="/proxy-history" element={<Navigate to="/manual/proxy-history" replace />} />
              <Route path="/intruder" element={<Navigate to="/manual/intruder" replace />} />
              <Route path="/decoder" element={<Navigate to="/manual/decoder" replace />} />
              <Route path="/comparer" element={<Navigate to="/manual/comparer" replace />} />
              <Route path="/proof-mode" element={<Navigate to="/proof" replace />} />
              <Route path="/auth-matrix" element={<Navigate to="/authorization-matrix" replace />} />

              {/* 404 Route Catch-All */}
              <Route path="*" element={<NotFound />} />
            </Routes>
          </Suspense>
        </main>
      </div>

      {/* Global Command Palette (Ctrl+K) */}
      <CommandPalette
        isOpen={commandPaletteOpen}
        onClose={() => setCommandPaletteOpen(false)}
      />
    </div>
  )
}

export default function App() {
  return (
    <CyberErrorBoundary>
      <BrowserRouter>
        <ScanProvider>
          <AppLayout />
        </ScanProvider>
      </BrowserRouter>
    </CyberErrorBoundary>
  )
}
