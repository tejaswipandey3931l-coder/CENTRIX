import { useNavigate } from "react-router-dom"
import { ShieldAlert, ArrowLeft, Home } from "lucide-react"
import { CyberButton } from "../components/ui/CyberButton"

export default function NotFound() {
  const navigate = useNavigate()

  return (
    <div className="flex flex-col items-center justify-center min-h-[70vh] p-6 text-center font-mono">
      <div className="w-16 h-16 rounded-full bg-critical/15 border border-critical/40 flex items-center justify-center text-critical mb-4 shadow-[0_0_20px_rgba(239,68,68,0.2)]">
        <ShieldAlert size={32} />
      </div>

      <div className="text-4xl font-bold font-display text-ink tracking-wider mb-2">
        404 // ROUTE OUT OF SCOPE
      </div>

      <p className="text-xs text-ink-3 max-w-md mb-6 font-sans leading-relaxed">
        The requested security command interface or asset path is not recognized within this target environment.
      </p>

      <div className="flex items-center gap-3">
        <CyberButton
          variant="secondary"
          size="sm"
          icon={<ArrowLeft size={14} />}
          onClick={() => navigate(-1)}
        >
          GO BACK
        </CyberButton>

        <CyberButton
          variant="primary"
          size="sm"
          hudCorners
          icon={<Home size={14} />}
          onClick={() => navigate("/overview")}
        >
          RETURN TO OVERVIEW
        </CyberButton>
      </div>
    </div>
  )
}
