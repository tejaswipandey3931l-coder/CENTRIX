import { useState } from "react"
import { Wand2, Copy, Check, ArrowRightLeft } from "lucide-react"
import { manualApi } from "../api/client"
import { CyberCard } from "../components/ui/CyberCard"
import { CyberButton } from "../components/ui/CyberButton"

const MODES = [
  ["url-decode", "URL Decode"],
  ["url-encode", "URL Encode"],
  ["base64-decode", "Base64 Decode"],
  ["base64-encode", "Base64 Encode"],
  ["json-pretty", "Beautify JSON"],
  ["hash-sha256", "SHA-256 Digest"],
]

export default function Decoder() {
  const [mode, setMode] = useState("url-decode")
  const [input, setInput] = useState("")
  const [output, setOutput] = useState("")
  const [copied, setCopied] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState("")

  const run = async () => {
    setError("")
    setBusy(true)
    try {
      const result = await manualApi.decode(mode, input)
      setOutput(result.output)
    } catch (reason: unknown) {
      setError(reason instanceof Error ? reason.message : "Transformation failed. Ensure input is formatted correctly.")
    } finally {
      setBusy(false)
    }
  }

  const copyOutput = async () => {
    try {
      await navigator.clipboard.writeText(output)
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    } catch {
      // ignore
    }
  }

  const swap = () => {
    setInput(output)
    setOutput("")
  }

  return (
    <div className="p-4 sm:p-6 lg:p-8 max-w-[1700px] mx-auto space-y-6">
      {/* Header */}
      <div className="flex flex-wrap items-start justify-between gap-4 border-b border-border pb-5">
        <div>
          <h1 className="text-xl font-bold tracking-wider text-ink uppercase font-display flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-blue" />
            Payload Decoder & Transformer Studio
          </h1>
          <p className="text-xs text-ink-3 font-mono mt-1">
            Encode, decode, hash, and format payloads and obfuscated attack strings during testing.
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <select
            value={mode}
            onChange={(e) => setMode(e.target.value)}
            className="bg-panel border border-border focus:border-cyan/50 rounded px-3 py-1.5 text-xs font-mono text-ink cursor-pointer"
          >
            {MODES.map(([id, label]) => (
              <option key={id} value={id}>
                {label}
              </option>
            ))}
          </select>

          <CyberButton
            variant="primary"
            size="sm"
            hudCorners
            loading={busy}
            icon={<Wand2 size={13} />}
            onClick={() => void run()}
          >
            TRANSFORM BUFFER
          </CyberButton>
        </div>
      </div>

      {error && (
        <div className="p-3.5 rounded border border-critical/40 bg-critical/10 text-critical text-xs font-mono">
          {error}
        </div>
      )}

      {/* Side-by-Side Panels */}
      <div className="grid lg:grid-cols-2 gap-6 font-mono text-xs">
        {/* Input Panel */}
        <CyberCard
          title="Input Payload Buffer"
          subtitle="Raw input bytes or string"
          action={
            input && (
              <CyberButton size="xs" variant="ghost" onClick={() => setInput("")}>
                Clear
              </CyberButton>
            )
          }
        >
          <textarea
            value={input}
            onChange={(e) => setInput(e.target.value)}
            rows={18}
            spellCheck={false}
            placeholder="Paste raw string, encoded token, or minified JSON here..."
            className="w-full bg-[#03060c] border border-border rounded p-3 text-xs font-mono text-ink selection:bg-cyan/30 focus:border-cyan/40"
          />
        </CyberCard>

        {/* Output Panel */}
        <CyberCard
          title="Transformed Output"
          subtitle="Processed buffer output"
          action={
            output && (
              <div className="flex items-center gap-2">
                <CyberButton
                  size="xs"
                  variant="secondary"
                  icon={<ArrowRightLeft size={11} />}
                  onClick={swap}
                >
                  Send to Input
                </CyberButton>

                <CyberButton
                  size="xs"
                  variant="outline"
                  icon={copied ? <Check size={11} className="text-emerald" /> : <Copy size={11} />}
                  onClick={() => void copyOutput()}
                >
                  {copied ? "Copied" : "Copy"}
                </CyberButton>
              </div>
            )
          }
        >
          <textarea
            value={output}
            readOnly
            rows={18}
            spellCheck={false}
            placeholder="Transformed output will appear here after clicking Transform..."
            className="w-full bg-[#03060c] border border-border rounded p-3 text-xs font-mono text-cyan selection:bg-cyan/30"
          />
        </CyberCard>
      </div>
    </div>
  )
}
