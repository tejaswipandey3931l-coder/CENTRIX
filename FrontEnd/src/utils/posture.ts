export interface PostureResult {
  score: string
  progress: number
  sublabel: string
  accent: "emerald" | "medium" | "critical" | "default"
  trend: {
    text: string
    status: "good" | "neutral" | "bad"
  }
}

export function calculatePosture(
  backendOnline: boolean | null,
  scansCount: number,
  findings: Array<{ severity?: string }>,
): PostureResult {
  if (backendOnline === false) {
    return {
      score: "OFFLINE",
      progress: 0,
      sublabel: "Backend unreachable",
      accent: "critical",
      trend: { text: "OFFLINE", status: "bad" },
    }
  }

  if (scansCount === 0) {
    return {
      score: "UNAUDITED",
      progress: 0,
      sublabel: "No scan data available",
      accent: "default",
      trend: { text: "NO DATA", status: "neutral" },
    }
  }

  let deductions = 0
  findings.forEach((f) => {
    const sev = f.severity?.toLowerCase()
    if (sev === "critical") deductions += 20
    else if (sev === "high") deductions += 10
    else if (sev === "medium") deductions += 4
    else if (sev === "low") deductions += 1
  })

  const scoreNum = Math.max(0, Math.min(100, 100 - deductions))
  const isHardened = scoreNum >= 85
  const isModerate = scoreNum >= 60

  return {
    score: `${scoreNum}/100`,
    progress: scoreNum,
    sublabel: isHardened
      ? "Hardened perimeter"
      : isModerate
        ? "Moderate exposure risk"
        : "Critical exposure threshold",
    accent: isHardened ? "emerald" : isModerate ? "medium" : "critical",
    trend: {
      text: isHardened ? "STABLE" : isModerate ? "MODERATE" : "CRITICAL",
      status: isHardened ? "good" : "bad",
    },
  }
}
