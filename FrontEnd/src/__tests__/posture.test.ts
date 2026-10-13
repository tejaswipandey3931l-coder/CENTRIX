import { describe, it, expect } from "vitest"
import { calculatePosture } from "../utils/posture"

describe("calculatePosture - Truthful Security Posture Engine", () => {
  it("reports OFFLINE when backend is unreachable", () => {
    const result = calculatePosture(false, 5, [{ severity: "Low" }])
    expect(result.score).toBe("OFFLINE")
    expect(result.progress).toBe(0)
    expect(result.sublabel).toBe("Backend unreachable")
    expect(result.accent).toBe("critical")
    expect(result.trend.status).toBe("bad")
  })

  it("reports UNAUDITED when zero scans have been executed", () => {
    const result = calculatePosture(true, 0, [])
    expect(result.score).toBe("UNAUDITED")
    expect(result.progress).toBe(0)
    expect(result.sublabel).toBe("No scan data available")
    expect(result.accent).toBe("default")
    expect(result.trend.text).toBe("NO DATA")
    expect(result.trend.status).toBe("neutral")
  })

  it("reports 100/100 Hardened perimeter when scans exist with 0 findings", () => {
    const result = calculatePosture(true, 2, [])
    expect(result.score).toBe("100/100")
    expect(result.progress).toBe(100)
    expect(result.sublabel).toBe("Hardened perimeter")
    expect(result.accent).toBe("emerald")
    expect(result.trend.text).toBe("STABLE")
    expect(result.trend.status).toBe("good")
  })

  it("accurately calculates deductions for Critical (20), High (10), Medium (4), Low (1)", () => {
    const findings = [
      { severity: "Critical" }, // -20
      { severity: "High" },     // -10
      { severity: "Medium" },   // -4
      { severity: "Low" },      // -1
    ]
    // Total deductions = 35 -> Score = 65
    const result = calculatePosture(true, 1, findings)
    expect(result.score).toBe("65/100")
    expect(result.progress).toBe(65)
    expect(result.sublabel).toBe("Moderate exposure risk")
    expect(result.accent).toBe("medium")
    expect(result.trend.text).toBe("MODERATE")
    expect(result.trend.status).toBe("bad")
  })

  it("correctly triggers Critical exposure threshold when score drops below 60", () => {
    const findings = [
      { severity: "Critical" }, // -20
      { severity: "Critical" }, // -20
      { severity: "High" },     // -10
    ]
    // Total deductions = 50 -> Score = 50 (< 60)
    const result = calculatePosture(true, 1, findings)
    expect(result.score).toBe("50/100")
    expect(result.sublabel).toBe("Critical exposure threshold")
    expect(result.accent).toBe("critical")
    expect(result.trend.text).toBe("CRITICAL")
  })

  it("clamps lowest score to 0/100 under massive vulnerability floods", () => {
    const findings = Array(10).fill({ severity: "Critical" }) // -200
    const result = calculatePosture(true, 1, findings)
    expect(result.score).toBe("0/100")
    expect(result.progress).toBe(0)
  })
})
