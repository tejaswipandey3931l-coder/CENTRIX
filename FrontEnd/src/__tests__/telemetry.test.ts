import { describe, it, expect } from "vitest"
import { calculateBackoffDelay, boundLogs } from "../utils/telemetry"

describe("calculateBackoffDelay", () => {
  it("computes exponential backoff sequence starting at 1000ms", () => {
    expect(calculateBackoffDelay(0)).toBe(1000)
    expect(calculateBackoffDelay(1)).toBe(1500)
    expect(calculateBackoffDelay(2)).toBe(2250)
    expect(calculateBackoffDelay(3)).toBe(3375)
    expect(calculateBackoffDelay(4)).toBe(5062)
    expect(calculateBackoffDelay(5)).toBe(7593)
  })

  it("caps maximum delay at 10000ms", () => {
    expect(calculateBackoffDelay(6)).toBe(10000)
    expect(calculateBackoffDelay(10)).toBe(10000)
    expect(calculateBackoffDelay(100)).toBe(10000)
  })
})

describe("boundLogs", () => {
  it("appends messages when under limit", () => {
    const logs = ["msg 1", "msg 2"]
    const next = boundLogs(logs, "msg 3", 5)
    expect(next).toEqual(["msg 1", "msg 2", "msg 3"])
  })

  it("truncates oldest logs when exceeding max limit", () => {
    const logs = ["old 1", "old 2", "keep 1", "keep 2"]
    const next = boundLogs(logs, "new 1", 3)
    expect(next).toEqual(["keep 1", "keep 2", "new 1"])
    expect(next.length).toBe(3)
  })
})
