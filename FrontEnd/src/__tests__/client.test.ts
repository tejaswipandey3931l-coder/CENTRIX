import { describe, it, expect } from "vitest"
import { ApiError } from "../api/client"

describe("ApiError class", () => {
  it("formats HTTP errors with status, data, and message", () => {
    const err = new ApiError("Endpoint not found", {
      status: 404,
      statusText: "Not Found",
      data: { detail: "Record missing" },
    })
    expect(err.message).toBe("Endpoint not found")
    expect(err.status).toBe(404)
    expect(err.statusText).toBe("Not Found")
    expect(err.data).toEqual({ detail: "Record missing" })
    expect(err.name).toBe("ApiError")
    expect(err.isOffline).toBe(false)
  })

  it("identifies network offline errors", () => {
    const err = new ApiError("CENTRIX backend offline", { isOffline: true })
    expect(err.isOffline).toBe(true)
  })
})
