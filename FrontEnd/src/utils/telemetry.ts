export function calculateBackoffDelay(
  attempt: number,
  baseMs = 1000,
  maxMs = 10000,
  factor = 1.5,
): number {
  return Math.min(maxMs, Math.floor(baseMs * Math.pow(factor, attempt)))
}

export function boundLogs(
  existingLogs: string[],
  newLog: string,
  maxLogs = 1500,
): string[] {
  const next = [...existingLogs, newLog]
  if (next.length > maxLogs) {
    return next.slice(next.length - maxLogs)
  }
  return next
}
