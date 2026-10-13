import React from "react"

export interface CyberTableColumn<T> {
  key: string
  title: React.ReactNode
  render?: (row: T, index: number) => React.ReactNode
  width?: string
  align?: "left" | "center" | "right"
  className?: string
}

interface CyberTableProps<T> {
  columns: CyberTableColumn<T>[]
  data: T[]
  keyExtractor: (item: T, index: number) => string
  onRowClick?: (item: T, index: number) => void
  emptyMessage?: string
  loading?: boolean
  className?: string
}

export function CyberTable<T>({
  columns,
  data,
  keyExtractor,
  onRowClick,
  emptyMessage = "No records found.",
  loading = false,
  className = "",
}: CyberTableProps<T>) {
  return (
    <div className={`w-full overflow-x-auto border border-border rounded-md bg-surface ${className}`}>
      <table className="w-full text-left border-collapse text-xs">
        <thead>
          <tr className="border-b border-border bg-[#090d17]">
            {columns.map((col) => (
              <th
                key={col.key}
                style={{ width: col.width }}
                className={`py-2.5 px-4 font-mono font-semibold uppercase tracking-wider text-[11px] text-ink-3 select-none ${
                  col.align === "right"
                    ? "text-right"
                    : col.align === "center"
                      ? "text-center"
                      : "text-left"
                } ${col.className || ""}`}
              >
                {col.title}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-border/60">
          {loading ? (
            <tr>
              <td colSpan={columns.length} className="p-8 text-center text-ink-3">
                <div className="inline-flex items-center gap-2 font-mono text-xs">
                  <span className="w-2 h-2 rounded-full bg-blue animate-pulse" />
                  Loading telemetry...
                </div>
              </td>
            </tr>
          ) : data.length === 0 ? (
            <tr>
              <td
                colSpan={columns.length}
                className="p-8 text-center text-ink-3 font-mono text-xs"
              >
                {emptyMessage}
              </td>
            </tr>
          ) : (
            data.map((row, index) => {
              const key = keyExtractor(row, index) || `cyber-row-${index}`
              return (
                <tr
                  key={key}
                  onClick={() => onRowClick?.(row, index)}
                  className={`transition-colors duration-100 ${
                    onRowClick
                      ? "cursor-pointer hover:bg-elevated/70 active:bg-elevated"
                      : "hover:bg-panel/60"
                  }`}
                >
                  {columns.map((col) => (
                    <td
                      key={col.key}
                      className={`py-3 px-4 text-ink-2 align-middle ${
                        col.align === "right"
                          ? "text-right"
                          : col.align === "center"
                            ? "text-center"
                            : "text-left"
                      } ${col.className || ""}`}
                    >
                      {col.render ? col.render(row, index) : (row as any)[col.key]}
                    </td>
                  ))}
                </tr>
              )
            })
          )}
        </tbody>
      </table>
    </div>
  )
}

export default CyberTable
