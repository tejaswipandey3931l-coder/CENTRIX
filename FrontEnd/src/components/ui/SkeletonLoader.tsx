export interface SkeletonLoaderProps {
  className?: string
  lines?: number
  variant?: "card" | "row" | "text" | "circle"
}

export function SkeletonLoader({
  className = "",
  lines = 1,
  variant = "text",
}: SkeletonLoaderProps) {
  if (variant === "circle") {
    return (
      <div
        className={`rounded-full bg-elevated/80 animate-pulse border border-border/40 ${className}`}
      />
    )
  }

  if (variant === "card") {
    return (
      <div
        className={`bg-panel border border-border/60 rounded-md p-4 space-y-3 animate-pulse ${className}`}
      >
        <div className="h-4 w-1/3 bg-elevated rounded" />
        <div className="h-8 w-1/2 bg-elevated rounded" />
        <div className="h-3 w-full bg-elevated/70 rounded" />
      </div>
    )
  }

  if (variant === "row") {
    return (
      <div className={`space-y-2.5 w-full ${className}`}>
        {Array.from({ length: lines }).map((_, idx) => (
          <div
            key={idx}
            className="h-10 bg-panel/70 border border-border/40 rounded flex items-center px-4 gap-4 animate-pulse"
          >
            <div className="h-3 w-16 bg-elevated rounded" />
            <div className="h-3 w-1/3 bg-elevated rounded" />
            <div className="h-3 w-1/4 bg-elevated rounded ml-auto" />
            <div className="h-3 w-12 bg-elevated rounded" />
          </div>
        ))}
      </div>
    )
  }

  return (
    <div className={`space-y-2 ${className}`}>
      {Array.from({ length: lines }).map((_, idx) => (
        <div
          key={idx}
          style={{ width: idx === lines - 1 && lines > 1 ? "70%" : "100%" }}
          className="h-3.5 bg-elevated/80 rounded animate-pulse"
        />
      ))}
    </div>
  )
}

export default SkeletonLoader
