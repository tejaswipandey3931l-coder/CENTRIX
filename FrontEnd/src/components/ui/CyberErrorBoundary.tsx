import { Component, type ErrorInfo, type ReactNode } from "react"
import { ErrorState } from "./ErrorState"

interface Props {
  children: ReactNode
  fallbackTitle?: string
}

interface State {
  hasError: boolean
  error: Error | null
  errorInfo: ErrorInfo | null
}

export class CyberErrorBoundary extends Component<Props, State> {
  public state: State = {
    hasError: false,
    error: null,
    errorInfo: null,
  }

  public static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error, errorInfo: null }
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error("[CENTRIX UI FAULT]", error, errorInfo)
    this.setState({ errorInfo })
  }

  private handleReset = () => {
    this.setState({ hasError: false, error: null, errorInfo: null })
    window.location.reload()
  }

  public render() {
    if (this.state.hasError) {
      const details = `${this.state.error?.message || "Unknown error"}\n\nStack:\n${this.state.error?.stack || ""}\n\nComponent Stack:\n${this.state.errorInfo?.componentStack || ""}`

      return (
        <div className="min-h-screen bg-[#050811] text-ink flex items-center justify-center p-6">
          <div className="max-w-xl w-full">
            <ErrorState
              title={this.props.fallbackTitle || "COMMAND INTERFACE RUNTIME EXCEPTION"}
              message="A client-side runtime exception interrupted the command center view. Diagnostic logs captured."
              details={details}
              onRetry={this.handleReset}
            />
          </div>
        </div>
      )
    }

    return this.props.children
  }
}
