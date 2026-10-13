class AgentError(Exception):
    """Base exception for agent errors."""
    pass

class AgentProviderError(AgentError):
    """Raised when the AI provider (e.g. xKiro) returns an error."""
    pass

class ApprovalRequiredError(AgentError):
    """Raised when an action requires human approval before proceeding."""
    pass

class PolicyViolationError(AgentError):
    """Raised when an agent attempts an action that violates security policies."""
    pass

class ToolExecutionError(AgentError):
    """Raised when a tool fails to execute."""
    pass
