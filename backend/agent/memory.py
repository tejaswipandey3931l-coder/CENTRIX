"""Context and transcript memory management for agent sessions."""
from __future__ import annotations

from typing import List, Dict, Any
from .models import AgentMessage, AgentMessageRole
from .redaction import redact_string


class SessionMemory:
    def __init__(self, max_messages: int = 40):
        self.max_messages = max_messages
        self._messages: List[AgentMessage] = []
        self._summary: str = ""

    def add_message(self, message: AgentMessage) -> None:
        if message.content:
            message.content = redact_string(message.content)
        self._messages.append(message)
        self._compact_if_needed()

    def add_messages(self, messages: List[AgentMessage]) -> None:
        for m in messages:
            self.add_message(m)

    def get_messages(self) -> List[AgentMessage]:
        result = []
        if self._summary:
            result.append(
                AgentMessage(
                    role=AgentMessageRole.SYSTEM,
                    content=f"Context Summary of previous steps:\n{self._summary}"
                )
            )
        result.extend(self._messages)
        return result

    def _compact_if_needed(self) -> None:
        if len(self._messages) > self.max_messages:
            # Preserve the initial system message if present
            system_msg = None
            if self._messages and self._messages[0].role == AgentMessageRole.SYSTEM:
                system_msg = self._messages[0]
                slice_start = 1
            else:
                slice_start = 0

            # Summarize the oldest non-system messages
            trim_count = len(self._messages) - self.max_messages + 5
            old_chunk = self._messages[slice_start : slice_start + trim_count]
            self._messages = (
                ([system_msg] if system_msg else []) + self._messages[slice_start + trim_count :]
            )

            # Append brief summary of trimmed actions
            trimmed_notes = []
            for msg in old_chunk:
                if msg.role == AgentMessageRole.ASSISTANT and msg.tool_calls:
                    names = [tc.function.get("name", "unknown") for tc in msg.tool_calls]
                    trimmed_notes.append(f"Action: {', '.join(names)}")
                elif msg.role == AgentMessageRole.TOOL:
                    snippet = (msg.content or "")[:80]
                    trimmed_notes.append(f"Result: {snippet}...")
            
            if trimmed_notes:
                summary_addition = "\n".join(trimmed_notes[:10])
                if self._summary:
                    self._summary += f"\n{summary_addition}"
                else:
                    self._summary = summary_addition
