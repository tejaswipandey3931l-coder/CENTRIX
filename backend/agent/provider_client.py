import asyncio
import httpx
from typing import List, Dict, Any

from .config import cfg
from .models import AgentMessage
from .errors import AgentProviderError
from .redaction import redact_payload

class XKiroClient:
    def __init__(self):
        self.base_url = cfg.ai_base_url
        self.api_key = cfg.xkiro_api_key
        self.headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }

    async def chat_completions(self, messages: List[AgentMessage], model: str, tools: List[Dict[str, Any]] | None = None) -> Dict[str, Any]:
        if not self.api_key or self.api_key == "your_key_here":
            raise AgentProviderError("XKIRO_API_KEY is not configured.")
        url = f"{self.base_url}/chat/completions"
        
        payload = {
            "model": model,
            "messages": [m.model_dump(exclude_none=True) for m in messages],
        }
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"
            
        # Redact before logging/sending if needed, but since this is going to the provider, 
        # we only redact logs, not the actual payload unless required by policy.
        # Actually, if we send internal secrets to the LLM, we should redact them.
        timeout = max(10, int(cfg.ai_request_timeout))
        last_error: Exception | None = None
        async with httpx.AsyncClient(timeout=timeout) as client:
            for attempt in range(3):
                try:
                    response = await client.post(url, headers=self.headers, json=payload)
                    response.raise_for_status()
                    data = response.json()
                    if not isinstance(data, dict):
                        raise AgentProviderError("xKiro returned a non-object response.")
                    return data
                except httpx.HTTPStatusError as exc:
                    last_error = exc
                    if exc.response.status_code < 500 and exc.response.status_code != 429:
                        detail = redact_payload(exc.response.text[:500])
                        raise AgentProviderError(f"xKiro API error ({exc.response.status_code}): {detail}") from exc
                except (httpx.RequestError, ValueError) as exc:
                    last_error = exc
                if attempt < 2:
                    await asyncio.sleep(0.5 * (2 ** attempt))
        raise AgentProviderError(f"xKiro request failed after retries: {last_error}") from last_error

provider_client = XKiroClient()
