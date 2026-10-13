import re
from typing import Any, Dict, List

def redact_string(text: str) -> str:
    if not isinstance(text, str):
        return text
    
    # Simple example redactor, could be expanded to regex matching
    # for API keys, tokens, auth headers etc.
    # In a real app we'd want this to be robust.
    # For now, just replacing known secrets from env
    from .config import cfg
    if cfg.xkiro_api_key and cfg.xkiro_api_key in text and cfg.xkiro_api_key != "your_xkiro_api_key_here":
        text = text.replace(cfg.xkiro_api_key, "[REDACTED_API_KEY]")
    return text

def redact_payload(payload: Any) -> Any:
    if isinstance(payload, dict):
        return {k: redact_payload(v) for k, v in payload.items()}
    elif isinstance(payload, list):
        return [redact_payload(item) for item in payload]
    elif isinstance(payload, str):
        return redact_string(payload)
    return payload
