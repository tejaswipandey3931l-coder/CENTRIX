import asyncio
from typing import Callable, Dict, Any, List

class EventBus:
    def __init__(self):
        self._subscribers: Dict[str, List[Callable]] = {}

    def subscribe(self, event_type: str, callback: Callable):
        if event_type not in self._subscribers:
            self._subscribers[event_type] = []
        self._subscribers[event_type].append(callback)

    def unsubscribe(self, event_type: str, callback: Callable):
        subscribers = self._subscribers.get(event_type, [])
        if callback in subscribers:
            subscribers.remove(callback)

    async def publish(self, event_type: str, payload: Any):
        if event_type in self._subscribers:
            for callback in self._subscribers[event_type]:
                if asyncio.iscoroutinefunction(callback):
                    await callback(payload)
                else:
                    callback(payload)

agent_events = EventBus()
