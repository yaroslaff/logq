from collections import deque
from datetime import timedelta, datetime

class RateCount:
    def __init__(self, window_seconds: int):
        self.window = timedelta(seconds=window_seconds)
        self.events = deque()
        self.max_count = 0
        self.max_range = (None, None)  # (start, end)

    def add(self, dt):
        """Добавляем событие (datetime в возрастающем порядке)."""
        self.events.append(dt)
        cutoff = dt - self.window
        while self.events and self.events[0] <= cutoff:
            self.events.popleft()

        if len(self.events) > self.max_count:
            self.max_count = len(self.events)
            self.max_range = (self.events[0], self.events[-1])

    def get_max(self) -> int:        
        return self.max_count

    def get_max_time(self) -> datetime:        
        return self.max_range[0]
