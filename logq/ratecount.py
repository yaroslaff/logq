from collections import deque
from datetime import timedelta, datetime
from typing import Any
import copy


class RateCount:
    def __init__(self, window_seconds: int):
        self.window = timedelta(seconds=window_seconds)
        self.events = deque()
        self.dataq = deque()
        self.top_dataq = None
        self.max_count = 0
        self.max_range = (None, None)  # (start, end)

    def add(self, dt: datetime, data: Any = None):
        self.events.append(dt)
        self.dataq.append(data)

        cutoff = dt - self.window
        while self.events and self.events[0] <= cutoff:
            self.events.popleft()
            self.dataq.popleft()

        if len(self.events) > self.max_count:
            self.max_count = len(self.events)
            self.max_range = (self.events[0], self.events[-1])
            self.top_dataq = copy.copy(self.dataq)
            # print("New max rate:", self.max_count , len(self.dataq), len(self.top_dataq), len(self.events), "from", self.max_range[0], "to", self.max_range[1])

    def get_max(self) -> int:        
        return self.max_count

    def get_max_time(self) -> datetime:
        return self.max_range[0]
