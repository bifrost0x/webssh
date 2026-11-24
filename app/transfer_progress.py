"""Rate limit for per-transfer progress events."""

import time


# Progress is informational; terminal state travels in its own events. A few
# updates per second keep the UI current without one Socket.IO message per
# chunk.
PROGRESS_INTERVAL_SECONDS = 0.25


class ProgressThrottle:
    """Decide which progress updates of one transfer are sent.

    The first update is always sent. Callers send one more update after the
    last chunk when ``flush()`` reports that a skipped update is outstanding,
    so the final byte count always reaches the client.
    """

    def __init__(self, interval=PROGRESS_INTERVAL_SECONDS, clock=time.monotonic):
        self._interval = interval
        self._clock = clock
        self._last_sent = None
        self._pending = False

    def ready(self):
        now = self._clock()
        if self._last_sent is None or now - self._last_sent >= self._interval:
            self._last_sent = now
            self._pending = False
            return True
        self._pending = True
        return False

    def flush(self):
        pending = self._pending
        self._pending = False
        return pending
