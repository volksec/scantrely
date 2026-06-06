"""
Adaptive per-thread rate limiter for ASM recon phases.

Usage:
    from rate_limiter import make_limiter, set_limiter, clear_limiter, wait, signal

    # Before running a module thread:
    lim = make_limiter("dns", "stealth")
    set_limiter(lim)
    try:
        ...
    finally:
        clear_limiter()

    # Inside recon functions:
    wait()                  # blocks until rate allows
    signal(status_code)     # feed HTTP status to adapt rate
"""
import threading, time, random

_local = threading.local()


# ─── Thread-local interface ──────────────────────────────────────────────────

def set_limiter(limiter):
    _local.lim = limiter

def get_limiter():
    return getattr(_local, "lim", None)

def clear_limiter():
    _local.lim = None

def wait():
    lim = get_limiter()
    if lim:
        lim.wait()

def signal(status: int):
    lim = get_limiter()
    if lim:
        lim.signal(status)


# ─── AdaptiveRateLimiter ─────────────────────────────────────────────────────

class AdaptiveRateLimiter:
    """
    Rate limiter with adaptive backoff:
    - On 403/429/502/503/504/500/timeout → cut rate by 50%
    - On 400/401/402 → cut rate by 20% (soft detection signal)
    - After ok_streak consecutive clean responses → restore rate by 50%
    """

    def __init__(self, rate: float, jitter: float = 0.0,
                 min_rate: float = 0.02, max_rate: float = None,
                 ok_streak: int = 20):
        """
        rate       : requests/second (0 = unlimited)
        jitter     : max extra random delay in seconds
        min_rate   : floor when backing off
        max_rate   : ceiling when recovering (default 4× base)
        ok_streak  : consecutive OKs needed before rate increases
        """
        self.base_rate  = rate
        self._rate      = rate
        self.jitter     = jitter
        self.min_rate   = min_rate
        self.max_rate   = max_rate if max_rate is not None else rate * 4
        self._ok_streak = ok_streak
        self._streak    = 0
        self._last      = 0.0
        self._lock      = threading.Lock()
        self.blocks     = 0   # total block events (for UI)

    # ── public ───────────────────────────────────────────────────────────────

    def wait(self):
        if self._rate <= 0:
            return
        with self._lock:
            delay = 1.0 / self._rate
            if self.jitter > 0:
                delay += random.uniform(0, self.jitter)
            gap    = time.monotonic() - self._last
            sleep  = max(0.0, delay - gap)
            # snapshot last BEFORE sleeping so concurrent threads don't pile up
            self._last = time.monotonic() + sleep
        if sleep > 0:
            time.sleep(sleep)

    def signal(self, status: int):
        """Feed a response status to adapt the rate."""
        # Hard blocks — cut rate by 50%
        if status in (403, 429, 503, 502, 500, 504) or status == 0:
            with self._lock:
                self._rate   = max(self.min_rate, self._rate * 0.5)
                self._streak = 0
                self.blocks += 1
        # Soft blocks — gentle backoff (auth/client errors that may indicate probing detection)
        elif status in (400, 401, 402):
            with self._lock:
                self._rate   = max(self.min_rate, self._rate * 0.8)
                self._streak = 0
        # Clean responses — recover rate faster (2× per streak instead of 1.15×)
        elif status in (200, 201, 202, 204, 206, 301, 302, 303, 304, 307, 308, 404, 410):
            with self._lock:
                self._streak += 1
                if self._streak >= self._ok_streak and self._rate < self.base_rate:
                    self._rate   = min(self.base_rate, self._rate * 1.5)
                    self._streak = 0

    @property
    def current_rate(self) -> float:
        return self._rate

    @property
    def current_delay(self) -> float:
        return (1.0 / self._rate) if self._rate > 0 else 0.0

    def status_dict(self) -> dict:
        return {
            "mode":          _mode_for(self),
            "base_rate":     round(self.base_rate, 3),
            "current_rate":  round(self._rate, 3),
            "current_delay": round(self.current_delay, 2),
            "jitter":        self.jitter,
            "blocks":        self.blocks,
        }


def _mode_for(lim: AdaptiveRateLimiter) -> str:
    for mode, _ in [("stealth", "stealth"), ("balanced", "balanced"), ("fast", "fast")]:
        for phase, cfg in PHASE_RATES.items():
            if mode in cfg and cfg[mode]:
                rate, jitter, min_r, max_r = cfg[mode]
                if (abs(lim.base_rate - rate) < 0.01 and
                    abs(lim.jitter - jitter) < 0.1 and
                    abs(lim.min_rate - min_r) < 0.01 and
                    abs(lim.max_rate - max_r) < 0.01):
                    return mode
    return "custom"


# ─── Phase rate configs ───────────────────────────────────────────────────────
# Each entry: (rate req/s, jitter sec, min_rate, max_rate)
# None = unlimited

PHASE_RATES: dict[str, dict[str, tuple | None]] = {
    "passive":  {"stealth": None, "balanced": None,              "fast": None},
    "dns":      {"stealth": (1.0,  0.5,  0.1,  5.0),
                 "balanced": (5.0,  0.2,  0.5,  20.0),
                 "fast":    (50.0, 0.0,  2.0,  200.0)},
    "http":     {"stealth": (0.5,  1.0,  0.1,  3.0),
                 "balanced": (3.0,  0.5,  0.5,  10.0),
                 "fast":    (10.0, 0.0,  1.0,  30.0)},
    "tech":     {"stealth": (0.3,  2.0,  0.1,  2.0),
                 "balanced": (2.0,  0.5,  0.2,  5.0),
                 "fast":    (5.0,  0.0,  0.5,  15.0)},
    "crawl":    {"stealth": (0.2,  3.0,  0.05, 1.0),
                 "balanced": (1.0,  1.0,  0.2,  3.0),
                 "fast":    (3.0,  0.0,  0.5,  10.0)},
    "fuzz":     {"stealth": (0.05, 5.0,  0.02, 0.2),
                 "balanced": (1.0,  1.0,  0.1,  5.0),
                 "fast":    (10.0, 0.0,  1.0,  30.0)},
    "portscan": {"stealth": (0.5,  2.0,  0.1,  2.0),
                 "balanced": (10.0, 0.0,  1.0,  50.0),
                 "fast":    (100.0,0.0,  5.0,  500.0)},
    "vulnscan": {"stealth": (0.3,  2.0,  0.05, 1.0),
                 "balanced": (2.0,  0.5,  0.2,  10.0),
                 "fast":    (10.0, 0.0,  1.0,  50.0)},
    "secrets":  {"stealth": None, "balanced": None, "fast": None},
}

MODES = ("stealth", "balanced", "fast")
DEFAULT_MODE = "stealth"


def make_limiter(phase: str, mode: str = DEFAULT_MODE):
    """Return an AdaptiveRateLimiter for the given phase/mode, or None if unlimited."""
    cfg = PHASE_RATES.get(phase, {})
    params = cfg.get(mode) or cfg.get("balanced")
    if params is None:
        return None
    rate, jitter, min_rate, max_rate = params
    return AdaptiveRateLimiter(rate=rate, jitter=jitter, min_rate=min_rate, max_rate=max_rate)
