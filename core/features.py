"""Behavioral feature engineering: entropy, lineage rarity, sliding windows.

The module turns :class:`~core.parser.LogEvent` objects into the tabular
feature vector consumed by :class:`~models.anomaly_engine.AnomalyEngine`:

* :func:`shannon_entropy` / :func:`special_char_density` — command-line
  obfuscation metrics (Base64/XOR/hex payloads read as high-entropy text),
* :func:`extract_features` — template IDF rarity + parent-child process pair
  rarity (from the Drain miner) plus raw command-line metrics,
* :class:`WindowStats` — per-(host, user) sliding windows producing rolling
  velocity (event counts per 60/900/3600 s), inter-event deltas, unique
  destination-IP fan-out per hour and the off-hours indicator.
"""

from __future__ import annotations

import math
import time
from collections import defaultdict, deque
from typing import Dict, List, Optional, Sequence, Tuple

import numpy as np
import pandas as pd

from core.parser import Drain, LogEvent

OFF_HOURS_DEFAULT: Tuple[int, ...] = (22, 23, 0, 1, 2, 3, 4, 5, 6)
WINDOW_SECONDS_DEFAULT: Tuple[int, ...] = (60, 900, 3600)
FANOUT_WINDOW_SECONDS: int = 3600
MAX_WINDOW_ENTRIES: int = 2000

FEATURE_COLUMNS: List[str] = [
    "template_rarity",
    "pair_rarity",
    "cmd_length",
    "cmd_entropy",
    "cmd_special_density",
    "off_hours",
    "rolling_events_60s",
    "rolling_events_900s",
    "rolling_events_3600s",
    "delta_since_last",
    "delta_to_recent_mean",
    "host_fan_out_1h",
]


def shannon_entropy(text: str, base: float = 2.0) -> float:
    """Shannon entropy of a string over its character distribution."""
    if not text:
        return 0.0
    counts: Dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(text)
    entropy = 0.0
    for count in counts.values():
        p = count / n
        entropy -= p * math.log(p, base)
    return entropy


def special_char_density(text: str) -> float:
    """Fraction of characters that are not alphanumeric."""
    if not text:
        return 0.0
    return sum(1 for ch in text if not ch.isalnum()) / len(text)


def cmdline_metrics(command_line: Optional[str]) -> Dict[str, float]:
    """Raw command-line metrics: length, Shannon entropy, special-char density."""
    cmd = command_line or ""
    return {
        "cmd_length": float(len(cmd)),
        "cmd_entropy": shannon_entropy(cmd),
        "cmd_special_density": special_char_density(cmd),
    }


class WindowStats:
    """Sliding per-(host, user) windows feeding the behavioral features."""

    def __init__(
        self,
        windows: Sequence[int] = WINDOW_SECONDS_DEFAULT,
        fanout_window: int = FANOUT_WINDOW_SECONDS,
        max_entries: int = MAX_WINDOW_ENTRIES,
    ):
        ordered = sorted({int(w) for w in windows if w and w > 0})
        self.windows: Tuple[int, ...] = tuple(ordered) or WINDOW_SECONDS_DEFAULT
        self.fanout_window = int(fanout_window)
        self.max_entries = int(max_entries)
        self._timestamps: Dict[str, deque] = defaultdict(lambda: deque(maxlen=self.max_entries))
        self._deltas: Dict[str, deque] = defaultdict(lambda: deque(maxlen=10))
        self._fanout: Dict[str, deque] = defaultdict(lambda: deque(maxlen=self.max_entries))

    def observe(self, event: LogEvent) -> Dict[str, float]:
        """Update windows with ``event`` and return the current window features."""
        key = event.entity
        now = float(event.epoch or 0.0)
        ts_q = self._timestamps[key]
        delta = 0.0
        if ts_q:
            delta = max(now - float(ts_q[-1]), 0.0)
            self._deltas[key].append(delta)
        ts_q.append(now)
        if event.dst_ip:
            self._fanout[key].append((now, event.dst_ip))

        features: Dict[str, float] = {}
        for window in self.windows:
            cutoff = now - window
            features[f"rolling_events_{window}s"] = float(sum(1 for t in ts_q if t >= cutoff))
        recent = list(self._deltas[key])
        features["delta_since_last"] = float(delta)
        features["delta_to_recent_mean"] = float(np.mean(recent[-5:])) if recent else 0.0
        fanout_cutoff = now - self.fanout_window
        fanout = {ip for (ts, ip) in self._fanout[key] if ts >= fanout_cutoff}
        features["host_fan_out_1h"] = float(len(fanout))
        return features


def extract_features(
    events: Sequence[LogEvent],
    drain: Drain,
    window: Optional[WindowStats] = None,
) -> pd.DataFrame:
    """Engineer the per-event behavioral feature vector (see :data:`FEATURE_COLUMNS`)."""
    window = window if window is not None else WindowStats()
    rows: List[Dict[str, float]] = []
    for ev in events:
        row: Dict[str, float] = {
            "template_rarity": float(drain.rarity(ev.template_id)),
            "pair_rarity": float(drain.pair_rarity(ev.parent_process, ev.process_name)),
        }
        row.update(cmdline_metrics(ev.command_line))
        hour = time.gmtime(ev.epoch).tm_hour if ev.epoch else None
        row["off_hours"] = float(1 if hour is not None and hour in OFF_HOURS_DEFAULT else 0)
        row.update(window.observe(ev))
        rows.append(row)
    return pd.DataFrame(rows, columns=FEATURE_COLUMNS)
