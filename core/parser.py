"""Multi-format log ingestion, normalization and Drain-style template mining.

This module implements the two halves of the "log parsing" stage of the SOC
anomaly detector:

1. **Normalization.** Heterogeneous telemetry sources (Linux ``auth.log`` /
   ``auditd``, Windows Sysmon JSON events and the Elastic Common Schema) are
   ingested and normalized into the unified :class:`LogEvent` schema::

       timestamp, host, user, process_name, parent_process, command_line,
       src_ip, dst_ip, raw_message

2. **Template mining.** :class:`Drain` is a fast, deterministic,
   Drain-inspired log template extractor. Variable parameters (IPs, ports,
   PIDs, hashes, UUIDs, paths, emails, times) are masked into canonical
   placeholders, raw messages are clustered into structural templates, and
   every template carries an inverse-document-frequency (IDF) rarity score
   plus a process parent-child pair rarity score.
"""

from __future__ import annotations

import json
import logging
import math
import re
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Variable masking (Drain-style parameter anonymization)
# ---------------------------------------------------------------------------

_MASK_RULES: List[Tuple["re.Pattern[str]", str]] = [
    # Network addresses
    (re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"), "<IP>"),
    (re.compile(r"(?<![0-9:A-Fa-f])(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b"), "<MAC>"),
    # Blobs: SHA-256, SHA-1, MD5-length hex, UUID
    (re.compile(r"\b[0-9a-fA-F]{64}\b"), "<HASH>"),
    (re.compile(r"\b[0-9a-fA-F]{40}\b"), "<HASH>"),
    (re.compile(r"\b[0-9a-fA-F]{32}\b"), "<HEX>"),
    (re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b"), "<UUID>"),
    # Filesystem paths (unix + windows) and emails
    # (unix paths match when "/" starts a token or path segment, including the
    # first token of the line)
    (re.compile(r"(?<![A-Za-z0-9_])/[A-Za-z0-9_.+\-/]+[A-Za-z0-9_.+\-/]?"), "<PATH>"),
    (re.compile(r"\b[A-Za-z]:[\\/][^\s:,;()\[\]{}'\"]+"), "<PATH>"),
    (re.compile(r"[A-Za-z0-9_.%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)+"), "<EMAIL>"),
    # Times (3-part first so "10:00:00" is consumed whole)
    (re.compile(r"(?<![\d:])(?:[0-9]{1,3}:){2}[0-9]{2}(?![\d:])"), "<TIME>"),
    (re.compile(r"(?<![\d:])(?:[0-9]{1,3}:){1}[0-9]{2}(?![0-9:])"), "<TIME>"),
    # Ports
    (re.compile(r"(?i)\bport[=:]?\s*\d{2,5}\b"), "<PORT>"),
    (re.compile(r"(?<=:)\d{3,5}(?![\d:])"), "<PORT>"),
    # Process IDs / TIDs
    (re.compile(r"(?i)\bpid[=:\[(\s]*\d+[\]\)\s]*"), "<PID>"),
    (re.compile(r"(?i)\btid[=:\[(\s]*\d+[\]\)\s]*"), "<PID>"),
    # Remaining hex blobs
    (re.compile(r"\b[0-9a-fA-F]{6,}\b"), "<HEX>"),
    # Volatile integers (Drain classic style: numbers become <NUM>)
    (re.compile(r"\b\d+\b"), "<NUM>"),
]


def mask_variables(text: str) -> str:
    """Mask variable parameters in ``text`` into canonical placeholders.

    Rules are applied in order: IPv4 -> MAC -> SHA-256/SHA-1/MD5/UUID ->
    paths/emails -> times -> ports -> PIDs -> remaining hex blobs -> all
    remaining integers as ``<NUM>``.
    """
    if not text:
        return text
    masked = text
    for pattern, replacement in _MASK_RULES:
        masked = pattern.sub(replacement, masked)
    return masked


_PLACEHOLDER_RE = re.compile(r"^<[^>]+>$")
_TOKEN_RE = re.compile(r"<[^<>\s]+>|[A-Za-z0-9]+")


def is_placeholder(token: str) -> bool:
    return bool(_PLACEHOLDER_RE.match(token))


def tokenize(masked: str) -> List[str]:
    """Split a masked line into Drain-style tokens (placeholders are single tokens)."""
    return [t for t in _TOKEN_RE.findall(masked or "")]


# ---------------------------------------------------------------------------
# Unified event schema
# ---------------------------------------------------------------------------

# Canonical JSON key names. ``host``/``user`` are legacy spellings still
# accepted on input (see ``_legacy_aliases`` below) so old corpora keep parsing.
_DICT_FIELDS: Tuple[str, ...] = (
    "timestamp",
    "entity_host",
    "entity_user",
    "process_name",
    "parent_process",
    "command_line",
    "src_ip",
    "dst_ip",
    "raw_message",
    "template_id",
    "source_format",
    "epoch",
)


@dataclass
class LogEvent:
    """Unified SOC telemetry event (the normalized internal event schema)."""

    timestamp: str = ""
    entity_host: str = ""
    entity_user: str = ""
    process_name: str = ""
    parent_process: str = ""
    command_line: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    raw_message: str = ""
    template_id: str = ""
    source_format: str = "generic"
    epoch: float = 0.0

    @property
    def entity(self) -> str:
        """Sliding-window key: host + user (or just the host when no user)."""
        return f"{self.entity_host}/{self.entity_user}" if self.entity_user else (
            self.entity_host or "unknown"
        )

    @property
    def host(self) -> str:
        """Legacy alias kept for compatibility with older consumers."""
        return self.entity_host

    @property
    def user(self) -> str:
        """Legacy alias kept for compatibility with older consumers."""
        return self.entity_user

    @classmethod
    def from_dict(cls, obj: Dict[str, Any]) -> "LogEvent":
        # Accept the legacy ``host``/``user`` spellings from older corpora.
        src = {("entity_host" if k == "host" else "entity_user" if k == "user" else k): v
               for k, v in obj.items()
               if k in _DICT_FIELDS or k in ("host", "user")}
        kwargs = {k: src[k] for k in _DICT_FIELDS if k in src and src[k] not in (None, "")}
        ev = cls(**kwargs)
        if not ev.epoch:
            ev.epoch = parse_timestamp(ev.timestamp) or 0.0
        return ev

    def to_dict(self) -> Dict[str, Any]:
        return {k: getattr(self, k) for k in _DICT_FIELDS}


# ---------------------------------------------------------------------------
# Drain-style template clustering
# ---------------------------------------------------------------------------


class _Cluster:
    __slots__ = ("signature", "template_id", "count")

    def __init__(self, signature: Sequence[str], template_id: str):
        self.signature = list(signature)
        self.template_id = template_id
        self.count = 1

    def similarity(self, tokens: Sequence[str]) -> float:
        """Fraction of aligned positions where the cluster and the line agree."""
        n = max(len(self.signature), len(tokens))
        if n == 0:
            return 0.0
        matches = sum(1 for a, b in zip(self.signature, tokens) if a == b)
        return matches / n


class Drain:
    """Fast Drain-style template miner over masked log tokens.

    Classic Drain keeps an ID-Ftree (prefix tree) of structural signatures
    and, for each line, walks to the bucket keyed by the first ``depth``
    tokens, then merges the line into the most similar cluster when the
    similarity ratio meets ``sim_threshold``; otherwise it spawns a new
    cluster.  This implementation uses a flat dict keyed by the padded first
    ``depth`` tokens — equivalent for selection and simpler, deterministic
    for a given corpus.

    The class additionally records:

    * ``template_frequency`` — number of log lines per template id,
    * ``n_docs`` — total lines mined,
    * ``pair_counts`` / ``n_pairs`` — process parent-child pair frequencies,
    * ``rarity(template_id)`` — ``log((n_docs + 1) / (freq + 1))`` (higher ==
      rarer; unseen templates are maximally rare).
    """

    def __init__(self, depth: int = 3, sim_threshold: float = 0.6):
        self.depth = max(1, int(depth))
        self.sim_threshold = float(sim_threshold)
        self.clusters: Dict[Tuple[str, ...], List[_Cluster]] = {}
        self._by_id: Dict[str, _Cluster] = {}
        self.template_frequency: Counter = Counter()
        self.n_docs: int = 0
        self.pair_counts: Counter = Counter()
        self.n_pairs: int = 0
        self._next_template_id: int = 0

    # ------------------------------------------------------------------ tree
    def _key(self, tokens: Sequence[str]) -> Tuple[str, ...]:
        padded = list(tokens[: self.depth])
        while len(padded) < self.depth:
            padded.append("")
        return tuple(padded)

    def _new_cluster(self, signature: List[str]) -> _Cluster:
        self._next_template_id += 1
        cluster = _Cluster(signature, f"T{self._next_template_id:04d}")
        self.clusters.setdefault(self._key(signature), []).append(cluster)
        self._by_id[cluster.template_id] = cluster
        return cluster

    # ------------------------------------------------------------------- add
    def add(self, tokens: Sequence[str]) -> str:
        """Add a masked token line; return the canonical template id."""
        toks = [t for t in tokens if t]
        key = self._key(toks)
        best: Optional[_Cluster] = None
        best_sim = 0.0
        for cluster in self.clusters.get(key, ()):
            sim = cluster.similarity(toks)
            if sim > best_sim:
                best, best_sim = cluster, sim
        if best is not None and best_sim >= self.sim_threshold:
            best.count += 1
            self.template_frequency[best.template_id] += 1
            self.n_docs += 1
            return best.template_id
        cluster = self._new_cluster(toks)
        self.template_frequency[cluster.template_id] = 1
        self.n_docs += 1
        return cluster.template_id

    def add_line(self, line: str) -> str:
        """Mask + tokenize a raw log line and cluster it into a template id."""
        return self.add(tokenize(mask_variables(line)))

    # ------------------------------------------------------------ templates
    def template(self, template_id: str) -> str:
        """Canonical structural template (masked) for a template id."""
        cluster = self._by_id.get(template_id)
        if cluster is None:
            return ""
        return " ".join(t for t in cluster.signature if t).strip()

    def template_tokens(self, template_id: str) -> List[str]:
        cluster = self._by_id.get(template_id)
        return list(cluster.signature) if cluster else []

    def rarity(self, template_id: str) -> float:
        """Template IDF rarity: ``log((n_docs + 1) / (freq + 1))`` — rare > 0,
        common templates approach 0, unseen templates are maximally rare."""
        if not template_id:
            return 0.0
        freq = self.template_frequency.get(template_id, 0)
        return math.log((self.n_docs + 1) / (freq + 1))

    # ---------------------------------------------------------------- pairs
    def add_pair(self, parent: str, child: str) -> None:
        if parent and child:
            self.pair_counts[(parent, child)] += 1
            self.n_pairs += 1

    def pair_rarity(self, parent: str, child: str) -> float:
        if not parent or not child:
            return 0.0
        count = self.pair_counts.get((parent, child), 0)
        return math.log((self.n_pairs + 1) / (count + 1))


def mine_templates(
    events: Sequence[LogEvent], drain: Optional[Drain] = None
) -> Tuple[Drain, List[LogEvent]]:
    """Mine Drain templates for ``events`` (assigns ``template_id`` + pairs)."""
    drain = drain if drain is not None else Drain()
    for ev in events:
        ev.template_id = drain.add_line(ev.raw_message or ev.command_line or "")
        drain.add_pair(ev.parent_process, ev.process_name)
    return drain, events


# ---------------------------------------------------------------------------
# Timestamp parsing
# ---------------------------------------------------------------------------

_TS_FORMATS = (
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S",
    "%Y/%m/%d %H:%M:%S",
    "%m/%d/%Y %H:%M:%S",
    "%Y-%m-%d %H:%M",
    "%Y-%m-%d",
)
_SYSLOG_RE = re.compile(r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(?:(\d{4})\s+)?(\d{2}:\d{2}:\d{2})\b")


def parse_timestamp(ts: str) -> Optional[float]:
    """Best-effort parse of common log timestamp formats to a Unix epoch.

    Supports ISO-8601 (with/without timezone), ``YYYY-MM-DD HH:MM:SS`` style,
    syslog-style ``Dec 19 2026 10:02:13`` (year assumed current when absent)
    and bare epoch strings.
    """
    if not ts:
        return None
    ts = ts.strip()
    for candidate in (ts, ts.replace("Z", "+00:00")):
        try:
            return datetime.fromisoformat(candidate).timestamp()
        except ValueError:
            continue
    for fmt in _TS_FORMATS:
        try:
            return datetime.strptime(ts, fmt).timestamp()
        except ValueError:
            continue
    m = _SYSLOG_RE.match(ts)
    if m:
        try:
            month = datetime.strptime(m.group(1), "%b").month
            year = int(m.group(3)) if m.group(3) else datetime.now().year
            h, mi, s = (int(x) for x in m.group(4).split(":"))
            return datetime(year, month, int(m.group(2)), h, mi, s).timestamp()
        except ValueError:
            return None
    try:
        return float(ts)
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# Format parsers: auth.log (Linux), Sysmon JSON, ECS JSONL, generic
# ---------------------------------------------------------------------------

_AUTH_LINE_RE = re.compile(
    r"^\s*(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+(?:\d{4}\s+)?\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<proc>\S+)\[(?P<pid>\d+)\]:\s*(?P<msg>.*)$"
)
_AUTH_USER_PATTERNS: List["re.Pattern[str]"] = [
    re.compile(r"[Aa]ccepted\s+(?:publickey|password|keyboard-interactive(?:/pam)?)\s+for\s+([A-Za-z0-9._@-]+)"),
    re.compile(r"session\s+opened\s+for\s+user\s+([A-Za-z0-9._@-]+)"),
    re.compile(r"session\s+closed\s+for\s+user\s+([A-Za-z0-9._@-]+)"),
    re.compile(r"pam_unix\([^)]*\):\s+session opened for user ([A-Za-z0-9._@-]+)"),
    re.compile(r"^([A-Za-z0-9._@-]+)\s+:\s+TTY="),
    re.compile(r"USER=([A-Za-z0-9._@-]+)"),
    re.compile(r"su:\s+(?:to\s+)?([A-Za-z0-9._@-]+)"),
]
_GENERIC_LINE_RE = re.compile(r"^\s*(?P<ts>\S+\s+\S+)\s+(?P<host>\S+)\s+(?P<user>\S+)\s*(?P<msg>.*)$")


def _basename(path: Optional[str]) -> str:
    if not path:
        return ""
    return path.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]


def _extract_auth_user(msg: str) -> str:
    for pattern in _AUTH_USER_PATTERNS:
        m = pattern.search(msg or "")
        if m and m.group(1):
            return m.group(1)
    return ""


def parse_auth_log_line(line: str) -> Optional[LogEvent]:
    """Parse a Linux ``auth.log``/``secure`` syslog line into a :class:`LogEvent`."""
    m = _AUTH_LINE_RE.match(line or "")
    if not m:
        return None
    ts = m.group("ts")
    msg = m.group("msg") or ""
    process_name = (m.group("proc") or "").split("[", 1)[0].strip()
    user = _extract_auth_user(msg)
    if process_name == "sudo":
        user = user or (msg.split(":", 1)[0].strip() if ":" in msg else user)
    return LogEvent(
        timestamp=ts,
        entity_host=m.group("host"),
        entity_user=user,
        process_name=process_name,
        parent_process="",
        command_line=msg,
        raw_message=msg,
        source_format="auth.log",
        epoch=parse_timestamp(ts) or 0.0,
    )


def parse_sysmon_event(obj: Dict[str, Any]) -> Optional[LogEvent]:
    """Parse a Windows Sysmon JSON event (``EventData``/``System`` envelope)."""
    ed = obj.get("EventData")
    if not isinstance(ed, dict):
        ed = obj if isinstance(obj, dict) else {}
    ts = (
        ed.get("UtcTime")
        or ed.get("TimeCreated")
        or obj.get("SystemTime")
        or obj.get("@timestamp")
        or ""
    )
    host = ed.get("HostName") or obj.get("ComputerName") or obj.get("Computer") or ""
    process_name = _basename(ed.get("Image") or ed.get("ProcessName"))
    parent_name = _basename(ed.get("ParentImage") or ed.get("SourceImage"))
    user = ed.get("TargetUserName") or ed.get("SourceUserName") or ed.get("UserName") or ""
    command_line = ed.get("CommandLine") or ""
    src_ip = ed.get("SourceIp") or ed.get("SourceAddress") or ed.get("SourceHostname") or ""
    dst_ip = ed.get("DestinationIp") or ed.get("DestinationAddress") or ""
    raw = ed.get("Message") or command_line
    return LogEvent(
        timestamp=str(ts or ""),
        entity_host=str(host or ""),
        entity_user=str(user or ""),
        process_name=process_name,
        parent_process=parent_name,
        command_line=str(command_line or ""),
        src_ip=str(src_ip or ""),
        dst_ip=str(dst_ip or ""),
        raw_message=str(raw or ""),
        source_format="sysmon",
        epoch=parse_timestamp(str(ts or "")) or 0.0,
    )


def _ecs_dig(obj: Any, *keys: str) -> str:
    """Resolve an ECS field supporting flat (``host.name``) and nested (``host``->``name``) forms."""
    for key in keys:
        if isinstance(obj, dict):
            direct = obj.get(key)
            if isinstance(direct, str) and direct:
                return direct
        node: Any = obj
        ok = True
        for part in key.split("."):
            if isinstance(node, dict):
                node = node.get(part)
            else:
                ok = False
                break
        if ok and isinstance(node, str) and node:
            return node
    return ""


def parse_ecs_event(obj: Dict[str, Any]) -> Optional[LogEvent]:
    """Parse an Elastic Common Schema JSON object into a :class:`LogEvent`."""
    if not isinstance(obj, dict):
        return None
    ts = _ecs_dig(obj, "@timestamp", "timestamp", "time")
    host = _ecs_dig(obj, "host.name", "hostname", "host")
    user = _ecs_dig(obj, "user.name", "username", "user")
    proc = obj.get("process") if isinstance(obj.get("process"), dict) else {}
    parent = proc.get("parent") if isinstance(proc.get("parent"), dict) else {}
    process_name = _ecs_dig(proc, "name", "executable") or _ecs_dig(obj, "process.name", "process.executable")
    parent_name = _ecs_dig(parent, "name", "executable") or _ecs_dig(
        obj, "process.parent.name", "process.parent.executable"
    )
    cmd = _ecs_dig(proc, "command_line", "args") or _ecs_dig(obj, "process.command_line", "process.args")
    src_ip = _ecs_dig(obj, "source.ip", "source_ip", "src_ip")
    dst_ip = _ecs_dig(obj, "destination.ip", "destination_ip", "dst_ip")
    msg = _ecs_dig(obj, "message", "event.original") or cmd
    return LogEvent(
        timestamp=ts,
        entity_host=host,
        entity_user=user,
        process_name=_basename(process_name),
        parent_process=_basename(parent_name),
        command_line=cmd,
        src_ip=src_ip,
        dst_ip=dst_ip,
        raw_message=msg or "",
        source_format="ecs",
        epoch=parse_timestamp(ts) or 0.0,
    )


def parse_generic_line(line: str) -> Optional[LogEvent]:
    """Parse a generic ``timestamp host user message`` line."""
    m = _GENERIC_LINE_RE.match(line or "")
    if not m:
        return None
    ts = m.group("ts")
    user = (m.group("user") or "").strip()
    msg = (m.group("msg") or "").strip()
    return LogEvent(
        timestamp=ts,
        entity_host=m.group("host"),
        entity_user=user,
        command_line=msg,
        raw_message=msg,
        source_format="generic",
        epoch=parse_timestamp(ts) or 0.0,
    )


def _dispatch_json_obj(obj: Any) -> Optional[LogEvent]:
    """Dispatch a decoded JSON object to the right parser."""
    if not isinstance(obj, dict):
        return None
    if "EventData" in obj or "System" in obj:
        return parse_sysmon_event(obj)
    if "timestamp" in obj or "process_name" in obj or "template_id" in obj or "source_format" in obj:
        return LogEvent.from_dict(obj)
    return parse_ecs_event(obj)


def read_events(source: Union[str, Path, Sequence[Union[LogEvent, Dict[str, Any]]]]) -> List[LogEvent]:
    """Read events from a file path or an iterable of events/records.

    ``.jsonl``/``.ndjson`` files may contain unified-schema events or Sysmon /
    ECS JSON records; ``auth.log``/``secure``/``syslog`` text files are parsed
    as auth.log lines; everything else falls back to generic lines.
    """
    if isinstance(source, LogEvent):
        return [source]
    if isinstance(source, (str, Path)):
        path = Path(source)
        if not path.exists():
            raise FileNotFoundError(f"no such log file: {path}")
        if path.suffix.lower() in (".jsonl", ".ndjson") or path.name.endswith(".jsonl"):
            return _read_jsonl_events(path)
        return _read_text_events(path)
    events: List[LogEvent] = []
    for item in source:
        if isinstance(item, LogEvent):
            events.append(item)
        elif isinstance(item, dict):
            ev = _dispatch_json_obj(item)
            if ev is not None:
                events.append(ev)
    return events


read_logs = read_events


def _read_jsonl_events(path: Path) -> List[LogEvent]:
    events: List[LogEvent] = []
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                ev = parse_auth_log_line(line) or parse_generic_line(line)
                if ev is not None:
                    events.append(ev)
                continue
            ev = _dispatch_json_obj(obj)
            if ev is not None:
                events.append(ev)
    return events


def _read_text_events(path: Path) -> List[LogEvent]:
    events: List[LogEvent] = []
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            ev = parse_auth_log_line(line) or parse_generic_line(line)
            if ev is not None:
                events.append(ev)
            else:
                logger.debug("unparsed log line (dropped): %s", line[:120])
    return events
