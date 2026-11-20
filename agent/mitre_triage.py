"""Local-LLM MITRE ATT&CK triage agent with deterministic offline fallback.

Connects asynchronously to a local Ollama server (``POST /api/generate``) in
JSON mode. The LLM is instructed to emit a strict, Pydantic-validated
:class:`IncidentCard` — MITRE tactic/technique mapping, a 3-sentence narrative
correlating the anomalous features with the parent-child lineage, and
containment steps plus SIEM hunting queries. Every call validates the response
strictly; any failure (offline server, empty/invalid output, schema drift)
falls back to :meth:`MITRETriageAgent.triage_offline`, which uses the curated
offline knowledge base in ``data/mitre_kb.json`` — deterministic and safe for
headless/CI environments where Ollama is unavailable.

No sensitive log payloads are sent anywhere: the prompt contains only
aggregated, already-masked telemetry (the parser masks IPs, PIDs, hashes,
paths, ...).
"""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Union

import httpx
from pydantic import BaseModel, ConfigDict, Field, field_validator

from models.anomaly_engine import severity_from_score

logger = logging.getLogger(__name__)


class IncidentCard(BaseModel):
    """Structured triage result for one deduplicated anomaly cluster."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    anomaly_id: str = Field(min_length=1)
    timestamp: str = Field(min_length=1)
    entity_host: str = Field(min_length=1)
    entity_user: str = Field(min_length=1)
    anomaly_score: float = Field(ge=0.0, le=1.0)
    severity: str = "medium"
    mitre_tactic_id: str = Field(pattern=r"^TA\d{4}$")
    mitre_tactic_name: str = Field(min_length=1)
    mitre_technique_id: str = Field(pattern=r"^T\d{4}(?:\.\d{1,3})?$")
    mitre_technique_name: str = Field(min_length=1)
    mitre_confidence: str = "medium"
    narrative: str = Field(min_length=1)
    containment_steps: List[str]
    hunting_queries: List[str]
    source_process_name: str = ""
    source_command_line: str = ""
    source_parent_name: str = ""
    source_ip: str = ""
    destination_ip: str = ""
    template_signature: str = ""

    @field_validator("severity")
    @classmethod
    def _validate_severity(cls, v: str) -> str:
        v = (v or "").strip().lower()
        v = {
            "fatal": "critical",
            "moderat": "medium",
            "moderate": "medium",
            "warn": "medium",
            "info": "low",
            "notice": "low",
            "none": "low",
            "unknown": "medium",
        }.get(v, v)
        if v not in {"low", "medium", "high", "critical"}:
            raise ValueError(f"invalid severity: {v!r}")
        return v

    @field_validator("mitre_confidence")
    @classmethod
    def _validate_confidence(cls, v: str) -> str:
        v = (v or "").strip().lower()
        v = {
            "moderat": "medium",
            "moderate": "medium",
            "possible": "medium",
            "hypothesis": "medium",
            "speculative": "low",
            "theoretical": "low",
            "likelihood": "medium",
            "likely": "high",
            "certain": "high",
            "proven": "high",
        }.get(v, v)
        if v not in {"low", "medium", "high"}:
            raise ValueError(f"invalid confidence: {v!r}")
        return v

    @field_validator("containment_steps", "hunting_queries")
    @classmethod
    def _clean_steps(cls, v: List[str]) -> List[str]:
        cleaned = [s.strip() for s in (v or []) if isinstance(s, str) and s.strip()]
        if not cleaned:
            raise ValueError("must contain at least one non-empty entry")
        return cleaned


# ---------------------------------------------------------------------------
# Prompt engineering for deterministic JSON triage
# ---------------------------------------------------------------------------

_PROMPT_TEMPLATE = """You are a senior SOC analyst triaging an automated log anomaly detector.

ANOMALY CONTEXT:
{context}

Respond with a single JSON object with EXACTLY these keys (no extra keys, no explanations, no code fences, no text before or after the object):
anomaly_id (string, echo the anomaly id from context)
timestamp (string, ISO-8601 of the anomalous event)
entity_host (string, affected host)
entity_user (string, affected user or "unknown")
anomaly_score (number, 0..1, echo the context score)
severity (string: low, medium, high, or critical)
mitre_tactic_id (string, format TA + 4 digits, e.g. TA0002)
mitre_tactic_name (string, MITRE tactic name)
mitre_technique_id (string, format T + 4 digits, optionally followed by .subid, e.g. T1059.001)
mitre_technique_name (string, MITRE technique name)
mitre_confidence (string: low, medium, or high)
narrative (string, 3 sentences correlating the anomalous features, the parent-child lineage, and potential actor intent)
containment_steps (list of strings, at least one actionable containment step)
hunting_queries (list of strings, at least one SIEM search query)
source_process_name (string)
source_command_line (string, telemetry variables shown as placeholders like <IP>, <HEX>, <PATH>, <NUM>)
source_parent_name (string)
source_ip (string)
destination_ip (string)
template_signature (string, structural log template)
"""


def _parse_json_object(raw: str) -> Dict[str, Any]:
    """Strip code fences and parse a strict JSON object from the LLM output."""
    text = (raw or "").strip()
    for fence in ("```json", "```"):
        if text.startswith(fence):
            text = text[len(fence) :].lstrip("\n")
    idx = text.rfind("```")
    if idx != -1:
        text = text[:idx].rstrip()
    obj = json.loads(text)
    if not isinstance(obj, dict):
        raise ValueError("expected a JSON object")
    return obj


def _context_items(row: Dict[str, Any]) -> Dict[str, str]:
    attributions = row.get("attributions") or []
    top = "; ".join(
        f"{a.get('feature')}={float(a.get('value', 0.0)):.4g} (z={float(a.get('z', 0.0)):.2f})"
        for a in attributions[:3]
    ) or "-"
    return {
        "anomaly_id": str(row.get("anomaly_id", row.get("incident_id", "INC-?"))),
        "timestamp": str(row.get("timestamp", "")),
        "host": str(row.get("entity_host", "")),
        "user": str(row.get("entity_user", "")),
        "severity": str(row.get("severity", "")),
        "anomaly_score": f"{float(row.get('anomaly_score') or 0.0):.3f}",
        "template_signature": str(row.get("template_signature", "")),
        "process_name": str(row.get("process_name", "")),
        "parent_process": str(row.get("parent_process", "")),
        "command_line": str(row.get("command_line", ""))[:400],
        "source_ip": str(row.get("src_ip", "")),
        "destination_ip": str(row.get("dst_ip", "")),
        "top_anomalous_features": top,
    }


# ---------------------------------------------------------------------------
# Deterministic offline triage (curated MITRE KB fallback)
# ---------------------------------------------------------------------------

_ACTOR_INTENTS: Dict[str, str] = {
    "T1059.001": "shell-based or PowerShell command execution / payload staging",
    "T1059.004": "scripted shell command execution",
    "T1105": "remote tool transfer or payload staging",
    "T1003": "credential dumping or hash extraction",
    "T1110.003": "credential-spraying brute force activity",
    "T1110.004": "credential-stuffing attack activity",
    "T1021.004": "lateral movement via SSH",
    "T1566.001": "spearphishing with a malicious attachment",
    "T1078.003": "unauthorized local account creation",
    "T1078.004": "cloud credential abuse",
}
_ACTOR_INTENT_DEFAULT = "an undetected reconnaissance or execution step"

DEFAULT_NARRATIVE = (
    "The unsupervised ensemble flagged {signature} on {host} for {entity} with anomaly score {anomaly_score}. "
    "The parent-child lineage {parent} -> {process} combined with the anomalous feature profile "
    "(template rarity, obfuscation metrics and burst velocity) is characteristic of {actor}. "
    "Correlate this alert with the most recent authentication and process-creation telemetry "
    "from the last 24 hours to confirm or rule out a stealthy execution chain."
)

DEFAULT_CONTAINMENT = [
    "Isolate {host} from the network (revoke access or move it to a quarantine VLAN) and suspend "
    "non-essential services for {entity}.",
    "Terminate the anomalous process tree on {host} ({parent} -> {process}) and quarantine any files "
    "written to /tmp, $HOME or /var/tmp in the last 24 hours.",
    "Enforce account controls: disable or rotate credentials used by {entity} on {host} if lateral "
    "movement is suspected.",
    "Search SIEM for corroboration: process={process} AND host={host} AND user={user} "
    "(dedupe by entity + template signature).",
]

DEFAULT_HUNTING_QUERIES = [
    'search: process="{process}" AND host="{host}" AND user="{user}"',
    'search: command_line="*base64*" OR command_line="*curl*" OR command_line="*wget*" OR command_line="*certutil*"',
    'search: process="hashcat" OR process="john" OR process="mimikatas" OR process="openssl"',
    'search: process="ssh" AND destination_ip!="" AND source_ip="{source_ip}"',
    'search: event="session opened" AND user="{user}" AND host="{host}"',
]


def _fill_map(row: Dict[str, Any]) -> Dict[str, str]:
    host = str(row.get("entity_host") or "unknown")
    user = str(row.get("entity_user") or "unknown")
    process = str(row.get("process_name") or "unknown")
    parent = str(row.get("parent_process") or "unknown")
    return {
        "host": host,
        "user": user,
        "entity": f"{host}/{user}" if user not in ("", "unknown") else host,
        "process": process,
        "parent": parent,
        "parent_name": parent,
        "child_name": process,
        "cmd": str(row.get("command_line") or "")[:300] or "an anomalous command line",
        "signature": str(row.get("template_signature") or "")[:300] or "an unseen behavioral pattern",
        "anomaly_id": str(row.get("anomaly_id") or row.get("incident_id") or "INC-?"),
        "anomaly_score": f"{float(row.get('anomaly_score') or 0.0):.2f}",
        "source_ip": str(row.get("src_ip") or ""),
        "destination_ip": str(row.get("dst_ip") or ""),
    }


def _render_narrative(entry: Dict[str, Any], row: Dict[str, Any]) -> str:
    fill = _fill_map(row)
    fill["actor"] = _ACTOR_INTENTS.get(entry.get("technique_id", ""), _ACTOR_INTENT_DEFAULT)
    template = entry.get("narrative_template") or DEFAULT_NARRATIVE
    try:
        text = template.format(**fill)
    except (KeyError, IndexError, ValueError):
        text = DEFAULT_NARRATIVE.format(**fill)
    return text.strip()


def _render_playbook(
    steps: Optional[Sequence[str]],
    default_steps: Sequence[str],
    row: Dict[str, Any],
) -> List[str]:
    fill = _fill_map(row)

    def render(s: str) -> str:
        try:
            return s.format(**fill)
        except (KeyError, IndexError, ValueError):
            return s

    chosen = [s for s in (steps or []) if str(s).strip()]
    if not chosen:
        chosen = [s for s in default_steps if str(s).strip()]
    return [render(str(s)) for s in chosen] or [render(s) for s in default_steps]


class MITRETriageAgent:
    """Triages deduplicated anomaly clusters into :class:`IncidentCard`s."""

    def __init__(
        self,
        ollama_url: Optional[str] = None,
        ollama_model: str = "llama3.2",
        kb_path: Union[str, Path] = "data/mitre_kb.json",
        timeout: float = 120.0,
        max_response_tokens: int = 2048,
        temperature: float = 0.05,
        offline: bool = False,
    ):
        self.ollama_url = ollama_url
        self.ollama_model = ollama_model
        self.kb_path = Path(kb_path)
        self.timeout = float(timeout)
        self.max_response_tokens = int(max_response_tokens)
        self.temperature = float(temperature)
        self.offline = bool(offline)
        self.stats: Dict[str, int] = {"online": 0, "fallback": 0}
        self.entries: List[Dict[str, Any]] = []
        if self.kb_path.exists():
            try:
                kb = json.loads(self.kb_path.read_text(encoding="utf-8"))
                self.entries = list(kb.get("techniques", []))
            except (json.JSONDecodeError, OSError) as exc:
                logger.warning("could not load MITRE KB %s: %s", self.kb_path, exc)

    # ------------------------------------------------------------------ API
    async def triage_anomalies(
        self,
        anomalies: Sequence[Dict[str, Any]],
        semaphore_limit: int = 4,
    ) -> List[IncidentCard]:
        """Triage each anomaly row; falls back to the offline KB on any failure."""
        sem = asyncio.Semaphore(semaphore_limit)

        async def _one(row: Dict[str, Any]) -> IncidentCard:
            if self.offline:
                return self.triage_offline(row)
            try:
                card = await self._triage_online(row)
            except Exception as exc:  # noqa: BLE001 - any failure falls back offline
                logger.warning(
                    "online triage failed for %s: %s — offline fallback",
                    row.get("anomaly_id", "?"),
                    exc,
                )
                self.stats["fallback"] += 1
                return self.triage_offline(row)
            self.stats["online"] += 1
            return card

        async def _bounded(row: Dict[str, Any]) -> IncidentCard:
            async with sem:
                return await _one(row)

        cards = await asyncio.gather(*[_bounded(row) for row in anomalies])
        return list(cards)

    async def _triage_online(self, row: Dict[str, Any]) -> IncidentCard:
        if not self.ollama_url:
            raise ValueError("no Ollama endpoint configured")
        payload: Dict[str, Any] = {
            "model": self.ollama_model,
            "prompt": self._build_prompt(row),
            "stream": False,
            "format": "json",
            "options": {
                "temperature": self.temperature,
                "num_predict": self.max_response_tokens,
                "repeat_penalty": 1.05,
            },
        }
        async with httpx.AsyncClient(timeout=httpx.Timeout(self.timeout)) as client:
            response = await client.post(self.ollama_url, json=payload)
            response.raise_for_status()
            data = response.json()
        raw = (data or {}).get("response", "") if isinstance(data, dict) else ""
        if not raw:
            raise ValueError("Ollama returned an empty response")
        obj = _parse_json_object(raw)
        return IncidentCard.model_validate(obj)

    # ----------------------------------------------------------- offline KB
    def triage_offline(self, row: Dict[str, Any]) -> IncidentCard:
        """Deterministic triage via the curated MITRE KB (no network)."""
        entry = self._match_kb_entry(row)
        return IncidentCard(
            anomaly_id=str(row.get("anomaly_id", row.get("incident_id", "INC-?"))),
            timestamp=str(row.get("timestamp", "")),
            entity_host=str(row.get("entity_host", "") or "unknown"),
            entity_user=str(row.get("entity_user", "") or "unknown"),
            anomaly_score=float(row.get("anomaly_score") or 0.0),
            severity=severity_from_score(float(row.get("anomaly_score") or 0.0)),
            mitre_tactic_id=str(entry.get("tactic_id", "TA0002")),
            mitre_tactic_name=str(entry.get("tactic_name", "Execution")),
            mitre_technique_id=str(entry.get("technique_id", "T1059")),
            mitre_technique_name=str(
                entry.get("technique_name", "Command and Scripting Interpreter")
            ),
            mitre_confidence=str(entry.get("confidence", "medium")),
            narrative=_render_narrative(entry, row),
            containment_steps=_render_playbook(
                entry.get("containment_steps"), DEFAULT_CONTAINMENT, row
            ),
            hunting_queries=_render_playbook(
                entry.get("hunting_queries"), DEFAULT_HUNTING_QUERIES, row
            ),
            source_process_name=str(row.get("process_name", "") or ""),
            source_command_line=str(row.get("command_line", "") or "")[:300],
            source_parent_name=str(row.get("parent_process", "") or ""),
            source_ip=str(row.get("src_ip", "") or ""),
            destination_ip=str(row.get("dst_ip", "") or ""),
            template_signature=str(row.get("template_signature", "") or ""),
        )

    def _match_kb_entry(self, row: Dict[str, Any]) -> Dict[str, Any]:
        text = " ".join(
            str(row.get(k) or "")
            for k in (
                "entity_host",
                "entity_user",
                "process_name",
                "parent_process",
                "command_line",
                "template_signature",
                "src_ip",
                "dst_ip",
            )
        ).lower()
        best: Dict[str, Any] = {}
        best_score = 0
        for entry in self.entries:
            score = 0
            for indicator in entry.get("indicators", []):
                if indicator and str(indicator).lower() in text:
                    score += 1
            if score == 0:
                continue
            weight = {"high": 3, "medium": 2, "low": 1}.get(entry.get("confidence"), 1)
            score *= weight
            if score > best_score:
                best, best_score = entry, score
        return best

    # ----------------------------------------------------------------- misc
    def _build_prompt(self, row: Dict[str, Any]) -> str:
        context = "\n".join(f"- {key}: {value}" for key, value in _context_items(row).items())
        return _PROMPT_TEMPLATE.replace("{context}", context)
