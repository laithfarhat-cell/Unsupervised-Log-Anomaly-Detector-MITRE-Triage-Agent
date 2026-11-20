"""SIEM-ready ECS JSON and standalone dark-mode HTML SOC briefing exporters.

* :func:`to_ecs_json` — writes ECS events (one JSON object per line) to
  ``triaged_incidents.json``.
* :func:`to_html` — writes a standalone, dark-mode SOC briefing page
  (``reports/soc_triage_report.html``) with severity badges, MITRE mapping
  tables and containment playbooks.
"""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Sequence, Tuple, Union

from agent.mitre_triage import IncidentCard

SEVERITY_NUM: Dict[str, int] = {"low": 1, "medium": 2, "high": 3, "critical": 4}
SEVERITY_COLOR: Dict[str, str] = {
    "low": "#4CAF50",
    "medium": "#FFC107",
    "high": "#FB8C00",
    "critical": "#F44336",
}


def _escape(text: str) -> str:
    return html.escape(str(text or ""), quote=True)


def _to_iso(ts: str) -> str:
    if not ts:
        return datetime.now(timezone.utc).isoformat()
    text = ts.strip()
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat()
    except ValueError:
        return text


# ---------------------------------------------------------------------------
# ECS export
# ---------------------------------------------------------------------------

def _ecs_record(card: IncidentCard) -> Dict[str, Any]:
    record: Dict[str, Any] = {
        "@timestamp": _to_iso(card.timestamp),
        "event": {
            "kind": "alert",
            "module": "soc_anomaly_detector",
            "provider": "soc_anomaly_detector",
            "severity": SEVERITY_NUM.get(card.severity, 2),
            "risk_score": round(float(card.anomaly_score), 4),
        },
        "host": {"name": card.entity_host, "type": "host"},
        "message": (
            f"{card.mitre_tactic_id} {card.mitre_technique_id} — {card.mitre_technique_name} "
            f"on {card.entity_host}: {card.narrative}"
        ),
        "mitre": {
            "tactic": {"id": card.mitre_tactic_id, "name": card.mitre_tactic_name},
            "technique": {"id": card.mitre_technique_id, "name": card.mitre_technique_name},
            "confidence": card.mitre_confidence,
        },
        "rule": {"id": card.anomaly_id, "name": f"SOC-ANOMALY-{card.anomaly_id}"},
        "severity": card.severity,
    }
    if card.entity_user and card.entity_user != "unknown":
        record["user"] = {"name": card.entity_user}
    if card.source_process_name:
        process: Dict[str, Any] = {"name": card.source_process_name}
        if card.source_command_line:
            process["command_line"] = card.source_command_line
        if card.source_parent_name:
            process["parent"] = {"name": card.source_parent_name}
        record["process"] = process
    if card.source_ip:
        record["source"] = {"ip": card.source_ip}
    if card.destination_ip:
        record["destination"] = {"ip": card.destination_ip}
    if card.template_signature:
        record["log"] = {"original": card.template_signature, "service": {"name": "soc_anomaly_detector"}}
    record["incident"] = {
        "id": card.anomaly_id,
        "detector": "soc_anomaly_detector",
        "playbook": card.containment_steps,
        "hunting_queries": card.hunting_queries,
    }
    return record


def to_ecs_json(cards: Sequence[IncidentCard], path: Union[str, Path]) -> Path:
    """Write SIEM-ready ECS events to ``path`` (one JSON object per line)."""
    out = Path(path)
    if str(out.parent) not in ("", "."):
        out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as fh:
        for card in cards:
            fh.write(json.dumps(_ecs_record(card)) + "\n")
    return out


# ---------------------------------------------------------------------------
# Dark-mode HTML briefing
# ---------------------------------------------------------------------------

CSS_DARK = """
:root { --bg:#0d1117; --panel:#161b22; --border:#2a313a; --text:#c9d1d9; --muted:#8b949e; --accent:#58a6ff; }
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--text); font-family: -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
header { padding: 28px 32px; background: var(--panel); border-bottom: 1px solid var(--border); }
header h1 { margin: 0; font-size: 24px; color: var(--accent); letter-spacing: -0.5px; }
header .subtitle { margin: 6px 0 0; color: var(--muted); font-size: 13px; }
main { padding: 24px 32px 64px; }
h2 { font-size: 18px; border-bottom: 1px solid var(--border); padding-bottom: 8px; margin-top: 36px; }
h3 { font-size: 15px; margin: 14px 0 4px; }
h4 { font-size: 13px; color: var(--accent); margin: 12px 0 4px; }
table { border-collapse: collapse; width: 100%; margin: 12px 0; background: var(--panel); }
th, td { border: 1px solid var(--border); padding: 6px 10px; text-align: left; font-size: 13px; }
th { background: #0d1117; color: var(--accent); font-weight: 600; }
tbody tr:nth-child(even) { background: #121a20; }
tbody tr:hover { background: #1c2630; }
.badge { display: inline-block; padding: 2px 10px; border-radius: 999px; font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.4px; }
.badge-low { background: #2ea04366; color: #7ee787; }
.badge-medium { background: #d2992266; color: #e3b341; }
.badge-high { background: #db6d2866; color: #ff9b59; }
.badge-critical { background: #f8514933; color: #ff7b72; }
.narrative { line-height: 1.6; max-width: 88ch; margin: 8px 0; }
ol.steps { line-height: 1.8; }
pre { background: #121a20; border: 1px solid var(--border); border-radius: 6px; padding: 10px; overflow-x: auto; font-size: 12px; color: var(--text); }
code { font-size: 12px; }
footer { padding: 16px 32px; border-top: 1px solid var(--border); color: var(--muted); font-size: 12px; }
"""

CSS_LIGHT = """
:root { --bg:#f6f8fa; --panel:#ffffff; --border:#d0d7de; --text:#24292f; --muted:#57606a; --accent:#0969da; }
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--text); font-family: -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
header { padding: 28px 32px; background: var(--panel); border-bottom: 1px solid var(--border); }
header h1 { margin: 0; font-size: 24px; color: var(--accent); }
header .subtitle { margin: 6px 0 0; color: var(--muted); font-size: 13px; }
main { padding: 24px 32px 64px; }
h2 { font-size: 18px; border-bottom: 1px solid var(--border); padding-bottom: 8px; margin-top: 36px; }
h3 { font-size: 15px; margin: 14px 0 4px; }
h4 { font-size: 13px; color: var(--accent); margin: 12px 0 4px; }
table { border-collapse: collapse; width: 100%; margin: 12px 0; background: var(--panel); }
th, td { border: 1px solid var(--border); padding: 6px 10px; text-align: left; font-size: 13px; }
th { background: #f6f8fa; color: #24292f; font-weight: 600; }
tbody tr:nth-child(even) { background: #fbfcfd; }
tbody tr:hover { background: #f0f4ff; }
.badge { display: inline-block; padding: 2px 10px; border-radius: 999px; font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.4px; }
.badge-low { background: #dafbe1; color: #1a7f37; }
.badge-medium { background: #fff8c5; color: #9a6700; }
.badge-high { background: #ffe2b2; color: #b45309; }
.badge-critical { background: #ffebe9; color: #cf222e; }
.narrative { line-height: 1.6; max-width: 88ch; margin: 8px 0; }
ol.steps { line-height: 1.8; }
pre { background: #f6f8fa; border: 1px solid var(--border); border-radius: 6px; padding: 10px; overflow-x: auto; font-size: 12px; color: var(--text); }
code { font-size: 12px; }
footer { padding: 16px 32px; border-top: 1px solid var(--border); color: var(--muted); font-size: 12px; }
"""


def _html_row(card: IncidentCard) -> str:
    sev = _escape(card.severity)
    return (
        "<tr>"
        f"<td><a href='#{_escape(card.anomaly_id)}'>{_escape(card.anomaly_id)}</a></td>"
        f"<td>{_escape(card.timestamp[:19])}</td>"
        f"<td>{_escape(card.entity_host)}</td>"
        f"<td>{_escape(card.entity_user)}</td>"
        f"<td><span class='badge badge-{sev}'>{sev}</span></td>"
        f"<td>{_escape(card.mitre_tactic_id)} — {_escape(card.mitre_tactic_name)}</td>"
        f"<td>{_escape(card.mitre_technique_id)} — {_escape(card.mitre_technique_name)}</td>"
        f"<td>{card.anomaly_score:.2f}</td>"
        f"<td>{len(card.containment_steps)}</td>"
        "</tr>"
    )


def _html_section(card: IncidentCard) -> str:
    sev = _escape(card.severity)
    anchor = _escape(card.anomaly_id)
    lines: List[str] = [
        f"<details id='{anchor}'>",
        f"<summary><span class='badge badge-{sev}'>{sev}</span> {anchor}: "
        f"{_escape(card.mitre_technique_id)} — {_escape(card.mitre_technique_name)}</summary>",
        "<div class='card-body'>",
        f"<p><strong>Timestamp:</strong> {_escape(card.timestamp[:19])}"
        f" · <strong>Host:</strong> {_escape(card.entity_host)}"
        + (f" · <strong>User:</strong> {_escape(card.entity_user)}" if card.entity_user != "unknown" else "")
        + f" · <strong>Score:</strong> {card.anomaly_score:.2f}</p>",
        f"<p class='narrative'>{_escape(card.narrative)}</p>",
    ]
    if card.source_command_line:
        lines.append(f"<pre><code>{_escape(card.source_command_line)}</code></pre>")
    mapping = [
        ("Tactic", f"{_escape(card.mitre_tactic_id)} — {_escape(card.mitre_tactic_name)}"),
        ("Technique", f"{_escape(card.mitre_technique_id)} — {_escape(card.mitre_technique_name)}"),
        ("Confidence", _escape(card.mitre_confidence)),
        ("Template", _escape(card.template_signature)),
    ]
    lines.append("<h4>MITRE Mapping</h4><table><thead><tr><th>Field</th><th>Value</th></tr></thead><tbody>")
    lines.extend(f"<tr><td>{label}</td><td>{value}</td></tr>" for label, value in mapping)
    lines.append("</tbody></table>")
    if card.containment_steps:
        steps = "".join(f"<li>{_escape(s)}</li>" for s in card.containment_steps)
        lines.append(f"<h4>Containment &amp; Response</h4><ol class='steps'>{steps}</ol>")
    if card.hunting_queries:
        queries = "<br>".join(_escape(q) for q in card.hunting_queries)
        lines.append(f"<h4>Threat Hunting Queries</h4><pre><code>{queries}</code></pre>")
    lines.append("</div></details>")
    return "".join(lines)


def to_html(
    cards: Sequence[IncidentCard],
    path: Union[str, Path],
    dark_mode: bool = True,
    title: str = "SOC Triage Briefing",
) -> Path:
    """Write a standalone dark-mode HTML SOC briefing page to ``path``."""
    out = Path(path)
    if str(out.parent) not in ("", "."):
        out.parent.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    css = CSS_DARK if dark_mode else CSS_LIGHT
    rows = [_html_row(card) for card in cards]
    sections = [_html_section(card) for card in cards]
    doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_escape(title)}</title>
<style>{css}</style>
</head>
<body>
<header>
  <h1>{_escape(title)}</h1>
  <p class="subtitle">Generated: {now} · {len(cards)} MITRE ATT&amp;CK incidents triaged by soc-anomaly-detector</p>
</header>
<main>
<h2>Incident Summary ({len(cards)})</h2>
<table>
  <thead>
    <tr><th>Incident</th><th>Time</th><th>Host</th><th>User</th><th>Severity</th><th>Tactic</th><th>Technique</th><th>Score</th><th>Playbook</th></tr>
  </thead>
  <tbody>
{chr(10).join(rows)}
  </tbody>
</table>
{chr(10).join(sections)}
</main>
<footer>
  <p>Standalone SOC briefing · Generated by soc-anomaly-detector</p>
</footer>
</body>
</html>"""
    out.write_text(doc, encoding="utf-8")
    return out


def export_all(
    cards: Sequence[IncidentCard],
    json_path: Union[str, Path] = "triaged_incidents.json",
    html_path: Union[str, Path] = "reports/soc_triage_report.html",
) -> Tuple[Path, Path]:
    """Export both formats; returns the ``(json_path, html_path)`` written."""
    return to_ecs_json(cards, json_path), to_html(cards, html_path)
