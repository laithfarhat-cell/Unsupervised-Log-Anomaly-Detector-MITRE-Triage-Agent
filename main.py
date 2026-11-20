#!/usr/bin/env python3
"""CLI entry point for the SOC anomaly detector + local LLM triage agent.

Subcommands: ``train``, ``hunt``, ``simulate`` (see ``--help``).
"""

from __future__ import annotations

import argparse
import asyncio
import importlib
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

import pandas as pd
import yaml
from rich import box
from rich.console import Console
from rich.table import Table

from agent.mitre_triage import IncidentCard, MITRETriageAgent
from core.features import extract_features
from core.parser import Drain, LogEvent, mine_templates, read_events
from models.anomaly_engine import AnomalyEngine, dedupe_anomalies, severity_from_score
from reporters.exporter import export_all

console = Console()
DEFAULT_KB_PATH = "data/mitre_kb.json"
SEVERITY_BADGE_COLOR = {"low": "green", "medium": "yellow", "high": "orange1", "critical": "red"}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="soc-triage",
        description="SOC anomaly detector + local-LLM MITRE ATT&CK triage agent",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    train = sub.add_parser("train", help="Train the unsupervised anomaly ensemble on baseline logs.")
    train.add_argument("-i", "--input", required=True, help="Baseline logs (jsonl, auth.log, Sysmon JSON, ECS).")
    train.add_argument("--model", default="models/soc_ensemble.joblib", help="Trained engine output path.")
    train.add_argument("--contamination", type=float, default=0.05, help="Isolation Forest contamination.")
    train.add_argument("--threshold", choices=["mad", "quantile"], default="mad", help="Threshold calibration.")
    train.set_defaults(func=cmd_train)

    hunt = sub.add_parser("hunt", help="Detect anomalies in live logs and triage them.")
    hunt.add_argument("-i", "--input", required=True, help="Live logs (jsonl, auth.log, Sysmon JSON, ECS).")
    hunt.add_argument("--model", default="models/soc_ensemble.joblib")
    hunt.add_argument("--ollama-model", default="llama3.2")
    hunt.add_argument("--ollama-url", default="http://localhost:11434/api/generate")
    hunt.add_argument("--html", default=None, help="HTML briefing path (default: reports/soc_triage_report.html).")
    hunt.add_argument("--json", default=None, help="ECS JSON path (default: triaged_incidents.json).")
    hunt.add_argument("--top", type=int, default=50, help="Max incidents to triage.")
    hunt.add_argument("--contamination", type=float, default=0.05, help="Isolation Forest contamination.")
    hunt.add_argument("--threshold", choices=["mad", "quantile"], default="mad", help="Threshold calibration.")
    hunt.add_argument("--offline", action="store_true", help="Skip Ollama; use the deterministic offline MITRE fallback.")
    hunt.set_defaults(func=cmd_hunt)

    sim = sub.add_parser("simulate", help="Run the full end-to-end simulation (generate, train, hunt, export).")
    sim.add_argument("--days", type=int, default=None, help="Simulation days (default: config.yaml).")
    sim.add_argument("--benign-count", type=int, default=None, help="Benign events (default: config.yaml).")
    sim.add_argument("--seed", type=int, default=None, help="Random seed (default: config.yaml).")
    sim.add_argument("--attack", action=argparse.BooleanOptionalAction, default=True, help="Include the attack campaign.")
    sim.add_argument("--output", default="simulated_soc_logs.jsonl", help="Generated log file path.")
    sim.add_argument("--model", default="models/soc_ensemble.joblib")
    sim.add_argument("--ollama-model", default="llama3.2")
    sim.add_argument("--ollama-url", default="http://localhost:11434/api/generate")
    sim.add_argument("--html", default=None)
    sim.add_argument("--json", default=None)
    sim.add_argument("--top", type=int, default=50)
    sim.add_argument("--contamination", type=float, default=0.05)
    sim.add_argument("--threshold", choices=["mad", "quantile"], default="mad")
    sim.add_argument("--offline", action="store_true")
    sim.set_defaults(func=cmd_simulate)

    return parser


def _load_config() -> Dict[str, Any]:
    path = Path("config.yaml")
    if not path.exists():
        return {}
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        return data if isinstance(data, dict) else {}
    except yaml.YAMLError as exc:
        console.print(f"[yellow]warning: could not parse config.yaml: {exc}[/yellow]")
        return {}


def _apply_config_defaults(args: argparse.Namespace) -> None:
    cfg = _load_config()
    reporters_cfg = cfg.get("reporters") or {}
    if getattr(args, "json", None) is None:
        args.json = reporters_cfg.get("json_path", "triaged_incidents.json")
    if getattr(args, "html", None) is None:
        args.html = reporters_cfg.get("html_path", "reports/soc_triage_report.html")
    if args.command == "simulate":
        sim_cfg = cfg.get("simulate") or {}
        for attr, fallback in (("days", 7), ("benign_count", 1200), ("seed", 42)):
            if getattr(args, attr, None) is None:
                setattr(args, attr, sim_cfg.get(attr, fallback))


# ---------------------------------------------------------------------------
# Pipeline helpers
# ---------------------------------------------------------------------------

def _detect_anomalies(events: Sequence[LogEvent], engine: AnomalyEngine, drain: Drain) -> pd.DataFrame:
    """Run the anomaly ensemble and join context + severity onto all events."""
    df = extract_features(events, drain)
    scored = engine.predict(df)
    out = pd.concat([df.reset_index(drop=True), scored.reset_index(drop=True)], axis=1)
    out["timestamp"] = [e.timestamp for e in events]
    out["entity_host"] = [e.entity_host for e in events]
    out["entity_user"] = [e.entity_user or "" for e in events]
    out["process_name"] = [e.process_name or "" for e in events]
    out["parent_process"] = [e.parent_process or "" for e in events]
    out["command_line"] = [e.command_line or "" for e in events]
    out["src_ip"] = [e.src_ip or "" for e in events]
    out["dst_ip"] = [e.dst_ip or "" for e in events]
    out["template_signature"] = [drain.template(e.template_id) if e.template_id else "" for e in events]
    out["severity"] = [severity_from_score(s) for s in out["anomaly_score"].to_numpy()]
    out["anomaly_key"] = [
        f"{h}|{u}|{sig}"
        for h, u, sig in zip(out["entity_host"], out["entity_user"], out["template_signature"])
    ]
    return out


def _print_severity_table(cards: Sequence[IncidentCard]) -> None:
    if not cards:
        console.print("[yellow]No incidents to triage.[/yellow]")
        return
    table = Table(title="MITRE ATT&CK Incidents", box=box.ROUNDED)
    for col in ("Incident", "Time", "Host", "User", "Severity", "Tactic", "Technique", "Score", "Playbook"):
        table.add_column(col, overflow="fold")
    for card in cards:
        color = SEVERITY_BADGE_COLOR.get(card.severity, "white")
        table.add_row(
            card.anomaly_id,
            (card.timestamp or "")[:19],
            card.entity_host,
            card.entity_user or "-",
            f"[{color}]{card.severity.upper()}[/{color}]",
            f"{card.mitre_tactic_id} — {card.mitre_tactic_name}",
            f"{card.mitre_technique_id} — {card.mitre_technique_name}",
            f"{card.anomaly_score:.2f}",
            f"{len(card.containment_steps)} steps · {len(card.hunting_queries)} queries",
        )
    console.print(table)


def _triage_and_report(
    anomalies: pd.DataFrame,
    args: argparse.Namespace,
    agent: MITRETriageAgent,
    raw_count: int,
) -> List[IncidentCard]:
    rows = anomalies.to_dict("records")
    cards = asyncio.run(agent.triage_anomalies(rows))
    console.print(
        f"Funnel: [bold]{raw_count}[/bold] raw events → [bold]{len(anomalies)}[/bold] "
        f"anomalies → [bold]{len(cards)}[/bold] triaged MITRE incidents"
    )
    _print_severity_table(cards)
    json_path, html_path = export_all(cards, json_path=args.json, html_path=args.html)
    console.print(f"Exported: [cyan]{json_path}[/cyan], [cyan]{html_path}[/cyan]")
    return cards


def _detect_and_report(
    events: Sequence[LogEvent],
    engine: AnomalyEngine,
    drain: Drain,
    args: argparse.Namespace,
) -> List[IncidentCard]:
    out = _detect_anomalies(events, engine, drain)
    anomalies = out[out["is_anomaly"]].copy()
    console.print(f"Anomalies: [bold]{len(anomalies)}[/bold] above threshold {engine.threshold_:.4f}")
    anomalies = dedupe_anomalies(anomalies, key_column="anomaly_key", top_k=args.top)
    agent = MITRETriageAgent(
        ollama_url=args.ollama_url,
        ollama_model=args.ollama_model,
        kb_path=DEFAULT_KB_PATH,
        offline=args.offline,
    )
    return _triage_and_report(anomalies, args, agent, raw_count=len(events))


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_train(args: argparse.Namespace) -> int:
    console.print("[bold]SOC Anomaly Detector — Train[/bold]")
    events = read_events(args.input)
    console.print(f"Read [cyan]{len(events)}[/cyan] baseline log events from [cyan]{args.input}[/cyan]")
    drain, events = mine_templates(events)
    df = extract_features(events, drain)
    engine = AnomalyEngine(contamination=args.contamination, threshold_method=args.threshold).fit(df)
    engine.save(args.model)
    console.print(f"[green]Trained ensemble on {len(df)} events → [cyan]{args.model}[/cyan][/green]")
    console.print(
        f"Features: {len(df.columns)}, threshold: [bold]{engine.threshold_:.4f}[/bold] "
        f"(method: {args.threshold}, contamination: {args.contamination})"
    )
    return 0


def cmd_hunt(args: argparse.Namespace) -> int:
    console.print("[bold]SOC Anomaly Detector — Hunt[/bold]")
    events = read_events(args.input)
    console.print(f"Read [cyan]{len(events)}[/cyan] log events from [cyan]{args.input}[/cyan]")
    drain, events = mine_templates(events)
    engine = AnomalyEngine.load(args.model) if os.path.exists(args.model) else None
    if engine is None:
        console.print(f"[yellow]No trained model at {args.model}; training from input logs...[/yellow]")
        engine = AnomalyEngine(
            contamination=args.contamination, threshold_method=args.threshold
        ).fit(extract_features(events, drain))
        engine.save(args.model)
    _detect_and_report(events, engine, drain, args)
    return 0


def cmd_simulate(args: argparse.Namespace) -> int:
    console.print("[bold]SOC Anomaly Detector — Simulate (end-to-end)[/bold]")
    generator = importlib.import_module("scripts.generate_soc_logs")
    console.print(
        f"Generating {args.benign_count} benign events over {args.days} day(s)"
        + (" + multi-stage attack campaign" if args.attack else "")
    )
    generator.generate_soc_logs(
        days=args.days,
        benign_count=args.benign_count,
        attack=args.attack,
        seed=args.seed,
        output=args.output,
    )
    console.print(f"Generated logs → [cyan]{args.output}[/cyan]")
    events = read_events(args.output)
    drain, events = mine_templates(events)
    df = extract_features(events, drain)
    engine = AnomalyEngine(contamination=args.contamination, threshold_method=args.threshold).fit(df)
    engine.save(args.model)
    _detect_and_report(events, engine, drain, args)
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    _apply_config_defaults(args)
    return int(args.func(args) or 0)


if __name__ == "__main__":
    raise SystemExit(main())
