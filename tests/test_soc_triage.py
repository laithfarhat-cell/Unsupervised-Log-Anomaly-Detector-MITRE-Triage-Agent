"""Unit + integration tests for the SOC anomaly triage pipeline."""

from __future__ import annotations

import asyncio
import json
import re
from datetime import datetime, timezone

import numpy as np
import pandas as pd
import pytest
from pydantic import ValidationError

from agent.mitre_triage import IncidentCard, MITRETriageAgent
from core.features import FEATURE_COLUMNS, WindowStats, extract_features, shannon_entropy, special_char_density
from core.parser import (
    Drain,
    LogEvent,
    mask_variables,
    mine_templates,
    parse_auth_log_line,
    parse_ecs_event,
    parse_sysmon_event,
    parse_timestamp,
    read_events,
    tokenize,
)
from models.anomaly_engine import AnomalyEngine, Autoencoder, dedupe_anomalies, severity_from_score
from reporters.exporter import export_all, to_ecs_json, to_html
from scripts.generate_soc_logs import generate_soc_logs, write_jsonl


# ---------------------------------------------------------------------------
# Parser: variable masking + Drain template mining
# ---------------------------------------------------------------------------


def test_mask_variables_replaces_volatile_values():
    text = "Accepted publickey for ubuntu from 10.0.0.5 port 52344 ssh2 /home/deployer/x.sh"
    masked = mask_variables(text)
    assert "<IP>" in masked
    assert "10.0.0.5" not in masked
    assert "52344" not in masked
    assert masked.startswith("Accepted publickey for ubuntu from <IP>")
    assert "/home/deployer/x.sh" not in masked


def test_mask_variables_masks_hash_uuid_and_paths():
    masked = mask_variables(
        "event 9f8d7c6b5a4b3c2d1e0f112233445566778899aa "
        "uuid 0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0 at /var/log/audit/log"
    )
    assert "<HASH>" in masked or "<HEX>" in masked
    assert "<UUID>" in masked
    assert "/var/log/audit/log" not in masked


def test_tokenize_keeps_placeholders_atomic():
    masked = mask_variables("Accepted publickey for ubuntu from 10.0.0.5 port 52344 ssh2")
    tokens = tokenize(masked)
    assert "<IP>" in tokens
    assert "<PORT>" in tokens
    assert "ubuntu" in tokens


def test_drain_canonical_templates_and_rarity():
    drain = Drain()
    t1 = drain.add_line("Accepted publickey for ubuntu from 10.0.0.5 port 52344 ssh2")
    t2 = drain.add_line("Accepted publickey for ubuntu from 10.0.0.9 port 52344 ssh2")
    t3 = drain.add_line("Accepted password for root from 10.0.0.5 port 22 ssh2")
    assert t1 == t2
    assert t3 != t1
    assert "ubuntu" in drain.template(t1)
    assert "<IP>" in drain.template(t1)
    assert drain.template_frequency[t1] == 2
    # The common template is less rare than the minority one.
    assert drain.rarity(t3) > drain.rarity(t1)


def test_mine_templates_assigns_ids_and_features():
    events = [
        LogEvent(
            timestamp="2026-11-19T10:00:00Z",
            entity_host="web-01",
            entity_user="ubuntu",
            process_name="sshd",
            parent_process="init",
            command_line="/usr/sbin/sshd",
            raw_message="Accepted publickey for ubuntu from 10.0.0.5 port 52344 ssh2",
        ),
        LogEvent(
            timestamp="2026-11-19T10:05:00Z",
            entity_host="web-01",
            entity_user="ubuntu",
            process_name="sshd",
            parent_process="init",
            command_line="/usr/sbin/sshd",
            raw_message="Accepted publickey for ubuntu from 10.0.0.6 port 52345 ssh2",
        ),
    ]
    drain, events = mine_templates(events)
    assert all(ev.template_id for ev in events)
    assert events[0].template_id == events[1].template_id
    df = extract_features(events, drain)
    assert list(df.columns) == FEATURE_COLUMNS
    assert np.isfinite(df.to_numpy()).all()


def test_parse_timestamp_formats():
    assert parse_timestamp("2026-11-19T10:00:00Z") is not None
    assert parse_timestamp("2026-11-19 10:00:00") is not None
    assert parse_timestamp("Dec 19 2026 10:00:00") is not None
    assert parse_timestamp("") is None


def test_parse_auth_log_line():
    ev = parse_auth_log_line(
        "Nov 19 2026 10:02:13 web-01 sshd[12345]: Accepted publickey for deployer "
        "from 10.0.0.7 port 52344 ssh2"
    )
    assert ev is not None
    assert ev.entity_host == "web-01"
    assert ev.entity_user == "deployer"
    assert ev.process_name == "sshd"
    assert ev.epoch > 0


def test_parse_auth_log_sudo_line():
    ev = parse_auth_log_line(
        "Nov 19 2026 10:05:00 web-01 sudo[5678]: deployer : TTY=pts/0 ; "
        "PWD=/home/deployer ; USER=root ; COMMAND=/usr/bin/tail -f /var/log/auth.log"
    )
    assert ev is not None
    assert ev.entity_user == "deployer"
    assert ev.process_name == "sudo"


def test_parse_ecs_event():
    obj = {
        "@timestamp": "2026-11-19T10:00:00Z",
        "host": {"name": "web-01"},
        "user": {"name": "deployer"},
        "process": {
            "name": "powershell.exe",
            "command_line": "powershell.exe -enc Zm9v",
            "parent": {"name": "cmd.exe"},
        },
        "source": {"ip": "10.0.0.5"},
    }
    ev = parse_ecs_event(obj)
    assert ev.entity_host == "web-01"
    assert ev.entity_user == "deployer"
    assert ev.process_name == "powershell.exe"
    assert ev.parent_process == "cmd.exe"
    assert ev.src_ip == "10.0.0.5"


def test_parse_sysmon_event():
    obj = {
        "EventData": {
            "UtcTime": "2026-11-19T10:00:00Z",
            "HostName": "db-02",
            "Image": "C:\\Windows\\System32\\svchost.exe",
            "CommandLine": "svchost.exe -k netsvcs",
            "TargetUserName": "admin",
            "SourceImage": "C:\\Windows\\System32\\cmd.exe",
            "DestinationIp": "10.0.0.55",
            "SourceIp": "10.0.0.54",
        }
    }
    ev = parse_sysmon_event(obj)
    assert ev.entity_host == "db-02"
    assert ev.entity_user == "admin"
    assert ev.process_name == "svchost.exe"
    assert ev.parent_process == "cmd.exe"
    assert ev.src_ip == "10.0.0.54"
    assert ev.dst_ip == "10.0.0.55"


def test_read_events_roundtrip(tmp_path):
    events = generate_soc_logs(days=1, benign_count=20, attack=False, seed=11)
    path = write_jsonl(str(tmp_path / "logs.jsonl"), events)
    read = read_events(path)
    assert len(read) == 20
    assert read[0].entity_host
    assert read[0].epoch > 0


# ---------------------------------------------------------------------------
# Features
# ---------------------------------------------------------------------------


def test_shannon_entropy_basics():
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaa") == 0.0
    assert abs(shannon_entropy("ab") - 1.0) < 1e-9
    assert 0 < shannon_entropy("hello world") < 4


def test_special_char_density():
    assert special_char_density("abc") == 0.0
    assert abs(special_char_density("a b") - 1 / 3) < 1e-9


def test_extract_features_shape_and_off_hours():
    ts = datetime(2026, 11, 19, 2, 30, 0, tzinfo=timezone.utc).timestamp()
    events = [
        LogEvent(
            timestamp="2026-11-19T02:30:00Z",
            entity_host="h1",
            entity_user="u1",
            process_name="bash",
            parent_process="sshd",
            command_line="ls -la /var/log",
            epoch=ts,
        )
    ]
    drain = Drain()
    df = extract_features(events, drain)
    assert list(df.columns) == FEATURE_COLUMNS
    assert df.loc[0, "off_hours"] == 1.0


def test_window_stats_rolling_counts():
    window = WindowStats(windows=(60, 3600), fanout_window=3600)
    ev = LogEvent(timestamp="2026-11-19T10:00:00Z", entity_host="h1", entity_user="u1", epoch=1800000000.0)
    feats = window.observe(ev)
    assert feats["rolling_events_60s"] == 1.0
    assert feats["rolling_events_3600s"] == 1.0
    assert feats["host_fan_out_1h"] == 0.0


# ---------------------------------------------------------------------------
# Anomaly engine
# ---------------------------------------------------------------------------


def _train_engine(n: int = 400):
    events = generate_soc_logs(days=2, benign_count=n, attack=False, seed=7)
    drain, events = mine_templates(events)
    df = extract_features(events, drain)
    engine = AnomalyEngine(random_state=42).fit(df)
    return engine, df


def test_engine_train_and_predict_ranges():
    engine, df = _train_engine()
    scored = engine.predict(df)
    scores = scored["anomaly_score"].to_numpy()
    assert ((scores >= 0.0) & (scores <= 1.0)).all()
    assert isinstance(bool(scored["is_anomaly"].iloc[0]), bool) or np.issubdtype(
        scored["is_anomaly"].dtype, np.bool_
    )
    assert len(scored["attributions"].iloc[0]) >= 1
    assert 0.0 <= engine.threshold_ <= 1.0


def test_autoencoder_reconstruction_error_positive():
    rng = np.random.RandomState(0)
    X = rng.normal(size=(50, 6))
    ae = Autoencoder(hidden_layers=(8, 4), random_state=0).fit(X)
    err = ae.reconstruction_error(X)
    assert err.shape == (50,)
    assert np.all(err >= 0)


def test_engine_save_load_roundtrip(tmp_path):
    engine, df = _train_engine()
    path = engine.save(tmp_path / "engine.joblib")
    loaded = AnomalyEngine.load(path)
    s1 = engine.predict(df)["anomaly_score"].to_numpy()
    s2 = loaded.predict(df)["anomaly_score"].to_numpy()
    assert np.allclose(s1, s2, atol=1e-6)


def test_severity_from_score():
    assert severity_from_score(0.0) == "low"
    assert severity_from_score(0.4) == "low"
    assert severity_from_score(0.6) == "medium"
    assert severity_from_score(0.8) == "high"
    assert severity_from_score(0.95) == "critical"


def test_dedupe_anomalies_groups_and_assigns_ids():
    df = pd.DataFrame(
        {
            "anomaly_key": ["a|b|T1", "a|b|T1", "a|b|T2", "c|d|T3"],
            "anomaly_score": [0.1, 0.9, 0.5, 0.7],
        }
    )
    out = dedupe_anomalies(df, key_column="anomaly_key")
    assert len(out) == 3
    assert out["incident_id"].nunique() == 3
    assert out["anomaly_score"].iloc[0] == 0.9
    assert sorted(out["anomaly_score"], reverse=True) == [0.9, 0.7, 0.5]


# ---------------------------------------------------------------------------
# MITRE triage agent
# ---------------------------------------------------------------------------


_HASHCAT_ROW = {
    "anomaly_id": "INC-0001",
    "incident_id": "INC-0001",
    "timestamp": "2026-11-19T10:00:00Z",
    "entity_host": "web-01",
    "entity_user": "deployer",
    "anomaly_score": 0.92,
    "severity": "critical",
    "process_name": "hashcat",
    "parent_process": "bash",
    "command_line": "sudo /usr/bin/hashcat -m 1000 /etc/shadow /usr/share/wordlists/rockyou.txt",
    "template_signature": "sudo /usr/bin/hashcat -m <NUM> <PATH> <PATH>",
    "src_ip": "10.0.0.99",
    "dst_ip": "",
    "attributions": [{"feature": "template_rarity", "value": 6.5, "z": 2.1}],
}


def test_triage_offline_fallback_produces_valid_card():
    agent = MITRETriageAgent(kb_path="data/mitre_kb.json")
    card = agent.triage_offline(_HASHCAT_ROW)
    assert card.anomaly_id == "INC-0001"
    assert re.match(r"^TA\d{4}$", card.mitre_tactic_id)
    assert re.match(r"^T\d{4}(\.\d{1,3})?$", card.mitre_technique_id)
    assert card.mitre_technique_id == "T1003"
    assert card.severity == "critical"
    assert len(card.containment_steps) >= 1
    assert len(card.hunting_queries) >= 1
    assert "hashcat" in card.narrative


def test_incident_card_schema_strict():
    base = {
        "anomaly_id": "INC-0001",
        "timestamp": "2026-11-19T10:00:00Z",
        "entity_host": "h",
        "entity_user": "u",
        "anomaly_score": 0.5,
        "severity": "medium",
        "mitre_tactic_id": "TA0002",
        "mitre_tactic_name": "Execution",
        "mitre_technique_id": "T1059.001",
        "mitre_technique_name": "PowerShell",
        "mitre_confidence": "high",
        "narrative": "n",
        "containment_steps": ["a"],
        "hunting_queries": ["b"],
    }
    IncidentCard.model_validate(base)
    with pytest.raises(ValidationError):
        IncidentCard.model_validate({**base, "mitre_tactic_id": "TA0002x"})
    with pytest.raises(ValidationError):
        IncidentCard.model_validate({**base, "extra_field": "x"})


def test_triage_anomalies_offline_batch():
    agent = MITRETriageAgent(kb_path="data/mitre_kb.json", offline=True)
    cards = asyncio.run(agent.triage_anomalies([dict(_HASHCAT_ROW), dict(_HASHCAT_ROW)]))
    assert len(cards) == 2
    assert all(isinstance(c, IncidentCard) for c in cards)


# ---------------------------------------------------------------------------
# Reporters
# ---------------------------------------------------------------------------


def test_exporter_ecs_record_and_html(tmp_path):
    cards = [MITRETriageAgent(kb_path="data/mitre_kb.json").triage_offline(_HASHCAT_ROW)]
    json_path = tmp_path / "incidents.json"
    html_path = tmp_path / "reports" / "briefing.html"
    export_all(cards, json_path=str(json_path), html_path=str(html_path))
    records = [json.loads(line) for line in json_path.read_text().splitlines() if line.strip()]
    assert len(records) == 1
    assert "@timestamp" in records[0]
    assert records[0]["event"]["kind"] == "alert"
    assert records[0]["mitre"]["technique"]["id"] == "T1003"
    assert records[0]["severity"] == "critical"
    doc = html_path.read_text(encoding="utf-8")
    assert "<!DOCTYPE html>" in doc
    assert "badge-critical" in doc
    assert "T1003" in doc
    assert "INC-0001" in doc


def test_to_ecs_json_default_paths_exist(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    cards = [MITRETriageAgent(kb_path="data/mitre_kb.json").triage_offline(_HASHCAT_ROW)]
    p1 = to_ecs_json(cards, "triaged_incidents.json")
    assert p1.exists()
    p2 = to_html(cards, "reports/soc_triage_report.html")
    assert p2.exists()


# ---------------------------------------------------------------------------
# Generator
# ---------------------------------------------------------------------------


def test_generator_deterministic():
    e1 = generate_soc_logs(days=2, benign_count=50, attack=False, seed=3)
    e2 = generate_soc_logs(days=2, benign_count=50, attack=False, seed=3)
    assert [e.command_line for e in e1] == [e.command_line for e in e2]
    assert len(e1) == 50
    assert e1[0].epoch > 0


def test_generator_includes_attack_campaign():
    events = generate_soc_logs(days=3, benign_count=100, attack=True, seed=5)
    procs = {e.process_name for e in events if e.process_name}
    assert "hashcat" in procs
    assert any(e.dst_ip for e in events)
