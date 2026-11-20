# SOC Anomaly Detector & Local LLM MITRE ATT&CK Triage Agent

[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![scikit-learn](https://img.shields.io/badge/scikit--learn-1.4%2B-orange.svg)](https://scikit-learn.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Ollama](https://img.shields.io/badge/ollama-local%2Fair-gapped-green.svg)](https://ollama.com/)
[![Tests](https://img.shields.io/badge/pytest-27%20passing-brightgreen.svg)](tests/)

A **privacy-first** unsupervised SOC log anomaly detector with a local
[MITRE ATT&CK](https://attack.mitre.org/) triage agent. High-volume system and
endpoint telemetry (Linux `auth.log`/`auditd`, Windows Sysmon JSON, Elastic
Common Schema JSONL) is normalized into a unified event schema, clustered into
structural templates, and scored with an unsupervised
[Isolation Forest](https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.IsolationForest.html)
+ autoencoder (`sklearn.neural_network.MLPRegressor`) ensemble. Only
high-risk anomalies are routed to a **local, air-gapped LLM** (via
[Ollama](https://ollama.com/)) for MITRE ATT&CK classification, narrative, and
incident response playbooks — or, with zero infrastructure, to a deterministic
offline knowledge base for headless CI/CD.

```
┌─────────────────────────────────────────────────────────────────────────┐
│  Raw logs (Linux auth.log / auditd · Windows Sysmon JSON · ECS JSONL)   │
│                        │                                                │
│                        ▼  core/parser.py + Drain (structural            │
│                          templates, masked, IDF rarity, pair rarity)    │
│                 Unified events + canonical templates                     │
│                        │                                                │
│                        ▼  core/features.py (Shannon entropy,            │
│                          lineage rarity, sliding host+user windows:    │
│                          rolling velocity, deltas, fan-out, off-hours)  │
│                 Behavioral feature frame                                 │
│                        │                                                │
│                        ▼  models/anomaly_engine.py                      │
│                 Isolation Forest + autoencoder ensemble                 │
│                 (anomaly_score ∈ [0,1], MAD/quantile thresholds,        │
│                  Z-score feature attributions)                          │
│                        │                                                │
│                        ▼  agent/mitre_triage.py                         │
│                 Local Ollama LLM (MITRE mapping, narrative,             │
│                 playbooks) + deterministic offline fallback             │
│                 (data/mitre_kb.json)                                    │
│                        │                                                │
│                        ▼  reporters/exporter.py                         │
│                 triaged_incidents.json (ECS) + reports/soc_triage_report.html │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Quickstart

```bash
# 1. Install dependencies (Python ≥ 3.10)
pip install -r requirements.txt

# 2. Generate a synthetic multi-day corpus (benign + 4-stage attack campaign)
python scripts/generate_soc_logs.py -o simulated_soc_logs.jsonl --benign-count 2000 --days 7

# 3. Train the unsupervised ensemble on baseline logs
python main.py train -i simulated_soc_logs.jsonl --model models/soc_ensemble.joblib

# 4. End-to-end simulation (generate → train → hunt → export)
python main.py simulate --days 7 --benign-count 2000

# 5. Hunt live logs with the local LLM triage agent (Ollama must be running)
python main.py hunt -i simulated_soc_logs.jsonl --ollama-model llama3.2 --html report.html

#    or fully offline (deterministic MITRE fallback, no Ollama needed):
python main.py hunt -i simulated_soc_logs.jsonl --offline
```

With a local Ollama server running (`ollama serve`, `ollama pull llama3.2`),
step 5 streams each anomaly to the LLM for MITRE ATT&CK classification and
playbook generation; without it, the deterministic offline triage
(`data/mitre_kb.json`) is used — identical funnel metrics, zero network.

## Module map

| Module | Purpose |
|--------|---------|
| `core/parser.py` | Multi-format log normalization + Drain-style template miner (masks `<IP>`, `<PORT>`, `<PID>`, `<HEX>`, `<HASH>`, `<UUID>`, `<PATH>`, …) |
| `core/features.py` | Shannon entropy, process lineage rarity, sliding-window behavioral features (velocity, deltas, fan-out, off-hours) |
| `models/anomaly_engine.py` | Isolation Forest + autoencoder ensemble, MAD/quantile calibration, Z-score attributions |
| `agent/mitre_triage.py` | Async Ollama Pydantic-validated triage agent + deterministic offline fallback |
| `reporters/exporter.py` | ECS JSON (`triaged_incidents.json`) + standalone dark-mode HTML SOC briefing |
| `main.py` | `train` / `hunt` / `simulate` CLI with a rich dashboard and funnel metrics |
| `scripts/generate_soc_logs.py` | Synthetic enterprise + multi-stage attack log generator |
| `data/mitre_kb.json` | Curated offline MITRE ATT&CK knowledge base (10 techniques) |
| `THEORY.md` | Architectural deep-dive (Drain math, IF path lengths, autoencoder MSE, prompt engineering) |
| `tests/test_soc_triage.py` | 27 unit + integration tests |

## CLI reference

```
soc-triage train  -i BASELINE_LOGS.jsonl [--model models/soc_ensemble.joblib]
                  [--contamination 0.05] [--threshold mad|quantile]

soc-triage hunt   -i LIVE_LOGS.jsonl [--model models/soc_ensemble.joblib]
                  [--ollama-model llama3.2] [--ollama-url http://localhost:11434/api/generate]
                  [--html reports/soc_triage_report.html] [--json triaged_incidents.json]
                  [--top 50] [--offline]

soc-triage simulate [--days 7] [--benign-count 1200] [--seed 42] [--attack|--no-attack]
                    [--output simulated_soc_logs.jsonl] [--model models/soc_ensemble.joblib]
                    [--ollama-model llama3.2] [--html …] [--json …] [--offline]
```

Defaults come from `config.yaml`. Log formats accepted by `-i`/`--input`:
`.jsonl` (unified schema *or* Sysmon/ECS records), `auth.log`/`secure` (Linux),
and generic `timestamp host user message` text files.

## Docker

```bash
docker compose up --build ollama-puller soc-triage   # pulls llama3.2 + runs the engine
docker compose logs -f soc-triage                    # live funnel dashboard
```

Artifacts are mounted into `./models`, `./reports`, `./data`, `./logs`.
The `soc-triage` service runs with a non-root user and requires no host
network for detection; Ollama is a separate service on localhost-only.

## Testing

```bash
python -m pytest -q          # 27 tests
```

## Outputs

* **`triaged_incidents.json`** — SIEM-ready ECS events, one JSON object per
  line: `@timestamp`, `host`, `user`, `process`, `source`/`destination`,
  `mitre.{tactic,technique,confidence}`, `event.severity`, severity badges,
  and `incident.{playbook, hunting_queries}`.
* **`reports/soc_triage_report.html`** — standalone dark-mode briefing with
  severity summary table, per-incident MITRE mapping, containment & response
  playbooks, and SIEM hunting queries.
* **Rich CLI dashboard** — funnel metrics
  (`Raw Events → Deduplicated Anomalies → Triaged MITRE Incidents`),
  color-coded severity badges, and the incident table.

## Privacy & security notes

* Volatile values are masked (`<IP>`, `<PORT>`, `<PID>`, `<HEX>`, `<HASH>`,
  `<UUID>`, `<PATH>`, …) before anything is logged or sent — see `THEORY.md`.
* The LLM prompt carries only masked, aggregated telemetry; nothing leaves the
  perimeter. `--offline` or Ollama downtime deterministically routes to the
  curated offline MITRE KB.
* `THEORY.md` documents the full design: Drain parsing, Isolation Forest path
  lengths, reconstruction-error scoring, MAD calibration, Z-score
  attribution, and the prompt-engineering contract for deterministic JSON triage.
