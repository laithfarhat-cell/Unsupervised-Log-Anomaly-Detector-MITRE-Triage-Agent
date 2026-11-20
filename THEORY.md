# SOC Anomaly Detector — Theory & Architecture

Architectural deep-dive covering Drain log parsing, Isolation Forest path-length
mathematics, reconstruction-error anomaly scoring, and prompt engineering for
deterministic JSON security triage.

---

## 1. System overview

```
Raw logs (Linux auth.log/auditd, Windows Sysmon JSON, ECS JSONL, ...)
        │
        ▼
core/parser.py            Multi-format normalization → unified LogEvent
                          + Drain-style template mining (structural signatures,
                          IDF rarity, process parent-child pair rarity)
        │
        ▼
core/features.py          Behavioral feature engineering:
                          Shannon entropy / special-char density (obfuscation),
                          template + lineage rarity, sliding host+user windows
                          (rolling velocity, deltas, destination fan-out, off-hours)
        │
        ▼
models/anomaly_engine.py  Unsupervised ensemble:
                            • Isolation Forest (path-length outliers)
                            • Autoencoder (MLPRegressor) reconstruction error
                          Unified anomaly_score ∈ [0,1]
                          (MAD / quantile threshold calibration, Z-score attributions)
        │
        ▼
agent/mitre_triage.py     Local Ollama LLM triage (MITRE mapping, narrative,
                          playbooks) + deterministic offline fallback
                          (data/mitre_kb.json)
        │
        ▼
reporters/exporter.py     ECS JSON (triaged_incidents.json) + dark-mode HTML
                          SOC briefing (reports/soc_triage_report.html)
        │
        ▼
main.py                   CLI: train | hunt | simulate (rich dashboard, funnel)
```

---

## 2. Drain: fast, deterministic structural template mining

`core/parser.py` implements Drain-inspired log template extraction. The classic
Drain builds an ID-Ftree (prefix tree) of structural signatures and merges a
line into a cluster when similarity meets a threshold. This implementation uses
a flat dict keyed by the padded first `depth` tokens — equivalent for cluster
selection, simpler and deterministic.

### 2.1 Variable masking

Before clustering, volatile parameters are masked into canonical placeholders
(ordered rules in `_MASK_RULES`):

| Mask | Example |
|------|---------|
| `<IP>` | `10.0.0.5` |
| `<MAC>` | `00:11:22:33:44:55` |
| `<HASH>` | SHA-256 / SHA-1 hex digests |
| `<HEX>` | 32-char MD5-ish hex, or any remaining 6+-char hex run |
| `<UUID>` | `9f8d7c6b-1234-5678-9abc-def012345678` |
| `<PATH>` | `/var/log/auth.log`, `C:\Windows\System32\svchost.exe` |
| `<EMAIL>` | `user@example.com` |
| `<TIME>` | `12:34:56` / `12:34:56` (2- and 3-part forms) |
| `<PORT>` | `port 52344`, `https://host:443/path` |
| `<PID>` | `pid=123`, `sshd[123]`, `tid[456]` |
| `<NUM>` | every remaining integer (Drain's classic "number" mask) |

### 2.2 Tokenization

`tokenize(masked_line)` — a small regex (`<[^<>\s]+>|[A-Za-z0-9]+`) splits the
masked line into tokens where placeholders are atomic tokens (`<IP>`, `<HEX>`).

### 2.3 Prefix key + similarity

`Drain._key(tokens)` = the first `depth` (default 3) tokens, padded with `""`.
Each cluster stores the full masked token signature of the first line that
created it. For a new line, candidates in the bucket are scored by

```
similarity(cluster, line) = |{i : cluster[i] == line[i]}| / max(len(cluster), len(line))
```

If the best similarity ≥ `sim_threshold` (default 0.6) the line is merged
(count += 1); otherwise a new cluster (template) is created. This mirrors
classic Drain's tree walk while allowing lines of different lengths to align.

### 2.4 Template ids and rarity (IDF)

- `template_frequency[tid]` — number of log lines mapped to the template.
- `n_docs` — total lines mined.
- `rarity(tid) = log((n_docs + 1) / (freq + 1))` — higher == rarer. Common
  templates → 0, unseen templates (live logs) → maximally rare,
  `log(n_docs + 1)`.
- `pair_counts[(parent, child)]` + `n_pairs` — process lineage rarity,
  `pair_rarity(parent, child) = log((n_pairs + 1) / (count + 1))`.

These feed the `template_rarity` and `pair_rarity` features
(`core/features.py`).

---

## 3. Behavioral feature engineering (`core/features.py`)

`extract_features(events, drain, window)` returns the feature frame
(`FEATURE_COLUMNS`):

* `template_rarity` — Drain IDF rarity of the event template.
* `pair_rarity` — Drain rarity of `(parent_process → process_name)`.
* `cmd_length`, `cmd_entropy` (Shannon entropy over characters, base-2),
  `cmd_special_density` — command-line obfuscation metrics
  (Base64/XOR/hex payloads read as high-entropy, special-char heavy text).
* `off_hours` — 1 if the event hour is in `OFF_HOURS_DEFAULT` (22,23,0–6).
* `rolling_events_60s / rolling_events_900s / rolling_events_3600s` — per
  `(host, user)` sliding velocity (event counts in each window).
* `delta_since_last`, `delta_to_recent_mean` — inter-event deltas (seconds).
* `host_fan_out_1h` — distinct destination IPs observed for the entity in the
  last hour (new-destination burst signal).

`WindowStats` keeps bounded deques (`maxlen = 2000`) per `(host, user)` entity
and evicts entries older than the largest window.

---

## 4. Isolation Forest (`models/anomaly_engine.py`)

### 4.1 Path length and the isolation score

For a point `x`, an isolation tree is grown until each point sits alone
(external node). The path length `h(x)` is the number of edges from the root to
the leaf. For a subsample of size `n` (sklearn: `max_samples="auto"` →
`min(n, 256)`), the average path length is bounded by

```
c(n) = 2H(n−1) − 2(n−1)/n,   H(k) = ln(k) + γ + 1/(2k)   (k = n − 1 ≥ 1)
```

where `H(i)` is the `i`-th harmonic number and `γ ≈ 0.5772` the
Euler–Mascheroni constant (for `n ≤ 1`, `c(n) = 0`).

The isolation score of a point, averaging `E[h(x)]` over ψ trees:

```
s(x) = 2^(−E[h(x)] / c(n))
```

Points with `s → 1` are isolated early (anomalous); points with `s → 0.5` are
deep in the tree (normal).

### 4.2 sklearn glue

sklearn's `IsolationForest` returns from `score_samples` the *opposite* of the
paper score (larger = more normal, offset by `offset_`). So our anomaly
signal is `raw_if = -if_.decision_function(X)`, min-max normalized on the
training range into `isf_score ∈ [0, 1]`:

```
isf_score = clip((raw_if − if_lo) / (if_hi − if_lo), 0, 1)
```

---

## 5. Autoencoder reconstruction error (`Autoencoder`)

`Autoencoder` wraps `sklearn.neural_network.MLPRegressor` (the task's
chosen engine) as an undercomplete network: `fit(X, X)` trains the
input→hidden→…→input mapping, `predict(X)` reconstructs. The anomaly deviation
is the mean squared reconstruction error per row:

```
mse(x) = (1/d) · Σᵢ (xᵢ − x̂ᵢ)²          (d = feature count)
```

Normalization mirrors Isolation Forest: `ae_score = clip((mse − ae_lo) /
(ae_hi − ae_lo), 0, 1)` on the training error range. Convergence warnings are
deliberately suppressed for tiny corpora — strict convergence isn't required
for a meaningful reconstruction signal.

---

## 6. Ensemble scoring, calibration and attribution

### 6.1 Combined score

```
anomaly_score = if_weight · isf_score + ae_weight · ae_score      (defaults 0.6/0.4)
```

### 6.2 Threshold calibration (`_calibrate_threshold`)

* `mad` (default): `threshold = median(scores) + mad_k · 1.4826 · MAD(scores)`,
  clipped to `[0, 1]` (MAD ≥ 0.01 floor for sensitivity).
* `quantile`: `threshold = quantile(scores, 1 − contamination)` (the
  contamination quantile from Isolation Forest training).

### 6.3 Z-score feature attribution

`train_means_`/`train_stds_` store the training feature statistics;
`_attributions` computes per-row

```
z_j = (x_j − μ_j) / σ_j        (σ_j floored at 1.0 for zero-variance features)
```

and `predict` returns the top-5 features by |z| per row — the explanation of
*which* features drove each alert. These flow into the triage prompt and the
ECS export.

### 6.4 Alert lifecycle

`dedupe_anomalies` collapses the noisy per-event anomaly stream: one row per
`(entity, template_signature)` key, keeping the highest `anomaly_score`,
assigning stable `INC-0001…` ids, sorted best-first.

---

## 7. MITRE triage agent (`agent/mitre_triage.py`)

### 7.1 Online path (local Ollama)

`triage_anomalies(rows)` fans out with a semaphore. Per row:

1. `POST {ollama_url}` (default `http://localhost:11434/api/generate`) with
   `{"model": ..., "prompt": ..., "stream": False, "format": "json",
   "options": {"temperature": 0.05, "num_predict": 2048, "repeat_penalty":
   1.05}}` — JSON mode guarantees the model emits a JSON object, not prose.
2. Response parsed: fences stripped, `json.loads`, then strict
   `IncidentCard.model_validate` (Pydantic v2, `extra="forbid"` — unknown keys
   reject the response and trigger the offline fallback).
3. Validators normalize drift (`severity`/`mitre_confidence` alias maps,
   technique-id patterns like `T1059.001`, list sanitizers).

### 7.2 Prompt engineering for deterministic JSON

The prompt lists the anomaly context (masked telemetry only) and an exact key
list ("no extra keys, no explanations, no code fences, output nothing else").
Each key's type/format is spelled out (`TA + 4 digits`, `T + 4 digits
optionally followed by .subid`, severity/confidence enums, "3 sentences",
"at least one"). Low temperature (0.05) reduces sampling noise. The
`format: "json"` server flag plus strict schema means the output is
parseable by construction; validators are the second line of defense.

### 7.3 Deterministic offline fallback

`triage_offline(row)` — pure function of the anomaly row (no network):

1. `_match_kb_entry(row)`: scores each KB entry by counting how many of its
   `indicators` appear (case-insensitive) in the row's host, user, process,
   parent, command line, template signature and IPs; weights by entry
   confidence.
2. Build the `IncidentCard` from the KB entry: `tactic_id`, `technique_id`,
   names, confidence, `containment_steps`, `hunting_queries` (rendered with
   the row context) and a `narrative_template` rendered with
   `{parent_name, child_name, cmd, host, entity, actor, ...}`.
3. If nothing matches, `DEFAULT_NARRATIVE`/`DEFAULT_CONTAINMENT`/
   `DEFAULT_HUNTING_QUERIES` produce a well-formed card with a generic
   `T1059` mapping.

The fallback is deterministic: identical input → identical `IncidentCard`.

### 7.4 Curated offline KB (`data/mitre_kb.json`)

10 technique entries covering the realistic triage vocabulary:
`T1059.001` (PowerShell), `T1059.004` (Unix Shell), `T1105` (Ingress Tool
Transfer), `T1003` (OS Credential Dumping), `T1110.003` (Password Spraying),
`T1110.004` (Credential Stuffing), `T1021.004` (SSH lateral movement),
`T1566.001` (Spearphishing Attachment), `T1078.003/004` (Valid Accounts). Each
entry carries `indicators`, `narrative_template`, `containment_steps`,
`hunting_queries` — the assets the offline triage consumes.

---

## 8. Privacy & security design

* **Masking** (§2.1) removes volatile values before any logging/triage.
* **Prompt hygiene**: the Ollama prompt contains only masked telemetry
  (template signature, process names, masked command line, IPs, Z-scores).
  No raw log lines, no user payloads are shipped.
* **Air-gap by default**: Ollama is a local, on-prem server; nothing in the
  pipeline phones out. The `--offline` flag (and the fully-local fallback)
  guarantee a headless/CI-safe path.
* **Strict validation**: any LLM response that deviates (invalid JSON, extra
  keys, out-of-range values) is rejected and replaced by the deterministic
  offline triage — the pipeline cannot silently trust drift.

---

## 9. Determinism & reproducibility

* Drain: dict iteration + greedy similarity → deterministic for a corpus.
* `AnomalyEngine`: `random_state` fixed for Isolation Forest and the
  autoencoder MLP; MAD/quantile thresholds are deterministic functions of the
  training scores.
* `triage_offline`: pure function of the anomaly row.
* Generator: `scripts/generate_soc_logs.py` seeds `random.Random(seed)` and
  generates a fixed multi-day corpus + the 4-stage attack campaign
  (macro → encoded PowerShell-style → credential dumping → lateral movement).
* Verified: `generate_soc_logs(seed=3, ...)` produces byte-identical corpora
  (`tests/test_soc_triage.py::test_generator_deterministic`).

---

## 10. Tuning knobs

| Knob | Default | Meaning |
|------|---------|---------|
| `models/anomaly_engine.AnomalyEngine(contamination=0.05)` | 5% of rows alert | |
| `threshold_method="mad"`, `mad_k=2.5` | median + 2.5·MAD | `quantile` alternative |
| `if_weight=0.6 / ae_weight=0.4` | ensemble blend | |
| `core/features.OFF_HOURS_DEFAULT` | 22,23,0–6 | off-hours indicator |
| `WindowStats(windows=(60, 900, 3600))` | rolling velocity | |
| `agent/mitre_triage MITRETriageAgent(temperature=0.05)` | low LLM drift | |

---

## 11. Known limitations

* Isolation Forest + MLP on hand-engineered features is a strong starting
  point; very subtle threats need richer telemetry (network flows, DNS,
  process creation auditing) — add them as new feature columns; the engine
  and attribution pipeline are agnostic to column names.
* The offline KB is a curated subset of MITRE tactics (§7.4) — extend
  `data/mitre_kb.json` for new environments.
* Drain uses whole-line structural matching; highly variable messages
  (many unique IDs) can still create many clusters — increase `depth` or
  widen `sim_threshold` if clusters fragment.
