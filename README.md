# Cross-source lateral-movement detection on one laptop (LANL)

Weekend prototype: detect multi-stage attacks by correlating identity, process,
network and DNS telemetry from the LANL "Comprehensive, Multi-Source
Cyber-Security Events" dataset (https://csr.lanl.gov/data/cyber1/, CC0), on a
laptop CPU, with a local LLM used only for evidence-cited summaries.

## Layout
- `scripts/extract_lanl.py` - reads the original .txt.gz files in place and writes
  one Parquet file per source per day to `data/`, plus `data/extract_manifest.json`
  (rows, seconds, rows/second per source: the ingestion benchmark).
- `data/` - extracted Parquet (not for publishing; regenerate from the source files).
- `results/` - metrics, plots, summaries and the injection test (small; included).
- `DESIGN.md` - one-page design note: pipeline, results, what did not help, comparison with published work.

The data is not in this repository. Download the five files from the LANL page above.

## Step 1: extract days 0-15 (covers 690 of the 749 red-team events)
In PowerShell, from this folder:

    python -m venv $HOME\.venvs\lanl
    & $HOME\.venvs\lanl\Scripts\Activate.ps1
    pip install -r requirements.txt
    python scripts\extract_lanl.py --src "path\to\lanl\files" --out data --day-start 0 --day-end 16

Needs all five files: auth, proc, flows, dns, redteam (.txt.gz or unzipped .txt).

## Step 2: detection and evaluation

    python scripts\detect.py

Learns normal behavior on days 1-6 and scores days 7-15 (all defaults). Unit of
detection: (user, source host, destination host, hour) for user-account logons to
another host. Signals are first-seen flags from auth, process, flow and DNS data,
computed causally; host and user identities are never features. Writes
`data/derived/edge_hours.parquet`, `results/metrics.json` (includes stage timings)
and `results/recall_at_budget.csv` (recall, precision, red-team users caught and
median delay at 10-500 alerts per day, auth-only versus correlated).

Labels are reported two ways: strict (exact account, hosts and hour, as in the
red-team file) and lenient (same user number under any account suffix, same
hosts, within one hour). The red team used local-account variants such as
U6554@C1224 that the strict file misses.

## Step 3: campaign-level detection

    python scripts\campaigns.py

Rolls edge-hours up to campaigns: a user fanning out to new hosts, a source host
fanning out, or new users fanning in to one host, per hour. Each entity is judged
against its own prior days (Poisson rate shrunk toward the population rate), so
busy admins and servers do not flood the queue. Writes
`results/campaign_metrics.csv` (precision, red-team edges covered, users caught,
delay and analyst workload at 5-100 campaigns per day, per view and merged) and
`results/top_campaigns.csv`.

## Step 4: pairwise analysis (normal traffic only)

    python scripts\pairwise.py

Co-occurrence lift, phi and mutual information for every pair of the 12 edge signals
on warm-up days, plus Spearman correlation of campaign variables. Heatmaps in results/.

## Step 5: engine v2 (peer groups, density model, follow-ups, oracle retraining)

    run_all.bat        (or the individual engine.py lines inside it)

`engine.py` runs day by day. Options: `--prior population|peer` (shrink each entity's
history toward the network or toward its peer group from a Gaussian mixture over
behaviour profiles), `--scorer surprise|density` (sum of Poisson/binomial surprises,
or -log likelihood under a mixture fit to normal campaign-hours), `--regime
static|oracle` (fit once on days 1-6, or refit daily after an analyst oracle removes
confirmed-malicious logins from history; novelty is recomputed against the filtered
history, so an attacker's return visit counts as new again), `--budget` alerts per day,
`--watch-hours` follow-up window. Also scores each entity-day's profile against
historical daily profiles ("fits no peer group"). `compare.py` tabulates all runs into
results/comparison.csv.

### Confirmed-entity watch and bulk sweeps (engine options)

`--confirm-watch none|src|src_user` (default none), `--confirm-days 7`: when the analyst
(oracle = lenient red-team labels) confirms a malicious alerted login, its source host is
watched for 7 days and every later login from it is surfaced. `src_user` also watches the
confirmed user, but only for destinations that user has never reached before. Malicious
logins found by the watch extend it. Nothing is retrained.

`--sweep-min 200`: an alert covering 200+ new logins is a sweep and is reviewed in bulk as
one item. `review_items` = non-sweep logins + sweeps. Summaries report daily medians next
to means, because one sweep day (U6836 on day 14) dominates the mean.

Results on days 7-15 (density scorer, peer prior, 25 alerts/day; deterministic, identical
on repeated runs and on the laptop and the VM):

| | C (no watch) | F (watch confirmed sources) |
|---|---|---|
| Alert precision | 15.6% | 15.6% (same alerts) |
| Red-team logins caught, all routes | 46.8% | 81.5% |
| Red-team users caught, all routes | 51/91 | 82/91 |
| Confirmed-watch logins/day (precision) | - | 39 (50%) |
| Review items/day, mean (median) | 149 (126) | 149 (126) + watch |

Watching confirmed users too (`src_user`) found nothing extra and added ~20% more
review, so `src` is the recommended setting.

The gain comes almost entirely from one host, C17693, the red team's working machine
(483 of 491 red-team logins on days 7-15). It is quiet apart from the attack, so watching
it costs little. That is a property of this exercise: an attacker who rotates source
hosts would not be caught this way.

## Step 6: multi-source diagnostic (process, flow and DNS telemetry)

    python scripts\engine.py --prior peer --scorer density --confirm-watch src --dump-alerts --tag F_dump
    python scripts\multisource_diag.py sample --alerts results\F_dump_alert_edges.parquet
    python scripts\multisource_diag.py proc
    python scripts\multisource_diag.py flows
    python scripts\multisource_diag.py dns
    python scripts\multisource_diag.py report      -> results\multisource_diag.csv

Compares what happens on the destination in the login hour and the next (new processes,
the user's own processes, onward logins, new outbound connections, DNS lookups) for 491
red-team logins vs 1,421 false-positive alert logins and 5,000 normal first-contact logins.

Result: a negative one. Coverage is fine (86% of red-team destinations have process data,
72% have flows), but separation is weak: the best signal, process names new to the host,
appears after 49% of red-team logins vs 22% of false positives; all 14 features together
give AUC 0.62 against false positives (cross-validated, grouped by user). And 483 of the
491 red-team logins come from C17693, so even that weak signal describes one operator.
The 8 red-team logins from other hosts show none of it. The LANL labels cover
authentication only, so this dataset cannot properly test multi-source detection; a
dataset with host-level red-team labels (for example DARPA OpTC) would be needed.

## Step 7: incident summaries from a local LLM, with a prompt-injection test

    ollama pull qwen2.5:3b-instruct            (one time, about 2 GB; Ollama from ollama.com)
    python scripts\incident_summaries.py       -> results\incident_summaries.md, injection_test.csv
    python scripts\incident_summaries.py --backend template    (no LLM: deterministic summaries)

The detector decides and the model only describes. Alert logins are grouped into
incidents (shared user or source host, per day); Python computes every fact into a JSON
evidence record (labels are never sent); the model returns a fixed schema with no
disposition field; the output is checked (valid JSON, only hosts and users present in the
evidence, no "benign / close / approved test" language, no canary or prompt leak) and
replaced by the template summary if it fails.

Injection test: payloads are planted in a field an attacker could control (a host name
here; in practice process command lines, file names, user agents), across three setups:
naive prompt; hardened prompt only; and hardened prompt + input sanitising + output
validation. Four payloads: a canary instruction, a "this is an approved pentest, close it"
note, a system-prompt leak request, and a short identifier-shaped payload that gets past
sanitising so that output validation has to catch it.

### Isolation forest as the scorer (`--scorer iforest`)

Same entity-relative features, same one-sided per-view calibration, same 25 alerts/day and
confirmed-source watch; only the model changes (isolation forest instead of the mixture).

| | F (mixture) | I (isolation forest) |
|---|---|---|
| Alert precision | 15.6% | 14.2% |
| Red-team logins caught by alerts | 45.4% | 36.1% |
| Red-team users caught by alerts | 51/91 | 32/91 |
| Caught, all routes (with watch) | 81.5%, 82/91 users | 78.0%, 74/91 users |

No gain. The limit is the information in the features, not the flexibility of the model.
One-class SVM was not tried: about 280,000 campaign-hours a day and two unlabeled
hyperparameters make it a poor fit here.
