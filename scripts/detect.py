#!/usr/bin/env python3
"""Stage 1 (per-source novelty) and Stage 2 (cross-source correlation) on LANL Parquet.

Unit of detection: an "edge-hour" = (user, source host, destination host, hour) of
interactive/network logons by user accounts (U*) to a different host.

Every feature is behavioral and computed causally (only data up to that hour):
first-time-seen flags from auth, process, flow and DNS telemetry, plus the
destination's popularity before that day. Host and user identities are never
features, so a detector cannot score well by memorizing the red team's machine.

Scores are unsupervised: each binary signal adds its "surprise", -log(base rate),
with base rates estimated on warm-up days only. Labels (redteam) are used only to
evaluate.

    auth-only score   = surprise of the auth signals          (one tool on its own)
    correlated score  = auth + process + flow + DNS signals   (one data lake)

Writes data/derived/edge_hours.parquet (scored test edge-hours) and
results/metrics.json (incl. timings) and results/recall_at_budget.csv.
"""
import argparse, glob, json, math, os, time
import duckdb
import numpy as np
import pandas as pd

AUTH_SIG = ["new_user_dst", "new_user_src", "new_src_dst", "ntlm", "first_ntlm_for_user",
            "any_fail", "rare_dst", "fanout3"]
CROSS_SIG = ["proc_first_user_on_dst", "proc_new_process_on_dst", "flow_new_pair", "dns_new_pair"]
BUDGETS = [10, 25, 50, 100, 250, 500]


def files(data, src, d0, d1):
    fs = [f for d in range(d0, d1) for f in glob.glob(os.path.join(data, src, f"day={d:02d}.parquet"))]
    if not fs:
        raise SystemExit(f"no {src} files for days {d0}-{d1 - 1} in {data}")
    return "[" + ",".join("'" + f.replace("\\", "/") + "'" for f in fs) + "]"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data", default="data")
    ap.add_argument("--out", default="results")
    ap.add_argument("--start", type=int, default=0, help="first day loaded (history only)")
    ap.add_argument("--warmup-end", type=int, default=7, help="days [start+1, warmup_end) set base rates")
    ap.add_argument("--end", type=int, default=16, help="exclusive; days [warmup_end, end) are scored")
    ap.add_argument("--threads", type=int, default=0)
    ap.add_argument("--memory", default="", help="DuckDB memory limit, e.g. 6GB")
    a = ap.parse_args()

    derived = os.path.join(a.data, "derived")
    os.makedirs(derived, exist_ok=True); os.makedirs(a.out, exist_ok=True)
    c = duckdb.connect()  # in-memory; spills to data/derived/tmp when RAM runs short
    if a.threads: c.execute(f"SET threads={a.threads}")
    if a.memory: c.execute(f"SET memory_limit='{a.memory}'")
    c.execute(f"SET temp_directory='{os.path.join(derived, 'tmp').replace(os.sep, '/')}'")
    T, rows = {}, {}

    def run(label, sql):
        t = time.time(); c.execute(sql); T[label] = round(time.time() - t, 1)
        print(f"  {label}: {T[label]}s", flush=True)

    S, W, E = a.start, a.warmup_end, a.end
    print(f"days loaded {S}-{E - 1}; warm-up {S + 1}-{W - 1}; scored {W}-{E - 1}", flush=True)

    # ---- Stage 0: ingest the slices we need -------------------------------------------
    run("auth_logons", f"""
        CREATE TABLE logon AS
        SELECT time, time // 3600 AS hr, src_user AS usr, src_host AS src, dst_host AS dst,
               auth_type, outcome
        FROM read_parquet({files(a.data, 'auth', S, E)})
        WHERE src_user LIKE 'U%' AND orientation = 'LogOn' AND src_host <> dst_host""")
    rows["auth_rows_scanned"] = c.sql(f"SELECT count(*) FROM read_parquet({files(a.data, 'auth', S, E)})").fetchone()[0]
    run("proc_starts", f"""
        CREATE TABLE p AS SELECT time // 3600 AS hr, "user" AS usr, host, process
        FROM read_parquet({files(a.data, 'proc', S, E)}) WHERE action = 'Start'""")
    run("flow_pairs", f"""
        CREATE TABLE fl AS SELECT src_host AS src, dst_host AS dst, min(time // 3600) AS h
        FROM read_parquet({files(a.data, 'flows', S, E)}) GROUP BY ALL""")
    run("dns_pairs", f"""
        CREATE TABLE dn AS SELECT src_host AS src, resolved_host AS dst, min(time // 3600) AS h
        FROM read_parquet({files(a.data, 'dns', S, E)}) GROUP BY ALL""")

    # ---- Stage 1: first-seen tables (causal novelty) -----------------------------------
    run("first_seen", """
        CREATE TABLE fs_ud AS SELECT usr, dst, min(hr) h FROM logon GROUP BY ALL;
        CREATE TABLE fs_us AS SELECT usr, src, min(hr) h FROM logon GROUP BY ALL;
        CREATE TABLE fs_sd AS SELECT src, dst, min(hr) h FROM logon GROUP BY ALL;
        CREATE TABLE fs_ntlm AS SELECT usr, min(hr) h FROM logon WHERE auth_type = 'NTLM' GROUP BY ALL;
        CREATE TABLE fs_puh AS SELECT usr, host, min(hr) h FROM p WHERE usr LIKE 'U%' GROUP BY ALL;
        CREATE TABLE new_proc AS
            SELECT host, h AS hr, count(*) n FROM (SELECT host, process, min(hr) h FROM p GROUP BY ALL)
            GROUP BY ALL""")
    run("dst_popularity", f"""
        CREATE TABLE pop AS
        SELECT f.dst, d.day, count(*) FILTER (WHERE f.h < d.day * 24) AS users_before
        FROM fs_ud f CROSS JOIN (SELECT range AS day FROM range({S + 1}, {E})) d
        GROUP BY ALL""")

    # ---- edge-hours with signals ---------------------------------------------------------
    run("edge_hours", f"""
        CREATE TABLE eh AS
        WITH g AS (
            SELECT usr, src, dst, hr, hr // 24 AS day, count(*) AS n_events,
                   max(auth_type = 'NTLM')::INT AS ntlm, max(outcome = 'Fail')::INT AS any_fail,
                   min(time) AS t0
            FROM logon GROUP BY usr, src, dst, hr),
        f AS (
            SELECT g.*,
              (ud.h = g.hr)::INT AS new_user_dst, (us.h = g.hr)::INT AS new_user_src,
              (sd.h = g.hr)::INT AS new_src_dst,
              coalesce(nt.h = g.hr, false)::INT AS first_ntlm_for_user,
              (coalesce(pp.users_before, 0) <= 2)::INT AS rare_dst,
              coalesce(puh.h BETWEEN g.hr AND g.hr + 1, false)::INT AS proc_first_user_on_dst,
              (coalesce(np0.n, 0) + coalesce(np1.n, 0) > 0)::INT AS proc_new_process_on_dst,
              coalesce(fl.h BETWEEN g.hr - 1 AND g.hr + 1, false)::INT AS flow_new_pair,
              coalesce(dn.h BETWEEN g.hr - 1 AND g.hr, false)::INT AS dns_new_pair
            FROM g
            JOIN fs_ud ud USING (usr, dst) JOIN fs_us us USING (usr, src) JOIN fs_sd sd USING (src, dst)
            LEFT JOIN fs_ntlm nt USING (usr)
            LEFT JOIN pop pp ON pp.dst = g.dst AND pp.day = g.day
            LEFT JOIN fs_puh puh ON puh.usr = g.usr AND puh.host = g.dst
            LEFT JOIN new_proc np0 ON np0.host = g.dst AND np0.hr = g.hr
            LEFT JOIN new_proc np1 ON np1.host = g.dst AND np1.hr = g.hr + 1
            LEFT JOIN fl ON fl.src = g.src AND fl.dst = g.dst
            LEFT JOIN dn ON dn.src = g.src AND dn.dst = g.dst)
        SELECT f.*, (sum(new_user_dst) OVER (PARTITION BY usr, hr) >= 3)::INT AS fanout3
        FROM f""")
    rt_glob = os.path.join(a.data, 'redteam', '*.parquet').replace(os.sep, '/')
    run("labels", f"""
        CREATE TABLE lab AS SELECT DISTINCT "user" AS usr, src_host AS src, dst_host AS dst,
            time // 3600 AS hr FROM read_parquet('{rt_glob}');
        -- lenient: same user number (any account suffix), same hosts, within one hour
        CREATE TABLE labl AS SELECT DISTINCT split_part(usr, '@', 1) AS un, src, dst, hr + o AS hr
            FROM lab CROSS JOIN (SELECT unnest([-1, 0, 1]) AS o);
        CREATE TABLE ehl AS
        SELECT eh.*, (lab.usr IS NOT NULL)::INT AS label,
               (labl.un IS NOT NULL)::INT AS label_lenient
        FROM eh LEFT JOIN lab USING (usr, src, dst, hr)
        LEFT JOIN labl ON labl.un = split_part(eh.usr, '@', 1) AND labl.src = eh.src
                      AND labl.dst = eh.dst AND labl.hr = eh.hr""")
    t = time.time()
    df = c.sql("SELECT * FROM ehl").df()
    T["to_pandas"] = round(time.time() - t, 1)

    # ---- scoring: unsupervised surprise -------------------------------------------------
    warm = df[(df.day < W) & (df.day > S)]   # day S is burn-in history only
    surprise = {s: -math.log(max(warm[s].mean(), 1e-6)) for s in AUTH_SIG + CROSS_SIG}
    df["score_auth"] = sum(df[s] * surprise[s] for s in AUTH_SIG)
    df["score_corr"] = df["score_auth"] + sum(df[s] * surprise[s] for s in CROSS_SIG)
    for k in ("score_auth", "score_corr"):   # label-free deterministic tie-break
        df[k] = df[k] + 1e-6 * np.log1p(df.n_events)
    df.to_parquet(os.path.join(derived, "edge_hours_all.parquet"), index=False)  # all days, for campaigns.py
    test = df[df.day >= W].copy()
    test.to_parquet(os.path.join(derived, "edge_hours.parquet"), index=False)

    # ---- evaluation: strict and lenient labels -------------------------------------------
    res = {"days_scored": [W, E - 1], "edge_hours_scored": int(len(test)),
           "positives_strict": int(test.label.sum()), "positives_lenient": int(test.label_lenient.sum()),
           "base_rates": {s: round(float(warm[s].mean()), 6) for s in AUTH_SIG + CROSS_SIG},
           "surprise": {s: round(v, 2) for s, v in surprise.items()}, "scores": {}}
    rec_rows = []
    for lab_col in ("label", "label_lenient"):
        y = test[lab_col]
        pos_total = int(y.sum())
        rt_users = test[y == 1].assign(un=lambda d: d.usr.str.split("@").str[0]).groupby("un").hr.min()
        for k in ("score_auth", "score_corr"):
            o = test.sort_values(k, ascending=False)
            tp = o[lab_col].cumsum().to_numpy(); n = np.arange(1, len(o) + 1)
            ap_ = float((tp / n)[o[lab_col].to_numpy() == 1].mean()) if pos_total else float("nan")
            res["scores"][f"{k}|{lab_col}"] = {"average_precision": round(ap_, 4)}
            rank = test.groupby("day")[k].rank(ascending=False, method="first")
            for b in BUDGETS:
                hit = (rank <= b) & (y == 1)
                caught = test[hit].assign(un=lambda d: d.usr.str.split("@").str[0]).groupby("un").hr.min()
                delay = (caught - rt_users.reindex(caught.index)).median() if len(caught) else None
                rec_rows.append({"labels": "strict" if lab_col == "label" else "lenient", "score": k,
                                 "alerts_per_day": b, "recall": round(int(hit.sum()) / max(pos_total, 1), 4),
                                 "precision": round(int(hit.sum()) / int((rank <= b).sum()), 4),
                                 "redteam_users_caught": int(len(caught)), "redteam_users": int(len(rt_users)),
                                 "median_delay_hours": None if delay is None else float(delay)})
    T["total_seconds"] = round(sum(v for v in T.values()), 1)
    res["timings_s"] = T
    res["rows"] = {**rows, "logons_kept": int(c.sql("SELECT count(*) FROM logon").fetchone()[0]),
                   "proc_starts": int(c.sql("SELECT count(*) FROM p").fetchone()[0])}
    out = pd.DataFrame(rec_rows)
    out.to_csv(os.path.join(a.out, "recall_at_budget.csv"), index=False)
    json.dump(res, open(os.path.join(a.out, "metrics.json"), "w"), indent=2)
    print(json.dumps(res["scores"], indent=1))
    print(out.to_string(index=False))
    c.close()


if __name__ == "__main__":
    main()
