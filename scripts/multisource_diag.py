#!/usr/bin/env python3
"""Does process / flow / DNS telemetry separate red-team logins from the false positives
the engine currently alerts on?  Diagnostic only: nothing here feeds the detector.

Groups (edge-hours = user, src, dst, hour; days 7-15):
  RT        all lenient red-team logins
  FP_alert  logins the engine alerted on that are not red team (sweeps excluded)
  FP_sweep  logins in bulk sweeps (sample)
  NEW       random first-contact (new user->dst) logins that are not red team (sample)

What happens on the DESTINATION in the login hour and the next one:
  pivot_*   it logs onto other hosts (auth: dst becomes a source); new = pair never seen
  proc_*    processes start on it (any user / this user / process names new to the host)
  flow_*    it opens connections (distinct peers / peers never contacted before)
  dns_*     it resolves names (distinct / never resolved before by it)
Plus coverage: does the host ever appear in proc / flows / dns at all.

Stages (each short, so it can run under a time limit):
  python scripts/multisource_diag.py sample --alerts results/<tag>_alert_edges.parquet
  python scripts/multisource_diag.py proc     (per day, first-seen + counts)
  python scripts/multisource_diag.py flows
  python scripts/multisource_diag.py dns
  python scripts/multisource_diag.py report   -> results/multisource_diag.csv
"""
import argparse, glob, os, sys, time
import duckdb, numpy as np, pandas as pd

ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
ap.add_argument("stage", choices=["sample", "proc", "flows", "dns", "report", "all"])
ap.add_argument("--data", default="data"); ap.add_argument("--work", default="data/derived/msd")
ap.add_argument("--out", default="results"); ap.add_argument("--alerts", default="")
ap.add_argument("--days", default="", help="subset of days for proc/flows, e.g. 0-7")
ap.add_argument("--n-new", type=int, default=5000); ap.add_argument("--n-sweep", type=int, default=1000)
a = ap.parse_args()
os.makedirs(a.work, exist_ok=True)
J = lambda *p: os.path.join(*p).replace(os.sep, "/")
c = duckdb.connect(); c.execute("SET preserve_insertion_order=false")
EH = J(a.data, "derived", "edge_hours_all.parquet")
W0, W1 = 7, 16


def dayfile(src, d):
    f = J(a.data, src, f"day={d:02d}.parquet")
    return f if os.path.exists(f) else None


def days():
    if a.days:
        lo, hi = map(int, a.days.split("-")); return range(lo, hi + 1)
    return range(0, W1)


def stage_sample():
    al = pd.read_parquet(a.alerts)
    K = ["usr", "src", "dst", "hr"]
    fp = al[(al.label_lenient == 0) & ~al.sweep][K].drop_duplicates()
    sw = al[(al.label_lenient == 0) & al.sweep][K].drop_duplicates()
    sw = sw.sample(min(a.n_sweep, len(sw)), random_state=0)
    c.register("fp", fp); c.register("sw", sw)
    S = c.sql(f"""
        WITH rt AS (SELECT usr, src, dst, hr, 'RT' g FROM read_parquet('{EH}') WHERE day BETWEEN {W0} AND {W1-1} AND label_lenient = 1),
             nw AS (SELECT * FROM (SELECT usr, src, dst, hr, 'NEW' g FROM read_parquet('{EH}')
                    WHERE day BETWEEN {W0} AND {W1-1} AND label_lenient = 0 AND new_user_dst = 1
                    ORDER BY usr, src, dst, hr) USING SAMPLE reservoir({a.n_new} ROWS) REPEATABLE (0))
        SELECT * FROM rt UNION ALL SELECT usr, src, dst, hr, 'FP_alert' FROM fp
        UNION ALL SELECT usr, src, dst, hr, 'FP_sweep' FROM sw UNION ALL SELECT * FROM nw""").df()
    S.to_parquet(J(a.work, "sample.parquet"), index=False)
    pd.DataFrame({"host": pd.unique(pd.concat([S.dst, S.src]))}).to_parquet(J(a.work, "hosts.parquet"), index=False)
    print(S.g.value_counts().to_string(), "\nhosts:", S.dst.nunique())


def per_day(src, key_sql, cols, where="TRUE"):
    """first-seen of (host, item) and hourly counts for hosts in the sample, one day at a time."""
    H = J(a.work, "hosts.parquet")
    for d in days():
        f = dayfile(src, d)
        out = J(a.work, f"{src}_{d:02d}.parquet")
        if not f or os.path.exists(out): continue
        t = time.time()
        c.execute(f"""COPY (SELECT {key_sql} FROM read_parquet('{f}') x
                     SEMI JOIN read_parquet('{H}') h ON h.host = x.{cols}
                     WHERE {where} GROUP BY ALL) TO '{out}' (FORMAT parquet)""")
        print(f"{src} day {d}: {time.time() - t:.1f}s", flush=True)


def stage_proc():
    per_day("proc", """host, process, "user" AS usr, time // 3600 AS hr, count(*) n""", "host", "action = 'Start'")


def stage_flows():
    per_day("flows", "src_host AS host, dst_host AS peer, time // 3600 AS hr, count(*) n", "src_host")


def stage_dns():
    per_day("dns", "src_host AS host, resolved_host AS peer, time // 3600 AS hr, count(*) n", "src_host")


def auc(pos, neg):
    pos, neg = np.asarray(pos, float), np.asarray(neg, float)
    if not len(pos) or not len(neg): return np.nan
    r = pd.Series(np.concatenate([pos, neg])).rank().to_numpy()
    return (r[:len(pos)].sum() - len(pos) * (len(pos) + 1) / 2) / (len(pos) * len(neg))


def stage_report():
    S = J(a.work, "sample.parquet")
    c.execute(f"CREATE TABLE s AS SELECT DISTINCT * FROM read_parquet('{S}')")
    have = {k: sorted(glob.glob(J(a.work, f"{k}_*.parquet"))) for k in ("proc", "flows", "dns")}
    for k, fs in have.items():
        if not fs: sys.exit(f"missing stage: {k}")
        c.execute(f"CREATE VIEW {k} AS SELECT * FROM read_parquet({fs})")
    q = f"""
    WITH pv AS (   -- auth pivots from the destination
        SELECT s.usr, s.src, s.dst, s.hr, count(DISTINCT e.dst) n_any,
               count(DISTINCT e.dst) FILTER (WHERE e.new_src_dst = 1) n_new,
               count(DISTINCT e.dst) FILTER (WHERE e.usr = s.usr) n_user
        FROM s JOIN read_parquet('{EH}') e ON e.src = s.dst AND e.hr BETWEEN s.hr AND s.hr + 1 AND e.dst <> s.src
        GROUP BY ALL),
    pfirst AS (SELECT host, process, min(hr) h FROM proc GROUP BY ALL),
    pr AS (
        SELECT s.usr, s.src, s.dst, s.hr, sum(p.n) n_any, sum(p.n) FILTER (WHERE p.usr = s.usr) n_user,
               count(DISTINCT p.process) FILTER (WHERE f.h = p.hr) n_newproc
        FROM s JOIN proc p ON p.host = s.dst AND p.hr BETWEEN s.hr AND s.hr + 1
        JOIN pfirst f ON f.host = p.host AND f.process = p.process
        GROUP BY ALL),
    ffirst AS (SELECT host, peer, min(hr) h FROM flows GROUP BY ALL),
    fo AS (
        SELECT s.usr, s.src, s.dst, s.hr, count(DISTINCT fl.peer) n_any,
               count(DISTINCT fl.peer) FILTER (WHERE f.h = fl.hr) n_new
        FROM s JOIN flows fl ON fl.host = s.dst AND fl.hr BETWEEN s.hr AND s.hr + 1
        JOIN ffirst f ON f.host = fl.host AND f.peer = fl.peer GROUP BY ALL),
    flogin AS (SELECT DISTINCT s.usr, s.src, s.dst, s.hr FROM s JOIN flows fl
               ON fl.hr BETWEEN s.hr - 1 AND s.hr + 1 AND ((fl.host = s.src AND fl.peer = s.dst) OR (fl.host = s.dst AND fl.peer = s.src))),
    dfirst AS (SELECT host, peer, min(hr) h FROM dns GROUP BY ALL),
    dn AS (
        SELECT s.usr, s.src, s.dst, s.hr, count(DISTINCT x.peer) n_any,
               count(DISTINCT x.peer) FILTER (WHERE f.h = x.hr) n_new
        FROM s JOIN dns x ON x.host = s.dst AND x.hr BETWEEN s.hr AND s.hr + 1
        JOIN dfirst f ON f.host = x.host AND f.peer = x.peer GROUP BY ALL),
    cov_p AS (SELECT DISTINCT host FROM proc), cov_f AS (SELECT DISTINCT host FROM flows),
    cov_d AS (SELECT DISTINCT host FROM dns)
    SELECT s.*,
      coalesce(pv.n_any, 0) pivot_hosts, coalesce(pv.n_new, 0) pivot_new_hosts, coalesce(pv.n_user, 0) pivot_same_user,
      coalesce(pr.n_any, 0) proc_events, coalesce(pr.n_user, 0) proc_events_user, coalesce(pr.n_newproc, 0) proc_new_names,
      coalesce(fo.n_any, 0) flow_peers, coalesce(fo.n_new, 0) flow_new_peers, (fl2.dst IS NOT NULL)::INT flow_sees_login,
      coalesce(dn.n_any, 0) dns_names, coalesce(dn.n_new, 0) dns_new_names,
      (cp.host IS NOT NULL)::INT cov_proc, (cf.host IS NOT NULL)::INT cov_flows, (cd.host IS NOT NULL)::INT cov_dns
    FROM s
    LEFT JOIN pv USING (usr, src, dst, hr) LEFT JOIN pr USING (usr, src, dst, hr)
    LEFT JOIN fo USING (usr, src, dst, hr) LEFT JOIN flogin fl2 USING (usr, src, dst, hr)
    LEFT JOIN dn USING (usr, src, dst, hr)
    LEFT JOIN cov_p cp ON cp.host = s.dst LEFT JOIN cov_f cf ON cf.host = s.dst LEFT JOIN cov_d cd ON cd.host = s.dst"""
    F = c.sql(q).df()
    F.to_parquet(J(a.work, "features.parquet"), index=False)
    feats = [x for x in F.columns if x not in ("usr", "src", "dst", "hr", "g")]
    rows = []
    for f in feats:
        r = {"feature": f}
        for g in ["RT", "FP_alert", "FP_sweep", "NEW"]:
            v = F[F.g == g][f]
            r[f"{g}_nonzero"] = round(float((v > 0).mean()), 3); r[f"{g}_mean"] = round(float(v.mean()), 2)
        r["AUC_RT_vs_FP_alert"] = round(auc(F[F.g == "RT"][f], F[F.g == "FP_alert"][f]), 3)
        r["AUC_RT_vs_NEW"] = round(auc(F[F.g == "RT"][f], F[F.g == "NEW"][f]), 3)
        rows.append(r)
    R = pd.DataFrame(rows)
    os.makedirs(a.out, exist_ok=True); R.to_csv(J(a.out, "multisource_diag.csv"), index=False)
    pd.set_option("display.width", 250); print(F.g.value_counts().to_string()); print(R.to_string(index=False))


st = {"sample": [stage_sample], "proc": [stage_proc], "flows": [stage_flows], "dns": [stage_dns],
      "report": [stage_report], "all": [stage_sample, stage_proc, stage_flows, stage_dns, stage_report]}[a.stage]
for fn in st: fn()
