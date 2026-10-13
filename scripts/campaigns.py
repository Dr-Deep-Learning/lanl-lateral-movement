#!/usr/bin/env python3
"""Campaign-level detection: roll edge-hours up to (entity, hour) and judge each
entity against its own history.

Three campaign views per hour (an analyst gets one alert per campaign, not per login):
  user fan-out : one account (user number, any domain suffix) reaching new hosts
  src  fan-out : one source host reaching new hosts
  dst  fan-in  : new users arriving at one host
Counts per entity-hour, from edge-hours (all causal):
  k_new  new targets (fan-out: new user->dst / new src->dst; fan-in: new user->dst)
  k_ntlm of those, over NTLM
  k_rare of those, to a rarely used host (fan-in: from a new source)
  k_x    of those, corroborated by other telemetry (new process, user's first process
         on the target, or first network flow between the hosts)
Self-baseline: each entity's hourly rate of each count from its own PRIOR days
(strictly before the current day), shrunk toward the population rate:
    lam = (prior_sum + A * pop_rate) / (prior_active_hours + A)
    surprise = -log P(K >= k | Poisson(lam))
Scores (no double counting): volume = Poisson surprise of k_new; composition = binomial
surprise of each share (k_ntlm/k_new, k_rare/k_new, k_x/k_new) against the entity's usual
share (prior counts, --share-prior pseudo-counts toward the population share).
auth-only = volume + NTLM share + rare share; correlated = auth-only + corroborated share.
Surprise is computed in log space (scipy logsf, falling back to the large-deviation
approximation when that underflows) and each signal's surprise is capped (--cap), so
no score is infinite; ties at the cap are broken by the uncapped value.
Training-period outliers: entities whose hourly new-target count during warm-up
exceeds the population's --outlier-pct percentile are flagged "habitual"; they are
left out of the population rates (so they do not inflate everyone's prior) and are
scored only against their own history.
Only entity-hours with a positive score can alert. Top-N per day, per view and merged.
Alerted campaigns from all views that share logins, or are the same entity in
adjacent hours, are grouped into incidents (results/incidents.csv).

Metrics, strict and lenient labels: campaign precision, red-team edge-hours covered
by alerted campaigns (recall), red-team users caught, median detection delay (hours),
and edges an analyst would review. Reads data/derived/edge_hours_all.parquet from
detect.py. Writes results/campaign_metrics.csv and results/top_campaigns.csv.
"""
import argparse, json, os, time
import duckdb
import numpy as np
import pandas as pd
from scipy.stats import binom, poisson

VIEWS = {  # key expression, novelty column, rarity column
    "user": ("split_part(usr, '@', 1)", "new_user_dst", "rare_dst"),
    "src":  ("src", "new_src_dst", "rare_dst"),
    "dst":  ("dst", "new_user_dst", "new_src_dst"),
}
SIGS = ["new", "ntlm", "rare", "x"]
BUDGETS = [5, 10, 25, 50, 100]


def log_tail(k, lam):
    """log P(X >= k) for X ~ Poisson(lam), finite everywhere (k >= 1)."""
    with np.errstate(divide="ignore", invalid="ignore"):
        lt = poisson.logsf(k - 1, lam)
        # large-deviation (Chernoff + Stirling) approximation where scipy underflows
        approx = -(lam - k + k * np.log(k / lam)) - 0.5 * np.log(2 * np.pi * k)
        bad = ~np.isfinite(lt) | (lt < -700)
        return np.where(bad, np.minimum(approx, 0.0), lt)


def log_tail_binom(k, n, q):
    """log P(Y >= k) for Y ~ Binomial(n, q), finite everywhere (1 <= k <= n)."""
    with np.errstate(divide="ignore", invalid="ignore"):
        lt = binom.logsf(k - 1, n, q)
        f = np.clip(k / n, 1e-12, 1.0)
        kl = f * np.log(f / q) + np.where(f < 1, (1 - f) * np.log((1 - f) / (1 - q)), 0.0)
        approx = -n * kl                      # Chernoff bound, exact when k == n
        bad = ~np.isfinite(lt) | (lt < -700)
        return np.where(bad, np.minimum(approx, 0.0), lt)


def rank_in_day(df, sc):
    """rank within day by capped score, ties broken by the uncapped score."""
    o = df.sort_values(["day", sc, sc + "_raw"], ascending=[True, False, False])
    return o.groupby("day").cumcount().add(1).reindex(df.index)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data", default="data")
    ap.add_argument("--out", default="results")
    ap.add_argument("--warmup-end", type=int, default=7, help="days before this set population rates; days from it are scored")
    ap.add_argument("--prior-hours", type=float, default=24.0, help="shrinkage strength A, in pseudo active-hours")
    ap.add_argument("--share-prior", type=float, default=20.0, help="pseudo-count B for an entity's usual shares")
    ap.add_argument("--cap", type=float, default=100.0, help="max surprise per signal (nats)")
    ap.add_argument("--outlier-pct", type=float, default=99.9, help="warm-up percentile of entity max hourly k_new")
    ap.add_argument("--incident-budget", type=int, default=25, help="merged campaigns per day grouped into incidents")
    a = ap.parse_args()
    W, A, B = a.warmup_end, a.prior_hours, a.share_prior
    os.makedirs(a.out, exist_ok=True)
    src = os.path.join(a.data, "derived", "edge_hours_all.parquet").replace(os.sep, "/")
    c = duckdb.connect()
    c.execute(f"SET temp_directory='{os.path.join(a.data, 'derived', 'tmp').replace(os.sep, '/')}'")
    T = {}
    t = time.time()
    c.execute(f"""CREATE TABLE e AS SELECT usr, src, dst, hr, day, ntlm, rare_dst, new_user_dst, new_src_dst,
                  proc_first_user_on_dst, proc_new_process_on_dst, flow_new_pair, label, label_lenient
                  FROM read_parquet('{src}')""")
    # positives in the scored window, under each labeling
    c.execute(f"""CREATE TABLE pos AS SELECT usr, split_part(usr, '@', 1) AS un, src, dst, hr, label, label_lenient
                  FROM e WHERE day >= {W} AND (label = 1 OR label_lenient = 1)""")
    T["load"] = round(time.time() - t, 1)

    scored, habit = {}, {}
    for v, (key, new, rare) in VIEWS.items():
        t = time.time()
        c.execute(f"""CREATE OR REPLACE TABLE eh AS
            SELECT {key} AS ent, hr, day, count(*) AS n_edges,
                   sum({new}) AS k_new, sum({new} * ntlm) AS k_ntlm, sum({new} * {rare}) AS k_rare,
                   sum({new} * greatest(proc_first_user_on_dst, proc_new_process_on_dst, flow_new_pair)) AS k_x,
                   max(label) AS y_strict, max(label_lenient) AS y_lenient
            FROM e GROUP BY ALL""")
        thr = c.sql(f"""SELECT quantile_cont(mx, {a.outlier_pct / 100}) FROM
                        (SELECT ent, max(k_new) AS mx FROM eh WHERE day < {W} GROUP BY ent)""").fetchone()[0]
        c.execute(f"""CREATE OR REPLACE TABLE habitual AS SELECT ent, max(k_new) AS warm_max FROM eh
                      WHERE day < {W} GROUP BY ent HAVING max(k_new) > {thr}""")
        rates = c.sql(f"""SELECT {', '.join(f'sum(k_{s}) / count(*)' for s in SIGS)} FROM eh
                          WHERE day < {W} AND ent NOT IN (SELECT ent FROM habitual)""").fetchone()
        rates = dict(zip(SIGS, rates))
        n_hab = c.sql("SELECT count(*) FROM habitual").fetchone()[0]
        habit[v] = {"threshold_k_new_per_hour": float(thr), "entities": int(n_hab),
                    "top": c.sql("SELECT ent, warm_max FROM habitual ORDER BY warm_max DESC LIMIT 10").fetchall()}
        df = c.sql(f"""
            WITH d AS (SELECT ent, day, count(*) AS h, {', '.join(f'sum(k_{s}) AS s_{s}' for s in SIGS)}
                       FROM eh GROUP BY ALL),
            p AS (SELECT ent, day, coalesce(sum(h) OVER w, 0) AS ph,
                         {', '.join(f'coalesce(sum(s_{s}) OVER w, 0) AS p_{s}' for s in SIGS)}
                  FROM d WINDOW w AS (PARTITION BY ent ORDER BY day
                                      ROWS BETWEEN UNBOUNDED PRECEDING AND 1 PRECEDING))
            SELECT x.*, p.ph, {', '.join(f'p.p_{s}' for s in SIGS)},
                   (x.ent IN (SELECT ent FROM habitual))::INT AS habitual
            FROM eh x JOIN p USING (ent, day) WHERE x.day >= {W}""").df()
        # volume: Poisson tail of k_new against the entity's own rate
        lam = ((df["p_new"] + A * rates["new"]) / (df["ph"] + A)).clip(lower=1e-9).to_numpy()
        n = df["k_new"].astype(float).to_numpy()
        df["rawsur_new"] = np.where(n > 0, -log_tail(n, lam), 0.0)
        # composition: binomial tail of each share among the new logins, against the
        # entity's usual share (prior counts shrunk toward the population share)
        for s in SIGS[1:]:
            q_pop = rates[s] / max(rates["new"], 1e-12)
            q = ((df[f"p_{s}"] + B * q_pop) / (df["p_new"] + B)).clip(1e-6, 1 - 1e-6).to_numpy()
            k = df[f"k_{s}"].astype(float).to_numpy()
            df[f"rawsur_{s}"] = np.where((n > 0) & (k > 0), -log_tail_binom(k, n, q), 0.0)
        for s in SIGS:
            df[f"sur_{s}"] = np.minimum(df[f"rawsur_{s}"], a.cap)
        for name, sigs in (("score_auth", ["new", "ntlm", "rare"]), ("score_corr", SIGS)):
            df[name] = sum(df[f"sur_{s}"] for s in sigs)
            df[name + "_raw"] = sum(df[f"rawsur_{s}"] for s in sigs)
        df["view"] = v
        scored[v] = df
        T[f"view_{v}"] = round(time.time() - t, 1)
        print(f"  {v}: {len(df):,} entity-hours scored, {int((df.score_corr > 0).sum()):,} with any surprise "
              f"({T[f'view_{v}']}s)", flush=True)

    keycol = {"user": "split_part(p.usr, '@', 1)", "src": "p.src", "dst": "p.dst"}
    rows = []
    totals = {lab: c.sql(f"SELECT count(*), count(DISTINCT un) FROM pos WHERE {lab} = 1").fetchone()
              for lab in ("label", "label_lenient")}
    first_hr = {lab: c.sql(f"SELECT un, min(hr) FROM pos WHERE {lab} = 1 GROUP BY un").df().set_index("un").iloc[:, 0]
                for lab in ("label", "label_lenient")}
    merged_all = pd.concat(scored.values(), ignore_index=True)
    for sc in ("score_auth", "score_corr"):
        for view in list(VIEWS) + ["merged"]:
            df = merged_all if view == "merged" else scored[view]
            cand = df[df[sc] > 0].copy()
            cand["rk"] = rank_in_day(cand, sc)
            for b in BUDGETS:
                al = cand[cand.rk <= b][["view", "ent", "hr", "n_edges", "y_strict", "y_lenient"]]
                c.register("al", al)
                cov = c.sql(" UNION ".join(
                    f"SELECT p.usr, p.src, p.dst, p.hr, p.un, p.label, p.label_lenient FROM pos p "
                    f"JOIN al ON al.view = '{vv}' AND al.ent = {keycol[vv]} AND al.hr = p.hr"
                    for vv in VIEWS)).df()
                for lab, ycol, name in (("label", "y_strict", "strict"), ("label_lenient", "y_lenient", "lenient")):
                    cv = cov[cov[lab] == 1]
                    caught = cv.groupby("un").hr.min()
                    delay = (caught - first_hr[lab].reindex(caught.index)).median() if len(caught) else None
                    rows.append({"labels": name, "score": sc, "view": view, "campaigns_per_day": b,
                                 "campaigns_alerted": len(al),
                                 "campaign_precision": round(float(al[ycol].mean()), 4) if len(al) else None,
                                 "edge_recall": round(len(cv) / max(totals[lab][0], 1), 4),
                                 "redteam_users_caught": int(len(caught)), "redteam_users": int(totals[lab][1]),
                                 "median_delay_hours": None if delay is None else float(delay),
                                 "edges_to_review_per_day": round(al.n_edges.sum() / max(al.hr.floordiv(24).nunique(), 1), 1)})
                c.unregister("al")
    out = pd.DataFrame(rows)
    out.to_csv(os.path.join(a.out, "campaign_metrics.csv"), index=False)
    top = merged_all.sort_values(["score_corr", "score_corr_raw"], ascending=False).head(40)
    top[["view", "ent", "day", "hr", "habitual", "n_edges", "k_new", "k_ntlm", "k_rare", "k_x", "ph", "p_new",
         "score_auth", "score_corr", "score_corr_raw", "y_strict", "y_lenient"]].round(2).to_csv(
        os.path.join(a.out, "top_campaigns.csv"), index=False)

    # ---- incidents: group alerted campaigns (merged queue, correlated score) -------------
    t = time.time()
    cand = merged_all[merged_all.score_corr > 0].copy()
    cand["rk"] = rank_in_day(cand, "score_corr")
    al = cand[cand.rk <= a.incident_budget].reset_index(drop=True)
    al["aid"] = np.arange(len(al))
    c.register("al", al[["aid", "view", "ent", "hr"]])
    keyexpr = {"user": "split_part(e.usr, '@', 1)", "src": "e.src", "dst": "e.dst"}
    ed = c.sql(" UNION ALL ".join(
        f"""SELECT al.aid, e.usr, e.src, e.dst, e.hr, e.ntlm, e.rare_dst,
                   greatest(e.proc_first_user_on_dst, e.proc_new_process_on_dst, e.flow_new_pair) AS corr,
                   e.proc_first_user_on_dst, e.proc_new_process_on_dst, e.flow_new_pair,
                   e.new_user_dst, e.new_src_dst, e.label, e.label_lenient
            FROM e JOIN al ON al.view = '{v}' AND al.ent = {keyexpr[v]} AND al.hr = e.hr""" for v in VIEWS)).df()
    c.unregister("al")
    parent = list(range(len(al)))
    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]; x = parent[x]
        return x
    def union(x, y):
        rx, ry = find(x), find(y)
        if rx != ry: parent[ry] = rx
    for _, g in ed.groupby(["usr", "src", "dst", "hr"]).aid:          # shared logins
        ids = g.unique()
        for x in ids[1:]: union(ids[0], x)
    for _, g in al.sort_values("hr").groupby(["view", "ent"]):         # same entity, adjacent hours
        prev = None
        for aid, hr in zip(g.aid, g.hr):
            if prev is not None and hr - prev[1] <= 1: union(prev[0], aid)
            prev = (aid, hr)
    al["incident"] = [find(x) for x in al.aid]
    ed["incident"] = al.incident.to_numpy()[ed.aid.to_numpy()]
    inc_rows = []
    for inc, g in al.groupby("incident"):
        e1 = ed[ed.incident == inc].drop_duplicates(["usr", "src", "dst", "hr"])
        new_e = e1[(e1.new_user_dst == 1) | (e1.new_src_dst == 1)]
        def share(col): return round(float(new_e[col].mean()), 3) if len(new_e) else None
        ents = "; ".join(f"{v}:" + ",".join(sorted(set(g[g.view == v].ent))[:4]) for v in VIEWS if (g.view == v).any())
        inc_rows.append({
            "incident": int(inc), "first_day": int(g.hr.min() // 24), "first_hr": int(g.hr.min()),
            "last_hr": int(g.hr.max()), "campaigns": len(g), "views": ",".join(sorted(set(g.view))),
            "entities": ents, "habitual_involved": int(g.habitual.max()),
            "logins": len(e1), "new_logins": len(new_e), "distinct_targets": int(new_e.dst.nunique()),
            "distinct_sources": int(new_e.src.nunique()), "distinct_users": int(new_e.usr.str.split("@").str[0].nunique()),
            "share_ntlm": share("ntlm"), "share_rare_dst": share("rare_dst"), "share_corroborated": share("corr"),
            "corr_first_user_process": int(new_e.proc_first_user_on_dst.sum()),
            "corr_new_process": int(new_e.proc_new_process_on_dst.sum()),
            "corr_new_flow": int(new_e.flow_new_pair.sum()),
            "max_score": round(float(g.score_corr.max()), 1),
            "redteam_logins_strict": int(e1.label.sum()), "redteam_logins_lenient": int(e1.label_lenient.sum())})
    inc = pd.DataFrame(inc_rows).sort_values(["max_score", "logins"], ascending=False)
    inc.to_csv(os.path.join(a.out, "incidents.csv"), index=False)
    T["incidents"] = round(time.time() - t, 1)
    tot_l = totals["label_lenient"][0]
    inc_summary = {"campaigns_per_day": a.incident_budget, "campaigns": int(len(al)), "incidents": int(len(inc)),
                   "incidents_with_redteam_lenient": int((inc.redteam_logins_lenient > 0).sum()),
                   "redteam_logins_covered_lenient": round(float(inc.redteam_logins_lenient.sum()) / max(tot_l, 1), 4)}
    json.dump({"timings_s": T, "positives": {k: {"edge_hours": v[0], "users": v[1]} for k, v in totals.items()},
               "prior_hours": A, "warmup_end": W, "cap": a.cap, "habitual": habit, "incidents": inc_summary},
              open(os.path.join(a.out, "campaign_run.json"), "w"), indent=2, default=str)
    show = out[(out.campaigns_per_day.isin([10, 25, 50])) & (out.view.isin(["user", "src", "merged"]))
               & (out.labels == "lenient")]
    print(show.drop(columns=["redteam_users", "labels"]).to_string(index=False))
    print("habitual (warm-up outliers):", {v: (h["entities"], round(h["threshold_k_new_per_hour"], 1)) for v, h in habit.items()})
    print("incidents:", inc_summary)
    print(inc.head(12)[["incident", "first_day", "campaigns", "views", "entities", "new_logins", "distinct_targets",
                        "share_ntlm", "share_rare_dst", "share_corroborated", "max_score",
                        "redteam_logins_lenient"]].to_string(index=False))


if __name__ == "__main__":
    main()
