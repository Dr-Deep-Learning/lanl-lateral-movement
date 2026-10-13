#!/usr/bin/env python3
"""Campaign detection engine, v2: peer groups, density model, follow-up watchlist,
and an optional daily retraining loop with an analyst oracle.

Runs day by day over edge-hours (data/derived/edge_hours_all.parquet). For each day d:

  1. Novelty flags are recomputed from HISTORY (days < d, minus anything excluded):
     new user->dst, new src->dst (first hour today), rare destination (<= 2 users before).
     Process / flow corroboration and NTLM come from detect.py unchanged.
  2. Campaigns: per view (user fan-out, source fan-out, destination fan-in) and hour,
     k_new and the shares of NTLM, rare, corroborated among the new logins.
  3. Priors for each entity come from its own history, shrunk toward a GROUP rate:
       --prior population : the whole network (v1 behaviour)
       --prior peer       : the entity's peer group, from a Gaussian mixture over
                            behaviour profiles (activity, fan-out, novelty rate, NTLM /
                            failure shares). Entities with < 3 active hours of history
                            fall back to the population.
  4. Scores:
       --scorer surprise : Poisson surprise of k_new + binomial surprise of each share
                           against the entity's usual share (log space, capped)
       --scorer iforest  : isolation forest on the same relative features, same one-sided
                           per-view calibration (a drop-in alternative to the mixture)
       --scorer density  : Gaussian mixture over entity-RELATIVE, sample-size-aware features
                           (signed deviance residuals: new logins vs the entity's expected
                           rate; NTLM / rare / corroborated counts vs its usual shares given
                           the number of new logins), fit on all history.
                           One-sided (only "more than usual" can score) and calibrated per
                           view: score = -log(share of history at least as unlikely).
  5. Alerts: top-N campaign-hours per day across views (--budget). Follow-up: every
     user and source host in an alert is watched for --watch-hours; their later logins
     are surfaced as follow-ups (counted separately, with their workload).
  6. Confirmed-entity watch (--confirm-watch): the analyst (oracle = lenient red-team labels)
     reviews each day's alerts. A confirmed-malicious login puts its SOURCE HOST on a watch for
     --confirm-days days: every later login from it is surfaced (attack hosts are quiet
     otherwise). With 'src_user' its USER is watched too, but only for logins to destinations
     that user has never reached before (compromised accounts keep ~100 normal logins a day).
     Malicious logins found by the watch extend it (the analyst pivots). No retraining.
  7. Workload: an alert whose campaign-hour has >= --sweep-min new logins is a SWEEP and is
     reviewed in bulk as one item; review_items = non-sweep logins + sweeps. Daily medians are
     reported next to means, since one sweep day dominates the mean.
  8. Regime:
       --regime static : population/peer/density models fit once on warm-up days
       --regime oracle : after each day an analyst (the oracle: lenient red-team labels)
                         reviews that day's alerts. Confirmed-malicious logins are removed
                         from history; everything else (benign alerts and all unalerted
                         activity, which may hide undetected attacks) stays. All models
                         are refit on the filtered history before the next day.

Also an entity-day "fits no peer group" detector: -log likelihood of the entity's own
daily profile under a mixture fit to historical daily profiles (alert at end of day).

Deterministic: every query that feeds a model fit or the alert ranking is ORDER BY'd, and
ties are broken by (view, entity, hour), so identical configs give identical results.

Writes results/<tag>_daily.csv, <tag>_summary.json (and _profile_anomaly.csv).
"""
import argparse, json, os, time
import duckdb
import numpy as np
import pandas as pd
from scipy.stats import binom, poisson
from sklearn.ensemble import IsolationForest
from sklearn.mixture import GaussianMixture
from sklearn.preprocessing import StandardScaler

VIEWS = {"user": ("un", "new_user_dst", "rare_dst", "dst"),
         "src": ("src", "new_src_dst", "rare_dst", "dst"),
         "dst": ("dst", "new_user_dst", "new_src_dst", "un")}
SHARES = ["ntlm", "rare", "x"]
PROFILE = ["act", "edges_per_h", "partners_per_day", "new_per_h", "ntlm_share", "fail_share", "rare_share", "x_share"]


def log_tail_pois(k, lam):
    with np.errstate(divide="ignore", invalid="ignore"):
        lt = poisson.logsf(k - 1, lam)
        approx = -(lam - k + k * np.log(k / lam)) - 0.5 * np.log(2 * np.pi * k)
        return np.where(~np.isfinite(lt) | (lt < -700), np.minimum(approx, 0.0), lt)


def log_tail_binom(k, n, q):
    with np.errstate(divide="ignore", invalid="ignore"):
        lt = binom.logsf(k - 1, n, q)
        f = np.clip(k / n, 1e-12, 1.0)
        kl = f * np.log(f / q) + np.where(f < 1, (1 - f) * np.log((1 - f) / (1 - q)), 0.0)
        return np.where(~np.isfinite(lt) | (lt < -700), np.minimum(-n * kl, 0.0), lt)


def fit_gmm(X, kmax=8, seed=0):
    best = None
    for k in range(2, kmax + 1):
        g = GaussianMixture(k, covariance_type="full", reg_covar=1e-3, random_state=seed, max_iter=200).fit(X)
        b = g.bic(X)
        if best is None or b < best[0]:
            best = (b, g)
    return best[1]


class Engine:
    def __init__(self, a):
        self.a = a
        self.c = duckdb.connect()
        tmp = os.path.join(a.data, "derived", "tmp").replace(os.sep, "/")
        self.c.execute(f"SET temp_directory='{tmp}'")
        if a.memory: self.c.execute(f"SET memory_limit='{a.memory}'")
        src = os.path.join(a.data, "derived", "edge_hours_all.parquet").replace(os.sep, "/")
        self.c.execute(f"""CREATE TABLE e AS SELECT usr, split_part(usr, '@', 1) AS un, src, dst, hr, day::INT AS day,
                n_events, ntlm, any_fail,
                greatest(proc_first_user_on_dst, proc_new_process_on_dst, flow_new_pair)::INT AS x,
                label, label_lenient
            FROM read_parquet('{src}') WHERE day < {a.end}""")
        self.c.execute("CREATE TABLE excluded (usr VARCHAR, src VARCHAR, dst VARCHAR, hr BIGINT)")
        self.c.execute("""CREATE TABLE hf (usr VARCHAR, un VARCHAR, src VARCHAR, dst VARCHAR, hr BIGINT, day INT,
                          n_events BIGINT, ntlm INT, any_fail INT, x INT, label INT, label_lenient INT,
                          new_user_dst INT, new_src_dst INT, rare_dst INT)""")
        self.models = {}

    # ---- 1. novelty flags for one day from (filtered) history --------------------------
    def flag_day(self, d):
        self.c.execute(f"""
            CREATE OR REPLACE TABLE today AS
            WITH hist AS (SELECT h.usr, h.src, h.dst FROM hf h
                          ANTI JOIN excluded x ON x.usr = h.usr AND x.src = h.src AND x.dst = h.dst AND x.hr = h.hr),
                 t AS (SELECT * FROM e WHERE day = {d})
            SELECT t.*,
                (ud.usr IS NULL AND t.hr = min(t.hr) OVER (PARTITION BY t.usr, t.dst))::INT AS new_user_dst,
                (sd.src IS NULL AND t.hr = min(t.hr) OVER (PARTITION BY t.src, t.dst))::INT AS new_src_dst,
                (coalesce(pop.n, 0) <= 2)::INT AS rare_dst
            FROM t
            LEFT JOIN (SELECT DISTINCT usr, dst FROM hist) ud ON ud.usr = t.usr AND ud.dst = t.dst
            LEFT JOIN (SELECT DISTINCT src, dst FROM hist) sd ON sd.src = t.src AND sd.dst = t.dst
            LEFT JOIN (SELECT dst, count(DISTINCT usr) AS n FROM hist GROUP BY dst) pop ON pop.dst = t.dst""")
        self.c.execute("""INSERT INTO hf SELECT usr, un, src, dst, hr, day, n_events, ntlm, any_fail, x, label,
                          label_lenient, new_user_dst, new_src_dst, rare_dst FROM today""")

    # ---- 2. campaign-hours (entity, hour) ----------------------------------------------
    def campaigns_sql(self, v, table, where="TRUE"):
        key, new, rare, partner = VIEWS[v]
        return f"""SELECT {key} AS ent, hr, day, count(*) AS n_edges, sum(n_events) AS events,
                   sum({new}) AS k_new, sum({new} * ntlm) AS k_ntlm, sum({new} * {rare}) AS k_rare,
                   sum({new} * x) AS k_x, sum(ntlm) AS ntlm_edges, sum(any_fail) AS fail_edges,
                   count(DISTINCT {partner}) AS partners, max(label) AS y_strict, max(label_lenient) AS y_lenient
                   FROM {table} WHERE {where} GROUP BY ALL"""

    def history(self, d, v, d0=1):
        """entity-day aggregates of filtered history, days [d0, d)."""
        self.c.execute(f"""CREATE OR REPLACE TABLE hist_ch AS {self.campaigns_sql(v,
            '(SELECT h.* FROM hf h ANTI JOIN excluded x ON x.usr = h.usr AND x.src = h.src AND x.dst = h.dst AND x.hr = h.hr)',
            f'day >= {d0} AND day < {d}')}""")
        return self.c.sql("""SELECT ent, day, count(*) AS h, sum(n_edges) AS n_edges, sum(k_new) AS k_new,
                   sum(k_ntlm) AS k_ntlm, sum(k_rare) AS k_rare, sum(k_x) AS k_x, sum(ntlm_edges) AS ntlm_edges,
                   sum(fail_edges) AS fail_edges, sum(partners) AS partners
                   FROM hist_ch GROUP BY ALL ORDER BY ent, day""").df()

    @staticmethod
    def profiles(ed):
        """per-entity behaviour profile from entity-day rows (sums over the rows given)."""
        g = ed.groupby("ent").agg(h=("h", "sum"), days=("day", "nunique"), n_edges=("n_edges", "sum"),
                                  k_new=("k_new", "sum"), k_ntlm=("k_ntlm", "sum"), k_rare=("k_rare", "sum"),
                                  k_x=("k_x", "sum"), ntlm_edges=("ntlm_edges", "sum"),
                                  fail_edges=("fail_edges", "sum"), partners=("partners", "sum"))
        return Engine.featurize(g)

    @staticmethod
    def featurize(g):
        f = pd.DataFrame(index=g.index)
        f["act"] = np.log1p(g.h / g.days)
        f["edges_per_h"] = np.log1p(g.n_edges / g.h)
        f["partners_per_day"] = np.log1p(g.partners / g.days)
        f["new_per_h"] = np.log1p(g.k_new / g.h)
        f["ntlm_share"] = (g.ntlm_edges + 0.5) / (g.n_edges + 1)
        f["fail_share"] = (g.fail_edges + 0.5) / (g.n_edges + 1)
        f["rare_share"] = (g.k_rare + 0.5) / (g.k_new + 1)
        f["x_share"] = (g.k_x + 0.5) / (g.k_new + 1)
        return f, g

    # ---- 3. models fit on a history window -----------------------------------------------
    def fit(self, d, v, d_from=1, d_to=None):
        a = self.a
        d_to = d if d_to is None else d_to
        ed = self.history(d_to, v, d_from)
        f, g = self.profiles(ed)
        # habitual: warm-up / history max hourly k_new above percentile
        mx = self.c.sql("SELECT ent, max(k_new) AS mx FROM hist_ch GROUP BY ent ORDER BY ent").df().set_index("ent").mx
        thr = float(np.percentile(mx, a.outlier_pct)) if len(mx) else 0
        habitual = set(mx[mx > thr].index)
        keep = ~g.index.isin(habitual)
        pop = {"new": g.k_new[keep].sum() / max(g.h[keep].sum(), 1)}
        for s in SHARES:
            pop[s] = g[f"k_{s}"][keep].sum() / max(g.k_new[keep].sum(), 1)
        m = {"pop": pop, "habitual": habitual, "thr": thr}
        if a.prior == "peer":
            ok = keep & (g.h >= 3)
            sc = StandardScaler().fit(f[ok])
            gm = fit_gmm(sc.transform(f[ok]), a.kmax)
            lab = pd.Series(gm.predict(sc.transform(f[ok])), index=f.index[ok])
            gg = g[ok].assign(c=lab)
            grp = gg.groupby("c").agg(h=("h", "sum"), k_new=("k_new", "sum"), k_ntlm=("k_ntlm", "sum"),
                                      k_rare=("k_rare", "sum"), k_x=("k_x", "sum"), n=("h", "size"))
            rates = pd.DataFrame({"new": grp.k_new / grp.h})
            for s in SHARES:
                rates[s] = (grp[f"k_{s}"] + 20 * pop[s]) / (grp.k_new + 20)
            m.update(scaler=sc, gmm=gm, group_rates=rates, group_sizes=grp.n.to_dict())
        # daily-profile model for the "fits no peer group" detector
        edd = ed[ed.h >= 2].set_index(["ent", "day"])
        fd, _ = self.featurize(edd.assign(days=1))
        if len(fd) > 50:
            sd = StandardScaler().fit(fd)
            gd = fit_gmm(sd.transform(fd), a.kmax)
            nll = -gd.score_samples(sd.transform(fd))
            m.update(day_scaler=sd, day_gmm=gd, day_nll_p99=float(np.percentile(nll, 99)))
        if a.scorer in ("density", "iforest"):
            hc = self.c.sql("""WITH cum AS (SELECT ent, day,
                       coalesce(sum(count(*)) OVER w, 0) AS ph, coalesce(sum(sum(k_new)) OVER w, 0) AS p_new,
                       coalesce(sum(sum(k_ntlm)) OVER w, 0) AS p_ntlm, coalesce(sum(sum(k_rare)) OVER w, 0) AS p_rare,
                       coalesce(sum(sum(k_x)) OVER w, 0) AS p_x
                       FROM hist_ch GROUP BY ent, day
                       WINDOW w AS (PARTITION BY ent ORDER BY day ROWS BETWEEN UNBOUNDED PRECEDING AND 1 PRECEDING))
                    SELECT h.*, cum.ph, cum.p_new, cum.p_ntlm, cum.p_rare, cum.p_x
                    FROM hist_ch h JOIN cum USING (ent, day) WHERE h.k_new > 0 ORDER BY ent, hr""").df()
            X = self.density_features(hc, pop)          # all entities: features are relative
            ds = StandardScaler().fit(X)
            if a.scorer == "density":
                gm = fit_gmm(ds.transform(X), a.kmax)
            else:                                        # same features, same calibration, different model
                gm = IsolationForest(n_estimators=200, max_samples=min(4096, len(X)), random_state=0,
                                     n_jobs=1).fit(ds.transform(X))
            m.update(dens_scaler=ds, dens_gmm=gm,
                     dens_hist_nll=np.sort(-gm.score_samples(ds.transform(X))))
        self.models[v] = m

    def density_features(self, df, pop):
        """entity-RELATIVE, sample-size-aware features (signed deviance residuals, ~N(0,1)
        under the entity's own normal): new logins vs its expected rate (Poisson), and each
        share vs its usual share (binomial, given the number of new logins). A single NTLM
        login is weak evidence; forty are strong. Shrunk toward population rates as before."""
        A, B = self.a.prior_hours, self.a.share_prior
        lam = ((df.p_new + A * pop["new"]) / (df.ph + A)).clip(lower=1e-9).to_numpy()
        k = df.k_new.to_numpy().astype(float)
        with np.errstate(divide="ignore", invalid="ignore"):
            dev = 2 * (np.where(k > 0, k * np.log(k / lam), 0.0) - (k - lam))
            cols = [np.sign(k - lam) * np.sqrt(np.clip(dev, 0, None))]
            for s in SHARES:
                q = ((df[f"p_{s}"] + B * pop[s]) / (df.p_new + B)).clip(1e-6, 1 - 1e-6).to_numpy()
                ks = df[f"k_{s}"].to_numpy().astype(float); n = k
                d = 2 * (np.where(ks > 0, ks * np.log(ks / (n * q)), 0.0)
                         + np.where(n - ks > 0, (n - ks) * np.log((n - ks) / (n * (1 - q))), 0.0))
                cols.append(np.sign(ks - n * q) * np.sqrt(np.clip(np.nan_to_num(d), 0, None)))
        return np.column_stack(cols)

    # ---- 4. score one day's campaign-hours ------------------------------------------------
    def score_day(self, d, v):
        a, m = self.a, self.models[v]
        A, B = a.prior_hours, a.share_prior
        ed = self.history(d, v)              # entity history up to d (filtered)
        f, g = self.profiles(ed) if len(ed) else (pd.DataFrame(), pd.DataFrame())
        t = self.c.sql(self.campaigns_sql(v, "today") + " ORDER BY ent, hr").df()
        t = t.merge(g[["h", "k_new"] + [f"k_{s}" for s in SHARES]].rename(
            columns={"h": "ph", "k_new": "p_new", **{f"k_{s}": f"p_{s}" for s in SHARES}}),
            left_on="ent", right_index=True, how="left").fillna({"ph": 0, "p_new": 0, **{f"p_{s}": 0 for s in SHARES}})
        t["habitual"] = t.ent.isin(m["habitual"]).astype(int)
        # group rates: peer group (if assigned) or population
        gr = pd.DataFrame({k: [m["pop"][k]] * len(t) for k in ["new"] + SHARES}, index=t.index)
        t["group"] = -1
        if a.prior == "peer" and len(f):
            okf = f[(g.h >= 3) & ~f.index.isin(m["habitual"])]
            if len(okf):
                cl = pd.Series(m["gmm"].predict(m["scaler"].transform(okf)), index=okf.index)
                t["group"] = t.ent.map(cl).fillna(-1).astype(int)
                has = t.group >= 0
                for k in ["new"] + SHARES:
                    gr.loc[has, k] = m["group_rates"][k].reindex(t.group[has]).to_numpy()
        lam = ((t.p_new + A * gr["new"]) / (t.ph + A)).clip(lower=1e-9).to_numpy()
        n = t.k_new.astype(float).to_numpy()
        t["lam"] = lam
        raw = {"new": np.where(n > 0, -log_tail_pois(n, lam), 0.0)}
        for s in SHARES:
            q = ((t[f"p_{s}"] + B * gr[s]) / (t.p_new + B)).clip(1e-6, 1 - 1e-6).to_numpy()
            k = t[f"k_{s}"].astype(float).to_numpy()
            raw[s] = np.where((n > 0) & (k > 0), -log_tail_binom(k, n, q), 0.0)
        for s, r in raw.items():
            t[f"sur_{s}"] = np.minimum(r, a.cap)
        t["score_raw"] = sum(raw.values())
        if a.scorer == "surprise":
            t["score"] = sum(t[f"sur_{s}"] for s in raw)
        else:                                     # density or iforest: -score_samples = higher is more unusual
            t["score"] = 0.0
            pos = t.k_new > 0
            if pos.any():
                X = self.density_features(t[pos], m["pop"])
                nll = -m["dens_gmm"].score_samples(m["dens_scaler"].transform(X))
                h = m["dens_hist_nll"]; N = len(h)
                # calibrated per view: -log of the share of history at least this unlikely
                tail = (1 + N - np.searchsorted(h, nll, side="left")) / (N + 1)
                excess = (X > 0).any(axis=1)              # one-sided: more than usual only
                t.loc[pos, "score"] = np.where(excess, -np.log(tail), 0.0)
                t.loc[pos, "score_raw"] = np.where(excess, nll, 0.0)   # tie-break beyond history
        t["view"] = v
        # daily profile anomaly for entities active today
        pa = None
        if "day_gmm" in m:
            tg = t.groupby("ent").agg(h=("hr", "size"), n_edges=("n_edges", "sum"), k_new=("k_new", "sum"),
                                      k_ntlm=("k_ntlm", "sum"), k_rare=("k_rare", "sum"), k_x=("k_x", "sum"),
                                      ntlm_edges=("ntlm_edges", "sum"), fail_edges=("fail_edges", "sum"),
                                      partners=("partners", "sum"), y_strict=("y_strict", "max"),
                                      y_lenient=("y_lenient", "max"))
            tg = tg[tg.h >= 2].assign(days=1)
            if len(tg):
                fd, _ = self.featurize(tg)
                tg["nll"] = -m["day_gmm"].score_samples(m["day_scaler"].transform(fd))
                tg["view"], tg["day"] = v, d
                pa = tg.reset_index()
        return t, pa


def summarize(alerts_by_day, follow_by_day, pos, budget, confirm_by_day=()):
    out = {}
    al = pd.concat(alerts_by_day, ignore_index=True) if alerts_by_day else pd.DataFrame()
    for lab, name in (("label_lenient", "lenient"), ("label", "strict")):
        P = pos[pos[lab] == 1]
        cov = al[["usr", "src", "dst", "hr", lab]].drop_duplicates(["usr", "src", "dst", "hr"]) if len(al) else al
        cv = cov[cov[lab] == 1] if len(cov) else cov
        first = P.groupby("un").hr.min()
        caught = cv.assign(un=cv.usr.str.split("@").str[0]).groupby("un").hr.min() if len(cv) else pd.Series(dtype=float)
        fu = pd.concat(follow_by_day, ignore_index=True) if follow_by_day else pd.DataFrame(columns=["usr", "src", "dst", "hr", lab])
        fu_pos = fu[fu[lab] == 1].drop_duplicates(["usr", "src", "dst", "hr"]) if len(fu) else fu
        if len(fu_pos) and len(cv):
            fu_pos = fu_pos.merge(cv[["usr", "src", "dst", "hr"]], how="left", indicator=True)
            fu_pos = fu_pos[fu_pos._merge == "left_only"]
        K = ["usr", "src", "dst", "hr"]
        cw = pd.concat(confirm_by_day, ignore_index=True) if len(confirm_by_day) else pd.DataFrame(columns=K + [lab])
        parts = [x[x[lab] == 1][K] for x in (cov, fu, cw) if len(x)]
        allp = pd.concat(parts).drop_duplicates() if parts else pd.DataFrame(columns=K)
        cwp = cw[cw[lab] == 1][K].drop_duplicates() if len(cw) else cw
        if len(cwp):
            prev = pd.concat([x[x[lab] == 1][K] for x in (cov, fu) if len(x)] or [pd.DataFrame(columns=K)])
            cwp = cwp.merge(prev.drop_duplicates(), how="left", indicator=True)
            cwp = cwp[cwp._merge == "left_only"]
        out[name] = {"edge_recall": round(len(cv) / max(len(P), 1), 4),
                     "confirmed_extra_recall": round(len(cwp) / max(len(P), 1), 4),
                     "total_recall": round(len(allp) / max(len(P), 1), 4),
                     "users_caught_any_route": int(allp.usr.str.split("@").str[0].nunique()) if len(allp) else 0,
                     "followup_extra_recall": round(len(fu_pos) / max(len(P), 1), 4),
                     "users_caught": int(len(caught)), "users": int(P.un.nunique()),
                     "median_delay_h": None if not len(caught) else float((caught - first.reindex(caught.index)).median())}
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data", default="data"); ap.add_argument("--out", default="results")
    ap.add_argument("--warmup-end", type=int, default=7); ap.add_argument("--end", type=int, default=16)
    ap.add_argument("--prior", choices=["population", "peer"], default="peer")
    ap.add_argument("--scorer", choices=["surprise", "density", "iforest"], default="surprise")
    ap.add_argument("--regime", choices=["static", "oracle"], default="static")
    ap.add_argument("--budget", type=int, default=25, help="campaign alerts per day")
    ap.add_argument("--watch-hours", type=int, default=24)
    ap.add_argument("--prior-hours", type=float, default=24.0); ap.add_argument("--share-prior", type=float, default=20.0)
    ap.add_argument("--cap", type=float, default=100.0); ap.add_argument("--outlier-pct", type=float, default=99.9)
    ap.add_argument("--kmax", type=int, default=8); ap.add_argument("--memory", default="")
    ap.add_argument("--confirm-watch", choices=["none", "src", "src_user"], default="none")
    ap.add_argument("--confirm-days", type=int, default=7)
    ap.add_argument("--sweep-min", type=int, default=200, help="new logins in one alert = bulk-review sweep")
    ap.add_argument("--dump-alerts", action="store_true", help="write <tag>_alert_edges.parquet")
    ap.add_argument("--tag", default="")
    a = ap.parse_args()
    tag = a.tag or f"{a.regime}_{a.prior}_{a.scorer}_b{a.budget}"
    os.makedirs(a.out, exist_ok=True)
    E = Engine(a); c = E.c
    T0 = time.time()
    for d in range(0, a.warmup_end):          # warm-up: flags only (day 0 = burn-in)
        E.flag_day(d)
    print(f"[{tag}] warm-up flagged in {time.time() - T0:.0f}s", flush=True)
    for v in VIEWS:
        E.fit(a.warmup_end, v)
    pos = c.sql(f"""SELECT usr, un, src, dst, hr, day, label, label_lenient FROM e
                    WHERE day >= {a.warmup_end} AND (label = 1 OR label_lenient = 1)""").df()
    alerts_by_day, follow_by_day, daily, pa_all = [], [], [], []
    watch = pd.DataFrame(columns=["kind", "ent", "dst", "since", "until"])
    conf = pd.DataFrame(columns=["kind", "ent", "until"]); confirm_by_day = []; dumps = []
    for d in range(a.warmup_end, a.end):
        t0 = time.time()
        E.flag_day(d)
        if a.regime == "oracle" and d > a.warmup_end:
            for v in VIEWS:
                E.fit(d, v)
        scored, pas = [], []
        for v in VIEWS:
            t, pa = E.score_day(d, v)
            scored.append(t)
            if pa is not None: pas.append(pa)
        S = pd.concat(scored, ignore_index=True)
        cand = S[S.score > 0].sort_values(["score", "score_raw", "view", "ent", "hr"],
                                          ascending=[False, False, True, True, True], kind="mergesort")
        al = cand.head(a.budget)
        # edges covered by today's alerts
        c.register("al", al[["view", "ent", "hr"]])
        edges_v = c.sql("""SELECT DISTINCT al.view, al.ent, t.usr, t.un, t.src, t.dst, t.hr, t.label, t.label_lenient, t.ntlm, t.x,
                                t.new_user_dst, t.new_src_dst, t.rare_dst
                         FROM today t JOIN al ON al.hr = t.hr AND (
                           (al.view = 'user' AND al.ent = t.un AND t.new_user_dst = 1)
                           OR (al.view = 'src' AND al.ent = t.src AND t.new_src_dst = 1)
                           OR (al.view = 'dst' AND al.ent = t.dst AND t.new_user_dst = 1))""").df()
        c.unregister("al")
        K = ["usr", "src", "dst", "hr"]
        # sweeps: alerts covering >= sweep_min logins are reviewed in bulk as one item
        sz = edges_v.groupby(["view", "ent"]).size()
        sweeps = sz[sz >= a.sweep_min]
        in_sweep = edges_v.set_index(["view", "ent"]).index.isin(sweeps.index)
        sweep_logins = edges_v[in_sweep].drop_duplicates(K)
        rest = edges_v[~in_sweep].drop_duplicates(K)
        rest = rest.merge(sweep_logins[K], how="left", indicator=True)
        rest = rest[rest._merge == "left_only"]
        review_items = len(rest) + len(sweeps)
        edges = edges_v.drop(columns=["view", "ent"]).drop_duplicates(K)
        alerts_by_day.append(edges)
        if a.dump_alerts and len(edges_v):
            dumps.append(edges_v.merge(al[["view", "ent", "hr", "score", "k_new"]], on=["view", "ent", "hr"], how="left")
                         .assign(day=d, sweep=lambda x: x.set_index(["view", "ent"]).index.isin(sweeps.index)))
        # follow-up: later logins on the exact pairs an alert newly reached (attacker returning)
        if len(watch):
            c.register("w", watch)
            fu = c.sql("""SELECT DISTINCT t.usr, t.src, t.dst, t.hr, t.label, t.label_lenient FROM today t JOIN w
                          ON t.hr > w.since AND t.hr <= w."until" AND t.dst = w.dst
                          AND ((w.kind = 'user' AND w.ent = t.un) OR (w.kind = 'src' AND w.ent = t.src))""").df()
            c.unregister("w")
            follow_by_day.append(fu)
        else:
            fu = pd.DataFrame()
        # confirmed-entity watch: logins today from hosts / users the analyst confirmed earlier
        cw = pd.DataFrame(columns=K + ["un", "label", "label_lenient"])
        if a.confirm_watch != "none" and len(conf):
            c.register("cf", conf[conf.until >= d])
            uq = ("OR (cf.kind = 'user' AND cf.ent = t.un AND t.new_user_dst = 1)" if a.confirm_watch == "src_user" else "")
            cw = c.sql(f"""SELECT DISTINCT t.usr, t.un, t.src, t.dst, t.hr, t.label, t.label_lenient FROM today t
                          JOIN cf ON (cf.kind = 'src' AND cf.ent = t.src) {uq}""").df()
            c.unregister("cf")
            if len(cw) and len(edges):          # already in today's alerts: not extra work
                cw = cw.merge(edges[K], how="left", indicator=True)
                cw = cw[cw._merge == "left_only"].drop(columns="_merge")
            confirm_by_day.append(cw)
        # analyst confirms: malicious alerted (and watch-surfaced) logins put their entities on watch
        if a.confirm_watch != "none":
            rev = pd.concat([edges[K + ["un", "label_lenient"]], cw[K + ["un", "label_lenient"]]])
            bad = rev[rev.label_lenient == 1]
            if len(bad):
                kinds = [bad.assign(kind="src", ent=bad.src)]
                if a.confirm_watch == "src_user": kinds.append(bad.assign(kind="user", ent=bad.un))
                nc = pd.concat(kinds)[["kind", "ent"]].drop_duplicates().assign(until=d + a.confirm_days)
                conf = (pd.concat([conf, nc]).groupby(["kind", "ent"], as_index=False).until.max())
        if len(edges):
            nw = pd.concat([
                edges.assign(kind="user", ent=edges.un)[["kind", "ent", "dst", "hr"]],
                edges.assign(kind="src", ent=edges.src)[["kind", "ent", "dst", "hr"]]])
            nw = nw.rename(columns={"hr": "since"}).assign(until=lambda x: x.since + a.watch_hours)
            watch = (pd.concat([watch, nw]).groupby(["kind", "ent", "dst"], as_index=False)
                     .agg(since=("since", "min"), until=("until", "max")))
        # oracle: confirmed-malicious logins from today's alerts leave the history
        if a.regime == "oracle" and len(edges):
            bad = edges[edges.label_lenient == 1][["usr", "src", "dst", "hr"]].drop_duplicates()
            if len(bad):
                c.register("bad", bad); c.execute("INSERT INTO excluded SELECT * FROM bad"); c.unregister("bad")
        if pas:
            pa_all.append(pd.concat(pas, ignore_index=True))
        npos_today = int((pos.day == d).sum())
        daily.append({"day": d, "campaign_hours": len(S), "alerts": len(al),
                      "alert_precision_lenient": round(float(al.y_lenient.mean()), 3) if len(al) else None,
                      "redteam_edges_today": npos_today,
                      "covered_lenient": int(edges.drop_duplicates(["usr", "src", "dst", "hr"]).label_lenient.sum()) if len(edges) else 0,
                      "logins_to_review": int(len(edges.drop_duplicates(["usr", "src", "dst", "hr"]))) if len(edges) else 0,
                      "followup_logins": int(len(fu)),
                      "review_items": int(review_items), "sweeps": int(len(sweeps)),
                      "sweep_logins": int(len(sweep_logins)),
                      "confirmed_logins": int(len(cw)), "confirmed_rt": int(cw.label_lenient.sum()) if len(cw) else 0,
                      "watched_entities": int((conf.until >= d + 1).sum()) if len(conf) else 0, "excluded_total": int(c.sql("SELECT count(*) FROM excluded").fetchone()[0]),
                      "seconds": round(time.time() - t0, 1)})
        print(f"[{tag}] day {d}: {daily[-1]}", flush=True)
    if dumps:
        pd.concat(dumps, ignore_index=True).to_parquet(os.path.join(a.out, f"{tag}_alert_edges.parquet"), index=False)
    dd = pd.DataFrame(daily)
    dd.to_csv(os.path.join(a.out, f"{tag}_daily.csv"), index=False)
    summ = {"tag": tag, "config": vars(a), "budget_per_day": a.budget,
            "alert_precision_lenient": round(float(np.nanmean(dd.alert_precision_lenient.astype(float))), 3),
            "logins_to_review_per_day": round(float(dd.logins_to_review.mean()), 1),
            "followup_logins_per_day": round(float(dd.followup_logins.mean()), 1),
            "review_items_per_day": round(float(dd.review_items.mean()), 1),
            "median_per_day": {k: float(dd[k].median()) for k in
                               ["logins_to_review", "review_items", "followup_logins", "confirmed_logins"]},
            "confirmed_logins_per_day": round(float(dd.confirmed_logins.mean()), 1),
            "confirmed_precision": round(float(dd.confirmed_rt.sum() / max(dd.confirmed_logins.sum(), 1)), 3),
            "metrics": summarize(alerts_by_day, follow_by_day, pos, a.budget, confirm_by_day),
            "seconds": round(time.time() - T0, 1)}
    if a.prior == "peer":
        summ["peer_groups"] = {v: {"k": int(E.models[v]["gmm"].n_components), "sizes": E.models[v]["group_sizes"],
                                   "rates": E.models[v]["group_rates"].round(4).to_dict()} for v in VIEWS}
    if pa_all:
        P = pd.concat(pa_all, ignore_index=True)
        P["rk"] = P.groupby("day").nll.rank(ascending=False, method="first")
        prof = {}
        for b in (10, 25, 50):
            s = P[P.rk <= b]
            prof[b] = {"precision_lenient": round(float(s.y_lenient.mean()), 3),
                       "redteam_entity_days_caught": int(s.y_lenient.sum()),
                       "redteam_entity_days": int(P.y_lenient.sum())}
        summ["profile_anomaly_per_day"] = prof
        P.sort_values("nll", ascending=False).head(200).to_csv(os.path.join(a.out, f"{tag}_profile_anomaly.csv"), index=False)
    json.dump(summ, open(os.path.join(a.out, f"{tag}_summary.json"), "w"), indent=2, default=str)
    print(json.dumps({k: summ[k] for k in summ if k not in ("config", "peer_groups")}, indent=1, default=str))


if __name__ == "__main__":
    main()
