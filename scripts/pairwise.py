#!/usr/bin/env python3
"""Pairwise analysis of detection signals on NORMAL training traffic (warm-up days only).

No red-team labels are used: design decisions should come from normal behavior, so the
detector is not tuned to this one red team.

1. Edge-hour signals (12 binary flags): for every pair, joint rate, lift
   P(a,b) / (P(a) P(b)), log2 lift, phi correlation, and normalized mutual information.
   Lift >> 1: the two fire together far more than chance (redundant: counting both
   double-counts). Lift << 1: they rarely co-occur in normal traffic, so seeing both is
   extra evidence (candidates for a joint test).
2. Campaign-hour variables (user and source fan-out, hours with new logins): Spearman
   correlation of volume (k_new, n_edges), shares (NTLM, rare, corroborated) and history.

Writes results/pairwise_signals.csv, pairwise_campaign_corr.csv and two heatmaps.
"""
import argparse, itertools, math, os
import duckdb
import numpy as np
import pandas as pd
import vizstyle as vz
import matplotlib.pyplot as plt

SIG = ["new_user_dst", "new_user_src", "new_src_dst", "ntlm", "first_ntlm_for_user", "any_fail",
       "rare_dst", "fanout3", "proc_first_user_on_dst", "proc_new_process_on_dst", "flow_new_pair", "dns_new_pair"]
SHORT = {"new_user_dst": "new user→dst", "new_user_src": "new user→src", "new_src_dst": "new src→dst",
         "ntlm": "NTLM", "first_ntlm_for_user": "user's 1st NTLM", "any_fail": "failure",
         "rare_dst": "rare dst", "fanout3": "fan-out ≥3", "proc_first_user_on_dst": "user's 1st proc on dst",
         "proc_new_process_on_dst": "new proc on dst", "flow_new_pair": "new flow pair", "dns_new_pair": "new DNS pair"}


def heatmap(mat, labels, title, path, center_label, vmax):
    vz.setup()
    fig, ax = plt.subplots(figsize=(8.6, 7.4))
    im = ax.imshow(mat, cmap=vz.DIVERGING, vmin=-vmax, vmax=vmax)
    ax.set_xticks(range(len(labels)), labels, rotation=45, ha="right")
    ax.set_yticks(range(len(labels)), labels)
    for i in range(len(labels)):
        for j in range(len(labels)):
            v = mat[i, j]
            if i != j and np.isfinite(v):
                ax.text(j, i, f"{v:.1f}", ha="center", va="center", fontsize=7,
                        color="#fcfcfb" if abs(v) > 0.6 * vmax else vz.INK)
    ax.set_title(title)
    cb = fig.colorbar(im, ax=ax, shrink=0.75)
    cb.set_label(center_label, color=vz.INK2); cb.outline.set_visible(False)
    fig.tight_layout(); fig.savefig(path, dpi=150); plt.close(fig)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data", default="data"); ap.add_argument("--out", default="results")
    ap.add_argument("--warmup-end", type=int, default=7)
    a = ap.parse_args()
    src = os.path.join(a.data, "derived", "edge_hours_all.parquet").replace(os.sep, "/")
    c = duckdb.connect()
    c.execute(f"CREATE VIEW w AS SELECT * FROM read_parquet('{src}') WHERE day < {a.warmup_end}")
    n = c.sql("SELECT count(*) FROM w").fetchone()[0]
    p = dict(zip(SIG, c.sql("SELECT " + ", ".join(f"avg({s})" for s in SIG) + " FROM w").fetchone()))
    pairs = list(itertools.combinations(SIG, 2))
    joint = c.sql("SELECT " + ", ".join(f"avg({x} * {y})" for x, y in pairs) + " FROM w").fetchone()
    rows = []
    def h(q): return -sum(v * math.log(v) for v in q if v > 0)
    for (x, y), pxy in zip(pairs, joint):
        px, py = p[x], p[y]
        lift = pxy / (px * py) if px * py > 0 else float("nan")
        phi = (pxy - px * py) / math.sqrt(px * (1 - px) * py * (1 - py)) if 0 < px < 1 and 0 < py < 1 else float("nan")
        cells = [pxy, px - pxy, py - pxy, 1 - px - py + pxy]
        mi = h([px, 1 - px]) + h([py, 1 - py]) - h(cells)
        nmi = mi / min(h([px, 1 - px]), h([py, 1 - py])) if min(px, py) > 0 else float("nan")
        rows.append({"a": x, "b": y, "rate_a": px, "rate_b": py, "joint_rate": pxy,
                     "joint_count": round(pxy * n), "lift": lift,
                     "log2_lift": math.log2(lift) if lift and lift > 0 else float("-inf"),
                     "phi": phi, "nmi": nmi})
    df = pd.DataFrame(rows).sort_values("log2_lift", ascending=False)
    df.round(6).to_csv(os.path.join(a.out, "pairwise_signals.csv"), index=False)
    k = len(SIG); m = np.full((k, k), np.nan)
    for r in rows:
        i, j = SIG.index(r["a"]), SIG.index(r["b"])
        v = r["log2_lift"] if np.isfinite(r["log2_lift"]) else -8
        m[i, j] = m[j, i] = v
    heatmap(m, [SHORT[s] for s in SIG],
            f"Signal co-occurrence in normal traffic (days 1–{a.warmup_end - 1}, {n/1e6:.1f}M edge-hours)",
            os.path.join(a.out, "pairwise_signals_lift.png"), "log2 lift  (0 = independent)", 8)

    # campaign-hour variables, user and source fan-out
    out = []
    for v, key, new in (("user", "split_part(usr, '@', 1)", "new_user_dst"), ("src", "src", "new_src_dst")):
        d = c.sql(f"""SELECT count(*) AS n_edges, sum({new}) AS k_new,
                         sum({new} * ntlm) / sum({new}) AS share_ntlm,
                         sum({new} * rare_dst) / sum({new}) AS share_rare,
                         sum({new} * greatest(proc_first_user_on_dst, proc_new_process_on_dst, flow_new_pair)) / sum({new}) AS share_corr,
                         sum(n_events) AS events
                  FROM w GROUP BY {key}, hr HAVING sum({new}) > 0""").df()
        cm = d.corr(method="spearman")
        cm.insert(0, "view", v); out.append(cm)
        lab = list(d.columns)
        heatmap(cm[lab].to_numpy(), lab, f"{v} fan-out campaign-hours: Spearman correlation (n={len(d):,})",
                os.path.join(a.out, f"pairwise_campaign_{v}.png"), "Spearman ρ", 1)
    pd.concat(out).round(3).to_csv(os.path.join(a.out, "pairwise_campaign_corr.csv"))
    pd.set_option("display.width", 200)
    print(f"edge-hours in warm-up: {n:,}")
    print(df[["a", "b", "joint_count", "lift", "log2_lift", "phi", "nmi"]].round(3).to_string(index=False))
    print(pd.concat(out).round(2).to_string())


if __name__ == "__main__":
    main()
