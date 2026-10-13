#!/usr/bin/env python3
"""Collect results/*_summary.json from engine.py into results/comparison.csv."""
import glob, json, os, sys
import pandas as pd

out = sys.argv[1] if len(sys.argv) > 1 else "results"
rows = []
for f in sorted(glob.glob(os.path.join(out, "*_summary.json"))):
    s = json.load(open(f)); m = s["metrics"]
    r = {"run": s["tag"], "regime": s["config"]["regime"], "prior": s["config"]["prior"],
         "scorer": s["config"]["scorer"], "alerts_per_day": s["budget_per_day"],
         "alert_precision": s["alert_precision_lenient"],
         "recall_lenient": m["lenient"]["edge_recall"], "followup_extra_recall": m["lenient"]["followup_extra_recall"],
         "users_caught": f'{m["lenient"]["users_caught"]}/{m["lenient"]["users"]}',
         "median_delay_h": m["lenient"]["median_delay_h"], "recall_strict": m["strict"]["edge_recall"],
         "logins_to_review_per_day": s["logins_to_review_per_day"],
         "followup_logins_per_day": s["followup_logins_per_day"], "runtime_s": s["seconds"]}
    cfg = s["config"]
    r["confirm_watch"] = cfg.get("confirm_watch", "none")
    if "total_recall" in m["lenient"]:
        r["confirmed_extra_recall"] = m["lenient"]["confirmed_extra_recall"]
        r["total_recall"] = m["lenient"]["total_recall"]
        r["users_caught_any_route"] = f'{m["lenient"].get("users_caught_any_route", "")}/{m["lenient"]["users"]}'
        r["confirmed_logins_per_day"] = s["confirmed_logins_per_day"]
        r["confirmed_precision"] = s["confirmed_precision"]
        r["review_items_per_day"] = s["review_items_per_day"]
        md = s["median_per_day"]
        r["median_logins_to_review"] = md["logins_to_review"]; r["median_review_items"] = md["review_items"]
        r["median_confirmed_logins"] = md["confirmed_logins"]
    pa = s.get("profile_anomaly_per_day", {}).get("25")
    if pa: r["profile_anomaly_prec@25"] = pa["precision_lenient"]
    rows.append(r)
# stale runs from before the density fix are dropped by name if their file is gone
df = pd.DataFrame(rows)
df.to_csv(os.path.join(out, "comparison.csv"), index=False)
pd.set_option("display.width", 250)
print(df.to_string(index=False))
