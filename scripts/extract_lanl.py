#!/usr/bin/env python3
"""Extract a time window of the LANL multi-source cyber dataset into Parquet.

Reads the original files where they are (.txt.gz or unzipped .txt), keeps only
events in [day_start, day_end), and writes one Parquet file per source per day:
    <out>/<source>/day=DD.parquet
It stops reading a file as soon as it passes day_end (the files are sorted by
time), and records rows, seconds and rows/second per source in
<out>/extract_manifest.json, so the run doubles as an ingestion benchmark.

Dataset: https://csr.lanl.gov/data/cyber1/ (CC0). Times are seconds from epoch 1.

Usage (Windows example):
    python extract_lanl.py --src "path\\to\\lanl\\files" --out "..\\data" --day-start 0 --day-end 16
"""
import argparse, json, os, platform, sys, time

import pyarrow as pa
import pyarrow.compute as pc
import pyarrow.csv as pcsv
import pyarrow.parquet as pq

DAY = 86400
SCHEMAS = {
    "auth":    ["time", "src_user", "dst_user", "src_host", "dst_host",
                "auth_type", "logon_type", "orientation", "outcome"],
    "proc":    ["time", "user", "host", "process", "action"],
    "flows":   ["time", "duration", "src_host", "src_port", "dst_host",
                "dst_port", "protocol", "packets", "bytes"],
    "dns":     ["time", "src_host", "resolved_host"],
    "redteam": ["time", "user", "src_host", "dst_host"],
}
INT_COLS = {"time", "duration", "protocol", "packets", "bytes"}


def extract(name, src, out, d0, d1, block_mb, progress_s=15):
    path = None
    for ext, comp in ((".txt.gz", "gzip"), (".txt", None)):
        cand = os.path.join(src, name + ext)
        if os.path.exists(cand):
            path, compression = cand, comp
            break
    if path is None:
        print(f"[{name}] missing: {os.path.join(src, name)}.txt(.gz) (skipped)")
        return None
    print(f"[{name}] reading {path}", flush=True)
    cols = SCHEMAS[name]
    types = {c: (pa.int64() if c in INT_COLS else pa.string()) for c in cols}
    reader = pcsv.open_csv(
        pa.input_stream(path, compression=compression),
        read_options=pcsv.ReadOptions(column_names=cols, block_size=block_mb << 20),
        convert_options=pcsv.ConvertOptions(column_types=types, null_values=["?"],
                                            strings_can_be_null=True),
    )
    # red team events are tiny and are the labels: always keep all of them
    lo, hi = (0, 10**12) if name == "redteam" else (d0 * DAY, d1 * DAY)
    os.makedirs(os.path.join(out, name), exist_ok=True)
    writers, per_day = {}, {}
    rows_in = rows_out = 0
    t0 = last = time.time()
    last_day = None
    try:
        for batch in reader:
            rows_in += batch.num_rows
            t = batch.column(0)
            if pc.min(t).as_py() >= hi:
                break
            b = batch.filter(pc.and_(pc.greater_equal(t, lo), pc.less(t, hi)))
            if b.num_rows:
                days = pc.divide(b.column(0), DAY)          # integer division
                for d in pc.unique(days).to_pylist():
                    part = b.filter(pc.equal(days, d))
                    if d not in writers:
                        f = os.path.join(out, name, f"day={d:02d}.parquet")
                        writers[d] = pq.ParquetWriter(f, part.schema, compression="zstd")
                    writers[d].write_batch(part)
                    per_day[d] = per_day.get(d, 0) + part.num_rows
                    rows_out += part.num_rows
                last_day = int(pc.max(days).as_py())
            now = time.time()
            if now - last > progress_s:
                print(f"[{name}] read {rows_in/1e6:,.1f}M rows, kept {rows_out/1e6:,.1f}M, "
                      f"at day {last_day}, {rows_in/(now-t0)/1e6:.2f}M rows/s", flush=True)
                last = now
    finally:
        for w in writers.values():
            w.close()
    secs = time.time() - t0
    print(f"[{name}] done: read {rows_in:,} rows, kept {rows_out:,} in {secs:,.0f}s "
          f"({rows_in/max(secs,1e-9)/1e6:.2f}M rows/s)", flush=True)
    return {"rows_read": rows_in, "rows_kept": rows_out, "seconds": round(secs, 1),
            "rows_per_sec": round(rows_in / max(secs, 1e-9)), "rows_per_day": per_day}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--src", required=True, help="folder with the LANL .txt.gz files")
    ap.add_argument("--out", required=True, help="output folder for Parquet files")
    ap.add_argument("--day-start", type=int, default=0)
    ap.add_argument("--day-end", type=int, default=16, help="exclusive")
    ap.add_argument("--sources", default="redteam,dns,flows,proc,auth")
    ap.add_argument("--block-mb", type=int, default=64)
    a = ap.parse_args()

    os.makedirs(a.out, exist_ok=True)
    manifest_path = os.path.join(a.out, "extract_manifest.json")
    manifest = json.load(open(manifest_path)) if os.path.exists(manifest_path) else {}
    manifest["machine"] = {"platform": platform.platform(), "processor": platform.processor(),
                           "cpu_count": os.cpu_count(), "python": sys.version.split()[0],
                           "pyarrow": pa.__version__}
    manifest["window_days"] = [a.day_start, a.day_end]
    for name in a.sources.split(","):
        r = extract(name.strip(), a.src, a.out, a.day_start, a.day_end, a.block_mb)
        if r:
            manifest.setdefault("sources", {})[name] = r
            json.dump(manifest, open(manifest_path, "w"), indent=2)
    print(f"manifest: {manifest_path}")


if __name__ == "__main__":
    main()
