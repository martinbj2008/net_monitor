#!/usr/bin/env python3
# hub_probe/upload_csv_to_pg.py — Step 4 uploader.
#
# Reads a CSV produced by probe_daemon.py and inserts new rows into
# probe_sample (docker/postgres/initdb/01_schema.sql).
#
# * de-dup by (ts, src, dst, proto, ip_ver) — matches the table PK
# * tracks a checkpoint file so we don't re-read old lines
# * intended to run on the machine that also has the docker postgres, e.g.
#     python3 upload_csv_to_pg.py --csv /tmp/rtt.csv \
#         --dsn 'postgresql://vps_probe:vps_probe@127.0.0.1:5432/vps_probe'
# * requires psycopg2 (or psycopg2-binary); if unavailable we exit non-zero
#   with a clear message so it's obvious what's missing.

import argparse
import csv
import os
import sys
from pathlib import Path

try:
    import psycopg2
    import psycopg2.extras
except ImportError:
    print("psycopg2 not installed. On the docker host run:\n"
          "  pip3 install psycopg2-binary\n"
          "or apt install python3-psycopg2", file=sys.stderr)
    sys.exit(2)


UPSERT = """
INSERT INTO probe_sample
  (ts, src, dst, dst_addr, proto, ip_ver, seq, rtt_ms, ok, batch_ts)
VALUES %s
ON CONFLICT (ts, src, dst, proto, ip_ver) DO NOTHING
"""


def load_rows(csv_path: Path, start_line: int):
    """Yield rows from CSV starting at start_line (1-based, excluding header).
    Returns (rows, next_line_number)."""
    rows = []
    with open(csv_path, "r", newline="") as f:
        r = csv.reader(f)
        header = next(r, None)   # discard header
        for i, rec in enumerate(r, start=1):
            if i < start_line:
                continue
            if len(rec) < 10:
                continue
            ts_iso, src, dst, dst_addr, proto, ip_ver, seq, rtt_ms, ok, batch \
                = rec[:10]
            rows.append((
                ts_iso,
                src, dst,
                dst_addr or None,
                proto,
                int(ip_ver),
                int(seq) if seq else None,
                int(rtt_ms) if rtt_ms else None,
                ok.lower() in ("true", "t", "1"),
                batch,
            ))
        next_line = i if rows else start_line - 1
    return rows, next_line + 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", required=True)
    ap.add_argument("--dsn", required=True,
                    help="postgresql://user:pass@host:port/db")
    ap.add_argument("--checkpoint",
                    help="file to remember last uploaded line "
                         "(default: <csv>.chk)")
    ap.add_argument("--from-start", action="store_true",
                    help="ignore checkpoint and reupload everything")
    args = ap.parse_args()

    csv_path = Path(args.csv)
    if not csv_path.exists():
        print(f"csv not found: {csv_path}", file=sys.stderr); sys.exit(1)

    chk_path = Path(args.checkpoint) if args.checkpoint \
               else csv_path.with_suffix(csv_path.suffix + ".chk")
    start_line = 1
    if not args.from_start and chk_path.exists():
        try:
            start_line = int(chk_path.read_text().strip()) + 1
        except Exception:
            start_line = 1

    rows, next_line = load_rows(csv_path, start_line)
    if not rows:
        print("[info] no new rows.")
        return

    print(f"[info] uploading {len(rows)} rows (from line {start_line}) ...")

    conn = psycopg2.connect(args.dsn)
    try:
        with conn:
            with conn.cursor() as cur:
                psycopg2.extras.execute_values(cur, UPSERT, rows,
                                               page_size=500)
    finally:
        conn.close()

    chk_path.write_text(str(next_line - 1))
    print(f"[done] uploaded {len(rows)} rows. checkpoint -> {chk_path} "
          f"(line {next_line - 1})")


if __name__ == "__main__":
    main()
