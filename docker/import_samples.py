#!/usr/bin/env python3
# import_samples.py - Import per-packet *.samples.jsonl files into PostgreSQL.
#
# Runs on the HUB (control) machine after leaf VPS scp their samples files.
#
# Usage:
#   python3 import_samples.py FILE1 FILE2 ...           # explicit files (probe.sh)
#   python3 import_samples.py --dir /path/to/results    # recursive scan
#   python3 import_samples.py --dry-run FILE ...        # parse only, don't write
#
# Only files matching *.samples.jsonl are processed. Aggregate *.jsonl are ignored.
#
# Idempotency: relies on PRIMARY KEY (ts, src, dst, proto, ip_ver) plus
# ON CONFLICT DO NOTHING. Re-importing the same file is a no-op.
#
# batch_ts is derived from the run_tag encoded in the filename, e.g.
#   20260714T1633.v4-icmp.samples.jsonl -> 2026-07-14T16:33:00Z (UTC).

import argparse
import glob
import json
import os
import re
import sys
from datetime import datetime, timezone

try:
    import psycopg2
    from psycopg2.extras import execute_values
except ImportError:
    sys.stderr.write("python3-psycopg2 missing. Install: apt-get install -y python3-psycopg2\n")
    sys.exit(2)

DEFAULT_DSN = os.environ.get(
    "PROBE_PG_DSN",
    "postgresql://probe:jPPErRzPbz0cMo2r8TfM1MD4@127.0.0.1:25432/probe",
)

# 20260714T1633.v4-icmp.samples.jsonl  or  20260714T1633.v6-tcp.samples.jsonl
FNAME_RE = re.compile(
    r"^(?P<tag>\d{8}T\d{4})\.(?P<ipver>v[46])-(?P<proto>icmp|tcp)\.samples\.jsonl$"
)


def parse_batch_ts(fname: str):
    """Return (batch_ts_datetime_utc, ipver_int, proto_str) or None if not a samples file."""
    m = FNAME_RE.match(os.path.basename(fname))
    if not m:
        return None
    tag = m.group("tag")  # YYYYMMDDTHHMM
    dt = datetime.strptime(tag, "%Y%m%dT%H%M").replace(tzinfo=timezone.utc)
    ipver = 4 if m.group("ipver") == "v4" else 6
    return dt, ipver, m.group("proto")


def load_samples(path: str, batch_ts, exp_ipver: int, exp_proto: str):
    """Yield rows as tuples matching probe_sample columns."""
    with open(path, "r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError as e:
                sys.stderr.write(f"[warn] {path}:{lineno} bad json: {e}\n")
                continue
            try:
                ts = rec["ts_utc"]
                src = rec["src"]
                dst = rec["dst_name"]
                dst_addr = rec["dst_addr"]
                proto = rec["proto"]
                ip_ver = int(rec["ip_ver"])
                seq = int(rec["seq"])
                rtt_ms = rec.get("rtt_ms")
                ok = bool(rec["ok"])
            except (KeyError, TypeError, ValueError) as e:
                sys.stderr.write(f"[warn] {path}:{lineno} bad field: {e}\n")
                continue

            # sanity check filename vs content
            if proto != exp_proto or ip_ver != exp_ipver:
                sys.stderr.write(
                    f"[warn] {path}:{lineno} mismatch fname vs record "
                    f"(fname={exp_proto}/v{exp_ipver}, rec={proto}/v{ip_ver}); skipped\n"
                )
                continue

            yield (
                ts,
                src,
                dst,
                dst_addr,
                proto,
                ip_ver,
                seq,
                int(rtt_ms) if rtt_ms is not None else None,
                ok,
                batch_ts,
            )


INSERT_SQL = """
INSERT INTO probe_sample
    (ts, src, dst, dst_addr, proto, ip_ver, seq, rtt_ms, ok, batch_ts)
VALUES %s
ON CONFLICT (ts, src, dst, proto, ip_ver) DO NOTHING
"""


def import_file(cur, path: str) -> tuple:
    """Return (rows_read, rows_inserted, batch_ts_iso)."""
    meta = parse_batch_ts(path)
    if meta is None:
        return (0, 0, None)  # skipped
    batch_ts, ipver, proto = meta

    rows = list(load_samples(path, batch_ts, ipver, proto))
    if not rows:
        return (0, 0, batch_ts.isoformat())

    # We want to know how many were actually inserted vs. skipped by ON CONFLICT.
    # execute_values doesn't natively return per-row status; use RETURNING trick.
    sql = INSERT_SQL.strip() + " RETURNING 1"
    inserted = 0
    # process in reasonable chunks to keep memory bounded
    CHUNK = 500
    for i in range(0, len(rows), CHUNK):
        chunk = rows[i:i + CHUNK]
        execute_values(cur, sql, chunk, page_size=CHUNK, fetch=True)
        inserted += cur.rowcount
    return (len(rows), inserted, batch_ts.isoformat())


def expand_files(paths, recursive_dir=None):
    files = []
    if recursive_dir:
        for root, _dirs, fs in os.walk(recursive_dir):
            for f in fs:
                if FNAME_RE.match(f):
                    files.append(os.path.join(root, f))
    for p in paths:
        if os.path.isdir(p):
            for root, _dirs, fs in os.walk(p):
                for f in fs:
                    if FNAME_RE.match(f):
                        files.append(os.path.join(root, f))
        elif any(ch in p for ch in "*?["):
            files.extend(glob.glob(p, recursive=True))
        else:
            files.append(p)
    # de-dup while preserving order
    seen = set()
    out = []
    for f in files:
        af = os.path.abspath(f)
        if af in seen:
            continue
        seen.add(af)
        out.append(f)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="*", help="samples.jsonl files (or dirs / globs)")
    ap.add_argument("--dir", help="recursively scan this directory for *.samples.jsonl")
    ap.add_argument("--dsn", default=DEFAULT_DSN, help="PostgreSQL DSN (env: PROBE_PG_DSN)")
    ap.add_argument("--dry-run", action="store_true", help="parse only, no DB write")
    args = ap.parse_args()

    files = expand_files(args.files, recursive_dir=args.dir)
    if not files:
        sys.stderr.write("no input files (use FILEs, --dir, or a glob)\n")
        sys.exit(1)

    if args.dry_run:
        total_rows = 0
        for p in files:
            meta = parse_batch_ts(p)
            if meta is None:
                print(f"SKIP  file={p} reason=filename-mismatch")
                continue
            batch_ts, ipver, proto = meta
            n = sum(1 for _ in load_samples(p, batch_ts, ipver, proto))
            total_rows += n
            print(f"DRY   file={p} rows={n} batch_ts={batch_ts.isoformat()}")
        print(f"SUMMARY files={len(files)} rows={total_rows} (dry-run)")
        return

    conn = psycopg2.connect(args.dsn)
    conn.autocommit = False
    cur = conn.cursor()

    ok_files = 0
    skip_files = 0
    total_read = 0
    total_ins = 0
    total_dup = 0
    errors = 0

    for p in files:
        try:
            rows_read, inserted, batch_ts_iso = import_file(cur, p)
        except Exception as e:
            conn.rollback()
            sys.stderr.write(f"[error] {p}: {e}\n")
            errors += 1
            continue

        if batch_ts_iso is None:
            print(f"SKIP  file={p} reason=filename-mismatch")
            skip_files += 1
            continue

        conn.commit()
        dup = rows_read - inserted
        total_read += rows_read
        total_ins += inserted
        total_dup += dup
        ok_files += 1
        print(
            f"IMPORT file={p} rows={rows_read} inserted={inserted} dup={dup} "
            f"batch_ts={batch_ts_iso}"
        )

    cur.close()
    conn.close()
    print(
        f"SUMMARY files_ok={ok_files} files_skip={skip_files} errors={errors} "
        f"rows={total_read} inserted={total_ins} dup={total_dup}"
    )
    sys.exit(0 if errors == 0 else 1)


if __name__ == "__main__":
    main()
