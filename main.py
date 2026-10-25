#!/usr/bin/env python3
"""Run the deletion-audit agent over a requests CSV and write output.csv.

    python3 code/main.py                      # dataset/deletion_requests.csv -> output.csv
    python3 code/main.py --requests dataset/sample_deletion_requests.csv --out /tmp/sample_pred.csv
"""
import argparse
import csv
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from audit.pipeline import Auditor  # noqa: E402

REPO = os.path.dirname(HERE)


def find_dataset(dataset=None, requests_path=None):
    if dataset and os.path.exists(dataset):
        return dataset
    if requests_path:
        req_dir = os.path.dirname(os.path.abspath(requests_path))
        if os.path.exists(os.path.join(req_dir, "user_identities.csv")):
            return req_dir
    for cand in (
        os.path.join(REPO, "dataset"),
        os.path.join(HERE, "dataset"),
        os.path.join(os.getcwd(), "dataset"),
    ):
        if os.path.exists(cand):
            return cand
    return os.path.join(REPO, "dataset")


def run(requests_path, out_path, dataset=None, cache=None):
    dataset = find_dataset(dataset, requests_path)
    cache = cache or os.path.join(REPO, ".cache", "ocr")
    agent = Auditor(dataset, cache)
    requests = agent.ds.read_requests(requests_path)
    universe = []  # every known request participates in claim elimination
    for name in ("deletion_requests.csv", "sample_deletion_requests.csv"):
        path = os.path.join(dataset, name)
        if os.path.exists(path):
            universe += agent.ds.read_requests(path)
    agent.prepare(requests, universe)
    rows = []
    for req in sorted(requests, key=lambda r: r["case_id"]):
        status, steps = agent.audit(req)
        rows.append({"case_id": req["case_id"], "deletion_status": status,
                     "steps_json": json.dumps(steps, ensure_ascii=False, separators=(",", ":"))})
    with open(out_path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["case_id", "deletion_status", "steps_json"])
        w.writeheader()
        w.writerows(rows)
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--requests", default=os.path.join(REPO, "dataset", "deletion_requests.csv"))
    ap.add_argument("--out", default=os.path.join(REPO, "output.csv"))
    ap.add_argument("--dataset", default=None)
    a = ap.parse_args()
    rows = run(a.requests, a.out, a.dataset)
    print(f"wrote {len(rows)} rows to {a.out}")


if __name__ == "__main__":
    main()
