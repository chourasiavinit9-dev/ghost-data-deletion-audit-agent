"""Evaluation workflow.

    python3 code/evaluation/main.py [--pred output_or_sample_pred.csv] [--gold dataset/sample_output.csv]
                                    [--requests dataset/sample_deletion_requests.csv]

With no --pred the auditor is run on the sample requests and scored against the
public sample_output.csv.  Metrics: case status accuracy, exact-case accuracy,
step-level precision/recall/F1 (set of steps), field-level accuracy (per field
over steps matched on phase+system+resource+operation), sequence accuracy
(exact ordered match and LCS ratio).  Also runs hand-written custom cases.
"""
import argparse, csv, json, os, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
CODE = os.path.dirname(HERE)
ROOT = os.path.dirname(CODE)
sys.path.insert(0, CODE)
from audit.intent import authorises_deletion          # noqa: E402
from audit.planner import build_plan                  # noqa: E402

FIELDS = ["phase", "system_id", "resource_id", "operation", "state", "evidence_id"]


def load(path):
    return {r["case_id"]: (r["deletion_status"], json.loads(r["steps_json"])) for r in csv.DictReader(open(path, encoding="utf-8"))}


def key(s):
    return tuple(s[f] for f in FIELDS)


def lcs(a, b):
    dp = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a)):
        for j in range(len(b)):
            dp[i + 1][j + 1] = dp[i][j] + 1 if a[i] == b[j] else max(dp[i][j + 1], dp[i + 1][j])
    return dp[-1][-1]


def score(gold, pred):
    n = len(gold)
    status = exact = seq_exact = 0
    tp = fp = fn = 0
    field_ok = {f: 0 for f in FIELDS}
    field_n = 0
    lcs_sum = lcs_den = 0
    for c, (gs, gst) in gold.items():
        ps, pst = pred.get(c, ("", []))
        status += gs == ps
        gk, pk = [key(s) for s in gst], [key(s) for s in pst]
        seq_exact += gk == pk
        exact += gs == ps and gk == pk
        G, P = set(gk), set(pk)
        tp += len(G & P); fp += len(P - G); fn += len(G - P)
        lcs_sum += lcs(gk, pk); lcs_den += max(len(gk), len(pk), 1)
        pm = {k[:4]: s for k, s in zip(pk, pst)}
        for k, s in zip(gk, gst):
            m = pm.get(k[:4])
            if m is None:
                continue
            field_n += 1
            for f in FIELDS:
                field_ok[f] += m[f] == s[f]
    p = tp / (tp + fp) if tp + fp else 1.0
    r = tp / (tp + fn) if tp + fn else 1.0
    return {
        "cases": n, "status_accuracy": status / n, "exact_case_accuracy": exact / n,
        "step_precision": p, "step_recall": r, "step_f1": 2 * p * r / (p + r) if p + r else 0.0,
        "field_accuracy": {f: (field_ok[f] / field_n if field_n else 0) for f in FIELDS},
        "field_accuracy_overall": sum(field_ok.values()) / (field_n * len(FIELDS)) if field_n else 0,
        "sequence_exact": seq_exact / n, "sequence_lcs_ratio": lcs_sum / lcs_den if lcs_den else 1.0,
    }


# ---- custom evaluation cases (synthetic, not from the dataset) ----------------
RULES = {"USER_PROFILE": "DELETE", "SUPPORT_MESSAGE": "REDACT", "ANALYTICS_PROFILE": "ANONYMIZE",
         "SECURITY_AUDIT_LOG": "RETAIN", "ACCOUNT_TOMBSTONE": "REDACT"}


def st(present=True, pii=True, enabled=False, restore=False):
    return {"present": present, "pii": pii, "enabled": enabled, "restore": restore}


def item(system, rid, cat, state, ev="evidence_x"):
    return {"system": system, "rid": rid, "cat": cat, "state": state, "evidence": ev}


def custom_cases():
    out = []
    # 1 non-deletion requests
    texts = ["Please update my phone number but keep the account.",
             "I want a copy of my data, this is an access request, not a request to erase it.",
             "Unsubscribe me from marketing lists only."]
    out.append(("non-deletion texts are NOT_APPLICABLE", all(not authorises_deletion(t) for t in texts)))
    out.append(("multilingual deletion text authorises", authorises_deletion("Por favor elimine mi cuenta y todos mis datos.")
                and authorises_deletion("アカウントを削除してください")))
    # 2 clean tombstone, retained audit log -> COMPLETE with evidence-backed verification only
    s, steps = build_plan([item("account_service", "account_900", "ACCOUNT_TOMBSTONE", st(True, False)),
                           item("security_service", "audit_record_1", "SECURITY_AUDIT_LOG", st(True, False)),
                           item("search_service", "search_doc_1", "USER_PROFILE", st(False, False))], RULES)
    out.append(("clean tombstone => COMPLETE, verification only, evidence cited",
                s == "COMPLETE" and {x["phase"] for x in steps} == {"VERIFICATION"} and all(x["evidence_id"] for x in steps)))
    # 3 tombstone still exposing PII + active flow + restore risk => INCOMPLETE, ordering
    s, steps = build_plan([item("account_service", "account_901", "ACCOUNT_TOMBSTONE", st(True, True)),
                           item("sync_service", "sync_1", "DATA_FLOW", st(True, False, enabled=True)),
                           item("backup_service", "backup_1", "BACKUP_ARCHIVE", st(True, True, restore=True)),
                           item("support_service", "msg_1", "SUPPORT_MESSAGE", st(True, True))], RULES)
    ops = [x["operation"] for x in steps]
    ok = (s == "INCOMPLETE" and [x["step_no"] for x in steps] == list(range(1, len(steps) + 1))
          and [x["phase"] for x in steps] == sorted((x["phase"] for x in steps), key=["FINDING", "REMEDIATION", "VERIFICATION"].index)
          and ops.index("DISABLE_DATA_FLOW") < ops.index("REDACT_RECORD")
          and all(x["evidence_id"] == "" for x in steps if x["phase"] != "FINDING"))
    out.append(("PII tombstone + active flow + restore risk => ordered INCOMPLETE plan", ok))
    # 4 retained record observed absent must not be verified present; unknown state still verified
    s, steps = build_plan([item("security_service", "audit_2", "SECURITY_AUDIT_LOG", st(False, False)),
                           item("security_service", "audit_3", "SECURITY_AUDIT_LOG", None)], RULES)
    out.append(("absent retained record skipped, unknown-state retained verified",
                [x["resource_id"] for x in steps] == ["audit_3"]))
    return out


def find_dataset(dataset=None):
    if dataset and os.path.exists(dataset):
        return dataset
    for cand in (
        os.path.join(ROOT, "dataset"),
        os.path.join(CODE, "dataset"),
        os.path.join(os.getcwd(), "dataset"),
    ):
        if os.path.exists(cand):
            return cand
    return os.path.join(ROOT, "dataset")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--gold", default=None)
    ap.add_argument("--requests", default=None)
    ap.add_argument("--dataset", default=None)
    ap.add_argument("--pred")
    a = ap.parse_args()
    ds = find_dataset(a.dataset)
    gold_path = a.gold or os.path.join(ds, "sample_output.csv")
    requests_path = a.requests or os.path.join(ds, "sample_deletion_requests.csv")
    pred_path = a.pred
    if not pred_path:
        pred_path = os.path.join(tempfile.mkdtemp(), "pred.csv")
        os.system(f'"{sys.executable}" "{os.path.join(CODE, "main.py")}" --requests "{requests_path}" --out "{pred_path}" --dataset "{ds}" > /dev/null')
    m = score(load(gold_path), load(pred_path))
    print(json.dumps(m, indent=2))
    res = custom_cases()
    for name, ok in res:
        print(("PASS " if ok else "FAIL ") + name)
    return 0 if all(ok for _, ok in res) else 1


if __name__ == "__main__":
    sys.exit(main())
