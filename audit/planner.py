"""Policy application: turn per-resource state into ordered findings,
remediation and verification steps."""

FIND, REME, VERI = "FINDING", "REMEDIATION", "VERIFICATION"
OP_ORDER = {  # (phase, operation) -> rank, exactly the order of the spec tables
    "REPORT_REMAINING_RECORD": 0, "REPORT_EXPOSED_PII": 1, "REPORT_ACTIVE_DATA_FLOW": 2, "REPORT_RESTORE_RISK": 3,
    "DISABLE_DATA_FLOW": 0, "BLOCK_RESTORE": 1, "DELETE_RECORD": 2, "REDACT_RECORD": 3, "ANONYMIZE_RECORD": 4,
    "VERIFY_RECORD_ABSENT": 0, "VERIFY_RECORD_PRESENT": 1, "VERIFY_RECORD_REDACTED": 2,
    "VERIFY_RECORD_ANONYMIZED": 3, "VERIFY_DATA_FLOW_DISABLED": 4, "VERIFY_RESTORE_BLOCKED": 5,
}
PHASE_ORDER = {FIND: 0, REME: 1, VERI: 2}
FINAL = {  # required action -> (remediation op/state, verification op/state)
    "DELETE": (("DELETE_RECORD", "ABSENT"), ("VERIFY_RECORD_ABSENT", "ABSENT")),
    "REDACT": (("REDACT_RECORD", "REDACTED"), ("VERIFY_RECORD_REDACTED", "REDACTED")),
    "ANONYMIZE": (("ANONYMIZE_RECORD", "ANONYMIZED"), ("VERIFY_RECORD_ANONYMIZED", "ANONYMIZED")),
}


def required_action(cat, rules):
    """deletion_rules.csv drives the treatment; flows are not a data category."""
    if cat == "DATA_FLOW":
        return "DISABLE"
    if cat == "BACKUP_ARCHIVE":
        return "BLOCK"
    return rules.get(cat)


def assess(item, action):
    """Return (finding_op or None) for one resource given its state at audit_at."""
    st = item["state"]
    if st is None:
        return None  # nothing observed: no claim can be made
    if action == "DELETE":
        return "REPORT_REMAINING_RECORD" if st["present"] else None
    if action in ("REDACT", "ANONYMIZE"):
        return "REPORT_EXPOSED_PII" if (st["present"] and st["pii"]) else None
    if action == "DISABLE":
        return "REPORT_ACTIVE_DATA_FLOW" if st["present"] and st["enabled"] else None
    if action == "BLOCK":
        return "REPORT_RESTORE_RISK" if st["present"] and st["restore"] else None
    return None


def verification_for(action):
    if action in FINAL:
        return FINAL[action][1]
    return {"DISABLE": ("VERIFY_DATA_FLOW_DISABLED", "DISABLED"),
            "BLOCK": ("VERIFY_RESTORE_BLOCKED", "BLOCKED"),
            "RETAIN": ("VERIFY_RECORD_PRESENT", "PRESENT")}[action]


def remediation_for(action):
    if action in FINAL:
        return FINAL[action][0]
    return {"DISABLE": ("DISABLE_DATA_FLOW", "DISABLED"), "BLOCK": ("BLOCK_RESTORE", "BLOCKED")}.get(action)


def build_plan(items, rules):
    """items: dicts with system, rid, cat, state, evidence.  Returns (status, steps)."""
    rows, violating = [], False
    for it in items:
        action = required_action(it["cat"], rules)
        if action is None:
            continue
        finding = assess(it, action)
        violating |= finding is not None
        if action == "RETAIN" and it["state"] and not it["state"]["present"]:
            continue  # a retained record observed absent cannot be "verified present"
        rows.append((it, action, finding))
    status = "INCOMPLETE" if violating else "COMPLETE"
    steps = []
    for it, action, finding in rows:
        if finding and status == "INCOMPLETE":
            steps.append(_s(FIND, it, finding, "PRESENT" if finding not in ("REPORT_ACTIVE_DATA_FLOW", "REPORT_RESTORE_RISK") else "ACTIVE", it["evidence"]))
            rem = remediation_for(action)
            steps.append(_s(REME, it, rem[0], rem[1], ""))
    for it, action, finding in rows:
        op, state = verification_for(action)
        steps.append(_s(VERI, it, op, state, "" if status == "INCOMPLETE" else it["evidence"]))
    steps.sort(key=lambda s: (PHASE_ORDER[s["phase"]], OP_ORDER[s["operation"]], s["system_id"], s["resource_id"]))
    for i, s in enumerate(steps, 1):
        s["step_no"] = i
    return status, steps


def _s(phase, it, op, state, evidence):
    return {"step_no": 0, "phase": phase, "system_id": it["system"], "resource_id": it["rid"],
            "operation": op, "state": state, "evidence_id": evidence or ""}
