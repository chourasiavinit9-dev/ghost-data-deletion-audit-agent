"""Normalise every evidence format into uniform observations.

An observation says: "in file F, at time T, resource R of system S (category C)
was seen in state X, mentioning identifier tokens I".  Later stages link
observations to users through those tokens and reason about state at audit_at.
"""
import json
import os
import re
import sqlite3
from collections import defaultdict

from .util import tokens, parse_ts, is_null, has_direct_identifier

PREFIX = {  # resource-id prefix -> (system_id, default category)
    "account": ("account_service", "USER_PROFILE"),
    "search": ("search_service", "SEARCH_INDEX_ENTRY"),
    "support": ("support_platform", "SUPPORT_MESSAGE"),
    "analytics": ("analytics_platform", "ANALYTICS_PROFILE"),
    "marketing": ("marketing_platform", "MARKETING_PROFILE"),
    "export": ("export_service", "USER_EXPORT"),
    "backup": ("backup_service", "BACKUP_ARCHIVE"),
    "data_flow": ("integration_service", "DATA_FLOW"),
    "audit_record": ("security_service", "SECURITY_AUDIT_LOG"),
    "legal_hold": ("legal_service", "LEGAL_HOLD_RECORD"),
    "tombstone": ("identity_service", "ACCOUNT_TOMBSTONE"),
    "object": ("object_storage", "SUPPORT_ATTACHMENT"),
    "email_delivery": ("email_delivery_service", "EMAIL_DELIVERY_LOG"),
    "cache": ("cache_service", "CACHE_ENTRY"),
}
RID_RE = re.compile(r"\b(" + "|".join(PREFIX) + r")_\d+\b")
SYSTEM_COLLECTIONS = {  # bundle/replica collection -> (system, category)
    "customer_profiles": ("account_service", "USER_PROFILE"),
    "customer_search_documents": ("search_service", "SEARCH_INDEX_ENTRY"),
    "customer_analytics_reports": ("analytics_platform", "ANALYTICS_PROFILE"),
    "support_conversations": ("support_platform", "SUPPORT_MESSAGE"),
    "ticket_attachments": ("support_platform", "SUPPORT_ATTACHMENT"),
    "customer_export_jobs": ("export_service", "USER_EXPORT"),
    "connector_configurations": ("integration_service", "DATA_FLOW"),
    "backup_catalog": ("backup_service", "BACKUP_ARCHIVE"),
    "security_audit_events": ("security_service", "SECURITY_AUDIT_LOG"),
    "retained_order_records": ("legal_service", "LEGAL_HOLD_RECORD"),
    "deleted_customer_references": ("identity_service", "ACCOUNT_TOMBSTONE"),
}


def rid_system(rid):
    pre = rid.rsplit("_", 1)[0]
    return PREFIX.get(pre, (None, None))


def mk(fid, ft, t, rid, cat=None, system=None, present=True, pii=False,
       enabled=None, restore=None, idents=None, links=None, via=""):
    sysd, catd = rid_system(rid)
    return {"fid": fid, "ft": ft, "t": t or ft, "rid": rid,
            "system": system or sysd, "cat": cat or catd, "present": present,
            "pii": pii, "enabled": enabled, "restore": restore,
            "idents": set(idents or ()), "links": set(links or ()), "via": via}


def _truthy(v):
    return str(v).strip().lower() in ("true", "1", "yes")


# ---------------------------------------------------------------- JSON records
def _bundle_record(fid, ft, snap_t, store, coll, r):
    system, cat = SYSTEM_COLLECTIONS.get(coll, (store, None))
    rid = r.get("resource_id")
    if not rid:
        return None
    idents = tokens({k: v for k, v in r.items() if k not in ("resource_id", "metrics", "recent_activity", "integrity_seal")})
    o = mk(fid, ft, snap_t, rid, cat=cat, system=system, idents=idents, via=coll)
    if cat == "ANALYTICS_PROFILE":
        o["pii"] = any(not is_null(r.get(k)) for k in ("user_id", "email", "phone", "email_hash"))
    elif cat == "ACCOUNT_TOMBSTONE":
        o["pii"] = any(not is_null(r.get(k)) for k in ("name", "email", "phone", "email_hash"))
    elif cat == "SUPPORT_MESSAGE":
        o["pii"] = has_direct_identifier(r.get("message_text"))
    elif cat == "DATA_FLOW":
        o["enabled"] = bool(r.get("enabled"))
    elif cat == "BACKUP_ARCHIVE":
        o["restore"] = bool(r.get("restore_allowed"))
    elif cat == "USER_EXPORT" and r.get("download_available") is False:
        o["present"] = False
    return o


def parse_bundle(fid, ft, d):
    obs, cover = [], []
    for s in d.get("snapshots", []):
        store, coll = s.get("data_store"), s.get("collection")
        st = parse_ts(s.get("captured_at")) or ft
        system = SYSTEM_COLLECTIONS.get(coll, (store, None))[0]
        if coll == "operational_record_history":
            obs += [o for r in s["records"] if (o := _lookup_row(fid, ft, r))]
            continue
        cover.append((system, st, False))
        for r in s.get("records", []):
            o = _bundle_record(fid, ft, st, store, coll, r)
            if o:
                obs.append(o)
    return obs, cover


LOOKUP_STATE = {  # (record_type, result) -> attributes
    ("USER_PROFILE", "FOUND"): {}, ("USER_PROFILE", "NOT_FOUND"): {"present": False},
    ("SEARCH_INDEX_ENTRY", "FOUND"): {}, ("SEARCH_INDEX_ENTRY", "NOT_FOUND"): {"present": False},
    ("SECURITY_AUDIT_LOG", "FOUND"): {}, ("SUPPORT_ATTACHMENT", "FOUND"): {},
    ("SUPPORT_ATTACHMENT", "NOT_FOUND"): {"present": False},
    ("SUPPORT_MESSAGE", "IDENTIFIABLE"): {"pii": True}, ("SUPPORT_MESSAGE", "REDACTED"): {},
    ("ANALYTICS_PROFILE", "IDENTIFIABLE"): {"pii": True}, ("ANALYTICS_PROFILE", "ANONYMIZED"): {},
    ("BACKUP_ARCHIVE", "ACTIVE"): {"restore": True}, ("BACKUP_ARCHIVE", "BLOCKED"): {"restore": False},
    ("DATA_FLOW", "ACTIVE"): {"enabled": True}, ("DATA_FLOW", "DISABLED"): {"enabled": False},
    ("USER_EXPORT", "FOUND"): {}, ("USER_EXPORT", "NOT_FOUND"): {"present": False},
    ("LEGAL_HOLD_RECORD", "FOUND"): {},
    ("ACCOUNT_TOMBSTONE", "IDENTIFIABLE"): {"pii": True}, ("ACCOUNT_TOMBSTONE", "REDACTED"): {},
    ("MARKETING_PROFILE", "FOUND"): {}, ("MARKETING_PROFILE", "NOT_FOUND"): {"present": False},
}


def _lookup_row(fid, ft, r, system=None, rid=None, rtype=None, result=None, subj=None, t=None):
    rid = rid or r.get("resource_id")
    rtype = rtype or r.get("record_type")
    result = result or r.get("result")
    subj = subj if subj is not None else (r.get("subject_reference") or r.get("lookup_value") or "")
    attrs = LOOKUP_STATE.get((rtype, result))
    if not rid or attrs is None:
        return None
    o = mk(fid, ft, t or parse_ts(r.get("recorded_at")) or ft, rid, cat=rtype,
           system=system or r.get("system"), idents=tokens(subj), via="lookup")
    o.update(attrs)
    return o


def parse_lookup_json(fid, ft, d):
    return [o for r in d["records"] if (o := _lookup_row(fid, ft, r))], []


def _export_item(fid, ft, system, r):
    rid = r["resource_id"]
    t = parse_ts(r.get("observed_at")) or ft
    cat = rid_system(rid)[1]
    vals = {k: v for k, v in r.items() if k not in ("resource_id", "observed_at", "hits", "profile", "status_code")}
    idents = tokens(vals) | tokens(r.get("profile")) | tokens(r.get("hits"))
    o = mk(fid, ft, t, rid, system=system, idents=idents, via="export")
    if system == "account_service":
        o["present"] = r.get("status_code") == 200 and r.get("profile") is not None
    elif system == "search_service":
        o["present"] = bool((r.get("hits") or {}).get("total"))
    elif cat == "ANALYTICS_PROFILE":
        o["pii"] = any(not is_null(r.get(k)) for k in ("email", "phone", "email_hash", "customer_reference"))
    elif cat == "SUPPORT_MESSAGE":
        o["pii"] = any(not is_null(r.get(k)) for k in ("requester_email", "requester_name", "requester_phone"))
    elif cat == "DATA_FLOW":
        o["enabled"] = bool(r.get("enabled"))
    elif cat == "BACKUP_ARCHIVE":
        o["restore"] = bool(r.get("restore_allowed"))
    return o


def parse_service_export(fid, ft, d):
    obs = []
    for system, sections in d.get("service_exports", {}).items():
        for items in sections.values():
            obs += [_export_item(fid, ft, system, r) for r in items]
    return obs, []


# ------------------------------------------------------------------- SQL files
def _load_sql(path):
    con = sqlite3.connect(":memory:")
    con.row_factory = sqlite3.Row
    con.executescript(open(path, encoding="utf-8").read())
    return con


INVENTORY = {  # table -> (system, category, id columns..)
    "customer_profiles": ("account_service", "USER_PROFILE"),
    "customer_search_documents": ("search_service", "SEARCH_INDEX_ENTRY"),
    "customer_analytics_profiles": ("analytics_platform", "ANALYTICS_PROFILE"),
    "support_records": ("support_platform", "SUPPORT_MESSAGE"),
    "customer_exports": ("export_service", "USER_EXPORT"),
    "connector_subscriptions": ("integration_service", "DATA_FLOW"),
    "backup_restore_entries": ("backup_service", "BACKUP_ARCHIVE"),
    "security_audit_records": ("security_service", "SECURITY_AUDIT_LOG"),
}


def _inv_row(fid, ft, table, r):
    system, cat = INVENTORY[table]
    d = dict(r)
    t = parse_ts(d.get("updated_at")) or ft
    o = mk(fid, ft, t, d["resource_id"], cat=cat, system=system,
           idents=tokens({k: v for k, v in d.items() if k not in ("resource_id",)}), via=table)
    if cat == "ANALYTICS_PROFILE":
        o["pii"] = any(not is_null(d.get(k)) for k in ("email", "phone", "email_hash", "customer_reference"))
    elif cat == "SUPPORT_MESSAGE":
        o["pii"] = any(not is_null(d.get(k)) for k in ("requester_email", "requester_name", "requester_phone"))
    elif cat == "DATA_FLOW":
        o["enabled"] = bool(d.get("enabled"))
    elif cat == "BACKUP_ARCHIVE":
        o["restore"] = bool(d.get("restore_allowed"))
    return o


def parse_sql(fid, ft, path):
    con = _load_sql(path)
    tables = [r[0] for r in con.execute("select name from sqlite_master where type='table'")]
    obs, cover = [], []
    merged = {}
    for tb in tables:
        cols = [c[1] for c in con.execute(f"pragma table_info({tb})")]
        rows = con.execute(f"select * from {tb}").fetchall()
        if tb == "snapshot_scope":
            cover += [(r["origin_system"], parse_ts(r["captured_at"]) or ft, True) for r in rows]
        elif tb in INVENTORY:
            obs += [_inv_row(fid, ft, tb, r) for r in rows]
        elif "record_json" in cols:
            for r in rows:
                rec = json.loads(r["record_json"])
                o = _bundle_record(fid, ft, parse_ts(r["updated_at"]) or ft, r["origin_system"], r["collection_name"], rec)
                if o:  # primary + replicas: present anywhere => present (replication drift)
                    prev = merged.get(o["rid"])
                    merged[o["rid"]] = _merge_tables(prev, o)
        elif tb.startswith("customer_profiles_"):
            cover.append(("account_service", ft, True))
            for r in rows:
                d = dict(r)
                o = mk(fid, ft, parse_ts(d["updated_at"]) or ft, d["resource_id"], idents=tokens(d), via=tb)
                merged[o["rid"]] = _merge_tables(merged.get(o["rid"]), o)
        elif tb == "search_documents_primary":
            for r in rows:
                d = dict(r)
                o = mk(fid, ft, parse_ts(d["indexed_at"]) or ft, d["resource_id"], idents=tokens(d),
                       links=[d["source_resource_id"]] if d.get("source_resource_id") else [], via=tb)
                merged[o["rid"]] = _merge_tables(merged.get(o["rid"]), o)
    obs += list(merged.values())
    return obs, cover


def _merge_tables(prev, new):
    if prev is None:
        return new
    for k in ("pii",):
        prev[k] = prev[k] or new[k]
    for k in ("enabled", "restore"):
        if new[k] is not None:
            prev[k] = bool(prev[k]) or new[k]
    prev["present"] = prev["present"] or new["present"]
    prev["idents"] |= new["idents"]
    prev["links"] |= new["links"]
    return prev


# ----------------------------------------------------------------------- logs
KV_RE = re.compile(r'([A-Za-z_][\w.]*)=("((?:[^"\\]|\\.)*)"|\S+)')


def parse_log_line(line):
    m = re.match(r"(\d{4}-\d\d-\d\dT[\d:]+Z)\s+(.*)$", line.rstrip("\n"))
    if not m:
        return None
    ts, rest = m.groups()
    rest = rest.replace('\\"', '"')
    d = {"_ts": ts}
    if rest.startswith("{"):
        try:
            for k, v in json.loads(rest).items():
                d[{"severity": "level"}.get(k, k)] = str(v)
            d.setdefault("service", d.get("logger", ""))
        except ValueError:
            return None
        return d
    mp = re.match(r"\|?\s*(\w+)\s*\|\s*([\w.]+)\s*\|\s*(\S+)\s*\|\s*(\w+)\s*\|\s*(.*)$", rest)
    mb = re.match(r"\[(\w+)\] \[([\w.]+)\] \[([^\]]*)\] (\w+): (.*)$", rest)
    ms = re.match(r"<\d+>1 (\S+) (\S+) (\S+) - - (.*)$", rest)
    if mp:
        d["level"], d["service"], d["trace_id"], d["event"], rest = mp.groups()
    elif mb:
        d["level"], d["service"], d["trace_id"], d["event"], rest = mb.groups()
    elif ms:
        _, d["service"], d["trace_id"], rest = ms.groups()
    for k, v, q in KV_RE.findall(rest):
        d.setdefault(k, q if v.startswith('"') else v)
    if d.get("function") and not d.get("service"):
        d["service"] = d["function"]
    if "requestId" in d:
        d.setdefault("trace_id", d["requestId"])
    if "message" in d and "event" not in d:  # cloud-runtime wrapper: inner key/values
        for k, v, q in KV_RE.findall(d["message"].replace('\\"', '"')):
            d.setdefault(k, q if v.startswith('"') else v)
    return d


def parse_log(fid, ft, path):
    groups = defaultdict(list)
    for i, line in enumerate(open(path, encoding="utf-8", errors="ignore")):
        d = parse_log_line(line)
        if d and d.get("event"):
            groups[d.get("trace_id") or f"line{i}"].append(d)
    obs = []
    for evs in groups.values():
        obs += _log_group(fid, ft, evs)
    return obs, []


LOG_IDENT_KEYS = ("lookup_key", "match_key", "subject_key", "subject_ref", "scan_key", "owner_key",
                  "correlation_key", "email", "customer_email", "requester_email", "owner_email",
                  "matched_value", "message_text", "customer_reference", "subject_reference",
                  "requester_name", "phone", "email_hash")


def _val(e, k):
    v = e.get(k)
    return None if is_null(v) else v


def _log_group(fid, ft, evs):
    idents = set()
    for e in evs:
        for k in LOG_IDENT_KEYS:
            idents |= tokens(_val(e, k))
    out = []
    for e in evs:
        o = _log_event(fid, ft, e, idents)
        if o:
            out.append(o)
    return _collapse(out)


def _log_event(fid, ft, e, idents):
    ev, rid, t = e.get("event"), e.get("resource_id"), parse_ts(e["_ts"]) or ft
    svc = e.get("service", "")
    if ev == "record_lookup":
        return _lookup_row(fid, ft, {}, system=e.get("system"), rid=rid, rtype=e.get("record_type"),
                           result=e.get("result"), subj=e.get("subject_reference"), t=t)
    if not rid or not RID_RE.search(rid):
        return None
    o = mk(fid, ft, t, rid, idents=idents, via=ev)
    if ev == "profile_lookup_completed":
        o["present"] = e.get("http_status") == "200" and e.get("rows") != "0"
        o["system"] = "account_service" if svc in ("account_service", "profile_service") else o["system"]
        o["noise"] = svc == "profile_service"
    elif ev == "index_query_completed":
        o["present"] = e.get("result") == "hit" or (e.get("total_hits") not in (None, "0") and e.get("result") != "miss")
    elif ev == "analytics_profile_read_completed":
        o["pii"] = any(_val(e, k) for k in ("email", "email_hash", "phone", "customer_reference"))
    elif ev == "analytics_identity_scan":
        o["pii"] = e.get("direct_identifiers", "0") != "0"
    elif ev == "analytics_profile_read":
        o["pii"] = e.get("direct_identifiers", "0") != "0"
    elif ev == "contact_lookup_completed":
        o["cat"], o["system"] = "MARKETING_PROFILE", "analytics_platform"
        o["present"] = e.get("rows") != "0"
    elif ev == "support_ticket_read_completed":
        o["pii"] = any(_val(e, k) for k in ("requester_email", "requester_name", "requester_phone"))
    elif ev == "message_pii_scan":
        o["pii"] = True
    elif ev == "message_read":
        o["pii"] = has_direct_identifier(e.get("message_text"))
    elif ev == "attachment_pii_scan":
        o["cat"] = "SUPPORT_ATTACHMENT"
    elif ev in ("export_metadata_read_completed", "export_download_check_completed"):
        o["present"] = _truthy(e.get("available", "true"))
    elif ev in ("connector_config_read_completed", "connector_heartbeat", "connector_config_loaded"):
        o["enabled"] = _truthy(e.get("enabled"))
        if ev != "connector_config_read_completed" and "scheduler_registered" in e:
            o["enabled"] = o["enabled"] and _truthy(e["scheduler_registered"])
    elif ev == "restore_policy_read_completed":
        o["restore"] = _truthy(e.get("restore_allowed")) and e.get("archive_present", "true") != "false"
    elif ev == "restore_candidate_evaluated":
        o["restore"] = _truthy(e.get("eligible")) and e.get("deletion_block") in (None, "none", "false", "null")
    elif ev == "restore_authorization_completed":
        o["restore"] = e.get("decision", "").lower() in ("allow", "allowed", "permit", "granted")
    elif ev == "audit_record_read_completed":
        o["present"] = e.get("rows") != "0"
    elif ev == "contact_query_completed" and svc == "support_replica":
        o["cat"], o["present"], o["pii"] = "SECONDARY_IDENTIFIER", e.get("rows") != "0", True
    elif ev == "deletion_marker_check":
        return None
    else:
        return None
    return o


def _collapse(obs):
    """Several events about the same resource in one trace -> one observation."""
    byrid = {}
    for o in obs:
        p = byrid.get(o["rid"])
        if p is None:
            byrid[o["rid"]] = o
            continue
        for k in ("pii",):
            p[k] = p[k] or o[k]
        for k in ("enabled", "restore"):
            if o[k] is not None:
                p[k] = o[k] if p[k] is None else (p[k] and o[k] if k == "enabled" and o["via"] == "connector_config_loaded" else o[k])
        if o["cat"] != rid_system(o["rid"])[1]:
            p["cat"], p["system"] = o["cat"], o["system"]
        p["present"] = p["present"] and o["present"] if p["via"] == o["via"] else o["present"] if o["via"].endswith("completed") else p["present"]
        p["t"] = max(p["t"], o["t"])
    return list(byrid.values())


# ---------------------------------------------------------------- text records
def parse_handover(fid, ft, path):
    obs = []
    for line in open(path, encoding="utf-8"):
        if not line.startswith("- "):
            continue
        p = [x.strip() for x in line[2:].split("|")]
        if len(p) < 6:
            continue
        o = _lookup_row(fid, ft, {}, system=p[1], rid=p[2], rtype=p[3], result=p[4], subj=p[5], t=parse_ts(p[0]))
        if o:
            obs.append(o)
    return obs, []


def load_structured(ds, root):
    """Parse every non-media evidence file. Returns (observations, coverage, filetimes)."""
    obs, cover, ftimes = [], defaultdict(list), {}
    for m in ds.manifest:
        fid, ft = m["file_id"], parse_ts(m["captured_at"])
        ftimes[fid] = ft
        path = os.path.join(root, m["file_path"])
        ext = path.rsplit(".", 1)[-1]
        if ext in ("png", "pdf"):
            continue
        if ext == "sql":
            o, c = parse_sql(fid, ft, path)
        elif ext == "log":
            o, c = parse_log(fid, ft, path)
        elif ext == "txt":
            o, c = parse_handover(fid, ft, path)
        else:
            d = json.load(open(path, encoding="utf-8"))
            if "snapshots" in d:
                o, c = parse_bundle(fid, ft, d)
            elif "service_exports" in d:
                o, c = parse_service_export(fid, ft, d)
            elif d.get("records") and "record_type" in d["records"][0]:
                o, c = parse_lookup_json(fid, ft, d)
            else:
                o, c = _plain_collection(fid, ft, d)
        obs += o
        for system, t, strict in c:
            cover[fid].append((system, t, strict))
    return obs, cover, ftimes


def _plain_collection(fid, ft, d):
    coll = d.get("collection")
    t = parse_ts(d.get("captured_at")) or ft
    obs = [o for r in d.get("records", []) if (o := _bundle_record(fid, ft, t, d.get("source"), coll, r))]
    system = SYSTEM_COLLECTIONS.get(coll, (None, None))[0] or "analytics_platform"
    return obs, [(system, t, False)]
