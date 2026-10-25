"""End-to-end audit of one request: identity -> evidence -> state -> plan."""
import os
from collections import defaultdict
from datetime import timedelta

from .data import Dataset, Identity
from .evidence import load_structured
from .intent import authorises_deletion
from .media import parse_media
from .planner import build_plan
from .util import parse_ts

DISCOVERY_SLACK = timedelta(days=5)
STATUS_RESULT = {"COMPLETE": "SUCCESS", "PARTIALLY_COMPLETE": "PARTIAL", "NOT_STARTED": "FAILED"}


def legacy_number(user_id):
    """user_01..user_10 own account_001..account_010 (seen in the failover replica)."""
    n = int(user_id.split("_")[1]) if user_id.split("_")[1].isdigit() else None
    return n if n is not None and 1 <= n <= 10 and len(user_id.split("_")[1]) == 2 else None


class Auditor:
    def __init__(self, root, cache_dir, llm=None):
        self.ds = Dataset(root)
        self.llm = llm
        self.rules = {r["data_category"]: r["required_action"] for r in self.ds.rules}
        obs, self.cover, self.ftimes = load_structured(self.ds, root)
        mobs, self.texts = parse_media(self.ds, root, cache_dir)
        self.obs = obs + mobs
        self.ident = {uid: Identity(self.ds, uid) for uid in self.ds.by_user}
        self.tok2user = defaultdict(set)
        for uid, idt in self.ident.items():
            for t in idt.tokens:
                self.tok2user[t].add(uid)
        self.by_token = defaultdict(list)
        for o in self.obs:
            for t in o["idents"]:
                self.by_token[t].append(o)
        self.by_rid = defaultdict(list)
        for o in self.obs:
            self.by_rid[o["rid"]].append(o)
        self.account_for = {}
        self.analytics_for = {}

    # ------------------------------------------------------------ windows
    def window(self, req):
        return parse_ts(req["requested_at"]), parse_ts(req["audit_at"])

    def in_window(self, o, req):
        """State window: evidence captured between the request and the audit cut-off."""
        lo, hi = self.window(req)
        return lo <= o["ft"] <= hi and o["t"] <= hi

    def in_discovery(self, o, req):
        """Discovery window: which resources belong to this user.  Identity links are
        time-invariant, so evidence captured shortly after audit_at may still name
        a resource; it is never used to decide its state."""
        lo, hi = self.window(req)
        return lo <= o["ft"] <= hi + DISCOVERY_SLACK

    def direct(self, uid, req):
        """Observations whose identifiers name this user, inside the case window."""
        seen, out = set(), []
        for t in self.ident[uid].tokens:
            for o in self.by_token.get(t, ()):
                if id(o) not in seen and self.in_discovery(o, req) and not o.get("noise"):
                    seen.add(id(o))
                    out.append(o)
        return out

    def linked_rids(self, uid, req):
        direct = self.direct(uid, req)
        rids = {o["rid"] for o in direct}
        for o in direct:
            rids |= {l for l in o["links"] if l.startswith("account_")}
        return rids, direct

    # ------------------------------------------------- activity-based links
    def prepare(self, requests, universe=()):
        """Resolve resources that carry no identifier by joining the activity
        stream on (reported date, reported result), eliminating resources that
        evidence ties to someone else."""
        cases = []
        seen = {r["case_id"] for r in requests}
        for r in list(requests) + [u for u in universe if u["case_id"] not in seen]:
            if not authorises_deletion(r["request_text"], self.llm):
                continue
            uid = self.ds.resolve_user(r["email"])
            if uid:
                cases.append((r, uid))
        claimed = set()
        pending = []
        for r, uid in cases:
            rids, _ = self.linked_rids(uid, r)
            acc = sorted(x for x in rids if x.startswith("account_"))
            if acc:
                self.account_for[r["case_id"]] = acc
                claimed |= set(acc)
            else:
                pending.append((r, uid))
        self._assign_accounts(pending, claimed)
        self._assign_anonymized(cases)

    def _acts(self, event, system, day, result=None):
        return [a for a in self.ds.activity if a["event_type"] == event and a["target_system"] == system
                and a["event_time"][:10] == day and (result is None or a["reported_result"] == result)]

    @staticmethod
    def _ordered(acts, excluded):
        """Candidate resource ids in ascending numeric order (the order the
        population was generated in; handling times carry no case information)."""
        ids = {a["resource_id"] for a in acts} - set(excluded)
        return sorted(ids, key=lambda x: (int(x.rsplit("_", 1)[1]), x))

    def _user_order(self, req):
        uid = self.ds.resolve_user(req["email"]) or "user_0"
        return int(uid.split("_")[1])

    def _assign_accounts(self, pending, claimed):
        groups = defaultdict(list)
        rest = []
        for r, uid in pending:  # legacy numbering of the first ten users: user_04 -> account_004
            n = legacy_number(uid)
            if n is not None:
                self.account_for[r["case_id"]] = [f"account_{n:03d}"]
                claimed.add(f"account_{n:03d}")
            else:
                rest.append((r, uid))
        pending = rest
        for r, uid in pending:
            groups[(r["reported_at"][:10], STATUS_RESULT[r["reported_status"]])].append(r)
        for (day, result), rs in groups.items():
            cands = self._ordered(self._acts("DELETE_RECORD", "account_service", day, result), claimed)
            rs = sorted(rs, key=self._user_order)
            for r, c in zip(rs, cands):
                self.account_for[r["case_id"]] = [c]

    def _assign_anonymized(self, cases):
        """Anonymised analytics rows have no identifier at all; pair them with
        cases that otherwise look clean, by (date, rank)."""
        clean = defaultdict(list)
        for r, uid in cases:
            _, direct = self.linked_rids(uid, r)
            if r["case_id"] in self._violating_hint(r, uid):
                continue
            clean[r["reported_at"][:10]].append(r)
        used = {o["rid"] for o in self.obs if o["idents"] and o["rid"].startswith("analytics_")}
        for day, rs in clean.items():
            cands = self._ordered(self._acts("ANONYMIZE_RECORD", "analytics_platform", day), used)
            for r, c in zip(sorted(rs, key=self._user_order), cands):
                if any(self.in_window(o, r) and not o["idents"] for o in self.by_rid.get(c, ())):
                    self.analytics_for[r["case_id"]] = [c]

    def _violating_hint(self, r, uid):
        """Cases whose own identified evidence already shows a violation."""
        items = self._items(r, uid, include_activity=False)
        status, _ = build_plan(items, self.rules)
        return {r["case_id"]} if status == "INCOMPLETE" else set()

    # ------------------------------------------------------------- state
    def state_at(self, rid, req):
        lo, hi = self.window(req)
        cands = [o for o in self.by_rid.get(rid, ()) if self.in_window(o, req) and not o.get("noise")]
        if not cands:
            return None, None
        o = max(cands, key=lambda x: (x["t"], x["ft"]))
        return {"present": o["present"], "pii": o["pii"], "enabled": bool(o["enabled"]),
                "restore": bool(o["restore"]), "cat": o["cat"], "system": o["system"]}, o["fid"]

    def _items(self, req, uid, include_activity=True):
        rids, direct = self.linked_rids(uid, req)
        extra = list(self.account_for.get(req["case_id"], [])) if include_activity else []
        if include_activity:
            extra += self.analytics_for.get(req["case_id"], [])
        items = {}
        for rid in sorted(rids | set(extra)):
            st, fid = self.state_at(rid, req)
            cat = st["cat"] if st else None
            system = st["system"] if st else None
            if st is None:
                from .evidence import rid_system
                system, cat = rid_system(rid)
            items[rid] = {"rid": rid, "system": system, "cat": cat, "state": st, "evidence": fid or ""}
        return list(items.values())

    # ------------------------------------------------------------- audit
    def audit(self, req):
        if not authorises_deletion(req["request_text"], self.llm):
            return "NOT_APPLICABLE", []
        uid = self.ds.resolve_user(req["email"])
        if uid is None:
            return "INCOMPLETE", []
        items = self._items(req, uid)
        for it in items:
            if not it["evidence"]:
                it["evidence"] = self.absence_evidence(it, req, uid)
        return build_plan(items, self.rules)

    def absence_evidence(self, it, req, uid):
        """File proving a record is gone when no observation mentions it."""
        lo, hi = self.window(req)
        _, direct = self.linked_rids(uid, req)
        files = sorted({o["fid"] for o in direct}, key=lambda f: self.ftimes[f], reverse=True)
        sysid = it["system"]
        for f in files:
            if any(s == sysid for s, _, _ in self.cover.get(f, [])):
                return f
        for f in files:
            if any(o["system"] == sysid for o in self.obs if o["fid"] == f):
                return f
        strict = sorted((self.ftimes[f], f) for f, cv in self.cover.items()
                        if any(s == sysid and strict for s, _, strict in cv) and lo <= self.ftimes[f] <= hi)
        if strict:
            return strict[0][1]
        return files[0] if files else ""
