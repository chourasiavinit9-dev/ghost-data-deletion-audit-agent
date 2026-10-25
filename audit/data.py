"""Loading of the participant-facing CSV files."""
import csv
import hashlib
import os
from collections import defaultdict

from .util import parse_ts


def read_csv(path):
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


class Dataset:
    """All structured inputs under dataset/ (no organiser-only files)."""

    def __init__(self, root):
        self.root = root
        self.identities = read_csv(os.path.join(root, "user_identities.csv"))
        self.audit_log = read_csv(os.path.join(root, "user_audit_log.csv"))
        self.activity = read_csv(os.path.join(root, "system_activity.csv"))
        self.rules = read_csv(os.path.join(root, "deletion_rules.csv"))
        self.manifest = read_csv(os.path.join(root, "evidence_files.csv"))
        self.by_user = {r["user_id"]: r for r in self.identities}
        self.email_to_user = {r["email"].lower(): r["user_id"] for r in self.identities}
        self.hist_email_to_user = {}
        for a in self.audit_log:
            if a["field_name"] == "email":
                self.hist_email_to_user.setdefault(a["old_value"].lower(), a["user_id"])
        self.activity_by_res = defaultdict(list)
        for a in self.activity:
            a["_t"] = parse_ts(a["event_time"])
            self.activity_by_res[a["resource_id"]].append(a)

    def read_requests(self, path):
        return read_csv(path)

    def resolve_user(self, email):
        """Current email wins, then a historical email. Returns user_id or None."""
        e = email.strip().lower()
        return self.email_to_user.get(e) or self.hist_email_to_user.get(e)


class Identity:
    """Every identifier (current and historical) that can expose one user."""

    def __init__(self, ds, user_id):
        self.user_id = user_id
        cur = ds.by_user[user_id]
        self.name, self.phone = cur["name"], cur["phone"]
        self.emails = {cur["email"].lower()}
        self.hashes = {cur["email_hash"].lower()}
        self.phones = {cur["phone"]}
        for a in ds.audit_log:
            if a["user_id"] != user_id:
                continue
            for v in (a["old_value"], a["new_value"]):
                if a["field_name"] == "email":
                    self.emails.add(v.lower())
                elif a["field_name"] == "email_hash":
                    self.hashes.add(v.lower())
                elif a["field_name"] == "phone":
                    self.phones.add(v)
        for e in list(self.emails):
            self.hashes.add(hashlib.sha256(e.encode()).hexdigest())

    @property
    def tokens(self):
        return self.emails | self.hashes | {self.user_id}
