"""Images and PDFs -> observations.

PDFs are read with pdftotext, screenshots with tesseract OCR (results cached).
OCR mangles e-mail addresses, so screenshots are tied to users through the
data-catalog LINK_RESOURCE_IDENTITY activity written when the screen was
captured (activity time = capture time + ~7 minutes) and by the resource ids
visible on screen.
"""
import hashlib
import os
import re
import shutil
import subprocess
from datetime import timedelta

from .evidence import mk, RID_RE, rid_system
from .util import tokens, parse_ts

LINK_LAG = timedelta(minutes=7, seconds=1)


def extract_text(path, cache_dir):
    os.makedirs(cache_dir, exist_ok=True)
    key = hashlib.sha1(open(path, "rb").read()).hexdigest()[:16]
    cached = os.path.join(cache_dir, key + ".txt")
    if os.path.exists(cached):
        return open(cached, encoding="utf-8").read()
    text = ""
    if path.endswith(".pdf"):
        if shutil.which("pdftotext"):
            text = subprocess.run(["pdftotext", "-layout", path, "-"], capture_output=True, text=True).stdout
        else:
            try:
                from pypdf import PdfReader
                reader = PdfReader(path)
                text = "\n".join(page.extract_text() or "" for page in reader.pages)
            except Exception:
                text = ""
    elif path.endswith(".png") and shutil.which("tesseract"):
        text = subprocess.run(["tesseract", path, "-", "--psm", "6"], capture_output=True, text=True).stdout
    open(cached, "w", encoding="utf-8").write(text)
    return text


def _state(rid, text, system):
    """Screens show live records: present, identifiable, enabled, restorable."""
    cat = rid_system(rid)[1]
    o = {"present": True}
    if cat == "ANALYTICS_PROFILE" or (cat == "SUPPORT_MESSAGE" and "attachment" not in text.lower()):
        o["pii"] = True
    if cat == "DATA_FLOW":
        o["enabled"] = not re.search(r"\b(disabled|paused|stopped)\b", text, re.I)
    if cat == "BACKUP_ARCHIVE":
        o["restore"] = not re.search(r"restore (blocked|denied)|\bblocked\b", text, re.I)
    if cat == "SUPPORT_MESSAGE" and re.search(r"Attachment properties|\.pdf", text):
        o["cat"], o["pii"] = "SUPPORT_ATTACHMENT", False
    if cat == "ACCOUNT_TOMBSTONE":
        o["pii"] = False
    return o


def parse_media(ds, root, cache_dir):
    obs, texts = [], {}
    media = [m for m in ds.manifest if m["file_path"].endswith((".png", ".pdf"))]
    for m in media:
        texts[m["file_id"]] = extract_text(os.path.join(root, m["file_path"]), cache_dir)
    links = [a for a in ds.activity if a["event_type"] == "LINK_RESOURCE_IDENTITY"]
    for m in media:
        fid, ft, text = m["file_id"], parse_ts(m["captured_at"]), texts[m["file_id"]]
        for a in links:
            if a["_t"] and abs((a["_t"] - ft - LINK_LAG).total_seconds()) <= 180:
                rid = a["resource_id"]
                o = mk(fid, ft, ft, rid, system=a["target_system"], idents=tokens(a["details"]), via="catalog")
                o.update(_state(rid, text, a["target_system"]))
                obs.append(o)
        if m["file_path"].endswith(".pdf"):
            obs += _pdf_rids(fid, ft, text, {o["rid"] for o in obs if o["fid"] == fid})
    return obs, texts


def _pdf_rids(fid, ft, text, seen):
    """PDFs are single-subject business documents: every identifier in them
    belongs to the one record(s) they name (e.g. a support attachment)."""
    out = []
    ids = tokens(text)
    for rid in sorted({m.group(0) for m in RID_RE.finditer(text)} - seen):
        o = mk(fid, ft, ft, rid, idents=ids, via="pdf")
        o.update(_state(rid, text, None))
        out.append(o)
    return out
