# Evaluation report

Reproduce: `python3 code/evaluation/main.py` (runs the auditor on the 32 public samples, scores against `dataset/sample_output.csv`, then runs the custom cases). Use `--pred <csv> --gold <csv>` to score any prediction file.

## Results on the 32 public samples

| Metric | Value |
|---|---|
| Case-level deletion-status accuracy | 32/32 = 100% |
| Exact-case accuracy (status + every step) | 30/32 = 93.75% |
| Step-level precision / recall / F1 | 1.000 / 0.990 / 0.995 |
| Field-level accuracy (matched steps): phase, system_id, resource_id, operation, state, evidence_id | 1.00 each |
| Sequence accuracy: exact ordered match / LCS ratio | 93.75% / 0.990 |

The full 518-case run has no gold labels; it was checked structurally: 518 rows sorted by case_id, valid JSON, consecutive step numbers, every cited evidence id exists, no cited evidence captured after `audit_at`. Status mix: INCOMPLETE 355, COMPLETE 153, NOT_APPLICABLE 10 (cases 533-542, all non-deletion requests).

## Custom evaluation cases (synthetic, in `code/evaluation/main.py`)

1. Non-deletion texts (profile update, "access request, not a request to erase it", marketing opt-out only) -> NOT_APPLICABLE.
2. Multilingual deletion requests (Spanish, Japanese) are recognised as authorising deletion.
3. Clean tombstone + retained audit log + deleted profile -> COMPLETE, verification steps only, each citing evidence.
4. Tombstone still exposing PII + active data flow + restore risk + unredacted support message -> INCOMPLETE; consecutive numbering, phases ordered, data flow disabled before redaction, remediation/verification evidence_id empty.
5. Retained record observed absent is not "verified present"; unknown-state retained record still gets its verification step.

All five pass.

## Failures found and improvements

- First sample score 18/32. Improvements, in order: identity resolution through historical emails and hashes; separating the state window (captured in [requested_at, audit_at]) from a wider discovery window (+5 days) used only to find which resources belong to the user; treating only snapshot_scope / account-only failover replicas as absence proof; SQL primary/replica merge; legacy `user_NN` -> `account_00N` numbering; activity-based linking for resources with no identifier (accounts, anonymised analytics) with claim elimination across all cases; OCR/pdftotext for media. Result 29/32 then 30/32.
- Classifier: two non-deletion requests (marketing-list-only opt-out; "information request, not a request to erase it") were read as deletion because the deletion verb survived negation stripping. Fixed by stripping those phrases; NOT_APPLICABLE count went from 8 to 10.
- Remaining misses (cases 18 and 20): the expected audit records (`audit_record_6645`, `audit_record_5569`) appear nowhere in participant-visible evidence, so they cannot be derived without guessing.
- Known limitation: ~22% of non-NA cases have no security-audit step; the sample gold shows a similar rate (no audit record exists in evidence for those users), but this was not verifiable on the hidden cases.
- Account/analytics linking relies on same-day activity heuristics; accuracy there is validated only on samples.
