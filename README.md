# Northstar Shop Deletion Audit Agent

AI-powered deletion-audit agent for **Northstar Shop** (HackerRank Orchestrate — *Ghost Data Still Exists*).

The agent investigates deletion requests across primary databases, secondary systems, search indexes, analytics platforms, support archives, integration sync pipelines, and backup snapshots to verify whether personal data has truly been deleted, identify ghost data and recreation risks, and produce ordered remediation plans.

---

## 1. Architecture Overview

The system processes each deletion request through five deterministic, policy-compliant stages:

1. **Intent Classification (`audit/intent.py`)**:
   - Evaluates `request_text` across multilingual request patterns (English, Spanish, Portuguese, German, French, Korean, Japanese).
   - Identifies non-deletion requests (access requests, updates, corrections, marketing-only opt-outs) after negation stripping.
   - Non-deletion requests immediately output `NOT_APPLICABLE` with `[]`.

2. **Identity Resolution (`audit/data.py`)**:
   - Resolves subjects using current identities (`user_identities.csv`) and historical identity audit logs (`user_audit_log.csv`).
   - Links current and past email addresses, SHA-256 hashes, phone numbers, and internal reference keys.

3. **Evidence Normalization & Multimodal Ingestion (`audit/evidence.py`, `audit/media.py`)**:
   - Ingests structured JSON bundles, SQLite/SQL database dumps, logs, and metadata.
   - Extracts business document content from PDFs (using `pdftotext` or `pypdf`) and screenshot evidence (using `tesseract` OCR).
   - Normalizes evidence into time-bounded observation states (`present`, `pii`, `enabled`, `restore`) anchored to each case's `requested_at` and `audit_at` cutoff window.

4. **Activity & Drift Analysis (`audit/pipeline.py`)**:
   - Inspects operational event logs (`system_activity.csv`) to resolve unlabelled records and trace primary/replica replication drift.
   - Discovers active data flows (`DATA_FLOW`) and unblocked backup restore paths (`BACKUP_ARCHIVE`).

5. **Remediation & Verification Planning (`audit/planner.py`)**:
   - Applies `deletion_rules.csv` to every identified resource.
   - If violations or recreation risks exist, assigns status `INCOMPLETE` and generates ordered `FINDING`, `REMEDIATION`, and `VERIFICATION` steps.
   - If all copies are verified compliant and no recreation pathways exist, assigns status `COMPLETE` with evidence-backed `VERIFICATION` steps.
   - Strictly enforces step numbering, phase order (`FINDING` -> `REMEDIATION` -> `VERIFICATION`), operation priority, and evidence citation conventions.

---

## 2. Directory Structure

```text
code/
├── audit/
│   ├── __init__.py
│   ├── data.py         # CSV ingestion, identity resolution
│   ├── evidence.py     # JSON, SQL, log normalization into observations
│   ├── intent.py       # Multilingual request intent classifier
│   ├── media.py        # PDF & image text extraction
│   ├── pipeline.py     # End-to-end audit coordinator & state reconstruction
│   ├── planner.py      # Deletion policy application & step ordering
│   └── util.py         # Token parsing, date utilities
├── evaluation/
│   ├── evaluate.py     # Evaluation runner entry point
│   ├── main.py         # Scoring metrics and custom test suite
│   ├── evaluation_report.md  # Benchmark results and custom test findings
│   └── usage_report.md       # Model token usage and cost accounting
├── main.py             # Main CLI entry point
├── requirements.txt    # Dependencies
└── README.md           # Setup and execution guide
```

---

## 3. Setup and Installation

### Prerequisites
- Python 3.9+
- Optional: `pdftotext` (`poppler-utils`), `tesseract` (`tesseract-ocr`)

### Install Dependencies
```bash
pip install -r requirements.txt
```

---

## 4. Running the Audit Agent

### Standard Run (reads `dataset/deletion_requests.csv` -> outputs `output.csv`)
```bash
python3 code/main.py
```
Or from within the `code/` directory:
```bash
python3 main.py
```

### Custom Options
```bash
python3 code/main.py --requests dataset/deletion_requests.csv --out output.csv --dataset dataset/
```

---

## 5. Running the Evaluation Workflow

Run the automated evaluation benchmark and custom test suite:
```bash
python3 code/evaluation/evaluate.py
```
Or:
```bash
python3 code/evaluation/main.py
```

To evaluate a specific predictions file against ground truth:
```bash
python3 code/evaluation/main.py --pred output.csv --gold dataset/sample_output.csv
```

### Metrics Evaluated:
- **Case Status Accuracy**: Correctness of `COMPLETE`, `INCOMPLETE`, `NOT_APPLICABLE`.
- **Exact-Case Accuracy**: Exact match of status and all ordered steps.
- **Step-level Precision, Recall, and F1**: Evaluation of generated step sets.
- **Field-level Accuracy**: Field correctness (`phase`, `system_id`, `resource_id`, `operation`, `state`, `evidence_id`).
- **Sequence Accuracy**: Exact order matching and Longest Common Subsequence (LCS) ratio.
- **Custom Test Cases**: Verification of edge cases, non-deletion intents, multilinguality, and ordering rules.

---

## 6. Submission Artifacts

- **Predictions CSV**: `output.csv` (518 cases with `case_id`, `deletion_status`, `steps_json`)
- **Code Archive**: `code.zip` (containing runnable code, `README.md`, and `evaluation/` reports)
- **Chat Transcript**: `log.txt` (structured session transcript per `AGENTS.md`)
