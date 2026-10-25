# Usage report (final full run: 518 cases -> output.csv)

The final run is fully deterministic and rule based. No LLM or other hosted model was called.

| Provider / model | Calls | Input tokens | Output tokens | Est. cost |
|---|---|---|---|---|
| none | 0 | 0 | 0 | $0.00 |
| **Overall** | 0 | 0 | 0 | $0.00 |

Per request: 0 calls, 0 tokens average, $0.00.

Local tools only: `tesseract` OCR for PNG screenshots and `pdftotext` / `pypdf` for PDFs (cached in `.cache/ocr`, not part of the submission). `audit/intent.py` has an optional LLM fallback hook (callable passed to `authorises_deletion`); it is unused in the final run, and any credentials would come from environment variables only.
