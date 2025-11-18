
# Searchable Encryption for Secure Cloud Document Sharing

This project implements a practical demonstration of searchable encryption (SSE) for cloud‑style document storage. Users can:
1. Upload documents (.txt / .pdf / .docx or paste text)
2. Encrypt them client‑side on submission (server holding only ciphertext + metadata)
3. Associate keywords which are stored as trapdoor tokens (keyed hashes)
4. Perform secure keyword searches without revealing plaintext keywords to the server
5. Measure search efficiency & scalability
6. Validate confidentiality (no plaintext leakage in encrypted blobs)
7. Reset / wipe all data securely

> Educational / prototype purpose: Not a hardened production system. It omits advanced leakage protections (access pattern hiding, forward privacy) offered by more formal SSE schemes like OXT or Sophos. Use it to learn concepts, not to store high‑risk data.

---
## Technology Stack Overview

| Layer | Technology | Purpose |
|-------|------------|---------|
| Web Framework | Flask | HTTP routing, request handling, template rendering |
| UI / Styling | Bootstrap 5, Bootstrap Icons | Responsive layout, consistent styling, iconography |
| Visualization | Chart.js | Efficiency query time line chart + average indicator |
| Crypto Primitives | `cryptography` (Fernet), PBKDF2-HMAC-SHA256 | Authenticated encryption of documents; key derivation from master password |
| Trapdoor / Index | SHA-256 keyed hash (index key + lowercase(keyword)) | Deterministic token; server stores token → doc IDs mapping, not plaintext |
| Document Parsing | PyPDF2, pdfminer.six fallback, python-docx | Extract text from PDF/DOCX before encryption |
| Persistence | JSON (`state.json`) | Survives restarts: ciphertexts, metadata, keyword token index |
| Bulk / Reset Ops | Custom Flask routes | Add many synthetic docs; erase all encrypted data safely |

---
## Cryptography Details

Document Encryption:
- Uses Fernet (from `cryptography`). Under the hood: AES-128 in CBC + PKCS7 padding + HMAC-SHA256 integrity + version + timestamp (token format). Provides confidentiality + authenticity.
- Key Derivation: PBKDF2-HMAC-SHA256 with fixed salts and 100,000 iterations to derive two independent keys:
	- Encryption key → base64 for Fernet
	- Index key → used to derive trapdoor tokens

Trapdoor / Searchable Index:
- For each keyword: `token = SHA256(index_key || lowercase(keyword))`
- Stored server-side ONLY as hex token → set(doc_ids)
- Searching: user supplies plaintext keyword; server re-derives token and matches.
- Leakage: reveals result counts and whether a keyword was previously queried (deterministic tokens). Does not hide access pattern or frequency.

Confidentiality Validation (heuristic):
- Ensures ciphertext is base64 and contains no obvious plaintext markers or common words.
- Provides simple leakage check—not a formal cryptanalysis.

## Features

- Upload: `.txt`, `.pdf`, `.docx` or manual paste.
- Automatic text extraction (PyPDF2 → pdfminer fallback → DOCX paragraphs).
- Keyword indexing with trapdoor tokens.
- Fast search (O(1) token lookup + set retrieval) – typical < 1ms for demo scale.
- Efficiency test chart (query times + average dashed line).
- Confidentiality validation checks.
- Scalability generator (bulk synthetic documents).
- Full secure reset (requires confirmation word `erase`).

---
## Limitations / Security Considerations

- Deterministic trapdoor tokens leak equality of queries (keyword frequency / pattern leakage).
- No access pattern obfuscation (server learns which documents match each token).
- No forward secrecy / revocation logic; same master password derivations reused.
- PDF OCR not implemented; scanned PDFs produce no text.
- No user authentication or multi-tenant isolation.
- Salts are static—acceptable for demonstration; in production per‑deployment random salts + secret storage recommended.

Potential Improvements:
- Integrate proper SSE (e.g., OXT) with controlled leakage profile.
- Add per-user key isolation / rotation.
- Introduce rate limiting and auth tokens.
- Add OCR (Tesseract) for scanned PDFs.
- Implement document deletion & export encrypted blob endpoint.

---
## API / Routes Summary

| Method | Path | Description | Body Fields |
|--------|------|-------------|-------------|
| GET | `/` | UI dashboard | — |
| POST | `/upload` | Upload & encrypt document | `file`, `content`, `keywords`, `doc_id?` |
| POST | `/search` | Search by plaintext keyword | `search_keyword` |
| GET | `/decrypt/<doc_id>` | View decrypted content | — |
| GET | `/validate/<doc_id>` | Confidentiality heuristics | — |
| POST | `/efficiency-test` | Run repeated searches; timing stats | `eff_keyword`, `iterations`, `include_series?` |
| POST | `/generate-bulk` | Add synthetic docs for scalability | `count?` |
| POST | `/reset` | Wipe all encrypted data (requires confirm) | `confirm=erase` |

Return shapes are JSON for API (except decrypt view / index UI pages). Errors use `{"error": "message"}` pattern.

---
## Installation & Run

Requirements:
- Python 3.9+
- Packages listed in `requirements.txt`

Install:
```powershell
pip install -r requirements.txt
```

Run web app:
```powershell
python .\app.py
```
Browse: http://127.0.0.1:5000

Run console demo (optional benchmarking / sample):
```powershell
python .\searchable_encryption.py
```

Environment overrides (optional):
```powershell
set FLASK_SECRET=your-secret-here
set SE_MASTER_PASSWORD=StrongMasterPass2025!
```

---
## Reset / Data Wipe

UI: Click "Erase All" button (confirms) → wipes memory + `uploads/` + rewrites empty `state.json`.
API:
```powershell
curl -X POST -F "confirm=erase" http://127.0.0.1:5000/reset
```
Manual file removal:
```powershell
del state.json
del .\uploads\*
```

---
## Quick Start (From GitHub Clone)

Follow these steps if you just discovered this repository and want to run the project locally.

### 1. Prerequisites
- Python 3.9+ (3.11 recommended)
- Git installed
- Internet access to install dependencies

Optional tools:
- A virtual environment manager (`python -m venv` or `conda`)
- OCR tool (Tesseract) if later adding scanned PDF support (not required now)

### 2. Clone the Repository
```bash
git clone https://github.com/<your-org>/<your-repo>.git
cd <your-repo>
```

### 3. Create & Activate Virtual Environment (Recommended)
Windows (PowerShell):
```powershell
python -m venv venv
./venv/Scripts/Activate.ps1
```
macOS / Linux:
```bash
python3 -m venv venv
source venv/bin/activate
```

### 4. Install Dependencies
```powershell
pip install -r requirements.txt
```

If a dependency fails (e.g., `pdfminer.six` on some platforms) retry with:
```powershell
pip install --upgrade pip wheel setuptools
pip install -r requirements.txt
```

### 5. Optional: Set Secrets / Environment Variables
```powershell
set FLASK_SECRET=your-long-random-secret
set SE_MASTER_PASSWORD=YourStrongMasterPassword!
```
macOS / Linux:
```bash
export FLASK_SECRET=your-long-random-secret
export SE_MASTER_PASSWORD=YourStrongMasterPassword!
```
If unset, safe defaults are used (demo only).

### 6. Run the Web Application
```powershell
python .\app.py
```
Then open: http://127.0.0.1:5000

### 7. Use the Application
- Upload or paste text, add keywords, click Encrypt & Index.
- Search by keyword (case-insensitive match logic via trapdoor token).
- Generate 500 synthetic documents for scalability via the “Generate 500 Docs” button (choose keyword first).
- Run efficiency test to see average query time & chart.
- Erase All to reset state (requires confirmation; wipes `state.json` and `uploads/`).

### 8. Persisted State
- `state.json` stores encrypted documents and the keyword token index.
- It’s ignored via `.gitignore` to avoid committing sensitive test data.

### 9. Manual Wipe (Alternative)
```powershell
del state.json
del .\uploads\*
```
On next start a fresh state is created automatically.

### 10. Console Demo (Optional)
```powershell
python .\searchable_encryption.py
```
Shows encryption/search/scalability tasks in the terminal.

### 11. Troubleshooting
- Empty PDF content: File likely scanned (no embedded text) → use OCR or paste text.
- `ModuleNotFoundError`: Re-run dependency install.
- Unicode errors on `.txt`: Ensure file encoded UTF‑8; fallback decoding strips invalid chars.
- Slow bulk generation (500 docs): Normal on very low-power CPUs; reduces after first run due to caching.

### 12. Suggested Next Improvements
- Add authentication for multi-user scenarios.
- Implement document deletion per ID.
- Add OCR (Tesseract) for scanned PDFs.
- Switch to a formal SSE protocol with reduced leakage.

---

---
## Performance (Sample Demo Run)

| Operation | Example Time (ms) |
|-----------|-------------------|
| Single encryption (small doc) | 0.5 – 1.0 |
| Single search | < 0.01 |
| 100 repeated searches (avg) | ≈ 0.001 – 0.002 |
| Bulk add 95 docs | < 50 ms total (demo machine) |

Times depend on system CPU / Python interpreter. Trapdoor lookups scale with number of keywords, not raw ciphertext size.

---
## Folder Structure

```
cryptoProject/
	app.py                     # Flask app & routes
	searchable_encryption.py   # Core SSE class + demonstration script
	templates/                 # Jinja2 UI templates (index, decrypt, base)
	uploads/                   # Raw uploaded files (optional presence)
	state.json                 # Persistent encrypted state & metadata
	requirements.txt           # Dependencies
	README.md                  # This documentation
```

---
## Quick Usage Cheatsheet

Encrypt & index a doc:
1. Open UI → choose file or paste text.
2. Enter comma-separated keywords.
3. Press "Encrypt & Index" → success toast: `OK docXYZ | 6kw | 420B`.

Search:
1. Enter keyword → view trapdoor hash fragment + result set + time.

Efficiency test:
1. Provide keyword & iterations → run → chart + stats appear.

Reset:
1. Press "Erase All" → confirm prompt → data wiped.

---
## Disclaimer

This implementation is for educational use. Do not deploy for sensitive production workloads without a full security review, stronger SSE protocol adoption, proper secret management, authentication, monitoring, and compliance controls.

---
## Contributing / Next Steps

Ideas welcomed:
- Replace trapdoor hashing with formal SSE scheme
- Add per-document access controls
- Add OCR path for scanned PDFs
- Implement per-user namespaces & key rotation
- Provide export/import of encrypted state

Feel free to adapt and extend.

---
## License

No explicit license provided; treat as internal or educational code. Add one if you plan external distribution.


## Requirements

- Python 3.9+
- `cryptography` library

Install dependencies:

```powershell
pip install -r requirements.txt
```

## How to run

Run the demo end-to-end:

```powershell
python .\searchable_encryption.py
```

The script will:
1. Initialize the system with derived keys from a master password
2. Encrypt 5 sample documents and build the encrypted keyword index
3. Perform trapdoor-based searches and print response times
4. Validate confidentiality on sample encrypted documents
5. Scale to 100 documents and re-measure search performance
6. Decrypt one matching document to show authorized access works

## Notes

- The “cloud server” is simulated within one process (separate data structures). No plaintext keywords are stored server-side—only fixed-size token hashes.

## Web application (UI/UX)

This project includes a Flask web app with upload, search, validation, efficiency, and scalability testing.

Install dependencies and start the server:

```powershell
pip install -r .\requirements.txt
python .\app.py
```

Then open http://127.0.0.1:5000 in your browser.

Features in the UI:
- Upload a file (.txt, .pdf, .docx) or paste content; add comma-separated keywords; encrypt & index
- Search using the trapdoor mechanism (server only sees tokens, not plaintext)
- Run an efficiency test (N repeated queries) with an easy-to-read time chart
- Validate confidentiality for any document (JSON report in a modal)
- Generate synthetic documents to test scalability

PDF notes:
- Text extraction first tries PyPDF2. If that yields little/no text, it falls back to pdfminer.six.
- Scanned/image-only PDFs will not produce text unless OCR is added; paste the content or export a text-based PDF if needed.

## Project workflow and technologies

- Frontend/UI: Bootstrap 5 + Bootstrap Icons, Chart.js for visualization
	- Provides polished, responsive layouts; chart visualizes per-query times with an average line
- Backend: Flask
	- Serves routes for upload, search, decrypt, validate, efficiency testing, and bulk generation
- Cryptography: `cryptography` (Fernet) + PBKDF2-HMAC (SHA‑256)
	- Authenticated encryption of document contents; key derived from a master password
- Searchable index: keyed SHA‑256 token (trapdoor)
	- Stores only token hashes mapped to document IDs; no plaintext keywords persisted server-side
- Document parsing: PyPDF2 (PDF), python-docx (DOCX)
	- Extracts text from uploaded files before encryption
- Persistence: JSON state file (`state.json`)
	- Saves encrypted docs, encrypted index, and metadata across restarts

Typical flow:
1) Upload or paste text (+ keywords) → parse text (if PDF/DOCX)
2) Encrypt content with Fernet; build encrypted keyword index (token → doc IDs)
3) Search: client sends a keyword; server computes trapdoor token and looks up doc IDs
4) Efficiency: repeat searches; calculate min/avg/max; visualize series and average line
5) Validate: inspect encrypted blob properties and confirm no plaintext leakage
6) Scalability: generate many synthetic docs; re-check performance & stats

