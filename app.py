from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
import os
import time
import io
import logging
from searchable_encryption import SearchableEncryption
try:
    import PyPDF2
except Exception:
    PyPDF2 = None
try:
    from pdfminer.high_level import extract_text as pdfminer_extract_text
except Exception:
    pdfminer_extract_text = None
try:
    from docx import Document
except Exception:
    Document = None

# Configuration
MASTER_PASSWORD = os.environ.get("SE_MASTER_PASSWORD", "SecureCloudStorage2025!")
STATE_PATH = os.path.join(os.path.dirname(__file__), "state.json")
UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Initialize app and encryption system (loads state if exists)
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", "dev-secret")
se_system = SearchableEncryption.load_state(MASTER_PASSWORD, STATE_PATH)

# Configure simple logging
logging.basicConfig(level=logging.INFO)
logger = app.logger


def save_state():
    try:
        se_system.save_state(STATE_PATH)
    except Exception as e:
        app.logger.error(f"Failed to save state: {e}")


@app.route("/")
def index():
    stats = se_system.get_index_statistics()
    sample_index = list(se_system.encrypted_keyword_index.items())[:10]
    sample_index = [(h[:32] + "...", list(docs)) for h, docs in sample_index]
    return render_template(
        "index.html",
        stats=stats,
        doc_count=len(se_system.encrypted_documents),
        sample_index=sample_index,
        metadata=se_system.document_metadata,
    )


@app.route("/upload", methods=["POST"]) 
def upload():
    # Accept either a file upload or pasted text content
    doc_id = request.form.get("doc_id") or f"doc{len(se_system.encrypted_documents) + 1:03d}"
    keywords_raw = request.form.get("keywords", "").strip()
    pasted_content = request.form.get("content", "").strip()
    file = request.files.get("file")
    content = pasted_content  # will override if file provides text

    if file:
        if not file.filename:
            logger.info("[UPLOAD] File object present but empty filename")
        else:
            filename = file.filename
            ext = os.path.splitext(filename)[1].lower()
            mimetype = getattr(file, 'mimetype', 'unknown')
            logger.info(f"[UPLOAD] Received file: name={filename} ext={ext} mimetype={mimetype}")
            try:
                raw = file.read()
                logger.info(f"[UPLOAD] Raw bytes read: {len(raw)}")
                if not raw:
                    flash("Selected file appears empty (0 bytes).", "warning")
                    return redirect(url_for("index"))
                if ext == '.txt':
                    content = raw.decode('utf-8', errors='ignore').strip()
                elif ext == '.pdf':
                    text_out = ""
                    if PyPDF2:
                        try:
                            reader = PyPDF2.PdfReader(io.BytesIO(raw))
                            for p in reader.pages:
                                try:
                                    txt = p.extract_text() or ""
                                except Exception:
                                    txt = ""
                                text_out += (txt + "\n")
                        except Exception as e:
                            logger.warning(f"[UPLOAD] PyPDF2 error: {e}")
                    if (not text_out.strip()) and pdfminer_extract_text:
                        try:
                            text_out = pdfminer_extract_text(io.BytesIO(raw)) or ""
                        except Exception as e:
                            logger.warning(f"[UPLOAD] pdfminer error: {e}")
                    content = text_out.strip()
                elif ext == '.docx':
                    if not Document:
                        flash("DOCX support not installed (python-docx).", "warning")
                        return redirect(url_for("index"))
                    try:
                        doc = Document(io.BytesIO(raw))
                        content = "\n".join(p.text for p in doc.paragraphs).strip()
                    except Exception as e:
                        logger.exception("[UPLOAD] DOCX parse error")
                        flash(f"Failed to parse DOCX: {e}", "danger")
                        return redirect(url_for("index"))
                else:
                    flash("Unsupported file type. Use .txt / .pdf / .docx.", "warning")
                    return redirect(url_for("index"))
            except Exception as e:
                logger.exception("[UPLOAD] Unexpected read error")
                flash(f"File read failed: {e}", "danger")
                return redirect(url_for("index"))

    # If both file and pasted content provided, prefer file but keep both?
    if file and file.filename and pasted_content and pasted_content != content:
        logger.info("[UPLOAD] Pasted content ignored in favor of file content")

    # Post-processing for PDF empty extraction
    if file and file.filename and ext == '.pdf' and not content:
        flash("PDF contained no extractable text. If scanned, use OCR or paste text.", "danger")
        return redirect(url_for("index"))

    if not content:
        flash("No content provided. Upload a file or paste text.", "warning")
        logger.warning("[UPLOAD] Final content empty")
        return redirect(url_for("index"))

    keywords = [k.strip() for k in keywords_raw.split(",") if k.strip()]
    if not keywords:
        flash("Add keywords (comma-separated) before encrypting.", "warning")
        logger.warning("[UPLOAD] No keywords provided")
        return redirect(url_for("index"))

    try:
        result = se_system.encrypt_document(doc_id, content, keywords)
    except Exception as e:
        logger.exception("[UPLOAD] Encryption failed")
        flash(f"Encryption failed: {e}", "danger")
        return redirect(url_for("index"))
    logger.info(f"[UPLOAD] Encrypted {doc_id} kw={len(keywords)} enc_size={result['encrypted_size']}")
    save_state()
    # Short, compact confirmation (trim preview aggressively)
    preview = content[:60].replace('\n',' ') + ('...' if len(content) > 60 else '')
    flash(f"OK {doc_id} | {result['keywords_indexed']}kw | {result['encrypted_size']}B", "success")
    return redirect(url_for("index"))


@app.route("/search", methods=["POST"]) 
def search():
    keyword = request.form.get("search_keyword", "").strip()
    if not keyword:
        return jsonify({"error": "Empty keyword"}), 400

    result = se_system.search_encrypted(keyword)
    return jsonify(result)


@app.route("/decrypt/<doc_id>")
def decrypt(doc_id: str):
    try:
        content = se_system.decrypt_document(doc_id)
        return render_template("decrypt.html", doc_id=doc_id, content=content)
    except Exception as e:
        flash(str(e), "danger")
        return redirect(url_for("index"))


@app.route("/validate/<doc_id>")
def validate(doc_id: str):
    try:
        val = se_system.validate_confidentiality(doc_id)
        return jsonify(val)
    except Exception as e:
        return jsonify({"error": str(e)}), 404


@app.route("/efficiency-test", methods=["POST"]) 
def efficiency_test():
    # Measure average search time over N iterations for a given keyword
    keyword = request.form.get("eff_keyword", "security").strip() or "security"
    iterations = int(request.form.get("iterations", 100))
    include_series = request.form.get("include_series", "0") in {"1", "true", "True"}

    times = []
    for _ in range(iterations):
        r = se_system.search_encrypted(keyword)
        times.append(r["search_time"])
    avg = sum(times) / len(times) if times else 0.0
    resp = {
        "keyword": keyword,
        "iterations": iterations,
        "avg_ms": round(avg * 1000, 6),
        "min_ms": round(min(times) * 1000, 6) if times else 0.0,
        "max_ms": round(max(times) * 1000, 6) if times else 0.0,
    }
    if include_series:
        resp["series_ms"] = [round(t * 1000, 6) for t in times]
    return jsonify(resp)


@app.route("/generate-bulk", methods=["POST"]) 
def generate_bulk():
    # Add a larger set of synthetic documents to test scalability
    try:
        count = int(request.form.get("count", 500))
    except Exception:
        count = 500
    primary_kw = (request.form.get("keyword", "security") or "security").strip()

    start = time.time()
    start_idx = len(se_system.encrypted_documents) + 1
    for i in range(start_idx, start_idx + count):
        doc_id = f"doc{i:03d}"
        content = (
            f"Research Document {i}: Advanced Topics in Computer Science\n"
            f"Covers security, encryption, data structures, algorithms, and distributed systems.\n"
        )
        # Index generated docs by the chosen keyword (singular) as requested
        keywords = [primary_kw]
        se_system.encrypt_document(doc_id, content, keywords)
    duration = time.time() - start
    save_state()
    return jsonify({
        "added": count,
        "seconds": round(duration, 4),
        "avg_ms_per_doc": round((duration / max(count, 1)) * 1000, 4),
        "total_docs": len(se_system.encrypted_documents),
        "keyword": primary_kw,
    })


@app.route("/reset", methods=["POST"])  # Secure wipe of in-memory + persisted state
def reset():
    confirm = request.form.get("confirm", "").lower().strip()
    if confirm != "erase":
        return jsonify({"error": "Confirmation word 'erase' required"}), 400
    before = {
        "documents": len(se_system.encrypted_documents),
        "keywords": len(se_system.encrypted_keyword_index),
        "state_file_exists": os.path.exists(STATE_PATH)
    }
    # Clear in-memory structures
    se_system.encrypted_documents.clear()
    se_system.encrypted_keyword_index.clear()
    se_system.document_metadata.clear()
    # Persist empty state
    try:
        se_system.save_state(STATE_PATH)
    except Exception as e:
        app.logger.error(f"[RESET] Failed to write empty state: {e}")
    # Remove uploaded raw files if any stored
    removed_files = []
    try:
        for name in os.listdir(UPLOAD_DIR):
            path = os.path.join(UPLOAD_DIR, name)
            if os.path.isfile(path):
                try:
                    os.remove(path)
                    removed_files.append(name)
                except Exception as e:
                    app.logger.warning(f"[RESET] Could not remove {name}: {e}")
    except FileNotFoundError:
        pass
    return jsonify({
        "status": "wiped",
        "before": before,
        "after": {
            "documents": len(se_system.encrypted_documents),
            "keywords": len(se_system.encrypted_keyword_index)
        },
        "removed_uploads": removed_files
    })


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
