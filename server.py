"""
LogSentinel-Mini web backend.

Single-user local service: upload a log file through the browser, the
pipeline (rules + Gemini) runs, results are stored in SQLite and returned
to the frontend. No auth — meant to run on your own machine for demos.

Run:
    uvicorn server:app --reload --port 8000
Then open http://localhost:8000
"""

from pathlib import Path
import shutil
import tempfile

from fastapi import FastAPI, UploadFile, File
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

from rules import detect_brute_force, lines_needing_llm_review
from llm_extract import analyze_chunk
from storage.db import init_db, insert_event, get_all_events

app = FastAPI(title="LogSentinel-Mini")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

CHUNK_SIZE = 20
init_db()


@app.get("/")
def index():
    return FileResponse(Path(__file__).parent / "web" / "index.html")


@app.get("/api/events")
def api_get_events():
    return {"events": get_all_events()}


@app.post("/api/analyze")
async def api_analyze(file: UploadFile = File(...)):
    with tempfile.NamedTemporaryFile(delete=False, suffix=".log") as tmp:
        shutil.copyfileobj(file.file, tmp)
        tmp_path = tmp.name

    lines = [
        l.rstrip("\n")
        for l in Path(tmp_path).read_text(errors="ignore").splitlines()
        if l.strip()
    ]

    rule_events = []
    llm_events = []
    llm_error = None

    # --- Layer 1: deterministic rules ---
    brute_force_hits = detect_brute_force(lines)
    brute_force_ips = {hit.source_ip for hit in brute_force_hits}

    for hit in brute_force_hits:
        event = {
            "severity": "HIGH",
            "event_type": "BRUTE_FORCE",
            "source_ip": hit.source_ip,
            "target_user": ", ".join(sorted(hit.target_users)),
            "is_attack": True,
            "confidence": 1.0,
            "summary": (
                f"{hit.failure_count} auth failures from {hit.source_ip} "
                f"between {hit.window_start} and {hit.window_end}."
            ),
            "recommended_action": "Block source IP and enforce rate limiting / fail2ban.",
        }
        insert_event(source=file.filename, event=event, detected_by="rule")
        rule_events.append(event)

    # --- Layer 2: LLM on the leftover ambiguous lines ---
    remaining = lines_needing_llm_review(lines, brute_force_ips)
    for i in range(0, len(remaining), CHUNK_SIZE):
        chunk = remaining[i : i + CHUNK_SIZE]
        if not chunk:
            continue
        try:
            result = analyze_chunk(chunk)
        except Exception as e:  # noqa: BLE001
            llm_error = str(e)
            continue
        for event in result.events:
            event_dict = event.model_dump()
            insert_event(source=file.filename, event=event_dict, detected_by="llm")
            llm_events.append(event_dict)

    return {
        "filename": file.filename,
        "total_lines": len(lines),
        "rule_events": rule_events,
        "llm_events": llm_events,
        "llm_lines_reviewed": len(remaining),
        "llm_error": llm_error,
    }


app.mount("/static", StaticFiles(directory=Path(__file__).parent / "web"), name="static")
