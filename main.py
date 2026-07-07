"""
LogSentinel-Mini pipeline
=========================

Layered detection:
  1. Deterministic rules  -> catches known patterns cheaply (brute force)
  2. LLM extraction        -> catches novel / ambiguous events the rules miss
  3. Storage                -> structured events persisted to SQLite
  4. Alerting                -> CRITICAL findings pushed to Telegram (optional)

Usage:
    export ANTHROPIC_API_KEY=sk-...
    python main.py data/sample_auth.log
"""

import sys
from pathlib import Path

from rules import detect_brute_force, lines_needing_llm_review
from llm_extract import analyze_chunk
from storage.db import init_db, insert_event
from alerts import send_alert

CHUNK_SIZE = 20


def load_lines(path: str) -> list[str]:
    return [l.rstrip("\n") for l in Path(path).read_text().splitlines() if l.strip()]


def run(log_path: str):
    init_db()
    lines = load_lines(log_path)
    print(f"Loaded {len(lines)} log lines from {log_path}\n")

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
        insert_event(source=log_path, event=event, detected_by="rule")
        print(f"[RULE]  BRUTE_FORCE  {hit.source_ip}  ({hit.failure_count} failures)")
        if event["severity"] == "CRITICAL":
            send_alert(event["summary"])

    print()

    # --- Layer 2: LLM handles what rules didn't already resolve ---
    remaining = lines_needing_llm_review(lines, brute_force_ips)
    print(f"{len(remaining)} lines remaining for LLM review (rules resolved the rest)\n")

    for i in range(0, len(remaining), CHUNK_SIZE):
        chunk = remaining[i : i + CHUNK_SIZE]
        if not chunk:
            continue
        try:
            result = analyze_chunk(chunk)
        except Exception as e:  # noqa: BLE001
            print(f"[LLM]   chunk {i}-{i+len(chunk)} skipped: {e}")
            continue

        for event in result.events:
            event_dict = event.model_dump()
            insert_event(source=log_path, event=event_dict, detected_by="llm")
            flag = "ATTACK" if event.is_attack else "benign"
            print(f"[LLM]   {event.event_type:<20} {event.severity:<8} {flag}  conf={event.confidence:.2f}")
            if event.severity == "CRITICAL":
                send_alert(f"{event.event_type}: {event.summary}")

    print("\nDone. Query storage/events.db for full results.")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python main.py <log_file_path>")
        sys.exit(1)
    run(sys.argv[1])
