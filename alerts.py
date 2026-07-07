"""Optional alerting. Sends a Telegram message for CRITICAL findings.
No-ops safely if TELEGRAM_TOKEN / TELEGRAM_CHAT_ID are not set, so the
project runs fully offline without any alerting configured."""

import os
import urllib.request
import urllib.parse

TELEGRAM_TOKEN = os.environ.get("TELEGRAM_TOKEN")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID")


def send_alert(text: str) -> None:
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        print(f"[ALERT - would send to Telegram, not configured]\n{text}\n")
        return
    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    data = urllib.parse.urlencode({"chat_id": TELEGRAM_CHAT_ID, "text": text}).encode()
    req = urllib.request.Request(url, data=data)
    try:
        urllib.request.urlopen(req, timeout=5)
    except Exception as e:  # noqa: BLE001
        print(f"[ALERT] failed to send Telegram message: {e}")
