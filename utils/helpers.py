"""
utils/helpers.py
------------------
Shared utility functions used across the app: scan-history storage
and small formatting helpers. Uses a plain CSV file (no database
library needed) so it's easy to read, inspect, or reset by hand.

Used by: app.py, report_generator.py
"""

import os
from datetime import datetime
import pandas as pd

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
HISTORY_PATH = os.path.join(DATA_DIR, "scan_history.csv")

HISTORY_COLUMNS = ["timestamp", "input_type", "preview", "risk_score", "risk_level", "category"]


def _ensure_history_file():
    """Create the data folder and an empty history CSV if they don't exist."""
    os.makedirs(DATA_DIR, exist_ok=True)
    if not os.path.exists(HISTORY_PATH):
        pd.DataFrame(columns=HISTORY_COLUMNS).to_csv(HISTORY_PATH, index=False)


def truncate_text(text, length=80):
    """Shorten text for table previews, keeping it single-line."""
    if not text:
        return ""
    clean = text.strip().replace("\n", " ")
    return clean if len(clean) <= length else clean[:length] + "..."


def save_scan(input_type, raw_input, risk_score, risk_level, category, preview_length=80):
    """Append one scan result to the history CSV. Never raises."""
    try:
        _ensure_history_file()
        row = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "input_type": input_type,
            "preview": truncate_text(raw_input, preview_length),
            "risk_score": int(risk_score),
            "risk_level": risk_level,
            "category": category,
        }
        df = pd.DataFrame([row])
        df.to_csv(HISTORY_PATH, mode="a", header=False, index=False)
        return True
    except Exception as e:
        print(f"[utils/helpers.py] Failed to save scan: {e}")
        return False


def load_history():
    """Return the full scan history as a pandas DataFrame, most recent first."""
    try:
        _ensure_history_file()
        df = pd.read_csv(HISTORY_PATH)
        return df.iloc[::-1].reset_index(drop=True)  # newest first
    except Exception as e:
        print(f"[utils/helpers.py] Failed to load history: {e}")
        return pd.DataFrame(columns=HISTORY_COLUMNS)


def get_stats():
    """Return aggregate counts for the Dashboard page."""
    df = load_history()
    stats = {
        "total_scans": len(df),
        "safe_count": int((df["risk_level"] == "SAFE").sum()) if not df.empty else 0,
        "medium_count": int((df["risk_level"] == "MEDIUM").sum()) if not df.empty else 0,
        "high_count": int((df["risk_level"] == "HIGH").sum()) if not df.empty else 0,
        "critical_count": int((df["risk_level"] == "CRITICAL").sum()) if not df.empty else 0,
    }
    return stats


def clear_history():
    """Wipe the scan history back to an empty file."""
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        pd.DataFrame(columns=HISTORY_COLUMNS).to_csv(HISTORY_PATH, index=False)
        return True
    except Exception as e:
        print(f"[utils/helpers.py] Failed to clear history: {e}")
        return False


def load_demo_messages():
    """
    Load demo scam messages from data/scam_messages.csv for the
    'Try a demo message' dropdown. Expects columns: category, message.
    Falls back to a small built-in set if the file is missing or the
    columns don't match, so the app never breaks because of this file.
    """
    csv_path = os.path.join(DATA_DIR, "scam_messages.csv")
    fallback = {
        "Lottery Scam": "Congratulations! You have won ₹50,000. Claim your prize immediately by clicking this link.",
        "Phishing / KYC": "Your bank account will be blocked within 30 minutes. Verify your KYC immediately using this link.",
        "Job Scam": "Congratulations! You have been selected for a work-from-home job. Pay ₹999 registration fee to confirm your position.",
        "Safe Message": "Your order has been shipped and will arrive tomorrow. Track your order from the official application.",
    }
    try:
        if not os.path.exists(csv_path):
            return fallback
        df = pd.read_csv(csv_path)
        if "category" not in df.columns or "message" not in df.columns:
            return fallback
        demo = {}
        for _, row in df.iterrows():
            demo[str(row["category"])] = str(row["message"])
        return demo if demo else fallback
    except Exception as e:
        print(f"[utils/helpers.py] Failed to load demo messages, using fallback: {e}")
        return fallback

