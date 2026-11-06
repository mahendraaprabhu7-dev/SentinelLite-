"""
SentinelLite: Defensive Authentication Log Analyzer
--------------------------------------------------
Analyzes local authentication logs for repeated failed login attempts.
Use only with logs you own or are authorized to analyze.

Run:
    streamlit run app.py
"""
from __future__ import annotations

import hashlib
import io
import re
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

import pandas as pd
import streamlit as st

# Example format:
# 2026-11-04 10:10:00,192.168.1.105,alice,FAILED
# 2026-11-04 10:10:15,192.168.1.105,alice,FAILED
LOG_PATTERN = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),"
    r"(?P<ip>[0-9a-fA-F:.]+),(?P<username>[A-Za-z0-9_.@-]+),"
    r"(?P<status>SUCCESS|FAILED)$"
)

DEFAULT_THRESHOLD = 5
DEFAULT_WINDOW_MINUTES = 5


def sha256_bytes(data: bytes) -> str:
    """Return the SHA-256 digest of bytes."""
    return hashlib.sha256(data).hexdigest()


def parse_log_text(text: str) -> tuple[pd.DataFrame, list[str]]:
    """Parse CSV-like authentication lines and return rows plus invalid-line notes."""
    rows = []
    invalid = []
    for line_number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = LOG_PATTERN.match(line)
        if not match:
            invalid.append(f"Line {line_number}: invalid format")
            continue
        item = match.groupdict()
        try:
            timestamp = datetime.strptime(item["timestamp"], "%Y-%m-%d %H:%M:%S")
        except ValueError:
            invalid.append(f"Line {line_number}: invalid timestamp")
            continue
        rows.append({
            "timestamp": timestamp,
            "ip": item["ip"],
            "username": item["username"],
            "status": item["status"],
        })
    return pd.DataFrame(rows, columns=["timestamp", "ip", "username", "status"]), invalid


def detect_bruteforce(
    logs: pd.DataFrame,
    threshold: int = DEFAULT_THRESHOLD,
    window_minutes: int = DEFAULT_WINDOW_MINUTES,
) -> pd.DataFrame:
    """Flag IP addresses with at least threshold failures in any sliding time window."""
    alerts = []
    failed = logs[logs["status"] == "FAILED"].sort_values("timestamp")
    window = timedelta(minutes=window_minutes)

    for ip, group in failed.groupby("ip"):
        events = list(group["timestamp"])
        left = 0
        for right, current in enumerate(events):
            while current - events[left] > window:
                left += 1
            count = right - left + 1
            if count >= threshold:
                alerts.append({
                    "ip": ip,
                    "failed_attempts": count,
                    "window_start": events[left],
                    "window_end": current,
                    "severity": "HIGH",
                    "alert": f"{count} failed logins within {window_minutes} minutes",
                })
                # Avoid generating a row for every overlapping event.
                break
    return pd.DataFrame(
        alerts,
        columns=["ip", "failed_attempts", "window_start", "window_end", "severity", "alert"],
    )


def make_sample_logs() -> str:
    """Create harmless synthetic sample data for demonstration."""
    rows = []
    start = datetime(2026, 11, 4, 10, 0, 0)
    for i in range(7):
        timestamp = start + timedelta(seconds=i * 30)
        rows.append(f"{timestamp:%Y-%m-%d %H:%M:%S},192.168.1.105,alice,FAILED")
    rows.append(f"{start + timedelta(minutes=8):%Y-%m-%d %H:%M:%S},192.168.1.105,alice,SUCCESS")
    rows.append(f"{start + timedelta(minutes=9):%Y-%m-%d %H:%M:%S},192.168.1.20,bob,SUCCESS")
    return "\n".join(rows)


def render_dashboard(logs: pd.DataFrame, alerts: pd.DataFrame, invalid: list[str], digest: str) -> None:
    st.subheader("Overview")
    c1, c2, c3 = st.columns(3)
    c1.metric("Log events", len(logs))
    c2.metric("Failed logins", int((logs["status"] == "FAILED").sum()))
    c3.metric("High-severity alerts", len(alerts))

    if not logs.empty:
        st.subheader("Login activity")
        counts = logs.groupby(["timestamp", "status"]).size().unstack(fill_value=0)
        st.line_chart(counts)

    st.subheader("Detection results")
    if alerts.empty:
        st.success("No activity matched the selected detection threshold.")
    else:
        st.dataframe(alerts, use_container_width=True)

    if invalid:
        with st.expander(f"Invalid lines ({len(invalid)})"):
            st.write("\n".join(invalid))

    st.subheader("Log integrity")
    st.code(f"SHA-256: {digest}")
    st.caption("This digest identifies the uploaded file bytes. Recompute it after download to compare integrity.")


def main() -> None:
    st.set_page_config(page_title="SentinelLite", page_icon="🛡️", layout="wide")
    st.title("🛡️ SentinelLite")
    st.write("A lightweight defensive authentication-log analyzer and integrity checker.")
    st.info("Use only with log files you own or are authorized to inspect. Detection is heuristic and may produce false positives.")

    uploaded = st.file_uploader("Upload an authentication log (.txt or .csv)", type=["txt", "csv"])
    with st.sidebar:
        st.header("Detection settings")
        threshold = st.slider("Failed attempts threshold", min_value=3, max_value=20, value=DEFAULT_THRESHOLD)
        window_minutes = st.slider("Time window (minutes)", min_value=1, max_value=30, value=DEFAULT_WINDOW_MINUTES)
        if st.button("Load synthetic demo"):
            st.session_state["demo_text"] = make_sample_logs()

    if uploaded is not None:
        raw_bytes = uploaded.getvalue()
        text = raw_bytes.decode("utf-8", errors="replace")
    elif "demo_text" in st.session_state:
        text = st.session_state["demo_text"]
        raw_bytes = text.encode("utf-8")
    else:
        st.markdown("### Expected log format")
        st.code("YYYY-MM-DD HH:MM:SS,IP_ADDRESS,USERNAME,SUCCESS_OR_FAILED")
        st.write("Example: `2026-11-04 10:10:00,192.168.1.105,alice,FAILED`")
        st.write("Upload a file or select **Load synthetic demo** in the sidebar.")
        return

    logs, invalid = parse_log_text(text)
    alerts = detect_bruteforce(logs, threshold, window_minutes)
    render_dashboard(logs, alerts, invalid, sha256_bytes(raw_bytes))

    report = io.StringIO()
    report.write("SentinelLite Incident Summary\n")
    report.write(f"Events analyzed: {len(logs)}\n")
    report.write(f"Failed logins: {int((logs['status'] == 'FAILED').sum()) if not logs.empty else 0}\n")
    report.write(f"Alerts: {len(alerts)}\n")
    report.write(f"SHA-256: {sha256_bytes(raw_bytes)}\n\n")
    if alerts.empty:
        report.write("No threshold-matching alerts detected.\n")
    else:
        report.write(alerts.to_csv(index=False))
    st.download_button("Download incident summary", report.getvalue(), file_name="sentinellite_report.txt", mime="text/plain")


if __name__ == "__main__":
    main()
