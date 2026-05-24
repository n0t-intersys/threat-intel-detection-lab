#!/usr/bin/env python3
"""
Log Anomaly Detector — Reads Windows Event Log / syslog CSV, uses statistical
baseline (mean ± 2σ) to flag anomalous login times, failed auth spikes,
and rare process execution events.

Usage:
    python log_anomaly_detector.py --input sample_data/auth_logs.csv --type windows
    python log_anomaly_detector.py --input sample_data/syslog.csv --type syslog
    python log_anomaly_detector.py --input sample_data/auth_logs.csv --output anomalies.json
    python log_anomaly_detector.py --generate-sample  # create sample data for testing
"""

import argparse
import csv
import json
import logging
import math
import random
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Statistical helpers
# ---------------------------------------------------------------------------

def mean(values: list[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def stdev(values: list[float]) -> float:
    if len(values) < 2:
        return 0.0
    mu = mean(values)
    variance = sum((v - mu) ** 2 for v in values) / (len(values) - 1)
    return math.sqrt(variance)


def z_score(value: float, mu: float, sigma: float) -> float:
    if sigma == 0:
        return 0.0
    return (value - mu) / sigma


# ---------------------------------------------------------------------------
# Anomaly findings
# ---------------------------------------------------------------------------

@dataclass
class Anomaly:
    category: str
    severity: str
    timestamp: str
    user: str
    source_ip: str
    event_id: str
    description: str
    z_score: float = 0.0

    def to_dict(self) -> dict:
        return {
            "category": self.category,
            "severity": self.severity,
            "timestamp": self.timestamp,
            "user": self.user,
            "source_ip": self.source_ip,
            "event_id": self.event_id,
            "description": self.description,
            "z_score": round(self.z_score, 2),
        }


# ---------------------------------------------------------------------------
# Log parsers
# ---------------------------------------------------------------------------

def parse_windows_event_log(path: Path) -> list[dict]:
    """
    Parse Windows Event Log CSV with columns:
    TimeGenerated, EventID, Computer, User, SourceIP, Message
    """
    events = []
    with path.open(newline="", encoding="utf-8-sig") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            events.append({
                "timestamp": row.get("TimeGenerated", ""),
                "event_id": row.get("EventID", ""),
                "computer": row.get("Computer", ""),
                "user": row.get("User", ""),
                "source_ip": row.get("SourceIP", ""),
                "message": row.get("Message", ""),
            })
    return events


def parse_syslog_csv(path: Path) -> list[dict]:
    """
    Parse syslog CSV with columns:
    Timestamp, Hostname, Process, User, SourceIP, Message
    """
    events = []
    with path.open(newline="", encoding="utf-8-sig") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            events.append({
                "timestamp": row.get("Timestamp", ""),
                "event_id": row.get("Process", "syslog"),
                "computer": row.get("Hostname", ""),
                "user": row.get("User", ""),
                "source_ip": row.get("SourceIP", ""),
                "message": row.get("Message", ""),
            })
    return events


def parse_timestamp(ts: str) -> datetime | None:
    formats = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%m/%d/%Y %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
    ]
    for fmt in formats:
        try:
            return datetime.strptime(ts.strip(), fmt)
        except ValueError:
            continue
    return None


# ---------------------------------------------------------------------------
# Detection engines
# ---------------------------------------------------------------------------

def detect_failed_auth_spikes(events: list[dict]) -> list[Anomaly]:
    """
    Flag hours with failed authentication counts > mean + 2σ.
    Windows: EventID 4625 | Syslog: "Failed password" in message
    """
    anomalies = []
    hourly_fails: dict[str, int] = defaultdict(int)

    for evt in events:
        is_fail = (evt["event_id"] == "4625" or
                   "failed password" in evt["message"].lower() or
                   "authentication failure" in evt["message"].lower())
        if not is_fail:
            continue
        dt = parse_timestamp(evt["timestamp"])
        if dt:
            hour_key = dt.strftime("%Y-%m-%d %H:00")
            hourly_fails[hour_key] += 1

    if not hourly_fails:
        return anomalies

    counts = list(hourly_fails.values())
    mu = mean(counts)
    sigma = stdev(counts)
    threshold = mu + 2 * sigma

    for hour, count in sorted(hourly_fails.items()):
        if count > max(threshold, 5):  # minimum 5 fails to trigger
            z = z_score(count, mu, sigma)
            # Find the most common user/IP in that hour
            hour_events = [e for e in events if hour[:13] in e["timestamp"]
                           and ("4625" == e["event_id"] or "failed" in e["message"].lower())]
            users = Counter(e["user"] for e in hour_events).most_common(1)
            ips = Counter(e["source_ip"] for e in hour_events).most_common(1)
            top_user = users[0][0] if users else "unknown"
            top_ip = ips[0][0] if ips else "unknown"

            anomalies.append(Anomaly(
                category="FAILED_AUTH_SPIKE",
                severity="HIGH" if z > 3 else "MEDIUM",
                timestamp=hour,
                user=top_user,
                source_ip=top_ip,
                event_id="4625",
                description=f"Failed auth spike: {count} failures in 1 hour (mean={mu:.1f}, σ={sigma:.1f}, z={z:.1f})",
                z_score=z,
            ))

    return anomalies


def detect_off_hours_logins(events: list[dict]) -> list[Anomaly]:
    """
    Flag logins outside normal business hours (22:00–05:00 UTC).
    EventID 4624 (successful logon).
    """
    anomalies = []
    for evt in events:
        is_logon = (evt["event_id"] == "4624" or
                    "accepted password" in evt["message"].lower() or
                    "session opened" in evt["message"].lower())
        if not is_logon:
            continue
        dt = parse_timestamp(evt["timestamp"])
        if not dt:
            continue
        hour = dt.hour
        if hour >= 22 or hour < 5:
            # Filter service accounts (commonly log on at night)
            user = evt.get("user", "")
            if user.endswith("$") or "service" in user.lower() or "svc" in user.lower():
                continue
            anomalies.append(Anomaly(
                category="OFF_HOURS_LOGIN",
                severity="MEDIUM",
                timestamp=evt["timestamp"],
                user=user,
                source_ip=evt.get("source_ip", ""),
                event_id="4624",
                description=f"Login at {dt.strftime('%H:%M')} UTC — outside business hours (22:00-05:00)",
                z_score=0.0,
            ))

    return anomalies


def detect_rare_processes(events: list[dict]) -> list[Anomaly]:
    """
    Flag processes that appear fewer than threshold times in the dataset.
    Useful for identifying LOLBins and unusual process execution.
    """
    anomalies = []
    RARE_PROCESS_THRESHOLD = 2
    SUSPICIOUS_PROCESSES = {
        "mimikatz", "procdump", "bloodhound", "sharphound", "cobaltstrike",
        "meterpreter", "nc.exe", "netcat", "psexec", "wce", "pwdump",
        "vssadmin", "wmic", "certutil", "regsvr32", "mshta", "wscript",
        "cscript", "rundll32", "msiexec", "odbcconf", "pcalua",
    }

    process_counts: Counter = Counter()
    for evt in events:
        msg = evt["message"].lower()
        for proc in SUSPICIOUS_PROCESSES:
            if proc in msg:
                process_counts[proc] += 1

    for proc, count in process_counts.items():
        if count <= RARE_PROCESS_THRESHOLD:
            matching = [e for e in events if proc in e["message"].lower()]
            first = matching[0] if matching else {}
            anomalies.append(Anomaly(
                category="SUSPICIOUS_PROCESS",
                severity="HIGH" if proc in {"mimikatz", "procdump", "meterpreter", "cobaltstrike"} else "MEDIUM",
                timestamp=first.get("timestamp", ""),
                user=first.get("user", ""),
                source_ip=first.get("source_ip", ""),
                event_id=first.get("event_id", ""),
                description=f"Suspicious process '{proc}' detected {count} time(s) — rare execution",
            ))

    return anomalies


def detect_brute_force_accounts(events: list[dict]) -> list[Anomaly]:
    """
    Flag individual user accounts with excessive failed logins.
    """
    anomalies = []
    user_fails: Counter = Counter()
    user_ips: dict[str, Counter] = defaultdict(Counter)

    for evt in events:
        is_fail = evt["event_id"] == "4625" or "failed password" in evt["message"].lower()
        if is_fail and evt.get("user"):
            user_fails[evt["user"]] += 1
            if evt.get("source_ip"):
                user_ips[evt["user"]][evt["source_ip"]] += 1

    for user, count in user_fails.items():
        if count >= 10:
            top_ip = user_ips[user].most_common(1)
            ip = top_ip[0][0] if top_ip else "unknown"
            anomalies.append(Anomaly(
                category="BRUTE_FORCE_USER",
                severity="CRITICAL" if count >= 50 else "HIGH",
                timestamp="",
                user=user,
                source_ip=ip,
                event_id="4625",
                description=f"Account '{user}' had {count} failed logins — possible brute force from {ip}",
                z_score=0.0,
            ))

    return anomalies


# ---------------------------------------------------------------------------
# Sample data generator
# ---------------------------------------------------------------------------

def generate_sample_data(output_path: Path) -> None:
    """Generate realistic sample Windows Event Log CSV for testing."""
    import random

    users = ["alice.johnson", "bob.smith", "carol.white", "svc_backup", "svc_monitoring"]
    ips = ["192.168.1.10", "192.168.1.20", "10.0.0.5", "203.0.113.50", "198.51.100.77"]
    events = []
    headers = ["TimeGenerated", "EventID", "Computer", "User", "SourceIP", "Message"]

    # Normal business hour logins
    for day in range(1, 8):
        for _ in range(random.randint(20, 40)):
            hour = random.randint(8, 17)
            minute = random.randint(0, 59)
            ts = f"2025-01-{day:02d} {hour:02d}:{minute:02d}:00"
            user = random.choice(users[:3])
            ip = random.choice(ips[:3])
            events.append([ts, "4624", "CORP-WS-01", user, ip, "Successful logon"])

    # Off-hours logins (anomalous)
    events.append(["2025-01-03 02:15:00", "4624", "CORP-WS-01", "alice.johnson", "198.51.100.77",
                   "Successful logon from external IP at 2am"])
    events.append(["2025-01-05 03:42:00", "4624", "CORP-WS-01", "bob.smith", "203.0.113.50",
                   "Successful logon"])

    # Failed logins (normal level — 2-4 per hour)
    for day in range(1, 7):
        for hour in range(8, 18):
            for _ in range(random.randint(0, 3)):
                ts = f"2025-01-{day:02d} {hour:02d}:{random.randint(0,59):02d}:00"
                events.append([ts, "4625", "CORP-WS-01", random.choice(users[:3]),
                               random.choice(ips[:3]), "Failed logon - bad password"])

    # Failed login SPIKE (anomalous — 60 failures in 1 hour from external IP)
    for i in range(60):
        ts = f"2025-01-04 14:{i:02d}:00" if i < 60 else f"2025-01-04 14:59:00"
        events.append([ts, "4625", "CORP-WS-01", "carol.white", "203.0.113.50",
                       "Failed logon - invalid credentials"])

    # Suspicious process (mimikatz)
    events.append(["2025-01-06 11:23:00", "4688", "CORP-WS-01", "bob.smith", "192.168.1.20",
                   "Process execution: mimikatz.exe /export"])

    # Suspicious process (vssadmin)
    events.append(["2025-01-06 11:25:00", "4688", "CORP-WS-01", "bob.smith", "192.168.1.20",
                   "Process execution: vssadmin delete shadows /all /quiet"])

    random.shuffle(events)

    with output_path.open("w", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(headers)
        writer.writerows(events)

    logger.info("Sample data written to %s (%d events)", output_path, len(events))


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def print_report(anomalies: list[Anomaly]) -> None:
    if not anomalies:
        print("\n  ✓ No anomalies detected.\n")
        return

    by_severity = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []}
    for a in anomalies:
        by_severity.get(a.severity, by_severity["LOW"]).append(a)

    icons = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}

    print(f"\n{'═'*75}")
    print(f"  LOG ANOMALY DETECTION REPORT  |  {len(anomalies)} anomalies found")
    print(f"{'═'*75}")

    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        for a in by_severity[sev]:
            print(f"\n  {icons[sev]} [{a.severity}] {a.category}")
            print(f"     Time    : {a.timestamp}")
            print(f"     User    : {a.user}")
            print(f"     Source  : {a.source_ip}")
            if a.z_score:
                print(f"     Z-score : {a.z_score:.2f}")
            print(f"     Detail  : {a.description}")

    print(f"\n{'═'*75}\n")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Detect anomalies in auth and process logs using statistical baselines.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--input", type=Path, help="CSV log file")
    parser.add_argument("--type", choices=["windows", "syslog"], default="windows")
    parser.add_argument("--output", type=Path, help="Write JSON anomaly report to file")
    parser.add_argument("--generate-sample", action="store_true", help="Generate sample data")
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if args.generate_sample:
        out = Path("sample_data/auth_logs.csv")
        out.parent.mkdir(exist_ok=True)
        generate_sample_data(out)
        return 0

    if not args.input:
        logger.error("Provide --input or --generate-sample")
        return 1

    if not args.input.exists():
        logger.error("Input file not found: %s", args.input)
        return 1

    if args.type == "windows":
        events = parse_windows_event_log(args.input)
    else:
        events = parse_syslog_csv(args.input)

    logger.info("Loaded %d log events from %s", len(events), args.input)

    anomalies = []
    anomalies += detect_failed_auth_spikes(events)
    anomalies += detect_off_hours_logins(events)
    anomalies += detect_rare_processes(events)
    anomalies += detect_brute_force_accounts(events)

    # De-duplicate
    seen = set()
    unique_anomalies = []
    for a in anomalies:
        key = f"{a.category}:{a.user}:{a.timestamp[:13]}"
        if key not in seen:
            seen.add(key)
            unique_anomalies.append(a)

    print_report(unique_anomalies)

    if args.output:
        report = {
            "source": str(args.input),
            "events_analyzed": len(events),
            "anomalies_found": len(unique_anomalies),
            "anomalies": [a.to_dict() for a in unique_anomalies],
        }
        with args.output.open("w") as fh:
            json.dump(report, fh, indent=2)
        logger.info("Report written to %s", args.output)

    return 0


if __name__ == "__main__":
    sys.exit(main())
