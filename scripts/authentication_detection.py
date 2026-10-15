import csv
from pathlib import Path
from datetime import datetime, timedelta
from collections import defaultdict

BASE_DIR = Path(__file__).resolve().parent.parent
LOG_FILE = BASE_DIR / "logs" / "synthetic_auth_logs.csv"

FAILED_LOGON = 4625
SUCCESS_LOGON = 4624
ACCOUNT_LOCKOUT = 4740
PRIVILEGED_LOGON = 4672

WINDOW = timedelta(minutes=5)
THRESHOLD = 5

def load_events():
    events = []

    with LOG_FILE.open(encoding="utf-8-sig", newline="") as file:
        reader = csv.DictReader(file)

        for row in reader:
            events.append({
                "time": datetime.strptime(
                    row["TimeCreated"], "%Y-%m-%d %H:%M:%S"
                ),
                "id": int(row["Id"]),
                "user": row["Username"],
                "ip": row["SourceIP"]
            })

    return sorted(events, key=lambda e: e["time"])


def detect_threats(events):
    failures = defaultdict(list)
    threshold_alerted = set()
    alerts = []

    for event in events:
        key = (event["user"], event["ip"])
        event_time = event["time"]
        event_id = event["id"]

        if event_id == FAILED_LOGON:
            failures[key].append(event_time)

            failures[key] = [
                t for t in failures[key]
                if event_time - t <= WINDOW
            ]

            if (
                len(failures[key]) >= THRESHOLD
                and key not in threshold_alerted
            ):
                alerts.append({
                    "rule": "AUTH-001",
                    "severity": "MEDIUM",
                    "description": "Repeated failed logons",
                    "user": event["user"],
                    "ip": event["ip"]
                })
                threshold_alerted.add(key)

        elif event_id == SUCCESS_LOGON:
            recent_failures = [
                t for t in failures[key]
                if timedelta(0) <= event_time - t <= WINDOW
            ]

            if len(recent_failures) >= THRESHOLD:
                alerts.append({
                    "rule": "AUTH-002",
                    "severity": "HIGH",
                    "description": "Successful logon after repeated failures",
                    "user": event["user"],
                    "ip": event["ip"]
                })

            failures[key] = []
            threshold_alerted.discard(key)

        elif event_id == ACCOUNT_LOCKOUT:
            alerts.append({
                "rule": "AUTH-003",
                "severity": "MEDIUM",
                "description": "Account lockout detected",
                "user": event["user"],
                "ip": event["ip"]
            })

        elif event_id == PRIVILEGED_LOGON:
            alerts.append({
                "rule": "AUTH-004",
                "severity": "INFO",
                "description": "Privileged logon event",
                "user": event["user"],
                "ip": event["ip"]
            })

    return alerts


def main():
    if not LOG_FILE.exists():
        print("ERROR: Synthetic log file not found.")
        return

    events = load_events()
    alerts = detect_threats(events)

    print("\n===== SOC AUTHENTICATION DETECTION =====")
    print(f"Events analyzed: {len(events)}")
    print(f"Alerts generated: {len(alerts)}")

    for alert in alerts:
        print(
            f"\n[{alert['severity']}] {alert['rule']}"
            f"\nDescription: {alert['description']}"
            f"\nUser: {alert['user']}"
            f"\nSource IP: {alert['ip']}"
        )

    print("\nDetection completed.")


if __name__ == "__main__":
    main()