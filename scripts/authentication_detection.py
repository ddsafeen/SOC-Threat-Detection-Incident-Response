
import csv
from pathlib import Path
from datetime import datetime, timedelta
from collections import defaultdict, deque

BASE_DIR = Path(__file__).resolve().parent.parent
LOG_FILE = BASE_DIR / "logs" / "synthetic_auth_logs.csv"

WINDOW = timedelta(minutes=5)
THRESHOLD = 5

EVENT_NAMES = {
    4624: "Successful Logon",
    4625: "Failed Logon",
    4740: "Account Lockout",
    4672: "Privileged Logon"
}


def load_events():
    events = []

    with LOG_FILE.open(
        encoding="utf-8-sig", newline=""
    ) as file:
        reader = csv.DictReader(file)

        for line_number, row in enumerate(reader, start=2):
            try:
                event = {
                    "time": datetime.strptime(
                        row["TimeCreated"],
                        "%Y-%m-%d %H:%M:%S"
                    ),
                    "id": int(row["Id"]),
                    "user": row["Username"].strip(),
                    "ip": row["SourceIP"].strip()
                }

                if not event["user"] or not event["ip"]:
                    raise ValueError("Missing user or IP")

                events.append(event)

            except (ValueError, KeyError, TypeError) as error:
                print(
                    f"[WARNING] Skipping row "
                    f"{line_number}: {error}"
                )

    return sorted(events, key=lambda e: e["time"])


def detect_threats(events):
    failures = defaultdict(deque)
    active_alerts = set()
    alerts = []

    def add_alert(rule, severity, description, event):
        alerts.append({
            "rule": rule,
            "severity": severity,
            "description": description,
            "time": event["time"].isoformat(),
            "user": event["user"],
            "ip": event["ip"]
        })

    for event in events:
        key = (event["user"], event["ip"])
        event_time = event["time"]
        event_id = event["id"]

        recent = failures[key]

        while recent and event_time - recent[0] > WINDOW:
            recent.popleft()

        if len(recent) < THRESHOLD:
            active_alerts.discard(key)

        if event_id == 4625:
            recent.append(event_time)

            if (
                len(recent) >= THRESHOLD
                and key not in active_alerts
            ):
                add_alert(
                    "AUTH-001",
                    "MEDIUM",
                    "Repeated failed logons",
                    event
                )
                active_alerts.add(key)

        elif event_id == 4624:
            if len(recent) >= THRESHOLD:
                add_alert(
                    "AUTH-002",
                    "HIGH",
                    "Successful logon after failures",
                    event
                )

            recent.clear()
            active_alerts.discard(key)

        elif event_id == 4740:
            add_alert(
                "AUTH-003",
                "MEDIUM",
                "Account lockout detected",
                event
            )

        elif event_id == 4672:
            add_alert(
                "AUTH-004",
                "INFO",
                "Privileged logon event",
                event
            )

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
            f"\nTime: {alert['time']}"
            f"\nDescription: {alert['description']}"
            f"\nUser: {alert['user']}"
            f"\nSource IP: {alert['ip']}"
        )

    print("\nDetection completed.")


if __name__ == "__main__":
    main()
