
import csv
import json
from pathlib import Path
from datetime import datetime
from collections import Counter

BASE_DIR = Path(__file__).resolve().parent.parent
LOG_FILE = BASE_DIR / "logs" / "synthetic_auth_logs.csv"
REPORT_DIR = BASE_DIR / "reports"
REPORT_FILE = REPORT_DIR / "CASE-001-investigation.json"

EVENT_TYPES = {
    4624: "Successful Logon",
    4625: "Failed Logon",
    4672: "Privileged Logon",
    4740: "Account Lockout"
}

def load_events():
    events = []

    with LOG_FILE.open(
        "r", encoding="utf-8-sig", newline=""
    ) as file:
        reader = csv.DictReader(file)

        for row in reader:
            events.append({
                "timestamp": row["TimeCreated"],
                "event_id": int(row["Id"]),
                "username": row["Username"],
                "source_ip": row["SourceIP"]
            })

    return sorted(
        events,
        key=lambda event: datetime.strptime(
            event["timestamp"], "%Y-%m-%d %H:%M:%S"
        )
    )


def investigate(events):
    counts = Counter(
        event["event_id"] for event in events
    )

    timeline = []

    for event in events:
        timeline.append({
            "time": event["timestamp"],
            "event": EVENT_TYPES.get(
                event["event_id"], "Unknown Event"
            ),
            "event_id": event["event_id"],
            "username": event["username"],
            "source_ip": event["source_ip"]
        })

    findings = []

    if counts[4625] >= 5:
        findings.append(
            "Five or more failed logon events observed."
        )

    if counts[4624] > 0 and counts[4625] > 0:
        findings.append(
            "Both successful and failed logons observed; "
            "review event order and account correlation."
        )

    if counts[4740] > 0:
        findings.append(
            "Account lockout event observed."
        )

    if counts[4672] > 0:
        findings.append(
            "Privileged logon event observed."
        )

    return {
        "case_id": "CASE-001",
        "dataset_type": "Synthetic",
        "status": "Investigation in progress",
        "total_events": len(events),
        "event_counts": {
            str(key): value
            for key, value in sorted(counts.items())
        },
        "timeline": timeline,
        "findings": findings,
        "conclusion": (
            "Suspicious authentication patterns observed "
            "in synthetic data. Unauthorized access "
            "has not been confirmed."
        )
    }


def main():
    if not LOG_FILE.exists():
        print("ERROR: Synthetic dataset not found.")
        return

    REPORT_DIR.mkdir(exist_ok=True)

    events = load_events()
    report = investigate(events)

    with REPORT_FILE.open(
        "w", encoding="utf-8"
    ) as file:
        json.dump(report, file, indent=4)

    print("\n===== SOC INCIDENT INVESTIGATION =====")
    print("Case ID:", report["case_id"])
    print("Dataset:", report["dataset_type"])
    print("Events analyzed:", report["total_events"])

    print("\n===== EVENT TIMELINE =====")

    for event in report["timeline"]:
        print(
            f"{event['time']} | "
            f"{event['event_id']} | "
            f"{event['username']} | "
            f"{event['source_ip']}"
        )

    print("\n===== INVESTIGATION FINDINGS =====")

    for finding in report["findings"]:
        print("-", finding)

    print("\nReport saved to:")
    print(REPORT_FILE)


if __name__ == "__main__":
    main()
