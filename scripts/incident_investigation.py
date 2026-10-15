
import json
from pathlib import Path
from collections import Counter

from authentication_detection import (
    load_events,
    detect_threats
)

BASE_DIR = Path(__file__).resolve().parent.parent
REPORT_DIR = BASE_DIR / "reports"
REPORT_FILE = REPORT_DIR / "CASE-001-investigation.json"

EVENT_TYPES = {
    4624: "Successful Logon",
    4625: "Failed Logon",
    4672: "Special Privileges Assigned",
    4740: "Account Lockout"
}


def investigate(events, alerts):
    counts = Counter(e["id"] for e in events)

    timeline = [
        {
            "timestamp": e["time"].isoformat(),
            "event_id": e["id"],
            "event_type": EVENT_TYPES.get(
                e["id"], "Unknown Event"
            ),
            "username": e["user"],
            "source_ip": e["ip"]
        }
        for e in events
    ]

    findings = []

    for alert in alerts:
        findings.append({
            "rule_id": alert["rule"],
            "severity": alert["severity"],
            "timestamp": alert["time"],
            "username": alert["user"],
            "source_ip": alert["ip"],
            "description": alert["description"]
        })

    return {
        "case_id": "CASE-001",
        "dataset_type": "Synthetic",
        "status": "Simulated investigation completed",
        "total_events": len(events),
        "total_alerts": len(alerts),
        "event_counts": {
            str(k): v for k, v in sorted(counts.items())
        },
        "timeline": timeline,
        "findings": findings,
        "assessment": (
            "Authentication patterns requiring review "
            "were detected in synthetic data. "
            "Unauthorized access is not confirmed."
        ),
        "containment_performed": False
    }


def main():
    try:
        events = load_events()
        alerts = detect_threats(events)

        report = investigate(events, alerts)

        REPORT_DIR.mkdir(
            parents=True, exist_ok=True
        )

        with REPORT_FILE.open(
            "w", encoding="utf-8"
        ) as file:
            json.dump(report, file, indent=4)

        print("\n===== SOC INCIDENT INVESTIGATION =====")
        print("Case ID:", report["case_id"])
        print("Events analyzed:", report["total_events"])
        print("Alerts generated:", report["total_alerts"])

        print("\n===== DETECTION FINDINGS =====")

        for finding in report["findings"]:
            print(
                f"\n[{finding['severity']}] "
                f"{finding['rule_id']}"
                f"\nTime: {finding['timestamp']}"
                f"\nUser: {finding['username']}"
                f"\nSource: {finding['source_ip']}"
                f"\nFinding: {finding['description']}"
            )

        print("\n===== EVENT TIMELINE =====")

        for event in report["timeline"]:
            print(
                f"{event['timestamp']} | "
                f"{event['event_id']} | "
                f"{event['username']} | "
                f"{event['source_ip']}"
            )

        print("\nReport saved:", REPORT_FILE)

    except (OSError, ValueError, KeyError) as error:
        print(f"ERROR: Investigation failed: {error}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
