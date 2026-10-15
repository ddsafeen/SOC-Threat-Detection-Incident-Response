
import csv
from collections import Counter
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
LOG_FILE = BASE_DIR / "logs" / "security_events.csv"

EVENT_NAMES = {
    4624: "Successful Logon",
    4625: "Failed Logon",
    4634: "Logoff",
    4672: "Special Privileges Assigned",
    4720: "User Account Created",
    4726: "User Account Deleted",
    4740: "Account Locked Out",
    1102: "Security Audit Log Cleared"
}

def analyze_logs():
    if not LOG_FILE.exists():
        print("ERROR: Security log CSV not found.")
        return

    counts = Counter()
    total = 0

    with LOG_FILE.open("r", encoding="utf-8-sig", newline="") as file:
        reader = csv.DictReader(file)

        for row in reader:
            try:
                event_id = int(row["Id"])
            except (ValueError, TypeError, KeyError):
                continue

            counts[event_id] += 1
            total += 1

    print("\n===== SOC SECURITY LOG ANALYSIS =====")
    print(f"Total Events Analyzed: {total}")

    for event_id, name in EVENT_NAMES.items():
        print(f"{event_id} - {name}: {counts[event_id]}")

    print("\n===== INITIAL ALERT REVIEW =====")

    if counts[4625] >= 5:
        print("[REVIEW] Multiple failed logon events found.")
    else:
        print("[INFO] Fewer than five failed logon events.")

    if counts[4740] > 0:
        print("[REVIEW] Account lockout events found.")

    if counts[1102] > 0:
        print("[REVIEW] Security audit log clearing detected.")

    print("\nAnalysis completed.")

if __name__ == "__main__":
    analyze_logs()
