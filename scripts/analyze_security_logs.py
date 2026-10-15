
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
        print("Export Windows Security Logs first.")
        return

    counts = Counter()
    invalid_rows = 0
    total = 0

    try:
        with LOG_FILE.open(
            "r", encoding="utf-8-sig", newline=""
        ) as file:
            reader = csv.DictReader(file)

            if not reader.fieldnames or "Id" not in reader.fieldnames:
                print("ERROR: Required CSV column 'Id' missing.")
                return

            for row in reader:
                try:
                    event_id = int(row["Id"])
                except (ValueError, TypeError, KeyError):
                    invalid_rows += 1
                    continue

                counts[event_id] += 1
                total += 1

    except (OSError, csv.Error) as error:
        print(f"ERROR: Could not read CSV: {error}")
        return

    print("\n===== SOC SECURITY LOG ANALYSIS =====")
    print(f"Total Events Analyzed: {total}")
    print(f"Invalid Rows Skipped: {invalid_rows}")

    print("\n===== EVENT DISTRIBUTION =====")

    for event_id, name in EVENT_NAMES.items():
        print(
            f"{event_id} - {name}: "
            f"{counts[event_id]}"
        )

    print("\n===== INITIAL SECURITY REVIEW =====")

    if counts[4625] >= 5:
        print(
            "[REVIEW] Five or more failed logon "
            "events found in the dataset."
        )
    else:
        print(
            "[INFO] Fewer than five failed logon "
            "events found."
        )

    if counts[4740] > 0:
        print(
            "[REVIEW] Account lockout events detected."
        )

    if counts[1102] > 0:
        print(
            "[REVIEW] Security audit log clearing detected."
        )

    if counts[4672] > 0:
        print(
            "[INFO] Privileged logon events recorded. "
            "Review context before classifying."
        )

    print("\nAnalysis completed.")
    print(
        "Note: Event counts alone do not "
        "confirm malicious activity."
    )


if __name__ == "__main__":
    analyze_logs()
