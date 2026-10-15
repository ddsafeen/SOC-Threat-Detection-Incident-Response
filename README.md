# SOC Threat Detection & Incident Response Lab

**Cybersecurity | SOC Analyst L1 | Threat Detection | Log Analysis | Incident Investigation**

## Project Overview

This project demonstrates a lightweight Security Operations Center (SOC) workflow using Python and Windows Security Event Logs.

The lab focuses on security log collection, authentication threat detection, event correlation, alert investigation, and incident reporting.

The solution was developed for a resource-constrained Windows environment without requiring a full SIEM deployment.

## Project Objectives

- Collect and analyze Windows Security Event Logs.
- Develop Python-based authentication detection rules.
- Identify repeated failed login attempts.
- Correlate failed and successful authentication events.
- Investigate suspicious security events.
- Generate structured JSON investigation reports.
- Document findings using SOC incident response practices.

## Technologies Used

| Technology | Purpose |
|---|---|
| Python | Security log analysis and detection |
| Windows Event Viewer | Security event inspection |
| PowerShell | Security log collection |
| CSV | Event data storage |
| JSON | Investigation evidence |
| MITRE ATT&CK | Threat behavior classification |
| GitHub | Project documentation |

## Lab Architecture

```text
Windows Security Event Logs
           |
           v
    PowerShell Export
           |
           v
     Python Analyzer
           |
           v
 Authentication Detection
           |
           v
   Alert Investigation
           |
           v
    JSON Incident Report
```

The authentication detection and investigation components were tested using synthetic Windows-style security events. Genuine Windows logs were used separately for initial event-count analysis.

## Detection Rules

| Rule ID | Detection | Severity |
|---|---|---|
| AUTH-001 | Repeated Failed Logons | Medium |
| AUTH-002 | Successful Logon After Repeated Failures | High |
| AUTH-003 | Account Lockout | Medium |
| AUTH-004 | Privileged Logon Event | Informational |

## Detection Results

**Synthetic dataset testing**

- Total events analyzed: 9
- Detection rules triggered: 4
- Alerts generated: 4

The test dataset includes repeated authentication failures, a subsequent successful logon, an account lockout event, and a separate privileged logon event.

All four expected detection rules triggered successfully during testing.

## Incident Investigation — CASE-001

**Case:** Suspicious Authentication Activity

**Priority:** High (Simulated)

**Environment:** Synthetic Security Logs

### Investigation Findings

Five failed authentication events were recorded for the same fictional account and source IP within two minutes.

A successful authentication event followed thirty seconds later.

An account lockout event and a separate privileged logon event were also recorded.

The sequence warranted investigation, but the available evidence did not confirm unauthorized access or system compromise.

## MITRE ATT&CK Mapping

| Technique | ID | Interpretation |
|---|---|---|
| Brute Force | T1110 | Potential password-guessing pattern |
| Valid Accounts | T1078 | Possible account misuse requiring investigation |

These are investigative hypotheses, not confirmed adversary techniques.

## Repository Structure

```text
SOC-Threat-Detection-Incident-Response/
├── scripts/
│   ├── analyze_security_logs.py
│   ├── authentication_detection.py
│   └── incident_investigation.py
├── logs/
│   └── synthetic_auth_logs.csv
├── reports/
│   ├── CASE-001-investigation.json
│   └── CASE-001-Final-Incident-Report.md
├── .gitignore
└── README.md
```

## How to Run

**Requirements:** Python 3 and the included synthetic dataset.

Run the authentication detection engine:

```bash
py scripts/authentication_detection.py
```

Run the investigation script:

```bash
py scripts/incident_investigation.py
```

The investigation script generates a structured JSON report in the `reports` directory.

The Windows Security Log Analyzer requires a separate local CSV export of Windows Security Events.

## Skills Demonstrated

- Windows Security Event Log Analysis
- Python Security Automation
- Authentication Threat Detection
- Rule-Based Alert Generation
- Security Event Correlation
- SOC Alert Triage
- Incident Investigation
- MITRE ATT&CK Mapping
- Security Incident Documentation

## Project Limitations

This project uses a lightweight Python detection engine rather than a production SIEM.

Authentication detection was validated using a controlled synthetic dataset. The results do not represent a confirmed real-world attack.

Further improvements could include time-window tuning, structured alert exports, additional log sources, and SIEM integration.

## Disclaimer

This project was developed for educational and authorized cybersecurity training. Synthetic events are clearly distinguished from genuine Windows Security Logs. No real-world compromise is claimed.
