# SOC Threat Detection & Incident Response Lab

**Cybersecurity | SOC Analyst L1 | Threat Detection | Windows Event Log Analysis | Incident Investigation**

## Project Overview

This project demonstrates a lightweight Security Operations Center (SOC) workflow using Python, PowerShell, and Windows Security Event Logs.

It includes Windows security log analysis, rule-based authentication threat detection, event correlation, alert investigation, and structured incident reporting.

The lab was designed for a resource-constrained Windows environment without deploying a full Security Information and Event Management (SIEM) platform.

The project uses two distinct data sources:

- **Genuine Windows Security Logs:** Used for local event-count analysis.
- **Synthetic Authentication Logs:** Used to test detection rules and investigate simulated suspicious authentication activity.

## Project Objectives

- Collect Windows Security Events using PowerShell.
- Analyze security event distributions using Python.
- Develop rule-based authentication detection logic.
- Detect repeated failed logons within a five-minute window.
- Correlate successful logons with preceding failures.
- Identify account lockout and privileged logon events.
- Generate investigation timelines and structured JSON reports.
- Document findings using SOC investigation practices.

## Technologies Used

| Technology | Purpose |
|---|---|
| Python | Log parsing, detection, correlation, reporting |
| Windows Event Viewer | Inspect Windows Security Events |
| PowerShell | Export local Windows Security Logs |
| CSV | Store event datasets |
| JSON | Store structured investigation findings |
| MITRE ATT&CK | Map potential threat behaviors |
| GitHub | Version control and project documentation |

## Lab Architecture

**Workflow 1 — Windows Security Log Analysis**

```text
Windows Security Event Logs
            |
            v
      PowerShell Export
            |
            v
  Local security_events.csv
            |
            v
  analyze_security_logs.py
            |
            v
 Event Counts & Initial Review
```

**Workflow 2 — Synthetic Authentication Detection**

```text
   synthetic_auth_logs.csv
             |
             v
 authentication_detection.py
             |
             v
    Rule-Based Alerts
             |
             v
  incident_investigation.py
             |
             v
 Event Timeline & Findings
             |
             v
 CASE-001-investigation.json
```

The workflows are separate. The authentication detection engine was validated using synthetic events rather than genuine Windows authentication incidents.

## Detection Rules

| Rule ID | Detection Logic | Severity |
|---|---|---|
| AUTH-001 | Five or more failed logons for the same account and source IP within five minutes | Medium |
| AUTH-002 | Successful logon following at least five recent failures for the same account and source IP | High |
| AUTH-003 | Account lockout event (4740) | Medium |
| AUTH-004 | Special privileges assigned event (4672) | Informational |

These are educational detection rules. An alert indicates activity requiring review, not necessarily malicious behavior.

## Detection Results

**Dataset:** Synthetic Windows-style authentication events

| Metric | Result |
|---|---|
| Events analyzed | 9 |
| Detection rules triggered | 4 |
| Alerts generated | 4 |
| Failed logons in test sequence | 5 |
| Detection window | 5 minutes |

All four expected detection rules triggered during the controlled test.

## Windows Security Log Analysis

A separate local Windows Security Log export was analyzed using `analyze_security_logs.py`.

The initial sample contained 500 events, including:

- 228 successful logon events (4624)
- 58 logoff events (4634)
- 214 special privileges assigned events (4672)

These counts describe the sampled events only. They do not establish suspicious activity or represent a complete security assessment.

The genuine Windows Security Log CSV is excluded from the public repository to avoid exposing local security information.

## Incident Investigation — CASE-001

**Case:** Suspicious Authentication Activity

**Priority:** High (Simulated)

**Environment:** Synthetic Authentication
