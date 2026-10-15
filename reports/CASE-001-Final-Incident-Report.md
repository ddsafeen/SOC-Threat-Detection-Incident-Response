# SOC Incident Investigation Report

## CASE-001 — Suspicious Authentication Activity

**Environment:** Synthetic Windows Security Logs  
**Case ID:** CASE-001  
**Date:** 15 October 2026  
**Analyst Role:** SOC Analyst L1 (Training Lab)  
**Priority:** High (Simulated)  
**Classification:** Suspicious Authentication Activity  
**Status:** Investigation completed for the supplied synthetic dataset

---

## 1. Executive Summary

A Python-based security monitoring system identified multiple failed authentication attempts followed by a successful logon for the same account and source IP.

Nine synthetic Windows security events were analyzed, generating four rule-based alerts.

The investigation identified suspicious authentication patterns requiring further validation. No actual unauthorized access or system compromise was confirmed.

## 2. Evidence Summary

| Event ID | Description | Count |
|---|---|---:|
| 4625 | Failed Logon | 5 |
| 4624 | Successful Logon | 2 |
| 4740 | Account Lockout | 1 |
| 4672 | Special Privileges Assigned | 1 |

**Evidence source:** `logs/synthetic_auth_logs.csv`

## 3. Authentication Timeline

| Time | Event | Account |
|---|---|---|
| 10:00–10:02 | Five failed logons | testuser |
| 10:02:30 | Successful logon | testuser |
| 10:03:00 | Account lockout | testuser |
| 10:04:00 | Privileged logon | admin |

All timestamps represent simulated events on 15 October 2026.

## 4. Detection Rules Triggered

- AUTH-001: Repeated Failed Logons — Medium
- AUTH-002: Successful Logon After Failures — High
- AUTH-003: Account Lockout — Medium
- AUTH-004: Privileged Logon Event — Informational

## 5. MITRE ATT&CK Mapping

**T1110 — Brute Force**

Repeated authentication failures may be consistent with password-guessing activity. The available evidence does not confirm an attack.

**T1078 — Valid Accounts**

A successful authentication following multiple failures warrants investigation for possible account misuse. The available evidence does not establish unauthorized access.

These mappings represent investigative hypotheses rather than confirmed attacker techniques.

## 6. Investigation Findings

1. Five failed logons were recorded for the same account and source IP within two minutes.
2. A successful logon followed thirty seconds later.
3. An account lockout event was recorded afterward. Its relationship to the preceding success requires additional context.
4. A separate privileged logon event was recorded for another account.
5. The dataset does not provide sufficient evidence to confirm malicious intent or compromise.

## 7. Recommended Incident Response

1. Validate the authentication activity with the account owner.
2. Review logon types, source systems, and additional authentication records.
3. Investigate whether the successful authentication was authorized.
4. Examine account lockout context and relevant identity-provider logs.
5. Escalate to SOC L2 if additional evidence supports compromise.
6. Consider approved account-protection measures if unauthorized access is confirmed.

## 8. Final Assessment

**Disposition:** Suspicious authentication pattern detected in a controlled synthetic dataset.

**Compromise status:** Not confirmed.

**Containment performed:** None — simulated investigation.

**Conclusion:** The project demonstrates authentication event correlation, rule-based alert detection, evidence review, and structured incident reporting using Python.

---

*This report documents an educational SOC investigation using fictional accounts and synthetic security events. It does not describe a real-world security incident.*