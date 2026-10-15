# CASE-001 — Authentication Security Investigation

## 1. Case Information

- **Case ID:** CASE-001
- **Investigation Type:** Authentication Security Monitoring
- **Environment:** Synthetic Windows Security Log Dataset
- **Investigation Status:** Initial Analysis
- **Priority:** High (Lab Classification)
- **Date:** 15 October 2026

## 2. Investigation Objective

Investigate suspicious authentication activity identified by the Python-based detection engine.

## 3. Detection Summary

| Rule ID | Description | Severity |
|---|---|---|
| AUTH-001 | Repeated failed logons | Medium |
| AUTH-002 | Successful logon after failures | High |
| AUTH-003 | Account lockout | Medium |
| AUTH-004 | Privileged logon event | Informational |

**Note:** These are expected alerts from the supplied synthetic dataset. Actual detection output must be verified separately.

## 4. Event Timeline

- 10:00:00–10:02:00 — Five failed logon events for testuser.
- 10:02:30 — Successful authentication recorded.
- 10:03:00 — Account lockout event recorded.
- 10:04:00 — Separate privileged logon event for admin.

## 5. Investigation Findings

The dataset contains repeated failed authentication events followed by a successful authentication event for the same account and source IP.

This sequence may indicate suspicious authentication activity, but the available evidence is insufficient to confirm unauthorized access.

The privileged logon event involves a different account and source and is not established as related to the primary authentication sequence.

## 6. Recommended SOC Response

1. Review authentication event timestamps and affected accounts.
2. Correlate source IP addresses and logon types.
3. Verify whether the successful authentication was authorized.
4. Investigate the account lockout context.
5. Escalate to SOC L2 if additional evidence supports account compromise.

## 7. Conclusion

The synthetic dataset demonstrates the detection of suspicious authentication patterns using Python-based correlation rules.

**Final classification:** Simulated suspicious authentication activity — unauthorized access not confirmed.

No real-world security incident or compromise is claimed.