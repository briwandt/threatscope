# ThreatScope Sample Hunt Report

**Case Identifier:** TS-2026-0511-01  
**Target Infrastructure:** Corporate Active Directory, Cloud Identity, Telecom Roaming, Kubernetes Cluster  
**Overall Risk Score:** 14/15  
**Severity:** CRITICAL  

---

## Executive Summary
During a scheduled hunt operation, ThreatScope identified a highly correlated, multi-stage intrusion traversing boundary VPN access, lateral movement, cloud role escalation, and telecom signaling tracking. The adversary successfully established identity persistence using a compromised contractor credential and deployed a cryptomining pod inside the production Kubernetes cluster. 

---

## Timeline of Correlated Events

| Timestamp (UTC) | Telemetry Source | Event Description | Severity |
| :--- | :--- | :--- | :--- |
| 07:41:22 | VPN / SIEM | Successful login for `contractor.mills` from RU IP (`185.220.101.44`) | HIGH |
| 07:44:02 | VPN / SIEM | Successful login for `contractor.mills` from US IP (`104.28.45.12`) | HIGH |
| 07:48:19 | MFA / SIEM | MFA Push Notification approved for `contractor.mills` | MEDIUM |
| 07:56:10 | Router / SIEM | SSH remote management enabled on `cisco-edge-12` by `contractor.mills` | HIGH |
| 08:02:44 | EDR / Host | PowerShell execution with encoded command on `CORP-LT-448` | HIGH |
| 08:04:30 | EDR / Host | WMI process call creating remote processes | HIGH |
| 08:06:55 | CloudIdentity | Azure role assignment: `GlobalAdmin` assigned to `contractor.mills` | CRITICAL |
| 08:21:55 | Telecom | Diameter signaling anomaly: unusual roaming authentication | HIGH |
| 08:25:13 | Telecom | SS7 signaling anomaly: location query volume spike (218 subscribers) | HIGH |
| 08:29:45 | Telecom | GTP roaming session anomaly | HIGH |
| 08:44:19 | CloudIdentity | OAuth consent granted to app `UnknownMailSync` with `Mail.Read` scopes | CRITICAL |

---

## Key Detections Mapped to MITRE ATT&CK

### 1. Initial Access & Persistence
* **T1078 - Valid Accounts**: Logins from geographically anomalous locations (Russia to US) within 3 minutes (impossible travel).
* **T1621 - Multi-Factor Authentication Request Generation**: MFA fatigue bypass via push approval.
* **T1550 - Use Alternate Authentication Material**: OAuth permissions granted to malicious application `UnknownMailSync`.

### 2. Execution & Lateral Movement
* **T1059.001 - PowerShell**: Encoded command shell executed under `winword.exe`.
* **T1047 - Windows Management Instrumentation**: Remote process execution via WMIC.
* **T1021 - Remote Services**: Remote management enabled over SSH.

### 3. Impact & Resource Hijacking
* **T1496 - Resource Hijacking**: Unauthorized XMRig container deployed in production.
* **T1003.006 - OS Credential Dumping**: Mimikatz execution extracting krbtgt secrets on Domain Controller.

---

## Containment & Remediation Guidelines
1. **Revoke Active Sessions**: Terminate all active sessions for `contractor.mills` and `user.alice`.
2. **Disable OAuth App**: Revoke OAuth app permissions for `UnknownMailSync`.
3. **Isolate Compromised Nodes**: Isolate internal host `CORP-LT-448` and container pod `api-cache-manager`.
4. **Telecom Egress Block**: Restrict roaming requests from untrusted foreign peer networks.
