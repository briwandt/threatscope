# engine/detections.py

def run_detections(events, raw_text=""):
    """
    Runs threat detections on a list of parsed events (dicts) or raw text fallback.
    """
    detections = []

    # 1. Suspicious Foreign VPN Access
    has_vpn_ru = False
    for ev in events:
        is_vpn = ev.get("event") == "vpn_login" or ev.get("category") == "vpn_iab"
        country = str(ev.get("country", "")).upper()
        if (is_vpn and country == "RU") or (ev.get("event") == "vpn_login" and "RU" in str(ev)):
            has_vpn_ru = True
            break
    if not has_vpn_ru and raw_text:
        if "vpn_login" in raw_text and ("country=RU" in raw_text or 'country": "RU' in raw_text):
            has_vpn_ru = True

    if has_vpn_ru:
        detections.append({
            "title": "Suspicious Foreign VPN Access",
            "severity": "HIGH",
            "confidence": "MEDIUM",
            "mitre": "T1078 - Valid Accounts",
            "description": "User authenticated from a foreign source location associated with elevated access risk.",
            "hunt_pivot": "Review VPN logins, failed authentication attempts, device fingerprints, and source ASN activity."
        })

    # 2. MFA Push Approved
    has_mfa = False
    for ev in events:
        is_mfa = ev.get("event") == "mfa_push" or ev.get("category") == "vpn_iab"
        result = str(ev.get("result", "")).lower()
        if ev.get("event") == "mfa_push" and (result == "approved" or "approved" in str(ev)):
            has_mfa = True
            break
    if not has_mfa and raw_text:
        if "mfa_push" in raw_text and "approved" in raw_text:
            has_mfa = True

    if has_mfa:
        detections.append({
            "title": "MFA Approval Following Suspicious Login",
            "severity": "HIGH",
            "confidence": "MEDIUM",
            "mitre": "T1621 - Multi-Factor Authentication Request Generation",
            "description": "MFA approval observed following suspicious authentication activity.",
            "hunt_pivot": "Investigate MFA fatigue, repeated push attempts, and anomalous device registrations."
        })

    # 3. PowerShell Execution
    has_powershell = False
    for ev in events:
        proc = str(ev.get("process", "")).lower()
        cmd = str(ev.get("command", "")).lower()
        if "powershell.exe" in proc or "powershell.exe" in cmd:
            has_powershell = True
            break
    if not has_powershell and raw_text:
        if "powershell.exe" in raw_text.lower():
            has_powershell = True

    if has_powershell:
        detections.append({
            "title": "PowerShell Execution",
            "severity": "HIGH",
            "confidence": "HIGH",
            "mitre": "T1059.001 - PowerShell",
            "description": "Potential living-off-the-land PowerShell execution detected.",
            "hunt_pivot": "Review encoded commands, parent processes, network activity, and process lineage."
        })

    # 4. WMI Lateral Movement Activity
    has_wmic = False
    for ev in events:
        proc = str(ev.get("process", "")).lower()
        cmd = str(ev.get("command", "")).lower()
        if "wmic.exe" in proc or "wmic.exe" in cmd:
            has_wmic = True
            break
    if not has_wmic and raw_text:
        if "wmic.exe" in raw_text.lower():
            has_wmic = True

    if has_wmic:
        detections.append({
            "title": "WMI Lateral Movement Activity",
            "severity": "HIGH",
            "confidence": "HIGH",
            "mitre": "T1047 - Windows Management Instrumentation",
            "description": "WMI execution may indicate lateral movement or remote execution activity.",
            "hunt_pivot": "Identify source hosts, created processes, authentication events, and target systems."
        })

    # 5. Privileged Cloud Role Assignment
    has_role = False
    for ev in events:
        role = str(ev.get("role", "")).lower()
        event_name = str(ev.get("event", "")).lower()
        if "globaladmin" in role or event_name == "azure_role_assignment":
            has_role = True
            break
    if not has_role and raw_text:
        if "GlobalAdmin" in raw_text:
            has_role = True

    if has_role:
        detections.append({
            "title": "Privileged Cloud Role Assignment",
            "severity": "CRITICAL",
            "confidence": "HIGH",
            "mitre": "T1098 - Account Manipulation",
            "description": "Privileged administrative role assignment detected in cloud identity infrastructure.",
            "hunt_pivot": "Review role assignment history, conditional access changes, and recent authentication patterns."
        })

    # 6. OAuth Persistence Activity
    has_oauth = False
    for ev in events:
        if "oauth" in str(ev).lower() or "oauth_app_consent" in ev or "permissions" in ev:
            has_oauth = True
            break
    if not has_oauth and raw_text:
        if "oauth" in raw_text.lower():
            has_oauth = True

    if has_oauth:
        detections.append({
            "title": "OAuth Persistence Activity",
            "severity": "CRITICAL",
            "confidence": "MEDIUM",
            "mitre": "T1550 - Use Alternate Authentication Material",
            "description": "Suspicious OAuth consent activity may indicate mailbox persistence or token abuse.",
            "hunt_pivot": "Investigate OAuth grants, application permissions, consent actor, and mailbox access patterns."
        })

    # 7. SS7 Signaling Anomaly
    has_ss7 = False
    for ev in events:
        proto = str(ev.get("protocol", "")).lower()
        if "ss7" in proto or "ss7" in str(ev).lower():
            has_ss7 = True
            break
    if not has_ss7 and raw_text:
        if "SS7" in raw_text:
            has_ss7 = True

    if has_ss7:
        detections.append({
            "title": "SS7 Signaling Anomaly",
            "severity": "HIGH",
            "confidence": "MEDIUM",
            "mitre": "T1430 - Location Tracking",
            "description": "Abnormal SS7 signaling activity may indicate subscriber tracking or telecom interception.",
            "hunt_pivot": "Review signaling origin networks, request volume spikes, and subscriber targeting behavior."
        })

    # 8. Diameter Signaling Abuse
    has_diameter = False
    for ev in events:
        proto = str(ev.get("protocol", "")).lower()
        if "diameter" in proto or "diameter" in str(ev).lower():
            has_diameter = True
            break
    if not has_diameter and raw_text:
        if "Diameter" in raw_text:
            has_diameter = True

    if has_diameter:
        detections.append({
            "title": "Diameter Signaling Abuse",
            "severity": "HIGH",
            "confidence": "MEDIUM",
            "mitre": "T1430 - Location Tracking",
            "description": "Unexpected Diameter roaming or authentication behavior detected.",
            "hunt_pivot": "Review roaming authentication requests, peer networks, and failed authentication anomalies."
        })

    # 9. GTP Roaming Session Anomaly
    has_gtp = False
    for ev in events:
        proto = str(ev.get("protocol", "")).lower()
        if "gtp" in proto or "gtp" in str(ev).lower():
            has_gtp = True
            break
    if not has_gtp and raw_text:
        if "GTP" in raw_text:
            has_gtp = True

    if has_gtp:
        detections.append({
            "title": "GTP Roaming Session Anomaly",
            "severity": "HIGH",
            "confidence": "MEDIUM",
            "mitre": "T1430 - Location Tracking",
            "description": "Abnormal roaming session activity identified within telecom infrastructure telemetry.",
            "hunt_pivot": "Analyze GTP tunnel activity, roaming partners, subscriber sessions, and session duration anomalies."
        })

    # 10. Contractor Verification Risk
    has_contractor = False
    for ev in events:
        status = str(ev.get("verification_status", "")).lower()
        resume = str(ev.get("resume_signal", "")).lower()
        if "unverified" in status or "overlapping" in resume or "contractor_risk" in str(ev).lower():
            has_contractor = True
            break
    if not has_contractor and raw_text:
        if "unverified" in raw_text:
            has_contractor = True

    if has_contractor:
        detections.append({
            "title": "Contractor Verification Risk",
            "severity": "MEDIUM",
            "confidence": "LOW",
            "mitre": "T1078 - Valid Accounts",
            "description": "Unverified contractor onboarding activity detected with elevated access requests.",
            "hunt_pivot": "Review onboarding records, access requests, VPN approvals, and privileged entitlement assignments."
        })

    # 11. SSH Remote Management Enabled
    has_ssh = False
    for ev in events:
        proto = str(ev.get("protocol", "")).lower()
        event_name = str(ev.get("event", "")).lower()
        if "ssh" in proto or "ssh" in str(ev).lower() or event_name == "remote_mgmt_enabled":
            has_ssh = True
            break
    if not has_ssh and raw_text:
        if "protocol=ssh" in raw_text or 'protocol": "ssh' in raw_text:
            has_ssh = True

    if has_ssh:
        detections.append({
            "title": "SSH Remote Management Enabled",
            "severity": "MEDIUM",
            "confidence": "MEDIUM",
            "mitre": "T1021 - Remote Services",
            "description": "SSH remote management enabled on edge infrastructure.",
            "hunt_pivot": "Review infrastructure changes, maintenance windows, actor identity, and originating IP addresses."
        })

    # 12. SIM Swap / HLR sim_update
    has_sim_swap = False
    for ev in events:
        event_name = str(ev.get("event", "")).lower()
        if event_name == "sim_update" or "sim_update" in str(ev).lower():
            has_sim_swap = True
            break
    if not has_sim_swap and raw_text:
        if "sim_update" in raw_text.lower():
            has_sim_swap = True

    if has_sim_swap:
        detections.append({
            "title": "SIM Swap / IMSI Modification",
            "severity": "HIGH",
            "confidence": "HIGH",
            "mitre": "T1098.006 - Account Manipulation: Additional Email Addresses",
            "description": "HLR database indicates a SIM card update (IMSI change) for a subscriber profile.",
            "hunt_pivot": "Verify update legitimacy with subscriber, check customer service logs, and inspect corresponding SMS OTP requests."
        })

    # 13. Cloud Audit Trail Modification
    has_trail_mod = False
    for ev in events:
        event_name = str(ev.get("event", "")).lower()
        if event_name == "updatetrail" or "stopped" in str(ev).lower() and "trail" in str(ev).lower():
            has_trail_mod = True
            break
    if not has_trail_mod and raw_text:
        if "updatetrail" in raw_text.lower() and "stopped" in raw_text.lower():
            has_trail_mod = True

    if has_trail_mod:
        detections.append({
            "title": "Cloud Audit Trail Modification",
            "severity": "CRITICAL",
            "confidence": "HIGH",
            "mitre": "T1562.001 - Impede Detection: Disable or Modify Tools",
            "description": "Cloud logging trail stopped or modified, impeding detection mechanisms.",
            "hunt_pivot": "Review CloudTrail trail status changes, caller credentials, and originating IP addresses."
        })

    # 14. Inhibit System Recovery (vssadmin / delete shadows)
    has_recovery_inhibit = False
    for ev in events:
        cmd = str(ev.get("command", "")).lower()
        proc = str(ev.get("process", "")).lower()
        if "vssadmin" in proc or "delete shadows" in cmd:
            has_recovery_inhibit = True
            break
    if not has_recovery_inhibit and raw_text:
        if "vssadmin" in raw_text.lower() or "delete shadows" in raw_text.lower():
            has_recovery_inhibit = True

    if has_recovery_inhibit:
        detections.append({
            "title": "Volume Shadow Copy Deletion",
            "severity": "CRITICAL",
            "confidence": "HIGH",
            "mitre": "T1490 - Inhibit System Recovery",
            "description": "Deletion of volume shadow copies detected, consistent with ransomware preparation.",
            "hunt_pivot": "Inspect the host immediately, isolate the machine, check for file system changes and encryption activity."
        })

    # 15. Windows Event Log Cleared
    has_event_clear = False
    for ev in events:
        cmd = str(ev.get("command", "")).lower()
        proc = str(ev.get("process", "")).lower()
        if "wevtutil" in proc or "cl security" in cmd or "wevtutil" in cmd:
            has_event_clear = True
            break
    if not has_event_clear and raw_text:
        if "wevtutil" in raw_text.lower() or "cl security" in raw_text.lower():
            has_event_clear = True

    if has_event_clear:
        detections.append({
            "title": "Windows Event Log Cleared",
            "severity": "CRITICAL",
            "confidence": "HIGH",
            "mitre": "T1562.002 - Impede Detection: Clear Windows Event Logs",
            "description": "Windows event logging utility (wevtutil) used to clear the Security log, consistent with anti-forensic activity.",
            "hunt_pivot": "Isolate the host immediately, inspect endpoint EDR alerts, and check AD domain controller logs for user session activity."
        })

    # 16. Suspicious CI/CD Build Behavior (Supply Chain)
    has_supply_chain = False
    for ev in events:
        dep = str(ev.get("dependency", "")).lower()
        runner = str(ev.get("runner", "")).lower()
        cmd = str(ev.get("command", "")).lower()
        if "colors-validator" in dep or "jenkins-worker" in runner or "postinstall" in str(ev).lower():
            has_supply_chain = True
            break
    if not has_supply_chain and raw_text:
        if "colors-validator" in raw_text.lower() or "jenkins-worker" in raw_text.lower() or "postinstall" in raw_text.lower():
            has_supply_chain = True

    if has_supply_chain:
        detections.append({
            "title": "Suspicious CI/CD Build Behavior",
            "severity": "HIGH",
            "confidence": "MEDIUM",
            "mitre": "T1195.002 - Supply Chain Compromise: Compromise Software Dependencies",
            "description": "Outbound network connection or deployment key creation detected from a Jenkins worker runner during post-install scripting.",
            "hunt_pivot": "Inspect the repository commit history, audit Jenkins build configs, and revoke the generated API keys."
        })

    # 17. Encrypted Archive Creation
    has_archive = False
    for ev in events:
        cmd = str(ev.get("command", "")).lower()
        proc = str(ev.get("process", "")).lower()
        if "7z" in proc or "7z" in cmd or "backup.7z" in cmd:
            has_archive = True
            break
    if not has_archive and raw_text:
        if "7z" in raw_text.lower() or "backup.7z" in raw_text.lower():
            has_archive = True

    if has_archive:
        detections.append({
            "title": "Encrypted Archive Creation",
            "severity": "HIGH",
            "confidence": "MEDIUM",
            "mitre": "T1560 - Archive Collected Data",
            "description": "Archive utility (7z.exe) utilized to compress collected corporate directories with password protection.",
            "hunt_pivot": "Review network share access logs, identify volume of files read, and inspect outbound data exfiltration indicators."
        })

    # 18. Kubernetes Cryptomining Pod
    has_k8s_mining = False
    for ev in events:
        cmd = str(ev.get("command", "")).lower()
        proc = str(ev.get("process", "")).lower()
        image = str(ev.get("image", "")).lower()
        if "xmrig" in proc or "xmrig" in cmd or "xmrig" in image or "supportxmr" in cmd:
            has_k8s_mining = True
            break
    if not has_k8s_mining and raw_text:
        if "xmrig" in raw_text.lower() or "supportxmr" in raw_text.lower():
            has_k8s_mining = True

    if has_k8s_mining:
        detections.append({
            "title": "Kubernetes Crypto-Mining Activity",
            "severity": "HIGH",
            "confidence": "HIGH",
            "mitre": "T1496 - Resource Hijacking",
            "description": "Cryptomining binary (XMRig) or mining pool connections detected inside a Kubernetes pod.",
            "hunt_pivot": "Inspect pod configurations, identify initial access vectors, review pod namespace permissions, and check network egress rules."
        })

    # 19. Kubernetes Cluster-Admin RoleBinding
    has_k8s_admin = False
    for ev in events:
        role = str(ev.get("role", "")).lower()
        event_name = str(ev.get("event", "")).lower()
        if "cluster-admin" in role or event_name == "createrolebinding" or "cluster-admin" in str(ev).lower():
            has_k8s_admin = True
            break
    if not has_k8s_admin and raw_text:
        if "cluster-admin" in raw_text.lower() or "createrolebinding" in raw_text.lower():
            has_k8s_admin = True

    if has_k8s_admin:
        detections.append({
            "title": "Kubernetes High-Privilege RoleBinding",
            "severity": "CRITICAL",
            "confidence": "HIGH",
            "mitre": "T1098 - Account Manipulation",
            "description": "A new ClusterRoleBinding assigning 'cluster-admin' permissions was created, potentially indicating persistent cluster compromise.",
            "hunt_pivot": "Review Kubernetes audit logs, verify the actor creating the binding, and inspect permissions of the targeted service account."
        })

    # 20. Credential Dumping via DCSync
    has_dcsync = False
    for ev in events:
        cmd = str(ev.get("command", "")).lower()
        proc = str(ev.get("process", "")).lower()
        if "dcsync" in cmd or "mimikatz" in proc or "mimikatz" in cmd:
            has_dcsync = True
            break
    if not has_dcsync and raw_text:
        if "dcsync" in raw_text.lower() or "mimikatz" in raw_text.lower():
            has_dcsync = True

    if has_dcsync:
        detections.append({
            "title": "Active Directory DCSync Attack",
            "severity": "CRITICAL",
            "confidence": "HIGH",
            "mitre": "T1003.006 - OS Credential Dumping: DCSync",
            "description": "Adversary simulated Active Directory replication (DCSync) to retrieve credential hashes (including krbtgt).",
            "hunt_pivot": "Immediately isolate the originating host, inspect security event logs for Event ID 4662 (Write SPN), and reset krbtgt keys."
        })

    # 21. Golden Ticket / Extended Kerberos Ticket Lifetime
    has_golden_ticket = False
    for ev in events:
        lifetime = str(ev.get("ticket_lifetime", ""))
        if lifetime == "99999" or "99999" in str(ev):
            has_golden_ticket = True
            break
    if not has_golden_ticket and raw_text:
        if "ticket_lifetime=99999" in raw_text or "99999" in raw_text:
            has_golden_ticket = True

    if has_golden_ticket:
        detections.append({
            "title": "Anomalous Kerberos Ticket Lifetime",
            "severity": "CRITICAL",
            "confidence": "HIGH",
            "mitre": "T1558.001 - Use Alternate Authentication Material: Golden Ticket",
            "description": "A Kerberos TGT request was observed with an exceptionally long lifetime (99999 minutes), consistent with Golden Ticket persistence.",
            "hunt_pivot": "Review Kerberos ticket requests (Event ID 4768), verify Domain Controller integrity, and perform AD forest recovery steps if verified."
        })

    # 22. Kerberoasting / Service Ticket Request
    has_kerberoast = False
    for ev in events:
        event_name = str(ev.get("event", "")).lower()
        enc_type = str(ev.get("ticket_encryption", "")).lower()
        if event_name == "tgs_request" and enc_type == "rc4":
            has_kerberoast = True
            break
    if not has_kerberoast and raw_text:
        if "tgs_request" in raw_text.lower() and "rc4" in raw_text.lower():
            has_kerberoast = True

    if has_kerberoast:
        detections.append({
            "title": "Kerberoasting Service Ticket Request",
            "severity": "HIGH",
            "confidence": "MEDIUM",
            "mitre": "T1558.003 - Steal or Modify Kerberos Tickets: Kerberoasting",
            "description": "A TGS request requesting RC4 ticket encryption was detected, likely indicating offline credential cracking preparation.",
            "hunt_pivot": "Correlate TGS requests (Event ID 4769) for weak encryption algorithms with anomalous source IPs and service accounts."
        })

    # 23. Anomalous Database Query Volume
    has_large_query = False
    for ev in events:
        records = ev.get("records_returned")
        if records is not None:
            try:
                if int(records) >= 1000000:
                    has_large_query = True
                    break
            except:
                pass
        query = str(ev.get("query", "")).lower()
        if "select *" in query and "pii" in query:
            has_large_query = True
            break
    if not has_large_query and raw_text:
        if "records_returned=" in raw_text:
            for word in raw_text.split():
                if "records_returned=" in word:
                    try:
                        val = int(word.split("=")[1])
                        if val >= 1000000:
                            has_large_query = True
                    except:
                        pass
        if "select *" in raw_text.lower() and "pii" in raw_text.lower():
            has_large_query = True

    if has_large_query:
        detections.append({
            "title": "Anomalous Database Query Volume",
            "severity": "HIGH",
            "confidence": "HIGH",
            "mitre": "T1114 - Data Staged",
            "description": "An exceptionally large database query was executed returning millions of records, indicating potential data staging.",
            "hunt_pivot": "Analyze database audit logs, trace API token lineage, examine client IP history, and check for outbound exfiltration tools."
        })

    # 24. Outbound Exfiltration to Cloud Storage / Mega
    has_mega_exfil = False
    for ev in events:
        cmd = str(ev.get("command", "")).lower()
        if "mega.nz" in cmd or "mega.nz" in str(ev).lower():
            has_mega_exfil = True
            break
    if not has_mega_exfil and raw_text:
        if "mega.nz" in raw_text.lower():
            has_mega_exfil = True

    if has_mega_exfil:
        detections.append({
            "title": "Exfiltration to Cloud Storage: Mega",
            "severity": "CRITICAL",
            "confidence": "HIGH",
            "mitre": "T1567.002 - Exfiltration Over Web Service: Exfiltration to Cloud Storage",
            "description": "Outbound exfiltration activity using curl or web uploads to the public mega.nz sharing platform.",
            "hunt_pivot": "Identify host outbound network sessions, analyze file read operations prior to connection, and block mega.nz destination."
        })

    return detections