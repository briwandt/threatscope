# engine/detections.py

def run_detections(input_text):
    detections = []

    def add_detection(title, severity, confidence, mitre, description, hunt_pivot):
        detections.append({
            "title": title,
            "severity": severity,
            "confidence": confidence,
            "mitre": mitre,
            "description": description,
            "hunt_pivot": hunt_pivot
        })

    if "vpn_login" in input_text and ("country=RU" in input_text or 'country": "RU' in input_text):
        add_detection(
            title="Suspicious Foreign VPN Access",
            severity="HIGH",
            confidence="MEDIUM",
            mitre="T1078 - Valid Accounts",
            description="User authenticated from a foreign source location associated with elevated access risk.",
            hunt_pivot="Review VPN logins, failed authentication attempts, device fingerprints, and source ASN activity."
        )

    if "mfa_push" in input_text and "approved" in input_text:
        add_detection(
            title="MFA Approval Following Suspicious Login",
            severity="HIGH",
            confidence="MEDIUM",
            mitre="T1621 - Multi-Factor Authentication Request Generation",
            description="MFA approval observed following suspicious authentication activity.",
            hunt_pivot="Investigate MFA fatigue, repeated push attempts, and anomalous device registrations."
        )

    if "powershell.exe" in input_text:
        add_detection(
            title="PowerShell Execution",
            severity="HIGH",
            confidence="HIGH",
            mitre="T1059.001 - PowerShell",
            description="Potential living-off-the-land PowerShell execution detected.",
            hunt_pivot="Review encoded commands, parent processes, network activity, and process lineage."
        )

    if "wmic.exe" in input_text:
        add_detection(
            title="WMI Lateral Movement Activity",
            severity="HIGH",
            confidence="HIGH",
            mitre="T1047 - Windows Management Instrumentation",
            description="WMI execution may indicate lateral movement or remote execution activity.",
            hunt_pivot="Identify source hosts, created processes, authentication events, and target systems."
        )

    if "GlobalAdmin" in input_text:
        add_detection(
            title="Privileged Cloud Role Assignment",
            severity="CRITICAL",
            confidence="HIGH",
            mitre="T1098 - Account Manipulation",
            description="Privileged administrative role assignment detected in cloud identity infrastructure.",
            hunt_pivot="Review role assignment history, conditional access changes, and recent authentication patterns."
        )

    if "oauth" in input_text.lower():
        add_detection(
            title="OAuth Persistence Activity",
            severity="CRITICAL",
            confidence="MEDIUM",
            mitre="T1550 - Use Alternate Authentication Material",
            description="Suspicious OAuth consent activity may indicate mailbox persistence or token abuse.",
            hunt_pivot="Investigate OAuth grants, application permissions, consent actor, and mailbox access patterns."
        )

    if "SS7" in input_text:
        add_detection(
            title="SS7 Signaling Anomaly",
            severity="HIGH",
            confidence="MEDIUM",
            mitre="T1430 - Location Tracking",
            description="Abnormal SS7 signaling activity may indicate subscriber tracking or telecom interception.",
            hunt_pivot="Review signaling origin networks, request volume spikes, and subscriber targeting behavior."
        )

    if "Diameter" in input_text:
        add_detection(
            title="Diameter Signaling Abuse",
            severity="HIGH",
            confidence="MEDIUM",
            mitre="T1430 - Location Tracking",
            description="Unexpected Diameter roaming or authentication behavior detected.",
            hunt_pivot="Review roaming authentication requests, peer networks, and failed authentication anomalies."
        )

    if "GTP" in input_text:
        add_detection(
            title="GTP Roaming Session Anomaly",
            severity="HIGH",
            confidence="MEDIUM",
            mitre="T1430 - Location Tracking",
            description="Abnormal roaming session activity identified within telecom infrastructure telemetry.",
            hunt_pivot="Analyze GTP tunnel activity, roaming partners, subscriber sessions, and session duration anomalies."
        )

    if "unverified" in input_text:
        add_detection(
            title="Contractor Verification Risk",
            severity="MEDIUM",
            confidence="LOW",
            mitre="T1078 - Valid Accounts",
            description="Unverified contractor onboarding activity detected with elevated access requests.",
            hunt_pivot="Review onboarding records, access requests, VPN approvals, and privileged entitlement assignments."
        )

    if "protocol=ssh" in input_text or 'protocol": "ssh' in input_text:
        add_detection(
            title="SSH Remote Management Enabled",
            severity="MEDIUM",
            confidence="MEDIUM",
            mitre="T1021 - Remote Services",
            description="SSH remote management enabled on edge infrastructure.",
            hunt_pivot="Review infrastructure changes, maintenance windows, actor identity, and originating IP addresses."
        )

    return detections