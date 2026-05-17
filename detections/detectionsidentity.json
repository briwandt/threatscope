import yaml


def run_detections(input_text):

    detections = []

    # =========================
    # LOAD YAML RULES
    # =========================

    with open(
        "detections/identity.yml",
        "r"
    ) as yaml_file:

        rule_data = yaml.safe_load(
            yaml_file
        )

    rules = rule_data["rules"]

    # =========================
    # MATCH RULES
    # =========================

    for rule in rules:

        matched = True

        for keyword in rule["match"]:

            if keyword.lower() not in input_text.lower():

                matched = False
                break

        if matched:

            detections.append({
                "title": rule["title"],
                "severity": rule["severity"],
                "confidence": rule["confidence"],
                "mitre": rule["mitre"],
                "description": rule["description"],
                "hunt_pivot": rule["hunt_pivot"]
            })

    # =========================
    # STATIC DETECTIONS
    # =========================

    if "powershell.exe" in input_text:

        detections.append({
            "title": "PowerShell Execution",
            "severity": "HIGH",
            "confidence": "HIGH",
            "mitre": "T1059.001 - PowerShell",
            "description": "Potential living-off-the-land PowerShell execution detected.",
            "hunt_pivot": "Review encoded commands, parent processes, network activity, and process lineage."
        })

    if "wmic.exe" in input_text:

        detections.append({
            "title": "WMI Lateral Movement Activity",
            "severity": "HIGH",
            "confidence": "HIGH",
            "mitre": "T1047 - Windows Management Instrumentation",
            "description": "WMI execution may indicate lateral movement or remote execution activity.",
            "hunt_pivot": "Identify source hosts, created processes, authentication events, and target systems."
        })

    if "SS7" in input_text:

        detections.append({
            "title": "SS7 Signaling Anomaly",
            "severity": "HIGH",
            "confidence": "MEDIUM",
            "mitre": "T1430 - Location Tracking",
            "description": "Abnormal SS7 signaling activity may indicate subscriber tracking or telecom interception.",
            "hunt_pivot": "Review signaling origin networks, request volume spikes, and subscriber targeting behavior."
        })

    if "Diameter" in input_text:

        detections.append({
            "title": "Diameter Signaling Abuse",
            "severity": "HIGH",
            "confidence": "MEDIUM",
            "mitre": "T1430 - Location Tracking",
            "description": "Unexpected Diameter roaming or authentication behavior detected.",
            "hunt_pivot": "Review roaming authentication requests, peer networks, and failed authentication anomalies."
        })

    if "GTP" in input_text:

        detections.append({
            "title": "GTP Roaming Session Anomaly",
            "severity": "HIGH",
            "confidence": "MEDIUM",
            "mitre": "T1430 - Location Tracking",
            "description": "Abnormal roaming session activity identified within telecom infrastructure telemetry.",
            "hunt_pivot": "Analyze GTP tunnel activity, roaming partners, subscriber sessions, and session duration anomalies."
        })

    if "unverified" in input_text:

        detections.append({
            "title": "Contractor Verification Risk",
            "severity": "MEDIUM",
            "confidence": "LOW",
            "mitre": "T1078 - Valid Accounts",
            "description": "Unverified contractor onboarding activity detected with elevated access requests.",
            "hunt_pivot": "Review onboarding records, access requests, VPN approvals, and privileged entitlement assignments."
        })

    if "protocol=ssh" in input_text:

        detections.append({
            "title": "SSH Remote Management Enabled",
            "severity": "MEDIUM",
            "confidence": "MEDIUM",
            "mitre": "T1021 - Remote Services",
            "description": "SSH remote management enabled on edge infrastructure.",
            "hunt_pivot": "Review infrastructure changes, maintenance windows, actor identity, and originating IP addresses."
        })

    return detections