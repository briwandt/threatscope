import streamlit as st
from openai import OpenAI
from streamlit_autorefresh import st_autorefresh

# =========================
# PAGE CONFIG
# =========================

st.set_page_config(
    page_title="ThreatScope",
    layout="wide"
)

# =========================
# GROQ CLIENT
# =========================

client = OpenAI(
    api_key=st.secrets["GROQ_API_KEY"],
    base_url="https://api.groq.com/openai/v1"
)

# =========================
# TITLE
# =========================

st.title("ThreatScope")

st.write(
    "AI-assisted defensive threat hunting platform for telecom and cloud environments."
)

# =========================
# SIMULATED SIEM TELEMETRY
# =========================

sample_logs = {

    "VPN / Initial Access Broker Activity": """
2026-05-11T07:41:22Z source=SIEM event=vpn_login user=contractor.mills status=success source_ip=185.220.101.44 country=RU device=new-device
2026-05-11T07:44:02Z source=SIEM event=vpn_login user=contractor.mills status=success source_ip=104.28.45.12 country=US device=known-laptop
2026-05-11T07:48:19Z source=SIEM event=mfa_push user=contractor.mills result=approved source_ip=185.220.101.44
""",

    "Edge Device / LOTL Activity": """
2026-05-11T07:51:30Z source=SIEM device=edge-fw-07 event=admin_login user=contractor.mills source_ip=185.220.101.44
2026-05-11T07:56:10Z source=SIEM device=cisco-edge-12 event=remote_mgmt_enabled protocol=ssh actor=contractor.mills
2026-05-11T08:02:44Z host=CORP-LT-448 process=powershell.exe command="-enc SQBFAFgA..." parent=winword.exe
2026-05-11T08:04:30Z host=CORP-LT-448 process=wmic.exe command="wmic process call create powershell.exe"
2026-05-11T08:06:55Z user=contractor.mills azure_role_assignment role=GlobalAdmin actor=contractor.mills
""",

    "Telecom Signaling Threats": """
2026-05-11T08:21:55Z source=telecom_signaling protocol=Diameter event=unusual_roaming_auth subscriber_region=US request_origin=foreign_network
2026-05-11T08:25:13Z source=telecom_signaling protocol=SS7 event=location_query_volume_spike subscriber_count=218 request_origin=foreign_network
2026-05-11T08:29:45Z source=telecom_signaling protocol=GTP event=abnormal_roaming_session subscriber_region=US request_origin=foreign_network
""",

    "Fraudulent Worker / Contractor Risk": """
2026-05-11T08:31:42Z applicant=remote.engineer.17 resume_signal=overlapping_employment verification_status=unverified requested_access=vpn,router_admin
2026-05-11T08:36:09Z worker=contractor.mills access_request=vpn,firewall_admin,cisco_edge_admin manager_approval=pending
2026-05-11T08:40:12Z worker=contractor.mills login_location_change=US_to_RU time_window_minutes=15 device_status=new-device
2026-05-11T08:44:19Z user=contractor.mills oauth_app_consent app=UnknownMailSync permissions=Mail.Read offline_access
"""
}

# =========================
# SIDEBAR SETTINGS
# =========================

st.sidebar.header("Settings")

auto_hunt = st.sidebar.checkbox(
    "Enable Auto Hunt Mode"
)

alert_threshold = st.sidebar.slider(
    "Alert Threshold",
    1,
    15,
    4
)

# =========================
# AUTO REFRESH
# =========================

if auto_hunt:

    st_autorefresh(
        interval=10000,
        key="threatscope_refresh"
    )

    st.sidebar.success(
        "Auto Hunt Mode Enabled"
    )

# =========================
# TELEMETRY SOURCE
# =========================

selected_source = st.selectbox(
    "Simulated SIEM / Environment Source",
    list(sample_logs.keys())
)

input_text = st.text_area(
    "Simulated SIEM / Environment Telemetry",
    value=sample_logs[selected_source],
    height=300
)

# =========================
# ANALYSIS TRIGGER
# =========================

if st.button("Analyze") or auto_hunt:

    # =========================
    # CORRELATION ENGINE
    # =========================

    risk_score = 0
    findings = []

    if "vpn_login" in input_text:
        risk_score += 1
        findings.append("VPN access activity detected")

    if "country=RU" in input_text:
        risk_score += 2
        findings.append("Foreign login location detected")

    if "powershell.exe" in input_text:
        risk_score += 2
        findings.append("PowerShell execution detected")

    if "wmic.exe" in input_text:
        risk_score += 2
        findings.append("WMI execution detected")

    if "oauth" in input_text.lower():
        risk_score += 2
        findings.append("OAuth consent activity detected")

    if "GlobalAdmin" in input_text:
        risk_score += 3
        findings.append("Privileged role assignment detected")

    if "SS7" in input_text:
        risk_score += 3
        findings.append("SS7 signaling anomaly detected")

    if "Diameter" in input_text:
        risk_score += 2
        findings.append("Diameter signaling anomaly detected")

    if "GTP" in input_text:
        risk_score += 2
        findings.append("GTP signaling anomaly detected")

    if "unverified" in input_text:
        risk_score += 2
        findings.append("Unverified contractor/applicant activity detected")

    if "protocol=ssh" in input_text:
        risk_score += 1
        findings.append("SSH remote management activity detected")

    # =========================
    # SEVERITY
    # =========================

    if risk_score >= 10:
        severity = "CRITICAL"

    elif risk_score >= 7:
        severity = "HIGH"

    elif risk_score >= 4:
        severity = "MEDIUM"

    else:
        severity = "LOW"

    # =========================
    # ALERTING ENGINE
    # =========================

    if len(findings) >= 2 and risk_score >= alert_threshold:

        st.error(
            "ALERT: Correlated telecom threat activity detected"
        )

    elif len(findings) >= 1:

        st.warning(
            "NOTICE: Suspicious activity observed"
        )

    else:

        st.success(
            "No significant threat indicators detected"
        )

    # =========================
    # DISPLAY CORRELATION RESULTS
    # =========================

    st.subheader("Correlation Engine Findings")

    st.write(f"Risk Score: {risk_score}")
    st.write(f"Severity: {severity}")

    for finding in findings:
        st.write(f"- {finding}")

    # =========================
    # PROMPT
    # =========================

    prompt = f"""
You are a defensive cyber threat intelligence analyst supporting a large telecom environment.

Analyze the activity for telecom-relevant threats, especially:

- Living-off-the-land behavior
- PowerShell abuse
- SSH abuse
- WMI execution
- Initial Access Broker activity
- telecom credential abuse
- VPN compromise
- edge infrastructure targeting
- SS7 abuse
- Diameter abuse
- GTP abuse
- roaming abuse
- cloud identity compromise
- OAuth persistence
- fraudulent contractor activity
- suspicious insider behavior

Focus only on defensive analysis, triage, containment, and threat hunting.

Activity:
{input_text}

Preliminary Correlation Findings:
{findings}

Calculated Risk Score:
{risk_score}

Calculated Severity:
{severity}

Identify combinations of weak signals that together may indicate advanced intrusion activity.

Include MITRE ATT&CK technique IDs where applicable.

Provide example SIEM hunt pivots and telemetry pivots.

Return the analysis in this format:

1. Executive Summary
2. Threat Category
3. Correlated Indicators
4. LOTL Indicators
5. Telecom Signaling Risk
6. Identity / Contractor Risk
7. Possible APT Scenario
8. MITRE ATT&CK Mapping
9. Recommended Hunt Queries
10. Recommended Containment Steps
11. Confidence
12. Severity
"""

    # =========================
    # GROQ LLM ANALYSIS
    # =========================

    with st.spinner("Analyzing telemetry with Groq LLM..."):

        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {
                    "role": "user",
                    "content": prompt
                }
            ]
        )

    # =========================
    # DISPLAY AI ANALYSIS
    # =========================

    st.subheader("ThreatScope AI Analysis")

    st.write(response.choices[0].message.content)